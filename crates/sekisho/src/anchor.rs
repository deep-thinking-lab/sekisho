use anyhow::{Context, Result, ensure};
use reqwest::Url;
use sekisho::store::{AuditRecord, Store};
use sekisho_core::{AuditEntry, AuditKind, Checkpoint, Principal, Timestamp, UserId};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

const DEFAULT_INTERVAL_SECONDS: u64 = 3600;
const DEFAULT_EVERY_ENTRIES: u64 = 1000;
const AUDIT_RETRY_ATTEMPTS: u8 = 3;
const AUDIT_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnchorConfig {
    pub(crate) webhook_url: Option<String>,
    pub(crate) token_file: Option<PathBuf>,
    pub(crate) interval_seconds: Option<u64>,
    pub(crate) every_entries: Option<u64>,
}

pub(crate) struct Anchor {
    webhook_url: Url,
    token: Option<String>,
    interval_seconds: u64,
    every_entries: u64,
    client: reqwest::Client,
}

#[derive(Clone)]
struct Failure {
    class: &'static str,
    status: Option<u16>,
}

#[derive(Clone)]
enum Attempt {
    Sent(u16),
    Failed(Failure),
}

#[derive(Default)]
struct FailureWindow {
    last_recorded: Option<tokio::time::Instant>,
    pending: u32,
}

impl FailureWindow {
    fn claim(&mut self) -> Option<u32> {
        let now = tokio::time::Instant::now();
        self.pending = self.pending.saturating_add(1);
        if self
            .last_recorded
            .is_some_and(|last| now.duration_since(last) < FAILURE_WINDOW)
        {
            return None;
        }
        let count = self.pending;
        self.pending = 0;
        self.last_recorded = Some(now);
        Some(count)
    }
}

impl Anchor {
    pub(crate) fn load(home: &Path, config: Option<AnchorConfig>) -> Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };
        let webhook_url = config
            .webhook_url
            .context("anchor webhook_url is required")?;
        let url = Url::parse(&webhook_url).context("invalid anchor webhook_url")?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "invalid anchor webhook_url"
        );
        let loopback = url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        ensure!(
            url.scheme() == "https" || loopback,
            "anchor webhook_url requires HTTPS or a loopback host"
        );
        let interval_seconds = config.interval_seconds.unwrap_or(DEFAULT_INTERVAL_SECONDS);
        ensure!(
            interval_seconds >= 60,
            "anchor interval_seconds must be at least 60"
        );
        let every_entries = config.every_entries.unwrap_or(DEFAULT_EVERY_ENTRIES);
        ensure!(every_entries > 0, "anchor every_entries must be at least 1");
        let token = config
            .token_file
            .map(|path| read_token(home, &path))
            .transpose()?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("cannot initialize anchor HTTP client")?;
        Ok(Some(Self {
            webhook_url: url,
            token,
            interval_seconds,
            every_entries,
            client,
        }))
    }

    pub(crate) async fn run(self, store: Arc<Store>) {
        let started_at = now();
        let interval_seconds = self.interval_seconds;
        let every_entries = self.every_entries;
        let mut failures = FailureWindow::default();
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let at = now();
            let check_store = store.clone();
            let checkpoint = tokio::task::spawn_blocking(move || {
                due_checkpoint(
                    check_store.as_ref(),
                    started_at,
                    at,
                    interval_seconds,
                    every_entries,
                )
            })
            .await;
            let checkpoint = match checkpoint {
                Ok(Ok(checkpoint)) => checkpoint,
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "anchor checkpoint check failed, retrying");
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
                Err(error) => {
                    tracing::error!(error = %error, "anchor checkpoint task failed, retrying");
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            if let Some(checkpoint) = checkpoint {
                self.send_with_retry(store.clone(), checkpoint, &mut failures)
                    .await;
            }
        }
    }

    async fn send_with_retry(
        &self,
        store: Arc<Store>,
        checkpoint: Checkpoint,
        failures: &mut FailureWindow,
    ) {
        let mut backoff = RETRY_BACKOFF;
        loop {
            let outcome = self.send(&checkpoint).await;
            match &outcome {
                Attempt::Sent(_) => {
                    if record_attempt_with_retry(store, checkpoint, outcome, 1)
                        .await
                        .is_err()
                    {
                        tracing::error!("anchor success audit failed after retries");
                    }
                    return;
                }
                Attempt::Failed(_) => {
                    if let Some(count) = failures.claim()
                        && record_attempt_with_retry(
                            store.clone(),
                            checkpoint.clone(),
                            outcome,
                            count,
                        )
                        .await
                        .is_err()
                    {
                        tracing::error!("anchor failure audit failed after retries");
                    }
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2).min(MAX_RETRY_BACKOFF);
        }
    }

    async fn send(&self, checkpoint: &Checkpoint) -> Attempt {
        let Ok(body) = serde_json::to_vec(checkpoint) else {
            return Attempt::Failed(Failure {
                class: "serialize",
                status: None,
            });
        };
        let mut request = self
            .client
            .post(self.webhook_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "sekisho-checkpoint")
            .body(body);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                Attempt::Sent(response.status().as_u16())
            }
            Ok(response) => Attempt::Failed(Failure {
                class: "http_status",
                status: Some(response.status().as_u16()),
            }),
            Err(error) if error.is_timeout() => Attempt::Failed(Failure {
                class: "timeout",
                status: None,
            }),
            Err(error) if error.is_connect() => Attempt::Failed(Failure {
                class: "connection",
                status: None,
            }),
            Err(_) => Attempt::Failed(Failure {
                class: "request",
                status: None,
            }),
        }
    }
}

fn due_checkpoint(
    store: &Store,
    started_at: Timestamp,
    now: Timestamp,
    interval_seconds: u64,
    every_entries: u64,
) -> Result<Option<Checkpoint>> {
    let Some(latest) = store.audit_latest_entry()? else {
        return Ok(None);
    };
    let previous = store.audit_latest_anchor_attempt()?;
    let retry = previous
        .as_ref()
        .is_some_and(|entry| entry.kind() == AuditKind::AnchorFailed);
    let entries_due = match &previous {
        Some(previous) => latest.seq().saturating_sub(previous.seq()) >= every_entries,
        None => latest.seq().saturating_add(1) >= every_entries,
    };
    let interval = i64::try_from(interval_seconds).unwrap_or(i64::MAX);
    let baseline = previous.as_ref().map_or(started_at, AuditEntry::at);
    let time_due = now.as_secs().saturating_sub(baseline.as_secs()) >= interval;
    if retry || entries_due || time_due {
        Ok(store.audit_checkpoint_at(now)?)
    } else {
        Ok(None)
    }
}

async fn record_attempt_with_retry(
    store: Arc<Store>,
    checkpoint: Checkpoint,
    outcome: Attempt,
    count: u32,
) -> Result<()> {
    for attempt in 1..=AUDIT_RETRY_ATTEMPTS {
        let retry_store = store.clone();
        let retry_checkpoint = checkpoint.clone();
        let retry_outcome = outcome.clone();
        let result = tokio::task::spawn_blocking(move || {
            record_attempt(
                retry_store.as_ref(),
                &retry_checkpoint,
                &retry_outcome,
                count,
            )
        })
        .await;
        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(error = %error, attempt, "anchor attempt audit failed, retrying");
            }
            Err(error) => {
                tracing::error!(error = %error, attempt, "anchor attempt audit task failed");
            }
        }
        if attempt < AUDIT_RETRY_ATTEMPTS {
            tokio::time::sleep(AUDIT_RETRY_BACKOFF).await;
        }
    }
    Err(anyhow::anyhow!("anchor attempt audit failed after retries"))
}

fn record_attempt(
    store: &Store,
    checkpoint: &Checkpoint,
    outcome: &Attempt,
    count: u32,
) -> Result<()> {
    let actor =
        Principal::User(UserId::try_from("system").map_err(|error| anyhow::anyhow!(error))?);
    let (kind, subject) = match outcome {
        Attempt::Sent(status) => (
            AuditKind::AnchorSent,
            json!({
                "checkpoint_seq": checkpoint.seq,
                "checkpoint_hash": checkpoint.entry_hash,
                "checkpoint_at": checkpoint.at,
                "key_id": checkpoint.key_id,
                "status": status,
            }),
        ),
        Attempt::Failed(failure) => (
            AuditKind::AnchorFailed,
            json!({
                "checkpoint_seq": checkpoint.seq,
                "checkpoint_hash": checkpoint.entry_hash,
                "checkpoint_at": checkpoint.at,
                "key_id": checkpoint.key_id,
                "error_class": failure.class,
                "status": failure.status,
                "count": count,
            }),
        ),
    };
    store.transact(now(), |_| {
        Ok((
            (),
            vec![AuditRecord {
                kind,
                actor,
                subject,
            }],
        ))
    })?;
    Ok(())
}

fn read_token(home: &Path, configured: &Path) -> Result<String> {
    let path = home.join(configured);
    crate::up::check_mode(&path, false)?;
    ensure!(
        fs::metadata(&path)?.len() <= 4096,
        "anchor token_file is too large"
    );
    let token = fs::read_to_string(&path).context("cannot read anchor token_file")?;
    let token = token.trim();
    ensure!(!token.is_empty(), "anchor token_file must not be empty");
    ensure!(
        !token.chars().any(char::is_control),
        "anchor token_file contains invalid characters"
    );
    Ok(token.to_owned())
}

fn now() -> Timestamp {
    Timestamp::from(time::OffsetDateTime::now_utc().unix_timestamp().max(0))
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn anchor_token_file_rejects_control_characters() {
        let home =
            std::env::temp_dir().join(format!("sekisho-anchor-token-{}", std::process::id()));
        fs::create_dir_all(&home).unwrap();
        let path = home.join("anchor.token");
        fs::write(&path, b"safe\ntoken").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let config = AnchorConfig {
            webhook_url: Some("https://example.com/checkpoint".to_owned()),
            token_file: Some(PathBuf::from("anchor.token")),
            interval_seconds: Some(60),
            every_entries: Some(1),
        };

        let error = Anchor::load(&home, Some(config))
            .err()
            .expect("control character must be rejected");
        assert!(
            format!("{error:#}").contains("contains invalid characters"),
            "{error:#}"
        );
        fs::remove_dir_all(home).unwrap();
    }
}
