pub mod slack;
use crate::{
    server::{Clock, approval_url},
    store::{AuditRecord, Store},
};
use reqwest::{Url, redirect::Policy};
use sekisho_core::{Action, Approval, AuditKind, Principal, UserId};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender, channel as mpsc_channel, error::TrySendError};

const MAX_ATTEMPTS: u8 = 3;
const AUDIT_RETRY_ATTEMPTS: u8 = 3;
const AUDIT_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const NOTIFICATION_QUEUE_CAPACITY: usize = 1000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum NotificationConfigError {
    #[error("notification URL is invalid")]
    InvalidUrl,
    #[error("notification URL requires HTTPS or a loopback host")]
    InsecureUrl,
    #[error("cannot initialize notification HTTP client")]
    Client,
    #[error("interactive Slack requires a signing secret and a nonempty map to human user ids")]
    InvalidSlack,
    #[error(
        "conflicting user mapping, TOTP setting or webhook origin for one Slack signing secret"
    )]
    ConflictingSlack,
}

pub struct NotificationChannel {
    destination: Destination,
}

enum Destination {
    Webhook {
        url: Url,
        token: Option<String>,
        include_params: bool,
    },
    Slack {
        url: Url,
        integration: Option<Arc<slack::SlackIntegration>>,
    },
}

impl NotificationChannel {
    pub fn webhook(
        url: String,
        token: Option<String>,
        include_params: bool,
    ) -> Result<Self, NotificationConfigError> {
        Ok(Self {
            destination: Destination::Webhook {
                url: notification_url(&url)?,
                token,
                include_params,
            },
        })
    }

    pub fn slack(webhook_url: String) -> Result<Self, NotificationConfigError> {
        Ok(Self {
            destination: Destination::Slack {
                url: notification_url(&webhook_url)?,
                integration: None,
            },
        })
    }

    pub fn interactive_slack(
        webhook_url: String,
        secret: String,
        users: std::collections::BTreeMap<String, String>,
        requires_totp: bool,
        include_params: bool,
    ) -> Result<Self, NotificationConfigError> {
        let url = notification_url(&webhook_url)?;
        let integration = slack::SlackIntegration::new(
            secret,
            users,
            requires_totp,
            include_params,
            url.clone(),
        )?;
        Ok(Self {
            destination: Destination::Slack {
                url,
                integration: Some(Arc::new(integration)),
            },
        })
    }

    pub fn slack_integrations(
        channels: &[Self],
    ) -> Result<Vec<Arc<slack::SlackIntegration>>, NotificationConfigError> {
        let mut integrations: Vec<Arc<slack::SlackIntegration>> = Vec::new();
        for channel in channels {
            if let Destination::Slack {
                integration: Some(integration),
                ..
            } = &channel.destination
            {
                if let Some(existing) = integrations
                    .iter()
                    .find(|existing| existing.same_secret(integration))
                {
                    if !existing.same_settings(integration) {
                        return Err(NotificationConfigError::ConflictingSlack);
                    }
                } else {
                    integrations.push(integration.clone());
                }
            }
        }
        Ok(integrations)
    }

    fn kind(&self) -> &'static str {
        match &self.destination {
            Destination::Webhook { .. } => "webhook",
            Destination::Slack { .. } => "slack",
        }
    }

    fn projection(&self) -> Projection {
        match &self.destination {
            Destination::Webhook { include_params, .. } => Projection::Webhook {
                include_params: *include_params,
            },
            Destination::Slack { integration, .. } => Projection::Slack {
                interactive: integration.is_some(),
                one_click: integration.as_ref().is_some_and(|i| i.one_click()),
            },
        }
    }
}

pub struct Notifications {
    senders: Vec<ChannelSender>,
    public_url: String,
}

impl Notifications {
    pub fn start(
        channels: Vec<NotificationChannel>,
        store: Arc<Store>,
        public_url: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, NotificationConfigError> {
        if channels.is_empty() {
            return Ok(Self {
                senders: Vec::new(),
                public_url,
            });
        }
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| NotificationConfigError::Client)?;
        let mut senders = Vec::with_capacity(channels.len());
        for (index, channel) in channels.into_iter().enumerate() {
            let name = format!("{}-{}", channel.kind(), index.saturating_add(1));
            let projection = channel.projection();
            let (sender, receiver) = mpsc_channel(NOTIFICATION_QUEUE_CAPACITY);
            let audit = ChannelAudit {
                name: name.clone(),
                store: store.clone(),
                clock: clock.clone(),
                failures: Arc::new(Mutex::new(FailureWindow::default())),
            };
            tokio::spawn(run_channel(ChannelWorker {
                destination: channel.destination,
                client: client.clone(),
                receiver,
                audit: audit.clone(),
            }));
            senders.push(ChannelSender {
                name,
                projection,
                sender,
                audit,
            });
        }
        Ok(Self {
            senders,
            public_url,
        })
    }

    pub(crate) fn enqueue_created(&self, approvals: &[Approval]) {
        for approval in approvals {
            for channel in &self.senders {
                let body = match channel.projection {
                    Projection::Webhook { include_params } => {
                        webhook_body(approval, &self.public_url, include_params)
                    }
                    Projection::Slack {
                        interactive,
                        one_click,
                    } => slack_body(approval, &self.public_url, interactive, one_click),
                };
                match channel.sender.try_send(Job { body }) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        if let Some(count) = channel.audit.claim_failure() {
                            let audit = channel.audit.clone();
                            tokio::spawn(async move {
                                let outcome = AttemptOutcome::Failed {
                                    class: "queue_full",
                                    status: None,
                                };
                                if audit.record_with_retry(1, &outcome, count).await.is_err() {
                                    tracing::error!(
                                        channel = %audit.name,
                                        "queue-full notification audit failed"
                                    );
                                }
                            });
                        }
                    }
                    Err(TrySendError::Closed(_)) => {
                        tracing::warn!(channel = %channel.name, "notification worker unavailable");
                    }
                }
            }
        }
    }
}

struct ChannelSender {
    name: String,
    projection: Projection,
    sender: Sender<Job>,
    audit: ChannelAudit,
}

#[derive(Clone, Copy)]
enum Projection {
    Webhook {
        include_params: bool,
    },
    /// `one_click`: a button may approve without TOTP and the message shows the
    /// params (`slack_requires_totp = false` and `include_params = true`).
    Slack {
        interactive: bool,
        one_click: bool,
    },
}

struct Job {
    body: Value,
}

struct ChannelWorker {
    destination: Destination,
    client: reqwest::Client,
    receiver: Receiver<Job>,
    audit: ChannelAudit,
}

#[derive(Clone)]
struct ChannelAudit {
    name: String,
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    failures: Arc<Mutex<FailureWindow>>,
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

impl ChannelAudit {
    fn claim_failure(&self) -> Option<u32> {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .claim()
    }

    async fn record_with_retry(
        &self,
        attempt: u8,
        outcome: &AttemptOutcome,
        count: u32,
    ) -> Result<(), ()> {
        for audit_attempt in 1..=AUDIT_RETRY_ATTEMPTS {
            if record_outcome(
                self.store.clone(),
                self.clock.clone(),
                &self.name,
                attempt,
                outcome,
                count,
            )
            .await
            .is_ok()
            {
                return Ok(());
            }
            if audit_attempt < AUDIT_RETRY_ATTEMPTS {
                tracing::warn!(
                    channel = %self.name,
                    attempt = audit_attempt,
                    "notification outcome audit failed, retrying"
                );
                tokio::time::sleep(AUDIT_RETRY_BACKOFF).await;
            }
        }
        Err(())
    }
}

enum AttemptOutcome {
    Sent {
        status: u16,
    },
    Failed {
        class: &'static str,
        status: Option<u16>,
    },
}

async fn run_channel(mut worker: ChannelWorker) {
    while let Some(job) = worker.receiver.recv().await {
        let mut backoff = RETRY_BACKOFF;
        for attempt in 1..=MAX_ATTEMPTS {
            let outcome = send_attempt(&worker.client, &worker.destination, &job).await;
            let sent = matches!(outcome, AttemptOutcome::Sent { .. });
            let count = if sent {
                Some(1)
            } else {
                worker.audit.claim_failure()
            };
            if let Some(count) = count
                && worker
                    .audit
                    .record_with_retry(attempt, &outcome, count)
                    .await
                    .is_err()
            {
                tracing::error!(
                    channel = %worker.audit.name,
                    "notification outcome audit failed after retries"
                );
            }
            if sent {
                break;
            }
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
        }
    }
}

async fn send_attempt(
    client: &reqwest::Client,
    destination: &Destination,
    job: &Job,
) -> AttemptOutcome {
    let (url, token) = match destination {
        Destination::Webhook {
            url,
            token,
            include_params: _,
        } => (url, token.as_deref()),
        Destination::Slack { url, .. } => (url, None),
    };
    let mut request = client.post(url.clone()).json(&job.body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => AttemptOutcome::Sent {
            status: response.status().as_u16(),
        },
        Ok(response) => AttemptOutcome::Failed {
            class: "http_status",
            status: Some(response.status().as_u16()),
        },
        Err(error) if error.is_timeout() => AttemptOutcome::Failed {
            class: "timeout",
            status: None,
        },
        Err(error) if error.is_connect() => AttemptOutcome::Failed {
            class: "connection",
            status: None,
        },
        Err(_) => AttemptOutcome::Failed {
            class: "request",
            status: None,
        },
    }
}

async fn record_outcome(
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    channel: &str,
    attempt: u8,
    outcome: &AttemptOutcome,
    count: u32,
) -> Result<(), ()> {
    let actor = Principal::User(UserId::try_from("system").map_err(|_| ())?);
    let (kind, subject) = match outcome {
        AttemptOutcome::Sent { status } => (
            AuditKind::NotifySent,
            json!({
                "channel": channel,
                "attempt": attempt,
                "status": status,
            }),
        ),
        AttemptOutcome::Failed { class, status } => (
            AuditKind::NotifyFailed,
            json!({
                "channel": channel,
                "attempt": attempt,
                "error_class": class,
                "status": status,
                "count": count,
            }),
        ),
    };
    tokio::task::spawn_blocking(move || {
        store
            .transact(clock.now(), |_| {
                Ok((
                    (),
                    vec![AuditRecord {
                        kind,
                        actor,
                        subject,
                    }],
                ))
            })
            .map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn webhook_body(approval: &Approval, public_url: &str, include_params: bool) -> Value {
    let mut body = json!({
        "approval_id": approval.id().as_str(),
        "agent_id": approval.action().agent_id().as_str(),
        "tool": approval.action().tool().as_str(),
        "target": approval.action().target(),
        "rule": approval.rule(),
        "expires_at": approval.expires_at(),
        "url": approval_url(public_url, approval.id().as_str()),
    });
    if include_params {
        body["params"] = approval.action().params().clone();
    }
    body
}

/// Longest canonical params text a Slack approver is shown in full.
const SLACK_PARAMS_LIMIT: usize = 1500;

/// The action's canonical (JCS) params with obvious secrets redacted, and
/// whether anything was redacted; `None` when too long to show whole.
pub(crate) fn slack_params(action: &Action) -> Option<(String, bool)> {
    let text = serde_jcs::to_string(action.params()).ok()?;
    if text.chars().count() > SLACK_PARAMS_LIMIT {
        return None;
    }
    let shown = redact_secrets(&text);
    let redacted = shown != text;
    Some((shown, redacted))
}

/// Whether `key` names a secret. Errs broad: redaction only costs one-click
/// approval, while a miss posts a secret to Slack. The key is split into words
/// at `_`, `-`, `.` and camelCase boundaries. A strong name anywhere in the
/// joined words matches (`accessToken`, `DB_PASSWORD`, `x.auth.header`); `key`
/// matches only as a whole word (`api_key`, `privateKey`, but not `monkey`).
fn secret_key(key: &str) -> bool {
    const STRONG: [&str; 10] = [
        "token",
        "password",
        "passwd",
        "secret",
        "credential",
        "apikey",
        "privatekey",
        "auth",
        "cookie",
        "session",
    ];
    let mut words: Vec<String> = Vec::new();
    let mut previous_lower = false;
    for c in key.chars() {
        if matches!(c, '_' | '-' | '.') {
            words.push(String::new());
            previous_lower = false;
            continue;
        }
        if (c.is_ascii_uppercase() && previous_lower) || words.is_empty() {
            words.push(String::new());
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        if let Some(word) = words.last_mut() {
            word.push(c.to_ascii_lowercase());
        }
    }
    let joined: String = words.concat();
    STRONG.iter().any(|name| joined.contains(name)) || words.iter().any(|word| word == "key")
}

const REDACTED: &str = "[redacted]";

/// Best-effort removal of obvious secrets before params leave for Slack:
/// GitHub, AWS and Slack token prefixes, `Bearer <token>`, and the value of any
/// `key=value` or `key: value` whose key, at a key position, names a secret
/// (see [`secret_key`]). This is display hygiene, not a guarantee, and any
/// redaction means the approver must use the web inbox.
pub(crate) fn redact_secrets(text: &str) -> String {
    const PREFIXES: [&str; 10] = [
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "AKIA",
        "ASIA",
        "xoxb-",
        "xoxp-",
    ];
    let token_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '=');
    let chars: Vec<char> = text.chars().collect();
    // A value: optional spaces, quotes or escapes, then token characters.
    let value_end = |start: usize| {
        let mut j = start;
        while j < chars.len() && matches!(chars[j], ' ' | '"' | '\\') {
            j += 1;
        }
        let value = j;
        while j < chars.len() && token_char(chars[j]) {
            j += 1;
        }
        (value, j)
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let rest: String = chars[i..chars.len().min(i + 12)].iter().collect();
        let boundary = i == 0 || !chars[i - 1].is_ascii_alphanumeric();
        if boundary && let Some(prefix) = PREFIXES.iter().find(|p| rest.starts_with(**p)) {
            let mut j = i + prefix.chars().count();
            while j < chars.len() && token_char(chars[j]) {
                j += 1;
            }
            out.push_str(REDACTED);
            i = j;
            continue;
        }
        if boundary && rest.to_ascii_lowercase().starts_with("bearer ") {
            let (value, end) = value_end(i + 7);
            if end > value {
                out.extend(&chars[i..value]);
                out.push_str(REDACTED);
                i = end;
                continue;
            }
        }
        if matches!(chars[i], '=' | ':') {
            let mut k = i;
            while k > 0 && matches!(chars[k - 1], '"' | '\\' | ' ') {
                k -= 1;
            }
            let mut start = k;
            while start > 0
                && (chars[start - 1].is_ascii_alphanumeric()
                    || matches!(chars[start - 1], '_' | '-' | '.'))
            {
                start -= 1;
            }
            // A key starts the text or follows a separator, not the middle of a word.
            let at_key_position = start == 0
                || matches!(
                    chars[start - 1],
                    ' ' | '\t' | '"' | '\'' | '{' | ',' | '&' | '?' | ';' | '(' | '\\'
                );
            let key = chars[start..k].iter().collect::<String>();
            let key = key.trim_start_matches(['-', '.']);
            if at_key_position && !key.is_empty() && secret_key(key) {
                let (mut value, mut end) = value_end(i + 1);
                // `Authorization: Bearer <token>`: keep the scheme, redact the token.
                let scheme = chars[value..end]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase();
                if matches!(scheme.as_str(), "bearer" | "basic" | "token")
                    && chars.get(end) == Some(&' ')
                {
                    (value, end) = value_end(end);
                }
                if end > value {
                    out.extend(&chars[i..value]);
                    out.push_str(REDACTED);
                    i = end;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Whether a Slack button may approve this action without TOTP. Shell commands,
/// ref deletions, forced or unknown-force pushes, params too long to show whole,
/// and params with anything redacted need the web inbox: the approver must see
/// exactly what a click approves.
pub(crate) fn one_click_approvable(action: &Action) -> bool {
    let tool = action.tool().as_str();
    let params = action.params();
    let shell = tool.starts_with("hook:") && tool.ends_with("/bash");
    let risky_push = tool == "git.push"
        && (params.get("delete") != Some(&json!(false))
            || params.get("force") != Some(&json!(false)));
    slack_params(action).is_some_and(|(_, redacted)| !redacted) && !shell && !risky_push
}

fn slack_body(approval: &Approval, public_url: &str, interactive: bool, one_click: bool) -> Value {
    let mut body = json!({
        "text": format!(
            "Approval required for agent {}: {} on {}. Open {}",
            approval.action().agent_id(),
            approval.action().tool(),
            escape_slack(approval.action().target()),
            approval_url(public_url, approval.id().as_str()),
        ),
    });
    if interactive {
        let text = format!(
            "Approval required for agent {}: {} on {}. Open {}",
            approval.action().agent_id(),
            approval.action().tool(),
            approval.action().target(),
            approval_url(public_url, approval.id().as_str())
        );
        let text: String = text.chars().take(3000).collect();
        // Params reach Slack only when the approver decides there (one-click
        // with the include_params opt-in), and then with secrets redacted.
        let action = approval.action();
        let digest = action
            .digest()
            .map(|digest| digest.to_string())
            .unwrap_or_default();
        let details = Some(if one_click {
            let (params, redacted) = slack_params(action).unwrap_or_else(|| {
                (
                    "(too long to show here; open the web inbox)".to_owned(),
                    false,
                )
            });
            let label = if redacted {
                "Parameters (some values redacted)"
            } else {
                "Parameters"
            };
            let note = if one_click_approvable(action) {
                ""
            } else {
                "\nApprove needs TOTP in the web inbox for this action."
            };
            format!("{label}: {params}\nAction digest: {digest}{note}")
        } else {
            format!(
                "Action digest: {digest}\nParameters are not shown in Slack. Open the web inbox to review and approve."
            )
        });
        body["blocks"] = json!([
            {"type":"section", "text":{"type":"plain_text", "text":text}},
            {"type":"actions", "elements":[
                {"type":"button", "text":{"type":"plain_text","text":"Approve"}, "action_id":"approve", "value":approval.id().as_str(), "style":"primary"},
                {"type":"button", "text":{"type":"plain_text","text":"Deny"}, "action_id":"deny", "value":approval.id().as_str(), "style":"danger"}
            ]}
        ]);
        if let (Some(details), Some(blocks)) = (details, body["blocks"].as_array_mut()) {
            blocks.insert(
                1,
                json!({"type":"section", "text":{"type":"plain_text", "text":details}}),
            );
        }
    }
    body
}

fn escape_slack(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn notification_url(raw: &str) -> Result<Url, NotificationConfigError> {
    let url = Url::parse(raw).map_err(|_| NotificationConfigError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NotificationConfigError::InvalidUrl);
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(NotificationConfigError::InsecureUrl);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::redact_secrets;

    #[test]
    fn obvious_secrets_are_redacted() {
        for (input, gone) in [
            (
                "curl -H 'Authorization: Bearer abc.def-ghi' x",
                "abc.def-ghi",
            ),
            ("export GITHUB_TOKEN=ghx123 && run", "ghx123"),
            (r#"{"password":"hunter2"}"#, "hunter2"),
            (r#"{"command":"login --password=\"p4ss\""}"#, "p4ss"),
            (
                "push with ghp_0123456789abcdefABCDEF",
                "ghp_0123456789abcdefABCDEF",
            ),
            ("github_pat_11ABCDEF_xyz", "github_pat_11ABCDEF_xyz"),
            ("AKIAIOSFODNN7EXAMPLE in use", "AKIAIOSFODNN7EXAMPLE"),
            (
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG",
                "wJalrXUtnFEMI/K7MDENG",
            ),
            ("api_key: sk_live_123", "sk_live_123"),
        ] {
            let output = redact_secrets(input);
            assert!(!output.contains(gone), "{input} -> {output}");
            assert!(output.contains("[redacted]"), "{input} -> {output}");
        }
        for plain in [
            r#"{"delete":false,"force":false,"old":"a","ref":"refs/heads/main"}"#,
            r#"{"monkey":"banana","keyboard_layout":"qwerty"}"#,
            "echo keyboard: qwerty",
        ] {
            assert_eq!(redact_secrets(plain), plain);
        }
        for secret in [
            "GITHUB_TOKEN=abc",
            "--password=abc",
            r#"{"client_secret":"abc"}"#,
            r#"{"accessToken":"abc"}"#,
            "DB_PASSWORD=abc",
            "x.auth.header: abc",
            r#"{"apiKey":"abc"}"#,
            r#"{"privateKey":"abc"}"#,
            r#"{"notatoken":"abc"}"#,
            "session_id=abc",
        ] {
            assert!(!redact_secrets(secret).contains("abc"), "{secret}");
        }
    }
}
