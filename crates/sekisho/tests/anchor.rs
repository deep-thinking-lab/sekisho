#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine as _;
use sekisho_core::{
    AuditEntry, AuditKind, Checkpoint, CoreError, Ed25519Signer, Principal, Signer, UserId,
    checkpoint,
};
use serde_json::Value;
use std::{
    fs,
    hash::BuildHasher,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const INPUT: &str = "operator\npassword\npassword\n";

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        let suffix = std::hash::RandomState::new().hash_one(name);
        Self(std::env::temp_dir().join(format!(
            "sekisho-anchor-{name}-{}-{suffix}",
            std::process::id()
        )))
    }

    fn initialize(&self) -> Running {
        let mut child = self
            .up_command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(INPUT.as_bytes())
            .unwrap();
        Running::wait_for_listening(child)
    }

    fn start(&self) -> Running {
        let child = self
            .up_command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Running::wait_for_listening(child)
    }

    fn up_command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekisho"));
        command.args(["up", "--home"]).arg(&self.0).args([
            "--bind",
            "127.0.0.1:0",
            "--admin-password-stdin",
        ]);
        command
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .env("SEKISHO_HOME", &self.0)
            .args(args)
            .output()
            .unwrap()
    }

    fn run_cli(&self, args: &[&str]) -> Output {
        let output = self.cli(args);
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn write_config(&self, config: &str) {
        fs::write(self.0.join("config.toml"), config).unwrap();
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("sekisho.db")).unwrap()
    }

    fn audit(&self) -> Vec<AuditEntry> {
        let connection = self.sql();
        connection
            .prepare("SELECT body FROM audit ORDER BY seq")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|body| serde_json::from_str(&body.unwrap()).unwrap())
            .collect()
    }

    fn audit_signer(&self) -> Ed25519Signer {
        let secret: [u8; 32] = fs::read(self.0.join("keys/audit.ed25519"))
            .unwrap()
            .try_into()
            .unwrap();
        Ed25519Signer::from_secret_bytes("audit", &secret)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running {
    child: Child,
}

impl Running {
    fn wait_for_listening(mut child: Child) -> Self {
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.unwrap().starts_with("Listening on ") {
                    let _ = send.send(());
                    return;
                }
            }
        });
        receive
            .recv_timeout(Duration::from_secs(20))
            .expect("server must become ready");
        Self { child }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone)]
struct HookState {
    requests: Arc<Mutex<Vec<Recorded>>>,
    statuses: Vec<u16>,
    hang: bool,
}

struct Recorded {
    content_type: Option<String>,
    authorization: Option<String>,
    body: Vec<u8>,
    at: Instant,
}

struct Hook {
    url: String,
    state: HookState,
    server: tokio::task::JoinHandle<()>,
}

impl Hook {
    async fn start(statuses: &[u16], hang: bool) -> Self {
        let state = HookState {
            requests: Arc::new(Mutex::new(Vec::new())),
            statuses: statuses.to_vec(),
            hang,
        };
        let app = Router::new()
            .route("/hook", post(record_hook))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, server }
    }

    async fn wait_for_requests(&self, count: usize) {
        let started = Instant::now();
        loop {
            if self.state.requests.lock().unwrap().len() >= count {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "webhook did not receive {count} requests"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn requests(&self) -> Vec<(Option<String>, Checkpoint, Instant)> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                (
                    request.content_type.clone(),
                    serde_json::from_slice(&request.body).unwrap(),
                    request.at,
                )
            })
            .collect()
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn record_hook(State(state): State<HookState>, headers: HeaderMap, body: Bytes) -> Response {
    let attempt = {
        let mut requests = state.requests.lock().unwrap();
        requests.push(Recorded {
            content_type: headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            authorization: headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            body: body.to_vec(),
            at: Instant::now(),
        });
        requests.len()
    };
    if state.hang {
        std::future::pending::<()>().await;
    }
    let status = state
        .statuses
        .get(attempt.saturating_sub(1))
        .copied()
        .unwrap_or(200);
    StatusCode::from_u16(status).unwrap().into_response()
}

fn wait_for_audit_kinds(home: &Home, expected: &[AuditKind]) {
    let started = Instant::now();
    loop {
        let entries = home.audit();
        if expected
            .iter()
            .all(|kind| entries.iter().any(|entry| entry.kind() == *kind))
        {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "audit kinds {expected:?} did not arrive"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn external_key(home: &Home) -> String {
    let signer = home.audit_signer();
    format!(
        "audit={}",
        base64::engine::general_purpose::STANDARD.encode(signer.public_key().to_bytes())
    )
}

fn assert_invalid(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verify_against(file: &Path, checkpoint_path: &Path, key: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .args(["audit", "verify"])
        .arg(file)
        .args([
            "--against-checkpoint",
            checkpoint_path.to_str().unwrap(),
            "--pubkey",
            key,
        ])
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_posts_signed_checkpoint_on_entry_threshold() {
    let home = Home::new("threshold");
    drop(home.initialize());
    let initial_entries = home.audit().len();
    let token_file = home.0.join("anchor.token");
    fs::write(&token_file, b"anchor-secret\n").unwrap();
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();
    let hook = Hook::start(&[200], false).await;
    home.write_config(&format!(
        "[anchor]\nwebhook_url = '{}'\ntoken_file = 'anchor.token'\ninterval_seconds = 3600\nevery_entries = {}\n",
        hook.url,
        initial_entries + 2
    ));
    let _server = home.start();

    tokio::time::sleep(Duration::from_millis(1200)).await;
    let started_entries = home.audit().len();
    assert!(started_entries < initial_entries + 2);
    assert!(
        hook.requests().is_empty(),
        "worker anchored before the entry threshold"
    );
    home.run_cli(&["agent", "add", "claude"]);
    hook.wait_for_requests(1).await;
    wait_for_audit_kinds(&home, &[AuditKind::AnchorSent]);

    let requests = hook.requests();
    assert_eq!(requests[0].0.as_deref(), Some("sekisho-checkpoint"));
    assert_eq!(
        hook.state.requests.lock().unwrap()[0]
            .authorization
            .as_deref(),
        Some("Bearer anchor-secret")
    );
    let posted = &requests[0].1;
    assert_eq!(
        posted.seq, started_entries as u64,
        "checkpoint should name the threshold entry"
    );
    let entries = home.audit();
    let anchored = entries
        .iter()
        .find(|entry| entry.seq() == posted.seq)
        .expect("checkpoint should name an audit entry");
    let expected = checkpoint(anchored, posted.at, &home.audit_signer()).unwrap();
    assert_eq!(posted, &expected);
    assert!(
        !serde_json::to_string(&home.audit())
            .unwrap()
            .contains("anchor-secret")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_records_cannot_be_impersonated() {
    let home = Home::new("impersonation");
    drop(home.initialize());
    let hook = Hook::start(&[200], false).await;
    home.write_config(&format!(
        "[anchor]\nwebhook_url = '{}'\ninterval_seconds = 3600\nevery_entries = 2\n",
        hook.url
    ));
    let _server = home.start();
    home.run_cli(&["agent", "add", "claude"]);
    hook.wait_for_requests(1).await;
    wait_for_audit_kinds(&home, &[AuditKind::AnchorSent]);

    let anchor = home
        .audit()
        .into_iter()
        .find(|entry| entry.kind() == AuditKind::AnchorSent)
        .expect("anchor attempt should be audited");
    let system = UserId::try_from("system").unwrap();
    assert_eq!(anchor.actor(), &Principal::User(system));
    for reserved in ["system", "System", "sekisho-admin", "SEKISHO-admin"] {
        assert!(
            matches!(
                UserId::try_from_human(reserved),
                Err(CoreError::ReservedUserId(_))
            ),
            "{reserved:?} must not create a human user"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_failure_is_audited_and_retried() {
    let home = Home::new("retry");
    drop(home.initialize());
    let hook = Hook::start(&[500, 200], false).await;
    home.write_config(&format!(
        "[anchor]\nwebhook_url = '{}'\ninterval_seconds = 3600\nevery_entries = 2\n",
        hook.url
    ));
    let _server = home.start();

    hook.wait_for_requests(2).await;
    wait_for_audit_kinds(&home, &[AuditKind::AnchorFailed, AuditKind::AnchorSent]);
    let requests = hook.requests();
    assert!(
        requests[1].2.duration_since(requests[0].2) >= Duration::from_millis(500),
        "retry should use backoff"
    );
    let failure = home
        .audit()
        .into_iter()
        .find(|entry| entry.kind() == AuditKind::AnchorFailed)
        .unwrap();
    assert_eq!(failure.subject()["error_class"], "http_status");
    assert_eq!(failure.subject()["status"], 500);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_task_survives_store_error() {
    let home = Home::new("store-error");
    drop(home.initialize());
    let initial_entries = home.audit().len();
    let hook = Hook::start(&[200], false).await;
    home.write_config(&format!(
        "[anchor]\nwebhook_url = '{}'\ninterval_seconds = 3600\nevery_entries = {}\n",
        hook.url,
        initial_entries + 2
    ));
    let _server = home.start();
    let connection = rusqlite::Connection::open(home.0.join("sekisho.db")).unwrap();
    let corrupt_seq: u64 = connection
        .query_row("SELECT coalesce(max(seq), 0) + 1 FROM audit", [], |row| {
            row.get(0)
        })
        .unwrap();
    connection
        .execute(
            "INSERT INTO audit(seq, body) VALUES (?, 'not-json')",
            [corrupt_seq],
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    connection
        .execute_batch(
            "CREATE TRIGGER fail_anchor_audit BEFORE INSERT ON audit \
             WHEN json_extract(NEW.body, '$.kind') = 'AnchorSent' \
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
    drop(connection);
    home.sql()
        .execute("DELETE FROM audit WHERE body = 'not-json'", [])
        .unwrap();

    home.run_cli(&["agent", "add", "after-store-error"]);
    home.run_cli(&["agent", "add", "cross-threshold"]);
    hook.wait_for_requests(1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    home.sql()
        .execute_batch("DROP TRIGGER fail_anchor_audit")
        .unwrap();
    wait_for_audit_kinds(&home, &[AuditKind::AnchorSent]);
    assert_eq!(
        home.audit()
            .iter()
            .filter(|entry| entry.kind() == AuditKind::AnchorSent)
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_failures_are_rate_limited() {
    let home = Home::new("rate-limited");
    drop(home.initialize());
    let hook = Hook::start(&[500, 500, 200], false).await;
    home.write_config(&format!(
        "[anchor]\nwebhook_url = '{}'\ninterval_seconds = 3600\nevery_entries = 2\n",
        hook.url
    ));
    let _server = home.start();

    hook.wait_for_requests(3).await;
    wait_for_audit_kinds(&home, &[AuditKind::AnchorFailed, AuditKind::AnchorSent]);
    let entries = home.audit();
    let failed = entries
        .iter()
        .filter(|entry| entry.kind() == AuditKind::AnchorFailed)
        .collect::<Vec<_>>();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].subject()["count"], 1);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.kind() == AuditKind::AnchorSent)
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchor_never_blocks_writes() {
    let home = Home::new("nonblocking");
    drop(home.initialize());
    let hook = Hook::start(&[], true).await;
    home.write_config(&format!(
        "[anchor]\nwebhook_url = '{}'\ninterval_seconds = 3600\nevery_entries = 2\n",
        hook.url
    ));
    let _server = home.start();
    hook.wait_for_requests(1).await;

    let started = Instant::now();
    home.run_cli(&["agent", "add", "while-webhook-hangs"]);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "audit write waited for the webhook"
    );
}

#[test]
fn verify_against_saved_anchor_detects_truncation() {
    let home = Home::new("verify-anchor");
    drop(home.initialize());
    home.run_cli(&["agent", "add", "first"]);
    let old_export = home.0.join("old.jsonl");
    home.run_cli(&["audit", "export", "--out", old_export.to_str().unwrap()]);

    home.run_cli(&["agent", "add", "second"]);
    let new_export = home.0.join("new.jsonl");
    home.run_cli(&["audit", "export", "--out", new_export.to_str().unwrap()]);
    let trailer: Value = fs::read_to_string(&new_export)
        .unwrap()
        .lines()
        .last()
        .map(|line| serde_json::from_str(line).unwrap())
        .unwrap();
    let anchor: Checkpoint = serde_json::from_value(trailer["checkpoint"].clone()).unwrap();
    let anchor_file = home.0.join("anchor.json");
    fs::write(&anchor_file, serde_json::to_vec(&anchor).unwrap()).unwrap();
    let key = external_key(&home);

    let accepted = verify_against(&new_export, &anchor_file, &key);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let new_chain = home.0.join("new-chain.jsonl");
    let new_contents = fs::read_to_string(&new_export).unwrap();
    let new_lines = new_contents.lines().collect::<Vec<_>>();
    fs::write(
        &new_chain,
        new_lines[..new_lines.len() - 1].join("\n") + "\n",
    )
    .unwrap();
    let accepted_chain = verify_against(&new_chain, &anchor_file, &key);
    assert!(
        accepted_chain.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted_chain.stderr)
    );
    let rejected = verify_against(&old_export, &anchor_file, &key);
    assert_invalid(&rejected);
    let error = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        error.contains(&format!("before checkpoint {}", anchor.seq)),
        "{error}"
    );

    let chain = home.0.join("old-chain.jsonl");
    let old_contents = fs::read_to_string(&old_export).unwrap();
    let entries = old_contents.lines().collect::<Vec<_>>();
    fs::write(&chain, entries[..entries.len() - 1].join("\n") + "\n").unwrap();
    let rejected_chain = verify_against(&chain, &anchor_file, &key);
    assert_invalid(&rejected_chain);
}

#[test]
fn anchor_requires_https_except_loopback() {
    let home = Home::new("https");
    drop(home.initialize());
    home.write_config(
        "[anchor]\nwebhook_url = 'http://example.com/checkpoint'\ninterval_seconds = 60\nevery_entries = 1\n",
    );
    let rejected = home
        .up_command()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let error = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        error.contains("HTTPS or a loopback host"),
        "unexpected error: {error}"
    );

    home.write_config(
        "[anchor]\nwebhook_url = 'http://127.0.0.1:9/checkpoint'\ninterval_seconds = 60\nevery_entries = 1\n",
    );
    let _server = home.start();
}

#[test]
fn anchor_token_file_must_stay_private() {
    let home = Home::new("token");
    drop(home.initialize());
    let token = home.0.join("anchor.token");
    fs::write(&token, b"secret").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
    home.write_config(
        "[anchor]\nwebhook_url = 'https://example.com/checkpoint'\ntoken_file = 'anchor.token'\ninterval_seconds = 60\nevery_entries = 1\n",
    );
    let rejected = home
        .up_command()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let error = String::from_utf8_lossy(&rejected.stderr);
    assert!(error.contains("0644"), "unexpected error: {error}");
}
