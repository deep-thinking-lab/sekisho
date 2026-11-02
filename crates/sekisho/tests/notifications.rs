#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    hash::BuildHasher,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const INPUT: &str = "operator\npassword\npassword\n";
const PUBLIC_URL: &str = "https://sekisho.example";
const POLICY: &str = r#"version = 1
[[rule]]
name = "push"
tool = "git.push"
decision = "ask"
"#;

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        let suffix = std::hash::RandomState::new().hash_one(name);
        Self(std::env::temp_dir().join(format!(
            "sekisho-notifications-{name}-{}-{suffix}",
            std::process::id()
        )))
    }

    fn initialize(&self) -> Running {
        self.start_with_input(Some(INPUT))
    }

    fn start(&self) -> Running {
        self.start_with_input(None)
    }

    fn start_with_input(&self, input: Option<&str>) -> Running {
        let mut child = self
            .command()
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        Running::wait_for_listening(child)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekisho"));
        command.args(["up", "--home"]).arg(&self.0).args([
            "--bind",
            "127.0.0.1:0",
            "--admin-password-stdin",
        ]);
        command
    }

    fn write_policy(&self) {
        fs::write(self.0.join("policy.toml"), POLICY).unwrap();
    }

    fn write_config(&self, config: &str) {
        fs::write(self.0.join("config.toml"), config).unwrap();
    }

    fn write_secret(&self, name: &str, contents: &str, mode: u32) {
        let path = self.0.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn add_agent(&self) -> String {
        self.add_agent_named("claude")
    }

    fn add_agent_named(&self, name: &str) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .env("SEKISHO_HOME", &self.0)
            .args(["agent", "add", name])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_owned()
    }

    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("sekisho.db")).unwrap()
    }

    fn audit(&self) -> Vec<Value> {
        let connection = self.sql();
        connection
            .prepare("SELECT body FROM audit ORDER BY seq")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|body| serde_json::from_str(&body.unwrap()).unwrap())
            .collect()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running {
    child: Child,
    url: String,
}

impl Running {
    fn wait_for_listening(mut child: Child) -> Self {
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if let Some(url) = line.unwrap().strip_prefix("Listening on ") {
                    let _ = send.send(url.to_owned());
                    return;
                }
            }
        });
        let url = match receive.recv_timeout(Duration::from_secs(20)) {
            Ok(url) => url,
            Err(error) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "server must become ready: {error}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        };
        Self { child, url }
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
    statuses: Arc<HashMap<String, u16>>,
    hang: bool,
}

struct Recorded {
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

struct Hook {
    url: String,
    state: HookState,
    server: tokio::task::JoinHandle<()>,
}

impl Hook {
    async fn start(statuses: &[(&str, u16)], hang: bool) -> Self {
        let state = HookState {
            requests: Arc::new(Mutex::new(Vec::new())),
            statuses: Arc::new(
                statuses
                    .iter()
                    .map(|(path, status)| ((*path).to_owned(), *status))
                    .collect(),
            ),
            hang,
        };
        let app = Router::new()
            .route("/{*path}", post(record_hook))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, server }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url)
    }

    async fn wait_for_requests(&self, count: usize) {
        let started = Instant::now();
        loop {
            let received = self.state.requests.lock().unwrap().len();
            if received >= count {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "webhook received {received} of {count} requests"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn requests(&self) -> Vec<(String, Option<String>, Value)> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                (
                    request.path.clone(),
                    request.authorization.clone(),
                    serde_json::from_slice(&request.body).unwrap(),
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

async fn record_hook(
    State(state): State<HookState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    state.requests.lock().unwrap().push(Recorded {
        path: path.clone(),
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: body.to_vec(),
    });
    if state.hang {
        std::future::pending::<()>().await;
    }
    let status = state.statuses.get(&path).copied().unwrap_or(500);
    StatusCode::from_u16(status).unwrap().into_response()
}

async fn check(base: &str, token: &str, params: Value) -> (Duration, Value) {
    check_with_client(&reqwest::Client::new(), base, token, params).await
}

async fn check_with_client(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    params: Value,
) -> (Duration, Value) {
    let started = Instant::now();
    let response = client
        .post(format!("{base}/v1/check?wait=0"))
        .bearer_auth(token)
        .json(&json!({
            "tool": "git.push",
            "target": "repo",
            "params": params,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = response.json().await.unwrap();
    (started.elapsed(), body)
}

fn webhook_config(url: &str, token_file: Option<&str>, include_params: bool) -> String {
    let token = token_file
        .map(|path| format!("token_file = '{path}'\n"))
        .unwrap_or_default();
    format!(
        "public_url = '{PUBLIC_URL}'\n[[notify]]\ntype = 'webhook'\nurl = '{url}'\n{token}include_params = {include_params}\n"
    )
}

fn wait_for_notification_audit(home: &Home, sent: usize, failed: usize) -> Vec<Value> {
    let started = Instant::now();
    loop {
        let entries = home.audit();
        let sent_count = entries
            .iter()
            .filter(|entry| entry["kind"] == "NotifySent")
            .count();
        let failed_count = entries
            .iter()
            .filter(|entry| entry["kind"] == "NotifyFailed")
            .count();
        if sent_count >= sent && failed_count >= failed {
            return entries;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "notification audit did not arrive: {entries:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn pending_approval_triggers_webhook_with_link() {
    let hook = Hook::start(&[("/hook", 200)], false).await;
    let home = Home::new("webhook");
    drop(home.initialize());
    home.write_policy();
    home.write_secret("notify.token", "bearer-secret\n", 0o600);
    home.write_config(&webhook_config(
        &hook.endpoint("/hook"),
        Some("notify.token"),
        false,
    ));
    let server = home.start();
    let token = home.add_agent();

    let (_, response) = check(&server.url, &token, json!({})).await;
    assert_eq!(response["decision"], "ask");
    let approval_id = response["approval_id"].as_str().unwrap();
    hook.wait_for_requests(1).await;
    let requests = hook.requests();
    let body = &requests[0].2;
    assert_eq!(requests[0].0, "/hook");
    assert_eq!(requests[0].1.as_deref(), Some("Bearer bearer-secret"));
    assert_eq!(body["approval_id"], approval_id);
    assert_eq!(body["agent_id"], "claude");
    assert_eq!(body["tool"], "git.push");
    assert_eq!(body["target"], "repo");
    assert_eq!(body["rule"], "push");
    assert!(body["expires_at"].is_i64());
    assert_eq!(body["url"], format!("{PUBLIC_URL}/approvals/{approval_id}"));
}

#[tokio::test]
async fn params_excluded_by_default() {
    let hook = Hook::start(&[("/hook", 200)], false).await;
    let home = Home::new("params");
    drop(home.initialize());
    home.write_policy();
    let url = hook.endpoint("/hook");
    home.write_config(&format!(
        "public_url = '{PUBLIC_URL}'\n\
         [[notify]]\ntype = 'webhook'\nurl = '{url}'\ninclude_params = false\n\
         [[notify]]\ntype = 'webhook'\nurl = '{url}'\ninclude_params = true\n"
    ));
    let server = home.start();
    let token = home.add_agent();
    let params = json!({"secret": "param-canary", "nested": {"value": "nested-canary"}});

    let (_, response) = check(&server.url, &token, params.clone()).await;
    assert_eq!(response["decision"], "ask");
    hook.wait_for_requests(2).await;
    let requests = hook.requests();
    let excluded = requests
        .iter()
        .find(|(_, _, body)| body.get("params").is_none())
        .expect("default webhook must omit params");
    assert!(
        !serde_json::to_string(&excluded.2)
            .unwrap()
            .contains("canary")
    );
    let included = requests
        .iter()
        .find(|(_, _, body)| body.get("params").is_some())
        .expect("opted-in webhook must include params");
    assert_eq!(included.2["params"], params);
}

#[tokio::test]
async fn slack_message_contains_link_not_params() {
    let hook = Hook::start(&[("/slack", 200)], false).await;
    let home = Home::new("slack");
    drop(home.initialize());
    home.write_policy();
    home.write_secret(
        "slack.url",
        &format!("{}\n", hook.endpoint("/slack")),
        0o600,
    );
    home.write_config(&format!(
        "public_url = '{PUBLIC_URL}'\n[[notify]]\ntype = 'slack'\nwebhook_url_file = 'slack.url'\n"
    ));
    let server = home.start();
    let token = home.add_agent();
    let params = json!({"secret": "slack-param-canary"});

    let (_, response) = check(&server.url, &token, params).await;
    let approval_id = response["approval_id"].as_str().unwrap();
    hook.wait_for_requests(1).await;
    let requests = hook.requests();
    let text = requests[0].2["text"].as_str().unwrap();
    assert!(text.contains("claude"));
    assert!(text.contains("git.push"));
    assert!(text.contains("repo"));
    assert!(text.contains(&format!("{PUBLIC_URL}/approvals/{approval_id}")));
    assert!(!text.contains("slack-param-canary"));
    assert!(!text.contains("params"));
}

#[tokio::test]
async fn notify_failure_does_not_block_approval() {
    let hook = Hook::start(&[("/hook", 200)], true).await;
    let home = Home::new("nonblocking");
    drop(home.initialize());
    home.write_policy();
    home.write_config(&webhook_config(&hook.endpoint("/hook"), None, false));
    let server = home.start();
    let token = home.add_agent();

    let (elapsed, response) = check(&server.url, &token, json!({})).await;
    assert_eq!(response["decision"], "ask");
    assert!(
        elapsed < Duration::from_secs(2),
        "approval response waited {elapsed:?}"
    );
    hook.wait_for_requests(1).await;
    assert_eq!(
        home.sql()
            .query_row(
                "SELECT count(*) FROM approvals WHERE state='Pending'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn notify_outcomes_are_audited() {
    let success = Hook::start(&[("/ok", 200)], false).await;
    let failure = Hook::start(&[("/fail", 500)], false).await;
    let home = Home::new("audit");
    drop(home.initialize());
    home.write_policy();
    home.write_secret("notify.token", "audit-secret-token\n", 0o600);
    home.write_config(&format!(
        "public_url = '{PUBLIC_URL}'\n\
         [[notify]]\ntype = 'webhook'\nurl = '{}'\ntoken_file = 'notify.token'\n\
         [[notify]]\ntype = 'webhook'\nurl = '{}'\n",
        success.endpoint("/ok"),
        failure.endpoint("/fail")
    ));
    let server = home.start();
    let token = home.add_agent();

    for _ in 0..2 {
        let (_, response) = check(&server.url, &token, json!({})).await;
        assert_eq!(response["decision"], "ask");
    }
    success.wait_for_requests(2).await;
    failure.wait_for_requests(6).await;
    let entries = wait_for_notification_audit(&home, 2, 1);
    assert_eq!(
        failure
            .requests()
            .iter()
            .filter(|(path, _, _)| path == "/fail")
            .count(),
        6
    );
    let sent = entries
        .iter()
        .filter(|entry| entry["kind"] == "NotifySent")
        .collect::<Vec<_>>();
    let failed = entries
        .iter()
        .filter(|entry| entry["kind"] == "NotifyFailed")
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|entry| {
        entry["subject"]["channel"] == "webhook-1" && entry["subject"]["status"] == 200
    }));
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["subject"]["channel"], "webhook-2");
    assert_eq!(failed[0]["subject"]["error_class"], "http_status");
    assert!(
        !serde_json::to_string(&entries)
            .unwrap()
            .contains("audit-secret-token")
    );
}

#[tokio::test]
async fn notification_queue_is_bounded() {
    let hook = Hook::start(&[("/hook", 200)], true).await;
    let home = Home::new("bounded-queue");
    drop(home.initialize());
    home.write_policy();
    home.write_config(&webhook_config(&hook.endpoint("/hook"), None, false));
    let server = home.start();
    let client = reqwest::Client::new();

    // Each agent may hold 20 pending approvals (DS-03), so fill the queue
    // from 51 agents.
    for agent in 0..51 {
        let token = home.add_agent_named(&format!("flood-{agent}"));
        for _ in 0..20 {
            let (_, response) = check_with_client(&client, &server.url, &token, json!({})).await;
            assert_eq!(response["decision"], "ask");
        }
    }
    hook.wait_for_requests(1).await;

    let started = Instant::now();
    let entries = loop {
        let entries = home.audit();
        if entries.iter().any(|entry| {
            entry["kind"] == "NotifyFailed" && entry["subject"]["error_class"] == "queue_full"
        }) {
            break entries;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "queue-full audit did not arrive: {entries:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        entries
            .iter()
            .filter(|entry| {
                entry["kind"] == "NotifyFailed" && entry["subject"]["error_class"] == "queue_full"
            })
            .count(),
        1
    );

    let token = home.add_agent();
    for _ in 0..20 {
        let (_, response) = check_with_client(&client, &server.url, &token, json!({})).await;
        assert_eq!(response["decision"], "ask");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        home.audit()
            .iter()
            .filter(|entry| {
                entry["kind"] == "NotifyFailed" && entry["subject"]["error_class"] == "queue_full"
            })
            .count(),
        1
    );
}

#[tokio::test]
async fn worker_survives_audit_error() {
    let hook = Hook::start(&[("/hook", 200)], false).await;
    let home = Home::new("worker-audit");
    drop(home.initialize());
    home.write_policy();
    home.write_config(&webhook_config(&hook.endpoint("/hook"), None, false));
    let server = home.start();
    let token = home.add_agent();
    home.sql()
        .execute_batch(
            "CREATE TRIGGER fail_notify_audit BEFORE INSERT ON audit \
             WHEN json_extract(NEW.body, '$.kind') = 'NotifySent' \
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();

    let (_, response) = check(&server.url, &token, json!({})).await;
    assert_eq!(response["decision"], "ask");
    hook.wait_for_requests(1).await;
    home.sql()
        .execute_batch("DROP TRIGGER fail_notify_audit")
        .unwrap();
    wait_for_notification_audit(&home, 1, 0);

    let (_, response) = check(&server.url, &token, json!({})).await;
    assert_eq!(response["decision"], "ask");
    hook.wait_for_requests(2).await;
    let entries = wait_for_notification_audit(&home, 2, 0);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["kind"] == "NotifySent")
            .count(),
        2
    );
}

#[tokio::test]
async fn notify_secret_files_require_0600() {
    let home = Home::new("modes");
    drop(home.initialize());
    home.write_secret("notify.token", "mode-secret-token\n", 0o644);
    home.write_config(&webhook_config(
        "http://127.0.0.1:9/hook",
        Some("notify.token"),
        false,
    ));
    let output = home.command().output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("notify.token") && error.contains("0644"),
        "{error}"
    );
    assert!(!error.contains("mode-secret-token"));
    fs::set_permissions(
        home.0.join("notify.token"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(home.start());

    let slack_url = "http://127.0.0.1:9/slack";
    home.write_secret("slack.url", &format!("{slack_url}\n"), 0o644);
    home.write_config("[[notify]]\ntype = 'slack'\nwebhook_url_file = 'slack.url'\n");
    let output = home.command().output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("slack.url") && error.contains("0644"),
        "{error}"
    );
    assert!(!error.contains(slack_url));
    fs::set_permissions(home.0.join("slack.url"), fs::Permissions::from_mode(0o600)).unwrap();
    drop(home.start());
}

const SLACK_SECRET: &str = "slack-signing-canary";

fn slack_config(hook: &Hook, requires_totp: Option<bool>) -> String {
    // One-click approval needs the params in Slack, so it needs the opt-in.
    let totp = requires_totp
        .map(|v| {
            let opt_in = if v { "" } else { "include_params = true\n" };
            format!("slack_requires_totp = {v}\n{opt_in}")
        })
        .unwrap_or_default();
    format!(
        "public_url = '{PUBLIC_URL}'\n[[notify]]\ntype = 'slack'\nwebhook_url_file = 'slack.url'\ninteractive = true\nsigning_secret_file = 'slack.secret'\nslack_users = {{ UADMIN = 'operator', UVIEWER = 'viewer', USELF = 'claude' }}\n{totp}# {}",
        hook.url
    )
}

async fn slack_home(name: &str, totp: Option<bool>) -> (Home, Running, Hook, String, String) {
    slack_home_with(name, |hook| slack_config(hook, totp)).await
}

async fn slack_home_with(
    name: &str,
    config: impl Fn(&Hook) -> String,
) -> (Home, Running, Hook, String, String) {
    let hook = Hook::start(&[("/slack", 200), ("/reply", 200)], false).await;
    let home = Home::new(name);
    drop(home.initialize());
    home.write_policy();
    home.write_secret("slack.url", &hook.endpoint("/slack"), 0o600);
    home.write_secret("slack.secret", SLACK_SECRET, 0o600);
    home.write_config(&config(&hook));
    for (id, role) in [("viewer", "Viewer"), ("claude", "Approver")] {
        let user = json!({"id":id,"password_hash":"", "totp_secret":null,"roles":[role]});
        home.sql()
            .execute(
                "INSERT INTO users(id,body) VALUES (?,?)",
                [id, &user.to_string()],
            )
            .unwrap();
    }
    let server = home.start();
    let token = home.add_agent();
    let (_, response) = check(&server.url, &token, SAFE_PUSH.clone()).await;
    let id = response["approval_id"].as_str().unwrap().to_owned();
    hook.wait_for_requests(1).await;
    (home, server, hook, token, id)
}

static SAFE_PUSH: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"old":"a","new":"b","delete":false,"force":false}));

fn slack_request(
    server: &Running,
    hook: &Hook,
    id: &str,
    user: &str,
    action: &str,
    timestamp: i64,
) -> reqwest::Request {
    let payload = json!({"type":"block_actions", "user":{"id":user}, "actions":[{"action_id":action,"value":id}], "response_url":hook.endpoint("/reply")});
    signed_slack_request(server, payload, timestamp)
}

fn signed_slack_request(server: &Running, payload: Value, timestamp: i64) -> reqwest::Request {
    let mut request = reqwest::Client::new()
        .post(format!("{}/integrations/slack/actions", server.url))
        .form(&[("payload", payload.to_string())])
        .build()
        .unwrap();
    let body = request.body().unwrap().as_bytes().unwrap();
    // OpenSSL is an independent HMAC oracle for the production implementation.
    let mut signer = Command::new("openssl")
        .args(["dgst", "-sha256", "-hmac", SLACK_SECRET])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = signer.stdin.take().unwrap();
    write!(input, "v0:{timestamp}:").unwrap();
    input.write_all(body).unwrap();
    drop(input);
    let output = signer.wait_with_output().unwrap();
    assert!(output.status.success());
    let signature = String::from_utf8(output.stdout).unwrap();
    let signature = format!("v0={}", signature.split_whitespace().last().unwrap());
    request
        .headers_mut()
        .insert("x-slack-signature", signature.parse().unwrap());
    request.headers_mut().insert(
        "x-slack-request-timestamp",
        timestamp.to_string().parse().unwrap(),
    );
    request
}

fn slack_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn pending_count(home: &Home) -> i64 {
    home.sql()
        .query_row(
            "SELECT count(*) FROM approvals WHERE state='Pending'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn slack_action_requires_valid_signature() {
    let (home, server, hook, _, id) = slack_home("signature", Some(false)).await;
    let mut req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    req.headers_mut().remove("x-slack-signature");
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        401
    );
    let mut req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    req.headers_mut().insert(
        "x-slack-signature",
        format!("v0={}", "0".repeat(64)).parse().unwrap(),
    );
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        401
    );
    let mut req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    *req.body_mut() = Some("payload=tampered".into());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        401
    );
    assert_eq!(pending_count(&home), 1);
    assert_eq!(hook.requests().len(), 1);
}

#[tokio::test]
async fn slack_signature_rejects_noncanonical_hex() {
    let (home, server, hook, _, id) = slack_home("noncanonical-signature", Some(false)).await;
    let timestamp = slack_now();
    let mut request = None;
    for offset in 0..=256 {
        let candidate = slack_request(&server, &hook, &id, "UADMIN", "approve", timestamp + offset);
        let signature = candidate
            .headers()
            .get("x-slack-signature")
            .unwrap()
            .to_str()
            .unwrap();
        if signature.starts_with("v0=0") {
            request = Some(candidate);
            break;
        }
    }
    let mut request = request.expect("one of 257 HMAC values must start with a zero nibble");
    let signature = request
        .headers()
        .get("x-slack-signature")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut bytes = signature.clone().into_bytes();
    bytes[3] = b'+';
    let noncanonical = String::from_utf8(bytes).unwrap();
    assert_eq!(noncanonical.len(), signature.len());
    request
        .headers_mut()
        .insert("x-slack-signature", noncanonical.parse().unwrap());

    assert_eq!(
        reqwest::Client::new()
            .execute(request)
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(pending_count(&home), 1);
}

#[tokio::test]
async fn slack_action_rejects_old_timestamp() {
    let (home, server, hook, _, id) = slack_home("replay", Some(false)).await;
    for timestamp in [slack_now() - 301, slack_now() + 301] {
        let req = slack_request(&server, &hook, &id, "UADMIN", "approve", timestamp);
        assert_eq!(
            reqwest::Client::new().execute(req).await.unwrap().status(),
            401
        );
    }
    assert_eq!(pending_count(&home), 1);
}

async fn refused_slack_user(user: &str, reason: &str) {
    let (home, server, hook, _, id) = slack_home(user, Some(false)).await;
    let req = slack_request(&server, &hook, &id, user, "approve", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(2).await;
    let body = &hook.requests()[1].2;
    assert_eq!(body["response_type"], "ephemeral");
    assert_eq!(body["replace_original"], false);
    assert!(body["text"].as_str().unwrap().contains(reason), "{body}");
    assert_eq!(pending_count(&home), 1);
}

#[tokio::test]
async fn slack_unknown_user_refused() {
    refused_slack_user("UNKNOWN", "not mapped").await;
}
#[tokio::test]
async fn slack_non_approver_refused() {
    refused_slack_user("UVIEWER", "Approver").await;
}
#[tokio::test]
async fn slack_self_approval_refused() {
    refused_slack_user("USELF", "own approval").await;
}

#[tokio::test]
async fn slack_approve_consumes_once_and_audits_channel() {
    let (home, server, hook, token, id) = slack_home("consume", Some(false)).await;
    let blocks = hook.requests()[0].2["blocks"].clone();
    let buttons = blocks.as_array().unwrap().last().unwrap()["elements"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(buttons.len(), 2);
    for button in &buttons {
        assert_eq!(button["value"], id);
    }
    for count in 2..=3 {
        let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
        assert_eq!(
            reqwest::Client::new().execute(req).await.unwrap().status(),
            200
        );
        hook.wait_for_requests(count).await;
    }
    hook.wait_for_requests(3).await;
    let replies = hook.requests();
    assert_eq!(replies[1].2["replace_original"], true);
    assert!(replies[1].2["text"].as_str().unwrap().contains("Approved"));
    assert!(replies[1].2.get("blocks").is_none());
    assert_eq!(replies[2].2["response_type"], "ephemeral");
    assert_eq!(
        check(&server.url, &token, SAFE_PUSH.clone()).await.1["decision"],
        "allow"
    );
    assert_eq!(
        check(&server.url, &token, SAFE_PUSH.clone()).await.1["decision"],
        "ask"
    );
    let entries = home.audit();
    let approved: Vec<_> = entries.iter().filter(|e| e["kind"] == "Approved").collect();
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0]["actor"], json!({"User":"operator"}));
    assert_eq!(approved[0]["subject"]["channel"], "slack");
    assert_eq!(approved[0]["subject"]["approval_id"], id);
    assert_eq!(
        entries.iter().filter(|e| e["kind"] == "Consumed").count(),
        1
    );
    assert!(
        !serde_json::to_string(&entries)
            .unwrap()
            .contains(SLACK_SECRET)
    );
}

#[tokio::test]
async fn slack_default_requires_totp_and_links_instead() {
    let (home, server, hook, _, id) = slack_home("totp", None).await;
    let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(2).await;
    let body = &hook.requests()[1].2;
    assert_eq!(body["response_type"], "ephemeral");
    assert!(
        body["text"]
            .as_str()
            .unwrap()
            .contains(&format!("{PUBLIC_URL}/approvals/{id}"))
    );
    assert_eq!(pending_count(&home), 1);
}

#[tokio::test]
async fn slack_deny_and_audit_failure_use_web_transaction() {
    let (home, server, hook, _, id) = slack_home("deny", Some(false)).await;
    home.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let req = slack_request(&server, &hook, &id, "UADMIN", "deny", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(2).await;
    assert_eq!(hook.requests()[1].2["response_type"], "ephemeral");
    assert!(
        hook.requests()[1].2["text"]
            .as_str()
            .unwrap()
            .contains("refused")
    );
    assert_eq!(pending_count(&home), 1);
    home.sql().execute_batch("DROP TRIGGER fail_audit").unwrap();
    let req = slack_request(&server, &hook, &id, "UADMIN", "deny", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(3).await;
    let entry = home
        .audit()
        .into_iter()
        .find(|e| e["kind"] == "Denied")
        .unwrap();
    assert_eq!(entry["subject"]["channel"], "slack");
    assert_eq!(entry["actor"], json!({"User":"operator"}));
    assert!(
        hook.requests()[2].2["text"]
            .as_str()
            .unwrap()
            .contains("Denied")
    );
}

#[tokio::test]
async fn slack_interactivity_requires_private_secret_and_user_mapping() {
    let hook = Hook::start(&[("/slack", 200)], false).await;
    let home = Home::new("interactive-config");
    drop(home.initialize());
    home.write_secret("slack.url", &hook.endpoint("/slack"), 0o600);
    home.write_secret("slack.secret", SLACK_SECRET, 0o644);
    let config = slack_config(&hook, Some(false));
    for config in [
        config.clone(),
        config.replace("signing_secret_file = 'slack.secret'\n", ""),
        config.replace(
            "slack_users = { UADMIN = 'operator', UVIEWER = 'viewer', USELF = 'claude' }\n",
            "",
        ),
    ] {
        home.write_config(&config);
        let output = home.command().output().unwrap();
        assert!(!output.status.success());
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains(SLACK_SECRET)
        );
    }
    home.write_secret("slack.secret", SLACK_SECRET, 0o600);
    home.write_config(&config);
    drop(home.start());
    home.write_config(&config.replace(
        "slack_users = { UADMIN = 'operator', UVIEWER = 'viewer', USELF = 'claude' }\n",
        "",
    ));
    let output = home.command().output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("nonempty map")
    );
}

#[tokio::test]
async fn slack_actions_reject_cookie_bearer_and_unsafe_reply_url() {
    let (home, server, hook, token, id) = slack_home("credentials", Some(false)).await;
    for (name, value) in [
        ("cookie", "sekisho_session=spoofed".to_owned()),
        ("authorization", format!("Bearer {token}")),
    ] {
        let mut req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
        req.headers_mut().insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        assert_eq!(
            reqwest::Client::new().execute(req).await.unwrap().status(),
            401
        );
    }
    let payload = json!({"type":"block_actions","user":{"id":"UADMIN"},"actions":[{"action_id":"approve","value":id}],"response_url":"http://untrusted.invalid/"});
    let req = signed_slack_request(&server, payload, slack_now());
    let response = reqwest::Client::new().execute(req).await.unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(pending_count(&home), 1);
    assert_eq!(hook.requests().len(), 1);
}

#[tokio::test]
async fn slack_same_app_channels_share_identity_configuration() {
    let (home, server, hook, token, _) = slack_home("same-app", Some(false)).await;
    drop(server);
    let config = slack_config(&hook, Some(false));
    let second = config.split_once("[[notify]]").unwrap().1;
    home.write_config(&format!("{config}\n[[notify]]{second}"));
    let server = home.start();
    let (_, response) = check(
        &server.url,
        &token,
        json!({"old":"a","new":"c","delete":false,"force":false}),
    )
    .await;
    let req = slack_request(
        &server,
        &hook,
        response["approval_id"].as_str().unwrap(),
        "UADMIN",
        "approve",
        slack_now(),
    );
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(4).await;
    assert_eq!(
        home.audit()
            .iter()
            .filter(|e| e["kind"] == "Approved")
            .count(),
        1
    );
    drop(server);
    home.write_config(&format!(
        "{config}\n[[notify]]{}",
        second.replace("slack_requires_totp = false", "slack_requires_totp = true")
    ));
    let output = home.command().output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("conflicting")
    );
}

#[tokio::test]
async fn slack_acknowledges_before_waiting_on_database() {
    let (home, server, hook, _, id) = slack_home("ack", Some(false)).await;
    let lock = home.sql();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    let response =
        tokio::time::timeout(Duration::from_secs(1), reqwest::Client::new().execute(req)).await;
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        response
            .expect("Slack must be acknowledged before database work completes")
            .unwrap()
            .status(),
        200
    );
    hook.wait_for_requests(2).await;
    assert_eq!(
        home.audit()
            .iter()
            .filter(|e| e["kind"] == "Approved")
            .count(),
        1
    );
}

#[tokio::test]
async fn slack_interactive_blocks_fit_slack_text_limit() {
    let (home, server, hook, token, _) = slack_home("text-limit", Some(false)).await;
    let response = reqwest::Client::new()
        .post(format!("{}/v1/check", server.url))
        .bearer_auth(token)
        .json(&json!({"tool":"git.push","target":"&".repeat(1024),"params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    hook.wait_for_requests(2).await;
    let body = &hook.requests()[1].2;
    let text = body["blocks"][0]["text"]["text"].as_str().unwrap();
    assert!(
        text.chars().count() <= 3000,
        "block length {}",
        text.chars().count()
    );
    assert!(text.contains(&"&".repeat(1024)));
    assert!(
        !serde_json::to_string(&home.audit())
            .unwrap()
            .contains(SLACK_SECRET)
    );
}

/// SEK-04: with one-click Slack approval, the message shows the exact params
/// and digest, and risky actions cannot be approved from a button.
#[tokio::test]
async fn slack_one_click_shows_params_and_refuses_risky_actions() {
    let (home, server, hook, token, _) = slack_home("one-click-risky", Some(false)).await;
    let delete = json!({"old":"a","new":"0","delete":true,"force":false});
    let (_, response) = check(&server.url, &token, delete).await;
    let id = response["approval_id"].as_str().unwrap().to_owned();
    hook.wait_for_requests(2).await;
    let message = &hook.requests()[1].2;
    let details = message["blocks"][1]["text"]["text"].as_str().unwrap();
    assert!(details.contains(r#""delete":true"#), "{details}");
    assert!(details.contains("Action digest: "), "{details}");
    assert!(details.contains("needs TOTP"), "{details}");
    let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(3).await;
    let reply = &hook.requests()[2].2;
    assert_eq!(reply["response_type"], "ephemeral");
    assert!(
        reply["text"]
            .as_str()
            .unwrap()
            .contains(&format!("{PUBLIC_URL}/approvals/{id}"))
    );
    let state: String = home
        .sql()
        .query_row("SELECT state FROM approvals WHERE id=?", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(state, "Pending");
    // Denying a risky action from Slack still works.
    let req = slack_request(&server, &hook, &id, "UADMIN", "deny", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(4).await;
    let state: String = home
        .sql()
        .query_row("SELECT state FROM approvals WHERE id=?", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(state, "Denied");
}

fn approval_state(home: &Home, id: &str) -> String {
    home.sql()
        .query_row("SELECT state FROM approvals WHERE id=?", [id], |r| r.get(0))
        .unwrap()
}

/// SEK-04 follow-up: without the include_params opt-in, Slack shows only the
/// digest, never the params, and a button cannot approve.
#[tokio::test]
async fn slack_one_click_without_include_params_hides_params_and_links() {
    let (home, server, hook, token, _) = slack_home_with("no-params", |hook| {
        slack_config(hook, Some(false)).replace("include_params = true\n", "")
    })
    .await;
    let params =
        json!({"old":"a","new":"c","delete":false,"force":false,"note":"slack-param-canary"});
    let (_, response) = check(&server.url, &token, params).await;
    let id = response["approval_id"].as_str().unwrap().to_owned();
    hook.wait_for_requests(2).await;
    let message = hook.requests()[1].2.to_string();
    assert!(!message.contains("slack-param-canary"), "{message}");
    assert!(message.contains("Action digest: "), "{message}");
    assert!(message.contains("not shown in Slack"), "{message}");
    let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(3).await;
    assert_eq!(hook.requests()[2].2["response_type"], "ephemeral");
    assert_eq!(approval_state(&home, &id), "Pending");
}

/// With the opt-in, Slack shows params with obvious secrets redacted, and a
/// button can approve a safe action.
#[tokio::test]
async fn slack_one_click_redaction_disables_one_click_approval() {
    let (home, server, hook, token, _) = slack_home("redacted", Some(false)).await;
    let params = json!({"old":"a","new":"c","delete":false,"force":false,
        "note":"password=hunter2 ghp_abcdefghij0123456789 Bearer sk-live-xyz"});
    let (_, response) = check(&server.url, &token, params).await;
    let id = response["approval_id"].as_str().unwrap().to_owned();
    hook.wait_for_requests(2).await;
    let details = hook.requests()[1].2["blocks"][1]["text"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(details.contains(r#""force":false"#), "{details}");
    for secret in ["hunter2", "ghp_abcdefghij0123456789", "sk-live-xyz"] {
        assert!(!details.contains(secret), "{details}");
    }
    assert!(details.contains("[redacted]"), "{details}");
    assert!(details.contains("needs TOTP"), "{details}");
    // What was redacted is not what the approver sees, so no one-click.
    let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(3).await;
    assert_eq!(hook.requests()[2].2["response_type"], "ephemeral");
    assert_eq!(approval_state(&home, &id), "Pending");

    // Nothing redacted: the button approves.
    let params = json!({"old":"a","new":"d","delete":false,"force":false,"monkey":"visible"});
    let (_, response) = check(&server.url, &token, params).await;
    let clean = response["approval_id"].as_str().unwrap().to_owned();
    hook.wait_for_requests(4).await;
    let details = hook.requests()[3].2["blocks"][1]["text"]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(details.contains(r#""monkey":"visible""#), "{details}");
    let req = slack_request(&server, &hook, &clean, "UADMIN", "approve", slack_now());
    assert_eq!(
        reqwest::Client::new().execute(req).await.unwrap().status(),
        200
    );
    hook.wait_for_requests(5).await;
    assert_eq!(approval_state(&home, &clean), "Approved");
}

/// Camel-case and dotted secret keys are redacted and so disable one-click;
/// `key` inside a longer word is not.
#[tokio::test]
async fn slack_broad_secret_keys_disable_one_click() {
    let (home, server, hook, token, _) = slack_home("broad-keys", Some(false)).await;
    let mut count = 1;
    for (index, (key, redact)) in [
        ("accessToken", true),
        ("DB_PASSWORD", true),
        ("x.auth.header", true),
        ("apiKey", true),
        ("privateKey", true),
        ("monkey", false),
        ("keyboard_layout", false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut params = json!({"old":"a","delete":false,"force":false});
        params["new"] = json!(format!("n{index}"));
        params[key] = json!("value-canary");
        let (_, response) = check(&server.url, &token, params).await;
        let id = response["approval_id"].as_str().unwrap().to_owned();
        count += 1;
        hook.wait_for_requests(count).await;
        let details = hook.requests()[count - 1].2["blocks"][1]["text"]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            !details.contains("value-canary"),
            redact,
            "{key}: {details}"
        );
        let req = slack_request(&server, &hook, &id, "UADMIN", "approve", slack_now());
        assert_eq!(
            reqwest::Client::new().execute(req).await.unwrap().status(),
            200
        );
        count += 1;
        hook.wait_for_requests(count).await;
        let expected = if redact { "Pending" } else { "Approved" };
        assert_eq!(approval_state(&home, &id), expected, "{key}");
    }
}
