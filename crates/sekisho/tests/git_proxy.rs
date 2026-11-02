#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    response::Response,
    routing::any,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sekisho::{
    git::proxy::{GitProxy, RemoteConfig},
    server::{
        AppState, CheckApi, Clock, InMemorySessions, InMemoryUsers, Role, SessionStore,
        SystemClock, User, router,
    },
    store::Store,
};
use sekisho_core::*;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tracing::instrument::WithSubscriber;

const SECRET: &str = "upstream-secret-do-not-log";
const POLICY: &str = r#"version = 1
[[rule]]
name = "fetch"
tool = "git.fetch"
decision = "allow"
[[rule]]
name = "agent branch"
tool = "git.push"
target = "127.0.0.1/owner/repo:refs/heads/agent/**"
decision = "allow"
[[rule]]
name = "protected"
tool = "git.push"
decision = "ask"
"#;

#[derive(Clone)]
struct Backend {
    root: PathBuf,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Fixed compare answer, or `None` to answer from the bare repository like GitHub.
    compare: Arc<Mutex<Option<(u16, String)>>>,
    calls: Arc<Mutex<Vec<String>>>,
    incomplete: Arc<AtomicUsize>,
    compare_gate: Arc<Mutex<Option<Arc<tokio::sync::Barrier>>>>,
    response_delay: Arc<AtomicUsize>,
}
async fn cgi(State(backend): State<Backend>, request: Request) -> Response {
    assert_eq!(
        request.headers()["authorization"],
        format!(
            "Basic {}",
            STANDARD.encode(format!("x-access-token:{SECRET}"))
        )
    );
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    backend.calls.lock().unwrap().push(path.clone());
    let body = match to_bytes(request.into_body(), 16 * 1024 * 1024).await {
        Ok(body) => body,
        Err(_) => {
            backend.incomplete.fetch_add(1, Ordering::SeqCst);
            return Response::builder().status(400).body(Body::empty()).unwrap();
        }
    };
    if path.ends_with("git-receive-pack") {
        backend.received.lock().unwrap().push(body.to_vec());
        let delay = backend.response_delay.load(Ordering::SeqCst);
        if delay > 0 {
            let (input, mut output) = std::io::pipe().unwrap();
            let file = std::fs::File::from(std::os::fd::OwnedFd::from(input));
            tokio::task::spawn_blocking(move || {
                let _ = output.write_all(b"begin");
                if delay != usize::MAX {
                    std::thread::sleep(std::time::Duration::from_millis(delay as u64));
                    let _ = output.write_all(b"end");
                }
            });
            let mut result = Response::builder().status(200);
            if delay == usize::MAX {
                result = result.header("content-length", "8");
            }
            return result
                .body(Body::new(reqwest::Body::from(tokio::fs::File::from_std(
                    file,
                ))))
                .unwrap();
        }
    }
    if path.contains("/repos/") {
        let gate = backend.compare_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.wait().await;
        }
        let fixed = backend.compare.lock().unwrap().clone();
        let (status, body) = match fixed {
            Some(answer) => answer,
            None => github_compare(&backend.root, &path),
        };
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
    }
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new("git")
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", backend.root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env("REQUEST_METHOD", method)
            .env("CONTENT_TYPE", content_type)
            .env("CONTENT_LENGTH", body.len().to_string())
            .env("REMOTE_USER", "sekisho")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&body).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let split = output
            .stdout
            .windows(4)
            .position(|v| v == b"\r\n\r\n")
            .unwrap();
        let mut response = Response::builder();
        for line in String::from_utf8_lossy(&output.stdout[..split]).lines() {
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("status") {
                response = response.status(
                    value
                        .trim()
                        .split(' ')
                        .next()
                        .unwrap()
                        .parse::<u16>()
                        .unwrap(),
                );
            } else {
                response = response.header(name, value.trim());
            }
        }
        response
            .body(Body::from(output.stdout[split + 4..].to_vec()))
            .unwrap()
    })
    .await
    .unwrap()
}

/// GitHub's compare API: 404 unless both commits exist upstream, otherwise the
/// status of `head` relative to `base`.
fn github_compare(root: &Path, path: &str) -> (u16, String) {
    let range = path.rsplit('/').next().unwrap();
    let (base, head) = range.split_once("...").unwrap();
    let repo = root.join("owner/repo.git");
    let exists = |id: &str| {
        git(&repo, &["cat-file", "-e", &format!("{id}^{{commit}}")])
            .status
            .success()
    };
    if !exists(base) || !exists(head) {
        return (404, r#"{"message":"Not Found"}"#.into());
    }
    let ancestor = |a: &str, b: &str| {
        git(&repo, &["merge-base", "--is-ancestor", a, b])
            .status
            .success()
    };
    let status = match (ancestor(base, head), ancestor(head, base)) {
        (true, true) => "identical",
        (true, false) => "ahead",
        (false, true) => "behind",
        (false, false) => "diverged",
    };
    (200, format!(r#"{{"status":"{status}"}}"#))
}

struct Fixture {
    dir: PathBuf,
    base: String,
    token: String,
    cookie: String,
    csrf: String,
    store: Arc<Store>,
    checks: Arc<CheckApi>,
    /// Fixed compare answer, or `None` to answer from the bare repository like GitHub.
    compare: Arc<Mutex<Option<(u16, String)>>>,
    calls: Arc<Mutex<Vec<String>>>,
    incomplete: Arc<AtomicUsize>,
    compare_gate: Arc<Mutex<Option<Arc<tokio::sync::Barrier>>>>,
    response_delay: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap()
}
fn git_ok(dir: &Path, args: &[&str]) {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
impl Fixture {
    async fn new() -> Self {
        Self::with_limit(16 * 1024 * 1024).await
    }
    async fn with_limit(limit: usize) -> Self {
        Self::with_options(limit, None, None).await
    }
    async fn with_options(limit: usize, slots: Option<usize>, deadline: Option<u64>) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sekisho-git-{}",
            std::hash::BuildHasher::hash_one(&std::hash::RandomState::new(), "git")
        ));
        std::fs::create_dir_all(dir.join("owner")).unwrap();
        git_ok(&dir, &["init", "--bare", "owner/repo.git"]);
        git_ok(
            &dir,
            &[
                "--git-dir=owner/repo.git",
                "config",
                "http.receivepack",
                "true",
            ],
        );
        git_ok(&dir, &["init", "work"]);
        git_ok(
            &dir.join("work"),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--allow-empty",
                "-m",
                "initial",
            ],
        );
        let received = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let incomplete = Arc::new(AtomicUsize::new(0));
        let compare_gate = Arc::new(Mutex::new(None));
        let response_delay = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let compare = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route("/{*path}", any(cgi))
            .with_state(Backend {
                root: dir.clone(),
                received: received.clone(),
                compare: compare.clone(),
                calls: calls.clone(),
                incomplete: incomplete.clone(),
                compare_gate: compare_gate.clone(),
                response_delay: response_delay.clone(),
            });
        let upstream_task = tokio::spawn(
            async move { axum::serve(listener, app).await.unwrap() }.with_current_subscriber(),
        );
        let signer = Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]));
        let store = Arc::new(Store::open(&dir.join("store.db"), signer).unwrap());
        let admin = UserId::try_from("admin").unwrap();
        let token = store
            .add_agent(
                &AgentId::try_from("claude").unwrap(),
                &admin,
                SystemClock.now(),
            )
            .unwrap()
            .expose()
            .to_owned();
        let users = Arc::new(InMemoryUsers::default());
        users
            .insert(User {
                id: admin.clone(),
                password_hash: String::new(),
                totp_secret: Some(vec![1; 20]),
                roles: [Role::Approver].into(),
            })
            .unwrap();
        let sessions = Arc::new(InMemorySessions::default());
        let session = sessions
            .create(&admin, SystemClock.now(), 43200, Some(1))
            .unwrap()
            .unwrap();
        let csrf = sessions
            .get(&session, SystemClock.now())
            .unwrap()
            .unwrap()
            .csrf_token;
        let cookie = format!("sekisho_session={}", session.expose());
        std::fs::write(dir.join("policy.toml"), POLICY).unwrap();
        std::fs::write(dir.join("token"), SECRET).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("token"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let checks = CheckApi::load(
            store.clone(),
            &dir.join("policy.toml"),
            Ed25519Signer::from_secret_bytes("grant", &[8; 32]).public_key(),
            None,
            &Principal::User(admin),
            SystemClock.now(),
        )
        .unwrap();
        let checks = Arc::new(checks);
        let proxy = GitProxy::load(
            &dir,
            vec![RemoteConfig {
                name: "origin".into(),
                api_url: Some(format!("{upstream}/api/v3")),
                case_insensitive: true,
                base_url: upstream,
                token_file: "token".into(),
            }],
            Some(limit),
        )
        .unwrap()
        .configure_push(slots, deadline)
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state =
            AppState::new_with_agents(users, sessions, store.clone(), Arc::new(SystemClock), true)
                .unwrap()
                .with_check_api(checks.clone())
                .with_git_proxy(Arc::new(proxy))
                .with_public_url(base.clone());
        let task = tokio::spawn(
            async move { axum::serve(listener, router(state)).await.unwrap() }
                .with_current_subscriber(),
        );
        Self {
            dir,
            base,
            token,
            cookie,
            csrf,
            store,
            checks,
            compare,
            calls,
            incomplete,
            compare_gate,
            response_delay,
            received,
            tasks: vec![task, upstream_task],
        }
    }
    fn reload(&self, policy: &str) {
        let path = self.dir.join("policy.toml");
        std::fs::write(&path, policy).unwrap();
        self.checks
            .reload_policy(
                &path,
                &Principal::User(UserId::try_from("admin").unwrap()),
                SystemClock.now(),
            )
            .unwrap();
    }
    fn url(&self) -> String {
        format!("{}/git/origin/owner/repo.git", self.base)
    }
    async fn push(&self, branch: &str) -> std::process::Output {
        let dir = self.dir.join("work");
        let url = self.url();
        let header = format!(
            "http.extraHeader=Authorization: Basic {}",
            STANDARD.encode(format!("any:{}", self.token))
        );
        let target = format!("HEAD:refs/heads/{branch}");
        tokio::task::spawn_blocking(move || git(&dir, &["-c", &header, "push", &url, &target]))
            .await
            .unwrap()
    }
    fn command(&self, branch: &str) -> Vec<u8> {
        let sha =
            String::from_utf8(git(&self.dir.join("work"), &["rev-parse", "HEAD"]).stdout).unwrap();
        let command = format!(
            "{} {} refs/heads/{branch}\0report-status",
            "0".repeat(40),
            sha.trim()
        );
        format!("{:04x}{command}0000", command.len() + 4).into_bytes()
    }
    async fn post(&self, body: Vec<u8>, encoding: &str) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/git-receive-pack", self.url()))
            .basic_auth("any", Some(&self.token))
            .header("content-encoding", encoding)
            .header("content-type", "application/x-git-receive-pack-request")
            .body(body)
            .send()
            .await
            .unwrap()
    }
    fn pending(&self) -> Vec<String> {
        self.store
            .audit_entries(0, 1000)
            .unwrap()
            .iter()
            .filter(|e| e.kind() == AuditKind::ApprovalRequested)
            .map(|e| e.subject()["approval_id"].as_str().unwrap().to_owned())
            .collect()
    }
    async fn approve(&self, id: &str) {
        assert_eq!(
            reqwest::Client::new()
                .post(format!("{}/approvals/{id}/approve", self.base))
                .header("cookie", &self.cookie)
                .header("x-csrf-token", &self.csrf)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[tokio::test]
async fn real_git_push_per_ref_and_single_use_approval() {
    let f = Fixture::new().await;
    let allowed = f.push("agent/test").await;
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let denied = f.push("main").await;
    assert!(!denied.status.success());
    let id = f.pending().pop().unwrap();
    let error = String::from_utf8_lossy(&denied.stderr);
    assert!(error.contains(&id), "{error}");
    assert!(
        error.contains(&format!("{}/approvals/{id}", f.base)),
        "{error}"
    );
    f.approve(&id).await;
    let approved = f.push("main").await;
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    // Restore the advertised old value so Git sends the identical command again.
    git_ok(
        &f.dir,
        &[
            "--git-dir=owner/repo.git",
            "update-ref",
            "-d",
            "refs/heads/main",
        ],
    );
    assert!(!f.push("main").await.status.success());
    assert_eq!(f.pending().len(), 2);
}

#[tokio::test]
async fn gzip_push_is_decided_like_plain() {
    let f = Fixture::new().await;
    let plain = f.command("main");
    let a = f
        .post(plain.clone(), "identity")
        .await
        .text()
        .await
        .unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&plain).unwrap();
    let b = f
        .post(gzip.finish().unwrap(), "gzip")
        .await
        .text()
        .await
        .unwrap();
    assert!(!f.pending().is_empty(), "plain={a} gzip={b}");
    assert!(a.contains(&f.pending()[0]));
    assert!(b.contains(&f.pending()[1]));
    let digests: Vec<_> = f
        .store
        .audit_entries(0, 100)
        .unwrap()
        .iter()
        .filter(|e| e.kind() == AuditKind::ActionRequested)
        .map(|e| e.subject()["action_digest"].clone())
        .collect();
    assert_eq!(digests.len(), 2);
    assert_eq!(digests[0], digests[1]);
    assert!(f.received.lock().unwrap().is_empty());
}
#[tokio::test]
async fn unparseable_push_rejected_not_forwarded() {
    let f = Fixture::new().await;
    for (body, encoding) in [
        (b"not git".to_vec(), "identity"),
        (f.command("agent/test"), "br"),
        (b"bad gzip".to_vec(), "gzip"),
    ] {
        let response = f.post(body, encoding).await;
        assert!(response.status().is_client_error());
    }
    assert!(f.received.lock().unwrap().is_empty());
}
#[tokio::test]
async fn fetch_is_a_decided_action() {
    let f = Fixture::new().await;
    let url = format!("{}/info/refs?service=git-upload-pack", f.url());
    assert_eq!(reqwest::get(&url).await.unwrap().status(), 401);
    assert_eq!(
        reqwest::Client::new()
            .get(&url)
            .bearer_auth(&f.token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        reqwest::Client::new()
            .get(&url)
            .basic_auth("any", Some(&f.token))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let entries = f.store.audit_entries(0, 100).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.kind() == AuditKind::ActionRequested
                && e.subject()["tool"] == "git.fetch"
                && e.subject()["target"] == "127.0.0.1/owner/repo")
    );
    f.reload("version = 1");
    assert_eq!(
        reqwest::Client::new()
            .get(&url)
            .basic_auth("any", Some(&f.token))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
}
#[tokio::test]
async fn upstream_credential_never_logged() {
    let capture = Arc::new(Mutex::new(Vec::new()));
    struct Writer(Arc<Mutex<Vec<u8>>>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || Writer(sink.clone()))
        .finish();
    use tracing_subscriber::util::SubscriberInitExt;
    subscriber.try_init().unwrap();
    async {
        let f = Fixture::new().await;
        assert!(f.push("agent/test").await.status.success());
        assert!(!f.push("main").await.status.success());
        let audit = serde_json::to_string(&f.store.audit_entries(0, 100).unwrap()).unwrap();
        assert!(
            !capture.lock().unwrap().is_empty(),
            "trace capture must observe the request"
        );
        for secret in [
            SECRET.to_owned(),
            f.token.clone(),
            STANDARD.encode(format!("x-access-token:{SECRET}")),
        ] {
            assert!(!audit.contains(&secret));
            assert!(!String::from_utf8_lossy(&capture.lock().unwrap()).contains(&secret));
        }
    }
    .await;
}

#[tokio::test]
async fn every_ref_must_be_allowed_before_forwarding() {
    let f = Fixture::new().await;
    let mut commands = f.command("agent/test");
    commands.truncate(commands.len() - 4);
    for branch in ["main", "release"] {
        let next = f.command(branch);
        // Capabilities belong only on the first command.
        let end = next.iter().position(|b| *b == 0).unwrap();
        let payload = &next[4..end];
        commands.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
        commands.extend_from_slice(payload);
    }
    commands.extend_from_slice(b"0000");
    let response = f.post(commands, "identity").await.text().await.unwrap();
    assert_eq!(f.pending().len(), 2);
    for id in f.pending() {
        assert!(response.contains(&id));
    }
    assert!(f.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unproven_fast_forward_is_forced() {
    let f = Fixture::new().await;
    f.reload(&POLICY.replace(
        "decision = \"allow\"\n[[rule]]\nname = \"protected\"",
        "params = { force = false }\ndecision = \"allow\"\n[[rule]]\nname = \"protected\"",
    ));
    for (status, body, force) in [
        (200, r#"{"status":"ahead"}"#, false),
        (200, r#"{"status":"identical"}"#, false),
        (200, r#"{"status":"behind"}"#, true),
        (200, r#"{"status":"diverged"}"#, true),
        (500, r#"{"status":"ahead"}"#, true),
        (404, r#"{"message":"Not Found"}"#, true),
        (200, "malformed", true),
    ] {
        *f.compare.lock().unwrap() = Some((status, body.into()));
        let count = f.pending().len();
        let _ = f
            .post(
                {
                    let mut c = f.command("agent/test");
                    c[4..44].fill(b'a');
                    c
                },
                "identity",
            )
            .await
            .bytes()
            .await
            .unwrap();
        if force {
            let pending = f.pending();
            assert_eq!(pending.len(), count + 1);
            let id = ApprovalId::try_from(pending.last().unwrap().as_str()).unwrap();
            let approval = f
                .store
                .transact(SystemClock.now(), |tx| {
                    Ok((tx.get_approval(&id)?.unwrap(), vec![]))
                })
                .unwrap();
            assert_eq!(
                approval.action().params()["force"],
                serde_json::Value::Bool(true)
            );
        } else {
            assert_eq!(f.pending().len(), count);
        }
    }
    // Only the two known non-force commands reached receive-pack.
    assert_eq!(f.received.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn gzip_forward_preserves_pack_bytes() {
    let f = Fixture::new().await;
    // An incompressible blob makes the pack much larger than either buffer.
    use rand_core::RngCore;
    let mut data = vec![0; 512 * 1024];
    rand_core::OsRng.fill_bytes(&mut data);
    std::fs::write(f.dir.join("work/blob"), data).unwrap();
    git_ok(&f.dir.join("work"), &["add", "blob"]);
    git_ok(
        &f.dir.join("work"),
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "blob",
        ],
    );
    let result = f.push("agent/test").await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plain = f.received.lock().unwrap()[0].clone();
    assert!(plain.len() > 512 * 1024);
    git_ok(
        &f.dir,
        &[
            "--git-dir=owner/repo.git",
            "update-ref",
            "-d",
            "refs/heads/agent/test",
        ],
    );
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&plain).unwrap();
    let response = f.post(gzip.finish().unwrap(), "gzip").await;
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await.unwrap();
    assert_eq!(f.received.lock().unwrap()[1], plain);
    assert!(
        git(
            &f.dir,
            &[
                "--git-dir=owner/repo.git",
                "rev-parse",
                "--verify",
                "refs/heads/agent/test"
            ]
        )
        .status
        .success()
    );
}

#[tokio::test]
async fn git_audit_failure_refuses_forwarding_and_consumption() {
    let f = Fixture::new().await;
    let response = f
        .post(f.command("main"), "identity")
        .await
        .text()
        .await
        .unwrap();
    let id = f.pending().pop().unwrap();
    assert!(response.contains(&id));
    f.approve(&id).await;
    rusqlite::Connection::open(f.dir.join("store.db")).unwrap().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(f.post(f.command("main"), "identity").await.status(), 503);
    assert!(f.received.lock().unwrap().is_empty());
    let id = ApprovalId::try_from(id.as_str()).unwrap();
    let approval = f
        .store
        .transact(SystemClock.now(), |tx| {
            Ok((tx.get_approval(&id)?.unwrap(), vec![]))
        })
        .unwrap();
    assert_eq!(approval.state(), ApprovalState::Approved);
}

#[tokio::test]
async fn configured_body_limit_applies_to_decoded_gzip() {
    let f = Fixture::with_limit(64).await;
    let plain = f.command("agent/test");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&plain).unwrap();
    for (bytes, encoding) in [(plain, "identity"), (gzip.finish().unwrap(), "gzip")] {
        assert_eq!(f.post(bytes, encoding).await.status(), 400);
    }
    assert!(f.received.lock().unwrap().is_empty());
    assert!(
        !f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.kind() == AuditKind::ActionRequested)
    );
}

#[tokio::test]
async fn unsafe_remote_configuration_is_rejected() {
    let f = Fixture::new().await;
    let config = |url: &str| RemoteConfig {
        name: "origin".into(),
        base_url: url.into(),
        api_url: None,
        case_insensitive: true,
        token_file: "token".into(),
    };
    for url in [
        "file:///tmp/repo",
        "https://user:secret@example.com",
        "https://example.com/?token=secret",
        "https://example.com/#secret",
        // DS-04: the upstream token must not travel over plain HTTP.
        "http://example.com",
        "http://10.0.0.5:8080",
    ] {
        assert!(
            GitProxy::load(&f.dir, vec![config(url)], None).is_err(),
            "{url}"
        );
    }
    for url in [
        "http://127.0.0.1:9000",
        "http://localhost:9000",
        "http://[::1]:9000",
    ] {
        assert!(
            GitProxy::load(&f.dir, vec![config(url)], None).is_ok(),
            "{url}"
        );
    }
    let mut plain_api = config("https://example.com");
    plain_api.api_url = Some("http://api.example.com".into());
    assert!(GitProxy::load(&f.dir, vec![plain_api], None).is_err());
    assert!(
        GitProxy::load(
            &f.dir,
            vec![config("https://example.com"), config("https://example.com")],
            None
        )
        .is_err()
    );
    assert!(GitProxy::load(&f.dir, vec![], Some(0)).is_err());
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(f.dir.join("token"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(GitProxy::load(&f.dir, vec![config("https://example.com")], None).is_err());
    std::fs::remove_file(f.dir.join("token")).unwrap();
    std::os::unix::fs::symlink(f.dir.join("policy.toml"), f.dir.join("token")).unwrap();
    assert!(GitProxy::load(&f.dir, vec![config("https://example.com")], None).is_err());
}

#[tokio::test]
async fn mixed_push_does_not_burn_approvals() {
    let f = Fixture::new().await;
    let _ = f
        .post(f.command("main"), "identity")
        .await
        .bytes()
        .await
        .unwrap();
    let id = f.pending()[0].clone();
    f.approve(&id).await;
    let mut commands = f.command("main");
    commands.truncate(commands.len() - 4);
    let next = f.command("release");
    let end = next.iter().position(|b| *b == 0).unwrap();
    let payload = &next[4..end];
    commands.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    commands.extend_from_slice(payload);
    commands.extend_from_slice(b"0000");
    let reply = f.post(commands, "identity").await.text().await.unwrap();
    assert!(reply.contains("approval required"));
    let approval = f
        .store
        .transact(SystemClock.now(), |tx| {
            Ok((
                tx.get_approval(&ApprovalId::try_from(id.as_str()).unwrap())?
                    .unwrap(),
                vec![],
            ))
        })
        .unwrap();
    assert_eq!(approval.state(), ApprovalState::Approved);
    assert!(f.received.lock().unwrap().is_empty());
    let _ = f
        .post(f.command("main"), "identity")
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(f.received.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn mixed_case_repo_cannot_bypass_deny() {
    let f = Fixture::new().await;
    f.reload(&format!("version = 1\n[[rule]]\nname = 'deny repo'\ntool = 'git.push'\ntarget = '127.0.0.1/owner/repo:refs/heads/**'\ndecision = 'deny'\n{}", POLICY.trim_start_matches("version = 1")));
    let response = reqwest::Client::new()
        .post(format!(
            "{}/git/origin/OWNER/REPO.git/git-receive-pack",
            f.base
        ))
        .basic_auth("any", Some(&f.token))
        .body(f.command("agent/test"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(response.contains("denied"), "{response}");
    assert!(f.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn denied_repo_triggers_no_upstream_calls() {
    let f = Fixture::new().await;
    f.reload("version = 1\n[[rule]]\nname = 'deny'\ntool = 'git.push'\ndecision = 'deny'");
    let command = f.command("main");
    let mut command = String::from_utf8(command).unwrap();
    command.replace_range(4..44, &"a".repeat(40));
    let reply = f
        .post(command.into_bytes(), "identity")
        .await
        .text()
        .await
        .unwrap();
    assert!(reply.contains("denied"));
    assert!(f.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn forwarded_push_outcome_is_audited() {
    let f = Fixture::new().await;
    assert!(f.push("agent/test").await.status.success());
    assert!(
        f.store
            .audit_entries(0, 1000)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "forwarded" && e.subject()["status"] == 200)
    );
}

impl Fixture {
    async fn replay_pack(&self) -> Vec<u8> {
        use rand_core::RngCore;
        let mut data = vec![0; 128 * 1024];
        rand_core::OsRng.fill_bytes(&mut data);
        std::fs::write(self.dir.join("work/blob"), data).unwrap();
        git_ok(&self.dir.join("work"), &["add", "blob"]);
        git_ok(
            &self.dir.join("work"),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-m",
                "blob",
            ],
        );
        assert!(self.push("agent/test").await.status.success());
        let body = self.received.lock().unwrap().pop().unwrap();
        git_ok(
            &self.dir,
            &[
                "--git-dir=owner/repo.git",
                "update-ref",
                "-d",
                "refs/heads/agent/test",
            ],
        );
        self.calls.lock().unwrap().clear();
        body
    }
    /// The client can see the refusal before the upstream notices the aborted
    /// body, so wait for the upstream side instead of racing it.
    async fn wait_incomplete(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.incomplete.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(self.incomplete.load(Ordering::SeqCst), 1);
    }
    fn assert_no_ref(&self) {
        assert!(
            !git(
                &self.dir,
                &[
                    "--git-dir=owner/repo.git",
                    "rev-parse",
                    "--verify",
                    "refs/heads/agent/test"
                ]
            )
            .status
            .success()
        );
        assert!(
            self.received.lock().unwrap().is_empty(),
            "upstream received a complete request"
        );
    }
}

#[tokio::test]
async fn corrupt_gzip_trailer_never_completes_upstream() {
    let f = Fixture::new().await;
    let body = f.replay_pack().await;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&body).unwrap();
    let mut bytes = gzip.finish().unwrap();
    let crc = bytes.len() - 8;
    bytes[crc] ^= 1;
    let response = f.post(bytes, "gzip").await;
    assert!(response.status().is_client_error() || response.status().is_server_error());
    f.wait_incomplete().await;
    f.assert_no_ref();
}

#[tokio::test]
async fn client_disconnect_mid_pack_never_completes_upstream() {
    let f = Fixture::new().await;
    let mut body = f.replay_pack().await;
    body.truncate(body.len() - 1);
    let address = f.base.trim_start_matches("http://").to_owned();
    let authorization = STANDARD.encode(format!("any:{}", f.token));
    tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        write!(socket, "POST /git/origin/owner/repo.git/git-receive-pack HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {authorization}\r\nContent-Type: application/x-git-receive-pack-request\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", body.len()).unwrap();
        socket.write_all(&body).unwrap();
        socket.write_all(b"\r\n").unwrap();
        socket.shutdown(std::net::Shutdown::Write).unwrap();
        use std::io::Read;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut response = Vec::new();
        let _ = socket.read_to_end(&mut response);
    }).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while f.incomplete.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    f.assert_no_ref();
}

#[tokio::test]
async fn over_limit_by_one_byte_never_completes_upstream() {
    let source = Fixture::new().await;
    let body = source.replay_pack().await;
    let f = Fixture::with_limit(body.len() - 1).await;
    let response = f.post(body, "identity").await;
    assert!(response.status().is_client_error() || response.status().is_server_error());
    f.wait_incomplete().await;
    f.assert_no_ref();
}

#[tokio::test]
async fn slow_client_times_out_and_frees_slot() {
    let f = Fixture::with_options(16 * 1024 * 1024, Some(1), Some(1)).await;
    let address = f.base.trim_start_matches("http://").to_owned();
    let authorization = STANDARD.encode(format!("any:{}", f.token));
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let (finish, wait_finish) = std::sync::mpsc::channel();
    let slow = tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        write!(socket, "POST /git/origin/owner/repo.git/git-receive-pack HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {authorization}\r\nContent-Length: 1000\r\n\r\n0").unwrap();
        ready.send(()).unwrap();
        use std::io::Read;
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut response = [0; 2048];
        let n = socket.read(&mut response).unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("400"));
        wait_finish.recv().unwrap();
    });
    waiting.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let response = f.post(b"not git".to_vec(), "identity").await;
            if response.status() == 503 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let response = f.post(b"not git".to_vec(), "identity").await;
            if response.status() == 400 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    finish.send(()).unwrap();
    slow.await.unwrap();
}

#[tokio::test]
async fn enterprise_compare_uses_configured_api_url() {
    let f = Fixture::new().await;
    f.reload(&POLICY.replace(
        "decision = \"allow\"\n[[rule]]\nname = \"protected\"",
        "params = { force = false }\ndecision = \"allow\"\n[[rule]]\nname = \"protected\"",
    ));
    let mut command = f.command("agent/test");
    command[4..44].fill(b'a');
    let _ = f.post(command, "identity").await.bytes().await.unwrap();
    assert!(
        f.calls
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.starts_with("/api/v3/repos/owner/repo/compare/"))
    );
}

#[tokio::test]
async fn upstream_failure_is_audited_and_keeps_approval_consumed() {
    let f = Fixture::new().await;
    let _ = f
        .post(f.command("main"), "identity")
        .await
        .bytes()
        .await
        .unwrap();
    let id = f.pending()[0].clone();
    f.approve(&id).await;
    f.tasks[1].abort();
    while !f.tasks[1].is_finished() {
        tokio::task::yield_now().await;
    }
    assert_eq!(f.post(f.command("main"), "identity").await.status(), 502);
    let approval = f
        .store
        .transact(SystemClock.now(), |tx| {
            Ok((
                tx.get_approval(&ApprovalId::try_from(id.as_str()).unwrap())?
                    .unwrap(),
                vec![],
            ))
        })
        .unwrap();
    assert_eq!(approval.state(), ApprovalState::Consumed);
    assert!(
        f.store
            .audit_entries(0, 1000)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "upstream_failed"
                && e.subject()["error_class"] == "connect")
    );
}

#[tokio::test]
async fn creates_deletes_and_force_independent_rules_skip_compare() {
    let f = Fixture::new().await;
    let _ = f
        .post(f.command("main"), "identity")
        .await
        .bytes()
        .await
        .unwrap();
    assert!(f.calls.lock().unwrap().is_empty());
    let mut delete = f.command("main");
    delete[4..44].fill(b'a');
    delete[45..85].fill(b'0');
    let _ = f.post(delete, "identity").await.bytes().await.unwrap();
    assert!(f.calls.lock().unwrap().is_empty());
    let mut update = f.command("agent/test");
    update[4..44].fill(b'a');
    let _ = f.post(update, "identity").await.bytes().await.unwrap();
    assert!(
        !f.calls
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.contains("/compare/"))
    );
}

#[tokio::test]
async fn force_comparisons_run_concurrently() {
    let f = Fixture::new().await;
    f.reload("version = 1\n[[rule]]\nname = 'safe'\ntool = 'git.push'\nparams = {force = false}\ndecision = 'allow'\n[[rule]]\nname = 'ask'\ntool = 'git.push'\ndecision = 'ask'");
    *f.compare.lock().unwrap() = Some((200, r#"{"status":"ahead"}"#.into()));
    *f.compare_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Barrier::new(2)));
    let mut commands = f.command("main");
    commands[4..44].fill(b'a');
    commands.truncate(commands.len() - 4);
    let mut next = f.command("release");
    // A different old commit, so the two compares are distinct and both run.
    next[4..44].fill(b'b');
    let end = next.iter().position(|b| *b == 0).unwrap();
    let payload = &next[4..end];
    commands.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
    commands.extend_from_slice(payload);
    commands.extend_from_slice(b"0000");
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        f.post(commands, "identity"),
    )
    .await
    .unwrap();
    let _ = response.bytes().await.unwrap();
    assert_eq!(
        f.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.contains("/compare/"))
            .count(),
        2
    );
    assert!(f.pending().is_empty());
    assert_eq!(f.received.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn push_slot_is_held_until_upstream_response_finishes() {
    let f = Fixture::with_options(16 * 1024 * 1024, Some(1), Some(3)).await;
    f.response_delay.store(500, Ordering::SeqCst);
    let first = f.post(f.command("agent/test"), "identity").await;
    assert_eq!(first.status(), 200);
    assert_eq!(f.post(b"not git".to_vec(), "identity").await.status(), 503);
    assert_eq!(first.bytes().await.unwrap(), "beginend");
    assert_eq!(f.post(b"not git".to_vec(), "identity").await.status(), 400);
}

#[tokio::test]
async fn push_response_obeys_total_deadline() {
    let f = Fixture::with_options(16 * 1024 * 1024, Some(1), Some(1)).await;
    f.response_delay.store(3000, Ordering::SeqCst);
    let response = f.post(f.command("agent/test"), "identity").await;
    assert_eq!(response.status(), 200);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1500), response.bytes())
            .await
            .unwrap()
            .is_err()
    );
    tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            if f.post(b"not git".to_vec(), "identity").await.status() == 400 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        f.store
            .audit_entries(0, 1000)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "upstream_failed"
                && e.subject()["error_class"] == "response_body")
    );
}

#[tokio::test]
async fn truncated_length_delimited_response_fails_and_is_audited() {
    let f = Fixture::new().await;
    f.response_delay.store(usize::MAX, Ordering::SeqCst);
    let response = f.post(f.command("agent/test"), "identity").await;
    assert!(response.bytes().await.is_err());
    assert!(
        f.store
            .audit_entries(0, 1000)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "upstream_failed"
                && e.subject()["error_class"] == "response_body")
    );
}

const FORCE_POLICY: &str = r#"version = 1
[[rule]]
name = "fetch"
tool = "git.fetch"
decision = "allow"
[[rule]]
name = "no force"
tool = "git.push"
params = { force = true }
decision = "deny"
[[rule]]
name = "agent branch"
tool = "git.push"
target = "127.0.0.1/owner/repo:refs/heads/agent/**"
params = { force = false }
decision = "allow"
[[rule]]
name = "protected"
tool = "git.push"
decision = "ask"
"#;

impl Fixture {
    fn commit(&self, message: &str) {
        git_ok(
            &self.dir.join("work"),
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                message,
            ],
        );
    }
    async fn push_refspec(&self, refspec: &str) -> std::process::Output {
        let dir = self.dir.join("work");
        let url = self.url();
        let header = format!(
            "http.extraHeader=Authorization: Basic {}",
            STANDARD.encode(format!("any:{}", self.token))
        );
        let refspec = refspec.to_owned();
        tokio::task::spawn_blocking(move || git(&dir, &["-c", &header, "push", &url, &refspec]))
            .await
            .unwrap()
    }
    fn upstream_ref(&self, name: &str) -> String {
        String::from_utf8(git(&self.dir, &["--git-dir=owner/repo.git", "rev-parse", name]).stdout)
            .unwrap()
            .trim()
            .to_owned()
    }
    fn head(&self) -> String {
        String::from_utf8(git(&self.dir.join("work"), &["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned()
    }
}

/// SEK-01: real force pushes are `force = true`, real fast-forwards are
/// `force = false`, against an upstream that 404s commits it does not have yet.
#[tokio::test]
async fn real_force_push_is_denied_and_fast_forward_allowed() {
    let f = Fixture::new().await;
    f.reload(FORCE_POLICY);
    let initial = f.head();
    f.commit("a");
    let created = f.push_refspec("HEAD:refs/heads/agent/x").await;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    f.commit("c");
    let fast_forward = f.push_refspec("HEAD:refs/heads/agent/x").await;
    assert!(
        fast_forward.status.success(),
        "fast-forward must be proven from the pack: {}",
        String::from_utf8_lossy(&fast_forward.stderr)
    );
    let tip = f.head();
    assert_eq!(f.upstream_ref("refs/heads/agent/x"), tip);
    // A fast-forward to a commit the upstream already has needs the compare API.
    let created = f
        .push_refspec(&format!("{initial}:refs/heads/agent/y"))
        .await;
    assert!(created.status.success());
    let moved = f.push_refspec("HEAD:refs/heads/agent/y").await;
    assert!(
        moved.status.success(),
        "{}",
        String::from_utf8_lossy(&moved.stderr)
    );
    // Rewrite history and force push: diverged from the upstream tip.
    git_ok(&f.dir.join("work"), &["reset", "-q", "--hard", &initial]);
    f.commit("b");
    let forced = f.push_refspec("+HEAD:refs/heads/agent/x").await;
    assert!(!forced.status.success());
    assert!(
        String::from_utf8_lossy(&forced.stderr).contains("Sekisho denied"),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(f.pending().is_empty(), "a force push is denied, not held");
    assert_eq!(f.upstream_ref("refs/heads/agent/x"), tip);
    // Rewriting to an unrelated root is forced too.
    git_ok(
        &f.dir.join("work"),
        &["checkout", "-q", "--orphan", "fresh"],
    );
    f.commit("root");
    let orphan = f.push_refspec("+HEAD:refs/heads/agent/x").await;
    assert!(!orphan.status.success());
    assert!(f.pending().is_empty());
    assert_eq!(f.upstream_ref("refs/heads/agent/x"), tip);
}

impl Fixture {
    /// One receive-pack command list updating `refs` from `old` to HEAD, no pack.
    fn commands(&self, refs: &[(&str, u8)]) -> Vec<u8> {
        let mut commands = Vec::new();
        for (index, (branch, old)) in refs.iter().enumerate() {
            let mut next = self.command(branch);
            next[4..44].fill(*old);
            let end = if index == 0 {
                next.len() - 4
            } else {
                next.iter().position(|b| *b == 0).unwrap()
            };
            if index == 0 {
                commands.extend_from_slice(&next[..end]);
            } else {
                let payload = &next[4..end];
                commands.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
                commands.extend_from_slice(payload);
            }
        }
        commands.extend_from_slice(b"0000");
        commands
    }
    fn compare_calls(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.contains("/compare/"))
            .count()
    }
}

const FORCE_DEPENDENT: &str = "version = 1\n[[rule]]\nname = 'safe'\ntool = 'git.push'\nparams = {force = false}\ndecision = 'allow'\n[[rule]]\nname = 'ask'\ntool = 'git.push'\ndecision = 'ask'";

/// DS-02: duplicate refs are refused before any store or upstream work, the
/// same compare is asked once per push, and one push asks at most 32.
#[tokio::test]
async fn push_compare_calls_are_deduplicated_and_capped() {
    let f = Fixture::new().await;
    f.reload(FORCE_DEPENDENT);
    *f.compare.lock().unwrap() = Some((200, r#"{"status":"ahead"}"#.into()));
    let duplicate = f.commands(&[("main", b'a'), ("main", b'a')]);
    let response = f.post(duplicate, "identity").await;
    assert_eq!(response.status(), 400);
    assert_eq!(f.compare_calls(), 0);

    let same = f.commands(&[("main", b'a'), ("release", b'a'), ("dev", b'a')]);
    let _ = f.post(same, "identity").await.bytes().await.unwrap();
    assert_eq!(f.compare_calls(), 1, "one distinct (old, new) pair");
    assert!(f.pending().is_empty(), "all three proven by the one answer");

    f.calls.lock().unwrap().clear();
    let names: Vec<String> = (0..40).map(|i| format!("b{i}")).collect();
    let olds = b"0123456789abcdef";
    let refs: Vec<(&str, u8)> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), olds[i % 16]))
        .collect();
    // Distinct olds need distinct compares; vary more than one byte.
    let mut body = f.commands(&refs);
    let mut offset = 0;
    for index in 0..40 {
        let start = body[offset..].windows(4).position(|_| true).unwrap() + offset + 4;
        body[start + 1] = olds[index / 16];
        let length =
            usize::from_str_radix(std::str::from_utf8(&body[offset..offset + 4]).unwrap(), 16)
                .unwrap();
        offset += length;
    }
    let _ = f.post(body, "identity").await.bytes().await.unwrap();
    assert!(f.compare_calls() <= 32, "{}", f.compare_calls());
}
