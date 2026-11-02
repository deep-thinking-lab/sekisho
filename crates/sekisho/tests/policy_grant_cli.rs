#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sekisho_core::{AuditEntry, AuditKind, Policy};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

static NEXT_HOME: AtomicUsize = AtomicUsize::new(0);
const INPUT: &str = "operator\ncorrect horse battery staple\ncorrect horse battery staple\n";

struct Home {
    path: PathBuf,
    server: Running,
}

struct Running {
    child: Child,
    url: String,
    totp_secret: String,
}

impl Home {
    fn start(name: &str) -> Self {
        let sequence = NEXT_HOME.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sekisho-policy-grant-{}-{sequence}-{name}",
            std::process::id()
        ));
        let mut child = Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .args(["up", "--home"])
            .arg(&path)
            .args(["--bind", "127.0.0.1:0", "--admin-password-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("sekisho up should start");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(INPUT.as_bytes())
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut secret = String::new();
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if let Some(value) = line.strip_prefix("TOTP secret: ") {
                    secret = value.to_owned();
                }
                if let Some(url) = line.strip_prefix("Listening on ") {
                    let _ = send.send((url.to_owned(), secret));
                    return;
                }
            }
            let _ = send.send((String::new(), String::new()));
        });
        let (url, totp_secret) = receive
            .recv_timeout(Duration::from_secs(20))
            .expect("server should become ready");
        assert!(!url.is_empty(), "server exited before becoming ready");
        Self {
            path,
            server: Running {
                child,
                url,
                totp_secret,
            },
        }
    }

    fn agent(&self) -> String {
        let output = self.run(&["agent", "add", "claude"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        String::from_utf8(output.stdout)
            .expect("agent token should be UTF-8")
            .trim()
            .to_owned()
    }

    /// Code for the step `offset` steps from now (the server accepts one either side).
    fn totp_at(&self, offset: u64) -> String {
        let secret = totp_rs::Secret::Encoded(self.server.totp_secret.clone())
            .to_bytes()
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, secret)
            .unwrap()
            .generate(now + 30 * offset)
    }

    fn reload(&self, offset: u64) -> std::process::Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .env("SEKISHO_HOME", &self.path)
            .args(["policy", "reload"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{}\n", self.totp_at(offset)).as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .env("SEKISHO_HOME", &self.path)
            .args(args)
            .output()
            .expect("sekisho command should run")
    }

    async fn check(&self, token: &str, tool: &str, target: &str, params: Value) -> Value {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/check", self.server.url))
            .bearer_auth(token)
            .json(&json!({"tool": tool, "target": target, "params": params}))
            .send()
            .await
            .expect("check request should complete");
        assert_eq!(
            response.status(),
            200,
            "{}",
            response.text().await.unwrap_or_default()
        );
        response.json().await.expect("check body should be JSON")
    }

    fn audit(&self) -> Vec<AuditEntry> {
        let connection = rusqlite::Connection::open(self.path.join("sekisho.db")).unwrap();
        connection
            .prepare("SELECT body FROM audit ORDER BY seq")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| serde_json::from_str(&row.unwrap()).unwrap())
            .collect()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = self.server.child.kill();
        let _ = self.server.child.wait();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_policy(home: &Home, policy: &str) {
    let path = home.path.join("policy.toml");
    fs::write(&path, policy).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn audit_kind(entries: &[AuditEntry], kind: AuditKind) -> usize {
    entries.iter().filter(|entry| entry.kind() == kind).count()
}

const ALLOW_FETCH: &str = r#"version = 1

[[rule]]
name = "fetch"
tool = "git.fetch"
target = "repo"
decision = "allow"
"#;

#[tokio::test]
async fn invalid_policy_keeps_old_active() {
    let home = Home::start("invalid-policy");
    let token = home.agent();
    write_policy(&home, ALLOW_FETCH);
    let loaded = home.reload(0);
    assert!(loaded.status.success(), "{:?}", loaded.stderr);
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({})).await["decision"],
        "allow"
    );
    let before = audit_kind(&home.audit(), AuditKind::PolicyLoaded);

    write_policy(&home, "version = 2\n");
    let invalid = home.reload(1);
    assert_eq!(invalid.status.code(), Some(1));
    assert!(!invalid.stderr.is_empty());
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({})).await["decision"],
        "allow"
    );
    assert_eq!(
        audit_kind(&home.audit(), AuditKind::PolicyLoaded),
        before,
        "an invalid reload must not append a PolicyLoaded entry"
    );
}

#[tokio::test]
async fn reload_writes_policy_loaded_audit() {
    let home = Home::start("reload-audit");
    let token = home.agent();
    let before = audit_kind(&home.audit(), AuditKind::PolicyLoaded);
    let next = r#"version = 1

[[rule]]
name = "fetch approval"
tool = "git.fetch"
target = "repo"
decision = "ask"
"#;
    write_policy(&home, next);
    let digest = Policy::parse(next.as_bytes()).unwrap().sha256;

    let reloaded = home.reload(0);
    assert!(reloaded.status.success(), "{:?}", reloaded.stderr);
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({})).await["decision"],
        "ask"
    );
    let entries = home.audit();
    assert_eq!(audit_kind(&entries, AuditKind::PolicyLoaded), before + 1);
    let loaded = entries
        .iter()
        .rev()
        .find(|entry| entry.kind() == AuditKind::PolicyLoaded)
        .unwrap();
    assert_eq!(loaded.subject()["policy_sha256"], digest.to_string());
}

#[tokio::test]
async fn grant_add_then_check_allows() {
    let home = Home::start("grant-add");
    let token = home.agent();
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({"force": false}))
            .await["decision"],
        "deny"
    );

    let added = home.run(&[
        "grant",
        "add",
        "--agent",
        "claude",
        "--tool",
        "git.fetch",
        "--target",
        "repo",
        "--param",
        "force=false",
        "--expires",
        "1h",
        "--max-uses",
        "2",
    ]);
    assert!(added.status.success(), "{:?}", added.stderr);
    let id = String::from_utf8(added.stdout).unwrap();
    let id = id.trim();
    assert!(id.starts_with("grt_"));

    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({"force": false}))
            .await["decision"],
        "allow"
    );
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({"force": true}))
            .await["decision"],
        "deny"
    );
    let listed = home.run(&["grant", "list"]);
    assert!(listed.status.success(), "{:?}", listed.stderr);
    assert!(
        String::from_utf8(listed.stdout).unwrap().contains(id),
        "grant list must include the issued grant"
    );
    let entries = home.audit();
    assert!(entries.iter().any(|entry| {
        entry.kind() == AuditKind::GrantIssued && entry.subject()["grant_id"] == id
    }));
}

#[tokio::test]
async fn grant_revoke_then_check_denies() {
    let home = Home::start("grant-revoke");
    let token = home.agent();
    let added = home.run(&[
        "grant",
        "add",
        "--agent",
        "claude",
        "--tool",
        "git.fetch",
        "--target",
        "repo",
        "--expires",
        "1h",
    ]);
    assert!(added.status.success(), "{:?}", added.stderr);
    let id = String::from_utf8(added.stdout).unwrap();
    let id = id.trim();
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({})).await["decision"],
        "allow"
    );

    let revoked = home.run(&["grant", "revoke", id]);
    assert!(revoked.status.success(), "{:?}", revoked.stderr);
    assert_eq!(
        home.check(&token, "git.fetch", "repo", json!({})).await["decision"],
        "deny"
    );
    let entries = home.audit();
    assert!(entries.iter().any(|entry| {
        entry.kind() == AuditKind::GrantRevoked && entry.subject()["grant_id"] == id
    }));
    let connection = rusqlite::Connection::open(home.path.join("sekisho.db")).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM grant_tombstones WHERE id=?",
                [id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    let listed = home.run(&["grant", "list"]);
    assert!(listed.status.success(), "{:?}", listed.stderr);
    let listed = String::from_utf8(listed.stdout).unwrap();
    let row = listed
        .lines()
        .find(|line| line.starts_with(id))
        .expect("revoked grant must remain listed");
    assert!(row.contains("revoked"), "{row}");
}

#[test]
fn policy_check_prints_rules_and_rejects_invalid() {
    let sequence = NEXT_HOME.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "sekisho-policy-check-{}-{sequence}.toml",
        std::process::id()
    ));
    fs::write(&path, ALLOW_FETCH).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .args(["policy", "check"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, "ok: 1 rules\n");

    let output = Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .args(["policy", "check", "--json"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("fetch"), "{stdout}");
    assert!(stdout.contains("git.fetch"), "{stdout}");
    assert!(stdout.contains("allow"), "{stdout}");

    fs::write(&path, "version = 2\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .args(["policy", "check"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unsupported policy version")
    );
    fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn policy_reload_requires_local_admin_token() {
    let home = Home::start("reload-auth");
    let token_path = home.path.join("admin.token");
    let token = fs::read_to_string(&token_path).unwrap();
    let url = fs::read_to_string(home.path.join("admin.url")).unwrap();
    let client = reqwest::Client::new();
    for request in [
        client.post(format!("{}/admin/policy/reload", url.trim())),
        client
            .post(format!("{}/admin/policy/reload", url.trim()))
            .bearer_auth("wrong"),
    ] {
        assert_eq!(request.send().await.unwrap().status(), 401);
    }
    // SEK-02: the token alone, readable by a same-user agent, cannot reload.
    assert_eq!(
        client
            .post(format!("{}/admin/policy/reload", url.trim()))
            .bearer_auth(token.trim())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let code = home.totp_at(0);
    let reload = || {
        client
            .post(format!("{}/admin/policy/reload", url.trim()))
            .bearer_auth(token.trim())
            .json(&json!({"totp": code}))
    };
    assert_eq!(reload().send().await.unwrap().status(), 204);
    assert_eq!(
        reload().send().await.unwrap().status(),
        401,
        "replayed code"
    );
    // A policy file others could have written is refused.
    let policy = home.path.join("policy.toml");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o620)).unwrap();
    let output = home.reload(1);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refused"),
        "{:?}",
        output.stderr
    );
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fs::metadata(token_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
