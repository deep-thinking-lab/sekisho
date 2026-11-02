#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sekisho_core::{AuditEntry, AuditKind, Principal, UserId};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
use time::format_description::well_known::Rfc3339;

const INPUT: &str = "operator\ncorrect horse battery staple\ncorrect horse battery staple\n";

struct Running {
    child: Child,
    url: String,
    totp_secret: String,
}

struct Home {
    path: PathBuf,
    server: Running,
}

impl Home {
    fn start(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sekisho-approvals-cli-{}-{name}",
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
        self.agent_named("claude")
    }

    fn agent_named(&self, name: &str) -> String {
        let output = self.run(&["agent", "add", name]);
        assert!(output.status.success(), "{:?}", output.stderr);
        String::from_utf8(output.stdout)
            .expect("agent token should be UTF-8")
            .trim()
            .to_owned()
    }

    async fn ask(&self, token: &str) -> String {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/check", self.server.url))
            .bearer_auth(token)
            .json(&json!({
                "tool": "git.push",
                "target": "github.com/example/repo:refs/heads/main",
                "params": {"old": "a", "new": "b", "delete": false, "force": false},
            }))
            .send()
            .await
            .expect("check request should complete");
        assert_eq!(
            response.status(),
            200,
            "{}",
            response.text().await.unwrap_or_default()
        );
        let body: Value = response.json().await.expect("check body should be JSON");
        assert_eq!(body["decision"], "ask");
        body["approval_id"].as_str().unwrap().to_owned()
    }

    fn totp(&self) -> String {
        self.totp_at(0)
    }

    /// Code for the step `offset` steps from now. The server accepts one step
    /// either side, so tests that need two codes use 0 and then 1.
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

    fn run_input(&self, args: &[&str], input: &str) -> std::process::Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .env("SEKISHO_HOME", &self.path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{input}\n").as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn state(&self, id: &str) -> String {
        rusqlite::Connection::open(self.path.join("sekisho.db"))
            .unwrap()
            .query_row("SELECT state FROM approvals WHERE id=?", [id], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sekisho"))
            .env("SEKISHO_HOME", &self.path)
            .args(args)
            .output()
            .expect("sekisho command should run")
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

async fn pending(name: &str) -> (Home, String) {
    let home = Home::start(name);
    let token = home.agent();
    let id = home.ask(&token).await;
    (home, id)
}

fn assert_cli_decision(name: &str, command: &str, kind: AuditKind) {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (home, id) = pending(name).await;
        let before = home.audit().len();
        let output = home.run_input(&["approvals", command, &id], &home.totp());
        assert!(output.status.success(), "{:?}", output.stderr);

        let entries = home.audit();
        assert_eq!(entries.len(), before + 1);
        let entry = entries.last().unwrap();
        assert_eq!(entry.kind(), kind);
        assert_eq!(entry.subject()["approval_id"], id);
        assert_eq!(
            entry.actor(),
            &Principal::User(UserId::try_from("operator").unwrap())
        );

        let connection = rusqlite::Connection::open(home.path.join("sekisho.db")).unwrap();
        let state: String = connection
            .query_row("SELECT state FROM approvals WHERE id=?", [&id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            state,
            if kind == AuditKind::Approved {
                "Approved"
            } else {
                "Denied"
            }
        );
    });
}

#[test]
fn approvals_list_shows_pending_approvals() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (home, id) = pending("list").await;
        let output = home.run(&["approvals", "list"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(&id), "{stdout}");
        assert!(stdout.contains("claude"), "{stdout}");
        assert!(
            stdout.contains("github.com/example/repo:refs/heads/main"),
            "{stdout}"
        );
        let connection = rusqlite::Connection::open(home.path.join("sekisho.db")).unwrap();
        let expires_at: i64 = connection
            .query_row(
                "SELECT expires_at FROM approvals WHERE id=?",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        let expires = time::OffsetDateTime::from_unix_timestamp(expires_at)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        assert!(stdout.contains(&expires), "{stdout}");
        assert!(
            stdout.contains("(in 14m)") || stdout.contains("(in 15m)"),
            "{stdout}"
        );
    });
}

#[test]
fn approvals_list_json_keeps_raw_expiry() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (home, id) = pending("list-json").await;
        let output = home.run(&["approvals", "list", "--json"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        let rows: Value = serde_json::from_slice(&output.stdout).unwrap();
        let row = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap();
        assert!(row["expires_at"].is_i64(), "{row}");
    });
}

#[test]
fn approvals_approve_writes_the_web_audit_record() {
    assert_cli_decision("approve", "approve", AuditKind::Approved);
}

#[test]
fn approvals_deny_writes_the_web_audit_record() {
    assert_cli_decision("deny", "deny", AuditKind::Denied);
}

/// SEK-02: `admin.token` alone, which an agent sharing the operator's OS user
/// can read, must not approve. Approving also needs the admin's TOTP code.
#[test]
fn local_admin_token_alone_cannot_approve() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (home, id) = pending("approve-totp").await;
        let token = fs::read_to_string(home.path.join("admin.token")).unwrap();
        let url = fs::read_to_string(home.path.join("admin.url")).unwrap();
        let client = reqwest::Client::new();
        let endpoint = format!("{}/admin/approvals/{id}/approve", url.trim());
        let bare = client
            .post(&endpoint)
            .bearer_auth(token.trim())
            .send()
            .await
            .unwrap();
        assert_eq!(bare.status(), 401);
        let wrong = client
            .post(&endpoint)
            .bearer_auth(token.trim())
            .json(&json!({"totp": "000000"}))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), 401);
        // The CLI prompts for a code; with no input it refuses.
        let output = home.run(&["approvals", "approve", &id]);
        assert!(!output.status.success());
        assert_eq!(home.state(&id), "Pending");

        // Denying is a state change too.
        let deny = client
            .post(format!("{}/admin/approvals/{id}/deny", url.trim()))
            .bearer_auth(token.trim())
            .send()
            .await
            .unwrap();
        assert_eq!(deny.status(), 401);
        assert_eq!(home.state(&id), "Pending");
        // The CLI has no argv flag for the code: argv is readable by other processes.
        let code = home.totp();
        let output = home.run(&["approvals", "approve", &id, "--totp", &code]);
        assert!(!output.status.success());
        assert_eq!(home.state(&id), "Pending");

        let output = home.run_input(&["approvals", "approve", &id], &code);
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(home.state(&id), "Approved");
        // A used code cannot be replayed for another approval.
        let token_agent = home.agent_named("claude-2");
        let second = home.ask(&token_agent).await;
        let output = home.run_input(&["approvals", "approve", &second], &code);
        assert!(!output.status.success());
        assert_eq!(home.state(&second), "Pending");
    });
}

/// A replayed code validates but cannot be consumed; it must stay a failed
/// attempt, or replaying it would reset the limiter and allow unlimited guesses.
#[test]
fn replayed_totp_code_does_not_reset_the_attempt_limiter() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let (home, id) = pending("approve-limit").await;
        let used = home.totp();
        let output = home.run_input(&["approvals", "approve", &id], &used);
        assert!(output.status.success(), "{:?}", output.stderr);
        let token = fs::read_to_string(home.path.join("admin.token")).unwrap();
        let url = fs::read_to_string(home.path.join("admin.url")).unwrap();
        let second = home.ask(&home.agent_named("claude-2")).await;
        let endpoint = format!("{}/admin/approvals/{second}/approve", url.trim());
        let client = reqwest::Client::new();
        let attempt = |code: String| {
            client
                .post(&endpoint)
                .bearer_auth(token.trim())
                .json(&json!({"totp": code}))
                .send()
        };
        for _ in 0..5 {
            assert_eq!(attempt(used.clone()).await.unwrap().status(), 401);
        }
        assert_eq!(attempt(home.totp_at(1)).await.unwrap().status(), 429);
        assert_eq!(home.state(&second), "Pending");
    });
}
