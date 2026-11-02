#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use sekisho_core::{Ed25519Signer, Signer};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        use std::hash::BuildHasher;
        Self(std::env::temp_dir().join(format!(
            "sekisho-up-{}-{}",
            std::process::id(),
            std::hash::RandomState::new().hash_one(1)
        )))
    }
    fn named(name: &str) -> Self {
        use std::hash::BuildHasher;
        Self(std::env::temp_dir().join(format!(
            "sekisho-up-{}-{}-{}",
            std::process::id(),
            name,
            std::hash::RandomState::new().hash_one(name)
        )))
    }
    fn command(&self) -> Command {
        self.command_bind("127.0.0.1:0")
    }
    fn command_bind(&self, bind: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sekisho"));
        command.args(["up", "--home"]).arg(&self.0).args([
            "--bind",
            bind,
            "--admin-password-stdin",
        ]);
        command
    }
    fn start(&self, input: &str) -> Running {
        self.start_command(self.command(), input)
    }
    fn start_command(&self, mut command: Command, input: &str) -> Running {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut output = String::new();
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                output.push_str(&line);
                output.push('\n');
                if let Some(url) = line.strip_prefix("Listening on ") {
                    send.send((url.to_owned(), output)).unwrap();
                    return;
                }
            }
        });
        let mut running = Running {
            child,
            url: String::new(),
            output: String::new(),
        };
        let (url, output) = receive
            .recv_timeout(Duration::from_secs(20))
            .expect("server must become ready");
        running.url = url;
        running.output = output;
        running
    }
    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("sekisho.db")).unwrap()
    }
    fn mode(&self, name: &str) -> u32 {
        fs::metadata(self.0.join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
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
    output: String,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
const INPUT: &str = "operator\ncorrect horse battery staple\ncorrect horse battery staple\n";

#[test]
fn system_user_id_is_reserved() {
    for id in ["system", "System", "sekisho-admin", "SEKISHO-admin"] {
        let home = Home::named(id);
        let mut child = home
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{id}\npassword\npassword\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(&format!("user id is reserved: {id}")),
            "unexpected error: {error}"
        );
        assert!(!home.0.join("admin.url").exists());
    }
}

#[tokio::test]
async fn first_run_creates_home_keys_db_policy() {
    let home = Home::new();
    let server = home.start(INPUT);
    assert_eq!(
        reqwest::get(format!("{}/healthz", server.url))
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    for path in [
        "keys/audit.ed25519",
        "keys/grant.ed25519",
        "sekisho.db",
        "policy.toml",
        "config.toml",
        "admin.token",
        "admin.url",
    ] {
        assert!(home.0.join(path).is_file(), "{path}");
    }
    sekisho_core::Policy::parse(&fs::read(home.0.join("policy.toml")).unwrap()).unwrap();
    let body: String = home
        .sql()
        .query_row("SELECT body FROM users WHERE id='operator'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let user: sekisho::server::User = serde_json::from_str(&body).unwrap();
    assert!(user.roles.contains(&sekisho::server::Role::Admin));
    Argon2::default()
        .verify_password(
            b"correct horse battery staple",
            &PasswordHash::new(&user.password_hash).unwrap(),
        )
        .unwrap();
    let secret = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        user.totp_secret.unwrap(),
    )
    .unwrap()
    .get_secret_base32();
    assert!(
        server
            .output
            .contains(&format!("otpauth://totp/Sekisho:operator?secret={secret}"))
    );
    assert!(!server.output.contains("correct horse"));
    let key: [u8; 32] = fs::read(home.0.join("keys/audit.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    let signer = Ed25519Signer::from_secret_bytes("audit", &key);
    let store =
        sekisho::store::Store::open(&home.0.join("sekisho.db"), std::sync::Arc::new(signer))
            .unwrap();
    let keys = [(
        "audit".into(),
        Ed25519Signer::from_secret_bytes("audit", &key).public_key(),
    )]
    .into();
    store.verify_audit(&keys).unwrap();
    let entries = store.audit_entries(0, 100).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.subject()["operation"] == "bootstrap_admin")
    );
    assert!(
        entries
            .iter()
            .any(|e| e.kind() == sekisho_core::AuditKind::PolicyLoaded)
    );
    assert!(!serde_json::to_string(&entries).unwrap().contains(&secret));
}
#[test]
fn up_creates_private_home_and_db() {
    let home = Home::new();
    let _server = home.start(INPUT);
    for path in ["", "keys"] {
        assert_eq!(home.mode(path), 0o700);
    }
    for path in [
        "keys/audit.ed25519",
        "keys/grant.ed25519",
        "sekisho.db",
        "admin.token",
        "admin.url",
    ] {
        assert_eq!(home.mode(path), 0o600);
    }
}
#[test]
fn refuses_wide_permissions() {
    let home = Home::new();
    fs::create_dir(&home.0).unwrap();
    fs::set_permissions(&home.0, fs::Permissions::from_mode(0o755)).unwrap();
    let output = home.command().output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains(home.0.to_str().unwrap()) && error.contains("0755"),
        "{error}"
    );
    fs::set_permissions(&home.0, fs::Permissions::from_mode(0o700)).unwrap();
    drop(home.start(INPUT));
    for path in [
        "keys",
        "keys/audit.ed25519",
        "keys/grant.ed25519",
        "admin.token",
        "admin.url",
    ] {
        fs::set_permissions(home.0.join(path), fs::Permissions::from_mode(0o744)).unwrap();
        let output = home.command().output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains(home.0.join(path).to_str().unwrap().trim_end_matches('/'))
                && error.contains("0744"),
            "{error}"
        );
        fs::set_permissions(
            home.0.join(path),
            fs::Permissions::from_mode(if path == "keys" { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
}
#[test]
fn up_refuses_world_readable_db() {
    let home = Home::new();
    drop(home.start(INPUT));
    fs::set_permissions(home.0.join("sekisho.db"), fs::Permissions::from_mode(0o644)).unwrap();
    let output = home.command().output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("sekisho.db") && error.contains("0644"),
        "{error}"
    );
}
#[test]
fn second_run_reuses_home() {
    let home = Home::new();
    drop(home.start(INPUT));
    let paths = [
        "keys/audit.ed25519",
        "keys/grant.ed25519",
        "policy.toml",
        "config.toml",
        "admin.token",
    ];
    let before: Vec<_> = paths
        .iter()
        .map(|p| fs::read(home.0.join(p)).unwrap())
        .collect();
    let server = home.start("");
    assert!(!server.output.contains("otpauth://"));
    for (path, bytes) in paths.iter().zip(before) {
        assert_eq!(fs::read(home.0.join(path)).unwrap(), bytes);
    }
    assert_eq!(
        home.sql()
            .query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn non_loopback_bind_requires_flag() {
    let home = Home::new();
    let output = home.command_bind("0.0.0.0:0").output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--insecure-bind")
    );
    assert!(!home.0.exists());
}
#[test]
fn keys_are_random_and_distinct() {
    let a = Home::new();
    let b = Home::new();
    drop(a.start(INPUT));
    drop(b.start(INPUT));
    let keys: Vec<_> = [&a, &b]
        .iter()
        .flat_map(|h| {
            ["audit", "grant"]
                .map(|name| fs::read(h.0.join(format!("keys/{name}.ed25519"))).unwrap())
        })
        .collect();
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|b| *b != 0));
        for other in &keys[..i] {
            assert_ne!(key, other);
        }
    }
}

#[tokio::test]
async fn non_loopback_bind_with_flag_warns_and_serves() {
    let home = Home::new();
    let mut command = home.command_bind("0.0.0.0:0");
    command.arg("--insecure-bind");
    let mut server = home.start_command(command, INPUT);
    let url = server.url.replace("0.0.0.0", "127.0.0.1");
    assert_eq!(
        reqwest::get(format!("{url}/healthz"))
            .await
            .unwrap()
            .status(),
        200
    );
    server.child.kill().unwrap();
    server.child.wait().unwrap();
    let mut stderr = String::new();
    server
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("WARNING") && stderr.contains("unencrypted"));
}

#[test]
fn invalid_passwords_leave_no_admin_and_can_be_retried() {
    for input in ["operator\n\n\n", "operator\nfirst\nsecond\n"] {
        let home = Home::new();
        let mut child = home
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("otpauth://")
        );
        assert_eq!(
            home.sql()
                .query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(home.start(INPUT));
    }
}

#[test]
fn startup_audit_failure_rolls_back_admin_and_refuses_to_serve() {
    let home = Home::new();
    assert!(!home.command().output().unwrap().status.success());
    home.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let mut child = home
        .command()
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
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("otpauth://")
    );
    for table in ["users", "audit"] {
        assert_eq!(
            home.sql()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    home.sql().execute_batch("DROP TRIGGER fail_audit").unwrap();
    drop(home.start(INPUT));
}

#[test]
fn existing_database_never_regenerates_missing_or_invalid_keys() {
    let home = Home::new();
    drop(home.start(INPUT));
    let audit = home.0.join("keys/audit.ed25519");
    fs::write(&audit, b"bad key").unwrap();
    assert!(!home.command().output().unwrap().status.success());
    assert_eq!(fs::read(&audit).unwrap(), b"bad key");
    fs::remove_file(&audit).unwrap();
    assert!(!home.command().output().unwrap().status.success());
    assert!(!audit.exists());
}

#[tokio::test]
async fn enrolled_admin_can_log_in_with_password_and_totp() {
    let home = Home::new();
    let server = home.start(INPUT);
    let body: String = home
        .sql()
        .query_row("SELECT body FROM users", [], |r| r.get(0))
        .unwrap();
    let user: sekisho::server::User = serde_json::from_str(&body).unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        user.totp_secret.unwrap(),
    )
    .unwrap();
    let code = totp.generate(time::OffsetDateTime::now_utc().unix_timestamp() as u64);
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/login", server.url))
        .send()
        .await
        .unwrap();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = client
        .post(format!("{}/login", server.url))
        .header("cookie", cookie)
        .form(&[
            ("user_id", "operator"),
            ("password", "correct horse battery staple"),
            ("totp", &code),
            ("csrf_token", cookie.split('=').nth(1).unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|h| h.to_str().unwrap().starts_with("sekisho_session="))
    );
}

fn agent(home: &Home, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .env("SEKISHO_HOME", &home.0)
        .args(["agent"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn agent_commands_require_initialized_home() {
    let home = Home::new();
    for args in [
        vec!["list"],
        vec!["add", "claude"],
        vec!["rotate", "claude"],
        vec!["remove", "claude"],
    ] {
        let output = agent(&home, &args);
        assert_eq!(output.status.code(), Some(1));
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("sekisho up"), "{error}");
        assert!(!home.0.exists());
    }
    // Failed enrollment leaves files but no bootstrap admin.
    assert!(!home.command().output().unwrap().status.success());
    let output = agent(&home, &["add", "claude"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("sekisho up")
    );
    assert_eq!(
        home.sql()
            .query_row("SELECT count(*) FROM agents", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn agent_commands_check_startup_permissions() {
    let home = Home::new();
    drop(home.start(INPUT));
    for path in [
        "",
        "keys",
        "keys/audit.ed25519",
        "keys/grant.ed25519",
        "sekisho.db",
    ] {
        let mode = home.mode(path);
        fs::set_permissions(home.0.join(path), fs::Permissions::from_mode(0o744)).unwrap();
        for args in [
            vec!["list"],
            vec!["add", "claude"],
            vec!["rotate", "claude"],
            vec!["remove", "claude"],
        ] {
            let output = agent(&home, &args);
            assert_eq!(output.status.code(), Some(1));
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(
                error.contains(home.0.join(path).to_str().unwrap().trim_end_matches('/'))
                    && error.contains("0744"),
                "{error}"
            );
        }
        fs::set_permissions(home.0.join(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    assert_eq!(
        home.sql()
            .query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn agent_commands_use_bootstrap_admin() {
    let home = Home::new();
    drop(home.start(INPUT));
    // A lexically earlier user must not replace the recorded bootstrap actor.
    let body: String = home
        .sql()
        .query_row("SELECT body FROM users", [], |r| r.get(0))
        .unwrap();
    let mut user: sekisho::server::User = serde_json::from_str(&body).unwrap();
    user.id = "aaa".try_into().unwrap();
    home.sql()
        .execute(
            "INSERT INTO users(id,body) VALUES (?,?)",
            ("aaa", serde_json::to_string(&user).unwrap()),
        )
        .unwrap();
    for args in [
        ["add", "claude"],
        ["rotate", "claude"],
        ["remove", "claude"],
    ] {
        let output = agent(&home, &args);
        assert!(output.status.success(), "{:?}", output.stderr);
    }
    let connection = home.sql();
    let mut query = connection
        .prepare("SELECT body FROM audit WHERE seq >= 2 ORDER BY seq")
        .unwrap();
    let entries: Vec<sekisho_core::AuditEntry> = query
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect();
    assert_eq!(entries.len(), 3);
    for entry in entries {
        assert_eq!(
            entry.actor(),
            &sekisho_core::Principal::User("operator".try_into().unwrap())
        );
        assert_eq!(entry.subject()["actor_id"], "operator");
    }
}

#[test]
fn default_command_runs_up_and_uses_sekisho_home() {
    let home = Home::new();
    let output = Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .env("SEKISHO_HOME", &home.0)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("missing setup input")
    );
    assert!(home.0.join("sekisho.db").is_file());
}

#[tokio::test]
async fn up_serves_check_api() {
    let home = Home::new();
    let server = home.start(INPUT);
    let added = agent(&home, &["add", "claude"]);
    assert!(added.status.success());
    let token = String::from_utf8(added.stdout).unwrap();
    let response = reqwest::Client::new()
        .post(format!("{}/v1/check", server.url))
        .bearer_auth(token.trim())
        .json(&serde_json::json!({"tool":"mcp:github/get_issue", "target":"github", "params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["decision"],
        "allow"
    );
}

#[tokio::test]
async fn up_loads_mcp_upstreams_from_config() {
    let home = Home::new();
    drop(home.start(INPUT));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    fs::write(home.0.join("config.toml"), format!(
        "mcp_wait_seconds = 0\nmcp_timeout_seconds = 1\n[mcp_limits]\ndiscovery_ttl_seconds = 60\nrequest_bytes = 256\nresponse_bytes = 4096\n[[mcp]]\nname = 'offline'\ntransport = 'http'\nurl = 'http://{address}/mcp'\n"
    )).unwrap();
    let server = home.start("");
    let added = agent(&home, &["add", "claude"]);
    assert!(added.status.success());
    let token = String::from_utf8(added.stdout).unwrap();
    let response = reqwest::Client::new()
        .post(format!("{}/mcp", server.url))
        .bearer_auth(token.trim())
        .header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"tools/list", "params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("Sekisho upstream tool discovery failed")
    );
    let count: i64 = home
        .sql()
        .query_row(
            "SELECT count(*) FROM audit WHERE body LIKE '%tools/list%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
    let failed: i64 = home
        .sql()
        .query_row(
            "SELECT count(*) FROM audit WHERE body LIKE '%upstream_failed%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(failed, 1);
    let response = reqwest::Client::new()
        .post(format!("{}/mcp", server.url))
        .bearer_auth(token.trim())
        .header("content-type", "application/json")
        .body("x".repeat(257))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn up_uses_configured_ttl_policy_and_grant_key() {
    let home = Home::new();
    drop(home.start(INPUT));
    fs::write(home.0.join("config.toml"), "approval_ttl_seconds = 60\n").unwrap();
    fs::write(
        home.0.join("policy.toml"),
        "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ndecision = 'ask'\n",
    )
    .unwrap();
    let server = home.start("");
    let added = agent(&home, &["add", "claude"]);
    assert!(added.status.success());
    let token = String::from_utf8(added.stdout).unwrap();
    let client = reqwest::Client::new();
    let request = || {
        client
            .post(format!("{}/v1/check", server.url))
            .bearer_auth(token.trim())
            .json(&serde_json::json!({"tool":"git.push", "target":"repo", "params":{}}))
    };
    let response: serde_json::Value = request().send().await.unwrap().json().await.unwrap();
    assert_eq!(response["decision"], "ask");
    let body: String = home
        .sql()
        .query_row(
            "SELECT body FROM approvals WHERE id=?",
            [response["approval_id"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body["expires_at"].as_i64().unwrap() - body["requested_at"].as_i64().unwrap(),
        60
    );
    let key: [u8; 32] = fs::read(home.0.join("keys/grant.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    let grant_key = Ed25519Signer::from_secret_bytes("grant", &key);
    let audit_key: [u8; 32] = fs::read(home.0.join("keys/audit.ed25519"))
        .unwrap()
        .try_into()
        .unwrap();
    let store = sekisho::store::Store::open(
        &home.0.join("sekisho.db"),
        std::sync::Arc::new(Ed25519Signer::from_secret_bytes("audit", &audit_key)),
    )
    .unwrap();
    let now = sekisho_core::Timestamp::from(time::OffsetDateTime::now_utc().unix_timestamp());
    let grant = sekisho_core::UnsignedGrant {
        id: "grt_aaaaaaaaaaaaaaaaaaaaaaaaaa".try_into().unwrap(),
        agent_id: "claude".try_into().unwrap(),
        tool: "git.push".try_into().unwrap(),
        target_glob: "repo".into(),
        params: Default::default(),
        not_before: now,
        expires_at: (now.as_secs() + 3600).into(),
        max_uses: Some(1),
        issued_by: "operator".try_into().unwrap(),
    }
    .sign(&grant_key)
    .unwrap();
    store.transact(now, |tx| {
        tx.insert_grant(&grant)?;
        Ok(((), vec![sekisho::store::AuditRecord { kind: sekisho_core::AuditKind::GrantIssued,
            actor: sekisho_core::Principal::User(grant.issued_by().clone()),
            subject: serde_json::json!({"grant_id":grant.id().as_str(), "agent_id":grant.agent_id().as_str(), "issued_by":grant.issued_by().as_str(), "expires_at":grant.expires_at()}) }]))
    }).unwrap();
    assert_eq!(
        request()
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()["decision"],
        "allow"
    );
    assert_eq!(
        request()
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()["decision"],
        "ask"
    );
}
