#![allow(clippy::unwrap_used)]
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use reqwest::{Client, Response};
use sekisho::{
    server::{AppState, Clock, SessionStore, SessionToken, UserDirectory, router},
    store::Store,
};
use sekisho_core::{AuditKind, Ed25519Signer, Principal, Timestamp, UserId};
use serde_json::json;
use std::{hash::BuildHasher, path::PathBuf, sync::Arc};

struct Db(PathBuf);
impl Db {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sekisho-auth-{}",
            std::hash::RandomState::new().hash_one(std::process::id())
        ));
        std::fs::create_dir(&dir).unwrap();
        let db = Self(dir.join("store.db"));
        let _store = db.open();
        let hash = Argon2::default()
            .hash_password(
                b"secret-password",
                &SaltString::encode_b64(b"fixed-test-salt!").unwrap(),
            )
            .unwrap()
            .to_string();
        db.sql()
            .execute(
                "INSERT INTO users(id, body) VALUES (?, ?)",
                (
                    "admin",
                    json!({"id":"admin", "password_hash":hash,
                "totp_secret":b"12345678901234567890".to_vec(), "roles":["Admin"]})
                    .to_string(),
                ),
            )
            .unwrap();
        db
    }
    fn open(&self) -> Store {
        Store::open(
            &self.0,
            Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32])),
        )
        .unwrap()
    }
    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.0).unwrap()
    }
    fn count(&self, table: &str) -> i64 {
        self.sql()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    fn fail_audit(&self) {
        self.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;").unwrap();
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
    }
}
struct FixedClock(i64);
impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0.into()
    }
}
struct Server {
    base: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(db: &Db, now: i64) -> Self {
        let store = Arc::new(db.open());
        let state = AppState::new(store.clone(), store, Arc::new(FixedClock(now)), true).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        Self { base, task }
    }
    async fn login(&self, id: &str, code: &str) -> Response {
        let client = Client::new();
        let prelogin = client
            .get(format!("{}/login", self.base))
            .send()
            .await
            .unwrap();
        let cookie = prelogin.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        client
            .post(format!("{}/login", self.base))
            .header("cookie", cookie)
            .form(&[
                ("user_id", id),
                ("password", "secret-password"),
                ("totp", code),
                ("csrf_token", cookie.split('=').nth(1).unwrap()),
            ])
            .send()
            .await
            .unwrap()
    }
    async fn home(&self, token: &SessionToken) -> Response {
        Client::new()
            .get(format!("{}/", self.base))
            .header("cookie", format!("sekisho_session={}", token.expose()))
            .send()
            .await
            .unwrap()
    }
}
fn code(now: u64) -> String {
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        b"12345678901234567890".to_vec(),
    )
    .unwrap()
    .generate(now)
}
fn token(response: &Response) -> SessionToken {
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|h| h.to_str().unwrap())
        .find(|s| s.starts_with("sekisho_session="))
        .unwrap();
    SessionToken::from_cookie(cookie.split(';').next().unwrap().split('=').nth(1).unwrap())
}
#[tokio::test]
async fn login_writes_audit_in_same_transaction() {
    let db = Db::new();
    let server = Server::start(&db, 1_700_000_000).await;
    let response = server.login("admin", &code(1_700_000_000)).await;
    assert_eq!(response.status(), 200);
    let token = token(&response);
    assert_eq!(server.home(&token).await.status(), 200);
    assert_eq!(db.count("sessions"), 1);
    let entries = db.open().audit_entries(0, 100).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind(), AuditKind::UserLogin);
    assert_eq!(
        entries[0].actor(),
        &Principal::User(UserId::try_from("admin").unwrap())
    );
    assert_eq!(entries[0].subject()["operation"], "login");
    let key = Ed25519Signer::from_secret_bytes("audit", &[7; 32]);
    use sekisho_core::Signer;
    db.open()
        .verify_audit(&[("audit".into(), key.public_key())].into())
        .unwrap();
    let stored: String = db
        .sql()
        .query_row("SELECT id FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_ne!(stored, token.expose());
    let audit = serde_json::to_string(&entries).unwrap();
    for secret in [
        token.expose(),
        "secret-password",
        "12345678901234567890",
        "$argon2id$",
    ] {
        assert!(!audit.contains(secret));
    }
}
#[tokio::test]
async fn login_refused_when_audit_fails() {
    let db = Db::new();
    db.fail_audit();
    let server = Server::start(&db, 1_700_000_000).await;
    let response = server.login("admin", &code(1_700_000_000)).await;
    assert_eq!(response.status(), 503);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(db.count("sessions"), 0);
    assert_eq!(db.count("audit"), 0);
    db.sql().execute_batch("DROP TRIGGER fail_audit").unwrap();
    assert_eq!(
        server.login("admin", &code(1_700_000_000)).await.status(),
        200
    );
}
#[tokio::test]
async fn sessions_survive_restart() {
    let db = Db::new();
    let server = Server::start(&db, 1_700_000_000).await;
    let response = server.login("admin", &code(1_700_000_000)).await;
    assert_eq!(response.status(), 200);
    let token = token(&response);
    let csrf = response.json::<serde_json::Value>().await.unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    drop(server);
    let restarted = Server::start(&db, 1_700_000_001).await;
    assert_eq!(restarted.home(&token).await.status(), 200);
    assert_eq!(
        db.open()
            .get(&token, 1_700_000_001.into())
            .unwrap()
            .unwrap()
            .csrf_token,
        csrf
    );
    assert!(
        db.open()
            .find(&UserId::try_from("admin").unwrap())
            .unwrap()
            .is_some()
    );
}
#[tokio::test]
async fn expired_sessions_rejected_after_restart() {
    let db = Db::new();
    let server = Server::start(&db, 1_700_000_000).await;
    let response = server.login("admin", &code(1_700_000_000)).await;
    assert_eq!(response.status(), 200);
    let token = token(&response);
    drop(server);
    let restarted = Server::start(&db, 1_700_043_200).await;
    assert_eq!(restarted.home(&token).await.status(), 401);
    assert!(
        db.open()
            .get(&token, 1_700_043_200.into())
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn totp_replay_rejected_after_restart() {
    let db = Db::new();
    let server = Server::start(&db, 1_700_000_000).await;
    let first_code = code(1_700_000_000);
    assert_eq!(server.login("admin", &first_code).await.status(), 200);
    drop(server);
    let restarted = Server::start(&db, 1_700_000_001).await;
    assert_eq!(restarted.login("admin", &first_code).await.status(), 401);
    assert_eq!(db.count("sessions"), 1);
    assert_eq!(db.count("audit"), 1);
    assert_eq!(
        restarted
            .login("admin", &code(1_700_000_030))
            .await
            .status(),
        200
    );
}
#[tokio::test]
async fn unknown_users_share_invalid_login_bucket() {
    let db = Db::new();
    let server = Server::start(&db, 1_700_000_000).await;
    for id in [
        "unknown-a",
        "unknown-b",
        "BAD USER",
        "unknown-c",
        "unknown-d",
    ] {
        assert_eq!(server.login(id, "").await.status(), 401);
    }
    // Every failure, throttled or not, gets the same 401.
    assert_eq!(server.login("unknown-e", "").await.status(), 401);
    assert_eq!(server.login("BAD ID", "").await.status(), 401);
    assert_eq!(
        server.login("admin", &code(1_700_000_000)).await.status(),
        200
    );
}
#[tokio::test]
async fn logout_audit_failure_keeps_session_and_revocation_survives_restart() {
    let db = Db::new();
    let server = Server::start(&db, 1_700_000_000).await;
    let response = server.login("admin", &code(1_700_000_000)).await;
    assert_eq!(response.status(), 200);
    let token = token(&response);
    let csrf = response.json::<serde_json::Value>().await.unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    db.fail_audit();
    let logout = || {
        Client::new()
            .post(format!("{}/logout", server.base))
            .header("cookie", format!("sekisho_session={}", token.expose()))
            .header("X-CSRF-Token", &csrf)
            .send()
    };
    let response = logout().await.unwrap();
    assert_eq!(response.status(), 503);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(server.home(&token).await.status(), 200);
    db.sql().execute_batch("DROP TRIGGER fail_audit").unwrap();
    assert_eq!(logout().await.unwrap().status(), 200);
    drop(server);
    let restarted = Server::start(&db, 1_700_000_001).await;
    assert_eq!(restarted.home(&token).await.status(), 401);
    let entries = db.open().audit_entries(0, 100).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].kind(), AuditKind::UserLogin);
    assert_eq!(entries[1].subject()["operation"], "logout");
}

#[test]
fn totp_step_is_atomic_across_connections() {
    let db = Db::new();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let store = db.open();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .create(
                        &UserId::try_from("admin").unwrap(),
                        1_700_000_000.into(),
                        43200,
                        Some(56_666_666),
                    )
                    .unwrap()
                    .is_some()
            })
        })
        .collect();
    let accepted = workers
        .into_iter()
        .map(|w| usize::from(w.join().unwrap()))
        .sum::<usize>();
    assert_eq!(accepted, 1);
    assert_eq!(db.count("sessions"), 1);
    assert_eq!(db.count("audit"), 1);
}
