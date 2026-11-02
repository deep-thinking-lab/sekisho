#![allow(clippy::unwrap_used, clippy::expect_used)]
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::Engine as _;
use reqwest::{Client, StatusCode};
use sekisho::server::{
    AppState, Clock, InMemoryAgents, InMemorySessions, InMemoryUsers, Role, SessionStore, User,
    router,
};
use sekisho_core::{AgentId, Timestamp, UserId};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        self.0.load(Ordering::SeqCst).into()
    }
}
struct Fixture {
    base: String,
    client: Client,
    users: Arc<InMemoryUsers>,
    sessions: Arc<InMemorySessions>,
    clock: Arc<TestClock>,
    agent_token: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let users = Arc::new(InMemoryUsers::default());
        let salt = SaltString::encode_b64(b"fixed-test-salt!").unwrap();
        let hash = Argon2::default()
            .hash_password(b"secret-password", &salt)
            .unwrap()
            .to_string();
        for (id, role) in [
            ("viewer", Role::Viewer),
            ("approver", Role::Approver),
            ("admin", Role::Admin),
        ] {
            users
                .insert(User {
                    id: UserId::try_from(id).unwrap(),
                    password_hash: hash.clone(),
                    totp_secret: Some(b"12345678901234567890".to_vec()),
                    roles: [role].into_iter().collect(),
                })
                .unwrap();
        }
        let sessions = Arc::new(InMemorySessions::default());
        let agents = Arc::new(InMemoryAgents::default());
        let agent_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
        agents
            .insert(AgentId::try_from("claude").unwrap(), &agent_token)
            .unwrap();
        let clock = Arc::new(TestClock(AtomicI64::new(1_700_000_000)));
        // Loopback is a trusted proxy here, so tests pick a client address
        // with X-Forwarded-For.
        let state =
            AppState::new_with_agents(users.clone(), sessions.clone(), agents, clock.clone(), true)
                .unwrap()
                .with_trusted_proxies(vec!["127.0.0.1".parse().unwrap()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            base,
            client: Client::new(),
            users,
            sessions,
            clock,
            agent_token,
            task,
        }
    }
    async fn prelogin(&self) -> String {
        let response = self
            .client
            .get(format!("{}/login", self.base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = response.text().await.unwrap();
        assert!(body.contains(cookie.split('=').nth(1).unwrap()));
        cookie
    }
    async fn login(&self, id: &str, password: &str, totp: &str) -> reqwest::Response {
        self.login_from("192.0.2.1", id, password, totp).await
    }
    /// From the trusted proxy itself, naming no client.
    async fn login_direct(&self, id: &str, password: &str, totp: &str) -> reqwest::Response {
        let cookie = self.prelogin().await;
        self.client
            .post(format!("{}/login", self.base))
            .header("cookie", &cookie)
            .form(&[
                ("user_id", id),
                ("password", password),
                ("totp", totp),
                ("csrf_token", cookie.split('=').nth(1).unwrap()),
            ])
            .send()
            .await
            .unwrap()
    }
    async fn login_from(
        &self,
        source: &str,
        id: &str,
        password: &str,
        totp: &str,
    ) -> reqwest::Response {
        let cookie = self.prelogin().await;
        self.client
            .post(format!("{}/login", self.base))
            .header("cookie", &cookie)
            .header("x-forwarded-for", source)
            .form(&[
                ("user_id", id),
                ("password", password),
                ("totp", totp),
                ("csrf_token", cookie.split('=').nth(1).unwrap()),
            ])
            .send()
            .await
            .unwrap()
    }
    async fn session(&self, id: &str) -> (String, String) {
        let token = self
            .sessions
            .create(
                &UserId::try_from(id).unwrap(),
                self.clock.now(),
                43200,
                None,
            )
            .unwrap()
            .unwrap();
        let csrf = self
            .sessions
            .get(&token, self.clock.now())
            .unwrap()
            .unwrap()
            .csrf_token;
        (format!("sekisho_session={}", token.expose()), csrf)
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        csrf: Option<&str>,
    ) -> reqwest::Response {
        let mut request = self
            .client
            .request(method.parse().unwrap(), format!("{}{path}", self.base))
            .header("cookie", cookie);
        if let Some(csrf) = csrf {
            request = request.header("X-CSRF-Token", csrf);
        }
        request.send().await.unwrap()
    }
}
#[tokio::test]
async fn healthz_leaks_nothing() {
    let f = Fixture::new().await;
    let r = f.request("GET", "/healthz", "", None).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "ok");
}
#[tokio::test]
async fn login_requires_totp_for_approvers() {
    let f = Fixture::new().await;
    for id in ["approver", "admin"] {
        assert_eq!(f.login(id, "secret-password", "").await.status(), 401);
        let code = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            b"12345678901234567890".to_vec(),
        )
        .unwrap()
        .generate(1_700_000_000);
        assert_eq!(f.login(id, "secret-password", &code).await.status(), 200);
    }
    assert_eq!(f.login("viewer", "secret-password", "").await.status(), 200);
}
#[tokio::test]
async fn login_failure_is_uniform() {
    let f = Fixture::new().await;
    let mut bodies = Vec::new();
    for (id, password, code) in [
        ("unknown", "secret-password", "123456"),
        ("approver", "wrong", "123456"),
        ("approver", "secret-password", "bad"),
    ] {
        let r = f.login(id, password, code).await;
        assert_eq!(r.status(), 401);
        assert!(!r.headers().contains_key("set-cookie"));
        bodies.push(r.text().await.unwrap());
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
}
#[tokio::test]
async fn login_rate_limited() {
    let f = Fixture::new().await;
    for _ in 0..5 {
        assert_eq!(f.login("viewer", "wrong", "").await.status(), 401);
    }
    assert_eq!(f.login("viewer", "secret-password", "").await.status(), 401);
    f.clock.0.fetch_add(900, Ordering::SeqCst);
    assert_eq!(f.login("viewer", "secret-password", "").await.status(), 200);
}
#[tokio::test]
async fn session_expires() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("viewer").await;
    assert_eq!(f.request("GET", "/", &cookie, None).await.status(), 200);
    f.clock.0.fetch_add(43200, Ordering::SeqCst);
    assert_eq!(f.request("GET", "/", &cookie, None).await.status(), 401);
}
#[tokio::test]
async fn logout_revokes() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("viewer").await;
    assert_eq!(
        f.request("POST", "/logout", &cookie, Some(&csrf))
            .await
            .status(),
        200
    );
    assert_eq!(f.request("GET", "/", &cookie, None).await.status(), 401);
}
#[tokio::test]
async fn csrf_required_for_browser_posts() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("approver").await;
    for path in ["/logout", "/approvals/123/approve", "/approvals/123/deny"] {
        assert_eq!(f.request("POST", path, &cookie, None).await.status(), 403);
        assert_eq!(
            f.request("POST", path, &cookie, Some("wrong"))
                .await
                .status(),
            403
        );
    }
    assert_eq!(
        f.request("POST", "/approvals/123/approve", &cookie, Some(&csrf))
            .await
            .status(),
        503
    );
}
#[tokio::test]
async fn bearer_routes_reject_cookie_sessions() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("admin").await;
    for path in ["/v1/check", "/mcp", "/git/remote/repo"] {
        assert_eq!(f.request("POST", path, &cookie, None).await.status(), 401);
        let r = f
            .client
            .post(format!("{}{path}", f.base))
            .bearer_auth(&f.agent_token)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            match path {
                "/v1/check" => 415,
                "/git/remote/repo" => 401,
                "/mcp" => 503,
                _ => 501,
            }
        );
        let r = f
            .client
            .post(format!("{}{path}", f.base))
            .bearer_auth("not-a-token")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }
}
#[tokio::test]
async fn git_basic_routes_reject_cookie_sessions() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("admin").await;
    let url = format!(
        "{}/git/origin/owner/repo.git/info/refs?service=git-upload-pack",
        f.base
    );
    for token in [&f.agent_token, "not-a-token"] {
        assert_eq!(
            f.client
                .get(&url)
                .basic_auth("any", Some(token))
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    assert_eq!(
        f.client
            .get(&url)
            .basic_auth("any", Some(&f.agent_token))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        f.client
            .get(&url)
            .basic_auth("any", Some("not-a-token"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}
#[tokio::test]
async fn wrong_role_gets_403() {
    let f = Fixture::new().await;
    for id in ["viewer", "approver", "admin"] {
        let (cookie, csrf) = f.session(id).await;
        assert_eq!(f.request("GET", "/", &cookie, None).await.status(), 200);
        assert_eq!(
            f.request("GET", "/audit", &cookie, None).await.status(),
            503
        );
        for (path, required) in [
            ("/approvals/a/approve", "approver"),
            ("/approvals/a/deny", "approver"),
            ("/admin/users", "admin"),
        ] {
            let expected = if id == required || id == "admin" {
                if path.starts_with("/approvals/") {
                    503
                } else {
                    501
                }
            } else {
                403
            };
            assert_eq!(
                f.request("POST", path, &cookie, Some(&csrf)).await.status(),
                expected,
                "{id} {path}"
            );
        }
    }
}
#[tokio::test]
async fn login_refused_when_session_store_fails() {
    let f = Fixture::new().await;
    f.sessions.set_failing(true);
    let r = f.login("viewer", "secret-password", "").await;
    assert_eq!(r.status(), 503);
    assert!(!r.headers().contains_key("set-cookie"));
}
#[tokio::test]
async fn logout_reports_store_failure() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("viewer").await;
    f.sessions.set_revoke_failing(true);
    let r = f.request("POST", "/logout", &cookie, Some(&csrf)).await;
    assert_eq!(r.status(), 503);
    assert!(!r.headers().contains_key("set-cookie"));
    f.sessions.set_revoke_failing(false);
    assert_eq!(f.request("GET", "/", &cookie, None).await.status(), 200);
}
#[tokio::test]
async fn login_requires_prelogin_token() {
    let f = Fixture::new().await;
    let r = f
        .client
        .post(format!("{}/login", f.base))
        .form(&[("user_id", "viewer"), ("password", "secret-password")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
#[tokio::test]
async fn prelogin_token_mismatch_rejected() {
    let f = Fixture::new().await;
    let cookie = f.prelogin().await;
    let r = f
        .client
        .post(format!("{}/login", f.base))
        .header("cookie", cookie)
        .form(&[
            ("user_id", "viewer"),
            ("password", "secret-password"),
            ("csrf_token", "wrong"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
#[tokio::test]
async fn user_store_failure_refuses_login() {
    let f = Fixture::new().await;
    f.users.set_failing(true);
    let r = f.login("viewer", "secret-password", "").await;
    assert_eq!(r.status(), 503);
    assert!(!r.headers().contains_key("set-cookie"));
}

#[tokio::test]
async fn issued_cookies_and_csrf_are_secure_and_fresh() {
    let f = Fixture::new().await;
    let pre = f
        .client
        .get(format!("{}/login", f.base))
        .send()
        .await
        .unwrap();
    let cookie = pre.headers()["set-cookie"].to_str().unwrap();
    for flag in ["HttpOnly", "SameSite=Strict", "Path=/login", "Max-Age=600"] {
        assert!(cookie.contains(flag));
    }
    let a = f.login("viewer", "secret-password", "").await;
    let cookies = a
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let session = cookies
        .iter()
        .find(|s| s.starts_with("sekisho_session="))
        .unwrap();
    for flag in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(session.contains(flag));
    }
    assert!(
        cookies
            .iter()
            .any(|s| s.starts_with("sekisho_prelogin=;") && s.contains("Max-Age=0"))
    );
    let csrf = a.json::<serde_json::Value>().await.unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = f
        .login("viewer", "secret-password", "")
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_ne!(csrf, b["csrf_token"]);
    let r = f
        .client
        .post(format!("{}/logout", f.base))
        .header("cookie", session.split(';').next().unwrap())
        .form(&[("csrf_token", csrf)])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
#[tokio::test]
async fn bearer_does_not_bypass_human_checks() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("approver").await;
    for cookie in ["", &cookie] {
        let r = f
            .client
            .post(format!("{}/approvals/a/approve", f.base))
            .bearer_auth("agent")
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), if cookie.is_empty() { 401 } else { 403 });
    }
}
#[tokio::test]
async fn all_human_routes_enforce_declared_role() {
    let f = Fixture::new().await;
    for id in ["viewer", "approver", "admin"] {
        let (cookie, csrf) = f.session(id).await;
        for spec in sekisho::server::routes::ROUTES {
            if let sekisho::server::routes::Access::Human(role) = spec.access {
                let path = spec.path.replace("{id}", "a").replace("{*path}", "test");
                let method = if spec.method == "*" {
                    "POST"
                } else {
                    spec.method
                };
                let r = f.request(method, &path, &cookie, Some(&csrf)).await;
                let actual = match id {
                    "viewer" => Role::Viewer,
                    "approver" => Role::Approver,
                    _ => Role::Admin,
                };
                let forbidden = !matches!(
                    (actual, role),
                    (Role::Admin, _)
                        | (Role::Approver, Role::Approver | Role::Viewer)
                        | (Role::Viewer, Role::Viewer)
                );
                if forbidden {
                    assert_eq!(r.status(), 403, "{id} {path}");
                } else {
                    assert_ne!(r.status(), 401, "{id} {path}");
                    assert_ne!(r.status(), 403, "{id} {path}");
                }
            }
        }
    }
}

#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
#[tokio::test]
async fn secrets_not_logged() {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .without_time()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    tracing::info!("capture-active");
    let f = Fixture::new().await;
    let r = f.login("viewer", "secret-password", "654321").await;
    let cookie = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            v.to_str()
                .ok()
                .filter(|v| v.starts_with("sekisho_session="))
        })
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = r.json::<serde_json::Value>().await.unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        f.request("POST", "/logout", &cookie, Some(&csrf))
            .await
            .status(),
        200
    );
    assert_eq!(
        f.login("viewer", "failed-secret-password", "987654")
            .await
            .status(),
        401
    );
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("login_failure"));
    assert!(logs.contains("login_success"));
    assert!(logs.contains("logout"));
    for secret in [
        "secret-password",
        "failed-secret-password",
        "654321",
        "987654",
        cookie.split('=').nth(1).unwrap(),
        &csrf,
    ] {
        assert!(!logs.contains(secret));
    }
}

#[tokio::test]
async fn privileged_user_without_enrolled_totp_cannot_login() {
    let f = Fixture::new().await;
    use sekisho::server::UserDirectory;
    let mut user = f
        .users
        .find(&UserId::try_from("admin").unwrap())
        .unwrap()
        .unwrap();
    user.totp_secret = None;
    f.users.insert(user).unwrap();
    let code = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        b"12345678901234567890".to_vec(),
    )
    .unwrap()
    .generate(1_700_000_000);
    assert_eq!(
        f.login("admin", "secret-password", &code).await.status(),
        401
    );
}
#[tokio::test]
async fn agent_cannot_approve() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("viewer").await;
    for path in ["/approvals/a/approve", "/approvals/a/deny"] {
        for cookie in ["", &cookie] {
            let r = f
                .client
                .post(format!("{}{path}", f.base))
                .bearer_auth("agent")
                .header("cookie", cookie)
                .header("X-CSRF-Token", &csrf)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), if cookie.is_empty() { 401 } else { 403 });
        }
    }
}

#[tokio::test]
async fn totp_accepts_only_one_step_of_skew() {
    let f = Fixture::new().await;
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        b"12345678901234567890".to_vec(),
    )
    .unwrap();
    for offset in [-60_i64, -30, 0, 30, 60] {
        let code = totp.generate((1_700_000_000_i64 + offset) as u64);
        assert_eq!(
            f.login("approver", "secret-password", &code).await.status(),
            if offset.abs() <= 30 { 200 } else { 401 }
        );
    }
}
#[tokio::test]
async fn non_loopback_cookies_are_secure() {
    let f = Fixture::new().await;
    let state = AppState::new(f.users.clone(), f.sessions.clone(), f.clock.clone(), false).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let pre = f.client.get(format!("{base}/login")).send().await.unwrap();
    let cookie = pre.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("; Secure"));
    let cookie = cookie.split(';').next().unwrap();
    let response = f
        .client
        .post(format!("{base}/login"))
        .header("cookie", cookie)
        .form(&[
            ("user_id", "viewer"),
            ("password", "secret-password"),
            ("csrf_token", cookie.split('=').nth(1).unwrap()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    for value in response.headers().get_all("set-cookie") {
        assert!(value.to_str().unwrap().contains("; Secure"));
    }
    task.abort();
}

#[tokio::test]
async fn session_lookup_failure_refuses_access() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("viewer").await;
    f.sessions.set_failing(true);
    for (method, path) in [("GET", "/"), ("POST", "/logout")] {
        let r = f.request(method, path, &cookie, Some(&csrf)).await;
        assert_eq!(r.status(), 503);
        assert!(!r.headers().contains_key("set-cookie"));
    }
    f.sessions.set_failing(false);
    assert_eq!(f.request("GET", "/", &cookie, None).await.status(), 200);
}
#[tokio::test]
async fn session_tokens_have_256_random_bits() {
    use base64::Engine;
    let f = Fixture::new().await;
    let (a, csrf) = f.session("viewer").await;
    let (b, other_csrf) = f.session("viewer").await;
    assert_ne!(a, b);
    assert_ne!(csrf, other_csrf);
    for token in [
        a.split('=').nth(1).unwrap(),
        b.split('=').nth(1).unwrap(),
        &csrf,
        &other_csrf,
    ] {
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .unwrap()
                .len(),
            32
        );
    }
}

#[tokio::test]
async fn unknown_user_still_performs_password_work() {
    let f = Fixture::new().await;
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for index in 0..3 {
        for (id, durations) in [
            ("approver".to_owned(), &mut known),
            (format!("unknown-{index}"), &mut unknown),
        ] {
            let cookie = f.prelogin().await;
            let request = f
                .client
                .post(format!("{}/login", f.base))
                .header("cookie", &cookie)
                .form(&[
                    ("user_id", id.as_str()),
                    ("password", "wrong"),
                    ("totp", "000000"),
                    ("csrf_token", cookie.split('=').nth(1).unwrap()),
                ]);
            let start = std::time::Instant::now();
            let response = request.send().await.unwrap();
            let elapsed = start.elapsed();
            assert_eq!(response.status(), 401);
            durations.push(elapsed);
        }
    }
    known.sort();
    unknown.sort();
    // This only detects removal of expensive verification, not a constant-time latency guarantee.
    assert!(
        unknown[1] >= known[1] / 8,
        "unknown {:?}, known {:?}",
        unknown,
        known
    );
}

#[tokio::test]
async fn login_body_limit() {
    let f = Fixture::new().await;
    assert_eq!(f.login("viewer", &"x".repeat(4096), "").await.status(), 413);
}
#[tokio::test]
async fn invalid_user_ids_share_one_bucket() {
    let f = Fixture::new().await;
    for index in 0..5 {
        assert_eq!(
            f.login(&format!("invalid/{index}"), "wrong", "")
                .await
                .status(),
            401
        );
    }
    assert_eq!(f.login("another invalid", "wrong", "").await.status(), 401);
    assert_eq!(f.login("viewer", "secret-password", "").await.status(), 200);
}
#[tokio::test]
async fn totp_code_cannot_be_replayed() {
    let f = Fixture::new().await;
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        b"12345678901234567890".to_vec(),
    )
    .unwrap();
    let code = totp.generate(1_700_000_000);
    assert_eq!(
        f.login("approver", "secret-password", &code).await.status(),
        200
    );
    for code in [code, totp.generate(1_699_999_970)] {
        let r = f.login("approver", "secret-password", &code).await;
        assert_eq!(r.status(), 401);
        assert!(!r.headers().contains_key("set-cookie"));
        assert_eq!(r.text().await.unwrap(), "invalid credentials");
    }
    assert_eq!(
        f.login("approver", "secret-password", &totp.generate(1_700_000_030))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn concurrent_totp_replay_is_rejected() {
    let f = Fixture::new().await;
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        b"12345678901234567890".to_vec(),
    )
    .unwrap();
    let code = totp.generate(1_700_000_000);
    let (a, b) = tokio::join!(
        f.login("approver", "secret-password", &code),
        f.login("approver", "secret-password", &code)
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 401]);
}

fn approver_code(f: &Fixture) -> String {
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        b"12345678901234567890".to_vec(),
    )
    .unwrap()
    .generate(f.clock.0.load(Ordering::SeqCst) as u64)
}

/// SEK-06: an attacker flooding wrong passwords for the admin neither locks
/// the admin out nor blocks a correct password and code, even from its own
/// blocked address; its other failures get the same 429.
#[tokio::test]
async fn login_throttle_lets_correct_password_and_totp_through() {
    let f = Fixture::new().await;
    for _ in 0..30 {
        let status = f
            .login_from("203.0.113.9", "approver", "wrong", "000000")
            .await
            .status();
        assert!(status == 401 || status == 429, "{status}");
    }
    // The blocked address gets 429 for a wrong password on a fresh account.
    assert_eq!(
        f.login_from("203.0.113.9", "viewer", "wrong", "")
            .await
            .status(),
        401
    );
    // The account is soft throttled: a right password with a wrong code fails.
    assert_eq!(
        f.login_from("198.51.100.7", "approver", "secret-password", "000000")
            .await
            .status(),
        401
    );
    // The right password and code sign in, even from the blocked address.
    let code = approver_code(&f);
    assert_eq!(
        f.login_from("203.0.113.9", "approver", "secret-password", &code)
            .await
            .status(),
        200
    );
}

/// SEK-06: with no resolvable client address, failures are not pooled into
/// one shared source bucket.
#[tokio::test]
async fn unresolved_source_is_not_throttled_as_one_bucket() {
    let f = Fixture::new().await;
    for _ in 0..25 {
        let status = f.login_direct("approver", "wrong", "000000").await.status();
        assert!(status == 401 || status == 429, "{status}");
    }
    assert_eq!(f.login_direct("viewer", "wrong", "").await.status(), 401);
}

/// SEK-06: guessing TOTP codes needs the password and is capped at ten wrong
/// codes per 15 minutes, after which even a correct code is refused.
#[tokio::test]
async fn wrong_totp_codes_after_correct_password_lock_the_account() {
    let f = Fixture::new().await;
    for _ in 0..10 {
        let status = f
            .login("approver", "secret-password", "000000")
            .await
            .status();
        assert!(status == 401 || status == 429, "{status}");
    }
    let code = approver_code(&f);
    assert_eq!(
        f.login("approver", "secret-password", &code).await.status(),
        401
    );
    f.clock.0.fetch_add(900, Ordering::SeqCst);
    let code = approver_code(&f);
    assert_eq!(
        f.login("approver", "secret-password", &code).await.status(),
        200
    );
}

/// SEK-06: while throttled, a wrong password and a right password with a wrong
/// code get the identical response, so the throttle is not a password oracle.
#[tokio::test]
async fn throttled_failures_are_indistinguishable() {
    let f = Fixture::new().await;
    for _ in 0..5 {
        assert_eq!(f.login("approver", "wrong", "000000").await.status(), 401);
    }
    let mut responses = Vec::new();
    for (index, password) in ["wrong", "secret-password", "also-wrong", "secret-password"]
        .into_iter()
        .enumerate()
    {
        let source = format!("198.51.100.{index}");
        let response = f.login_from(&source, "approver", password, "000000").await;
        let status = response.status();
        let set_cookie = response.headers().contains_key("set-cookie");
        responses.push((status, set_cookie, response.bytes().await.unwrap()));
    }
    assert_eq!(responses[0].0, 401);
    assert!(responses.windows(2).all(|w| w[0] == w[1]), "{responses:?}");
    let code = approver_code(&f);
    assert_eq!(
        f.login("approver", "secret-password", &code).await.status(),
        200
    );
}

/// SEK-06: concurrent wrong codes cannot get past the TOTP cap.
#[tokio::test]
async fn concurrent_wrong_codes_cannot_exceed_the_totp_cap() {
    let f = Fixture::new().await;
    let attempts: Vec<_> = (0..20)
        .map(|_| f.login("approver", "secret-password", "000000"))
        .collect();
    for response in futures_join_all(attempts).await {
        let status = response.status();
        assert!(status == 401 || status == 429, "{status}");
    }
    let code = approver_code(&f);
    assert_eq!(
        f.login("approver", "secret-password", &code).await.status(),
        401,
        "the cap is reached"
    );
}

async fn futures_join_all<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut set = Vec::new();
    for future in futures {
        set.push(Box::pin(future));
    }
    let mut outputs = Vec::new();
    // Poll all concurrently.
    let joined = std::future::poll_fn(|cx| {
        let mut done = true;
        for (index, future) in set.iter_mut().enumerate() {
            if outputs.len() <= index {
                outputs.push(None);
            }
            if outputs[index].is_none() {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => outputs[index] = Some(value),
                    std::task::Poll::Pending => done = false,
                }
            }
        }
        if done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    });
    joined.await;
    outputs.into_iter().map(|o| o.unwrap()).collect()
}

/// Gate review NEW-2: the TOTP lock must not reveal whether earlier guesses
/// had the right password. Ten wrong codes with the wrong password (admin)
/// and with the right password (approver), then, once the per-user window has
/// passed but the lock has not, the same probe gets byte-identical answers.
#[tokio::test]
async fn totp_lock_state_is_not_a_password_oracle() {
    let f = Fixture::new().await;
    for id in ["admin", "approver"] {
        let _ = f.login_from("198.51.100.1", id, "wrong", "000000").await;
    }
    f.clock.0.fetch_add(800, Ordering::SeqCst);
    for _ in 0..10 {
        let _ = f
            .login_from("198.51.100.2", "admin", "guess", "000000")
            .await;
        let _ = f
            .login_from("198.51.100.3", "approver", "secret-password", "000000")
            .await;
    }
    f.clock.0.fetch_add(150, Ordering::SeqCst);
    let mut answers = Vec::new();
    for (id, password) in [
        ("admin", "wrong"),
        ("approver", "wrong"),
        ("approver", "secret-password"),
    ] {
        let code = approver_code(&f);
        let response = f.login_from("198.51.100.4", id, password, &code).await;
        let status = response.status();
        let cookie = response.headers().contains_key("set-cookie");
        answers.push((id, status, cookie, response.bytes().await.unwrap().to_vec()));
    }
    let shape = |a: &(&str, StatusCode, bool, Vec<u8>)| (a.1, a.2, a.3.clone());
    assert_eq!(answers[0].1, 401);
    assert_eq!(shape(&answers[0]), shape(&answers[1]), "{answers:?}");
    // The right password and code while locked: still the same failure.
    assert_eq!(shape(&answers[1]), shape(&answers[2]), "{answers:?}");
}

/// NEW-2 follow-up: the per-address delay counts every failure, so wrong
/// passwords and a right password with wrong codes give the same statuses,
/// bodies and delay schedule.
#[tokio::test]
async fn source_delay_does_not_depend_on_the_password() {
    let f = Fixture::new().await;
    let mut schedules = Vec::new();
    for (source, id, password) in [
        ("198.51.100.20", "approver", "wrong"),
        ("198.51.100.21", "admin", "secret-password"),
    ] {
        let mut schedule = Vec::new();
        for _ in 0..22 {
            let started = std::time::Instant::now();
            let response = f.login_from(source, id, password, "000000").await;
            let status = response.status();
            let body = response.bytes().await.unwrap().to_vec();
            schedule.push((
                status,
                body,
                started.elapsed() >= std::time::Duration::from_millis(900),
            ));
        }
        schedules.push(schedule);
    }
    assert_eq!(schedules[0], schedules[1]);
    assert!(schedules[0][21].2, "failures past the limit are delayed");
    assert!(!schedules[0][0].2);
}
