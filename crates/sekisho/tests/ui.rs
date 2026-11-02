#![allow(clippy::unwrap_used, clippy::expect_used)]

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use reqwest::{Client, Response, StatusCode};
use sekisho::{
    server::{
        AppState, CheckApi, Clock, InMemorySessions, InMemoryUsers, Role, SessionStore, User,
        router,
    },
    store::Store,
};
use sekisho_core::{
    Action, AgentId, Approval, ApprovalId, ApprovalState, AuditEntry, AuditKind, Ed25519Signer,
    GrantId, Principal, Signer, Timestamp, ToolName, UnsignedGrant, UserId,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};

const POLICY: &str = r#"version = 1
[[rule]]
name = "main push"
tool = "git.push"
decision = "ask"
"#;

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        self.0.load(Ordering::SeqCst).into()
    }
}

struct Fixture {
    dir: PathBuf,
    base: String,
    client: Client,
    store: Arc<Store>,
    sessions: Arc<InMemorySessions>,
    clock: Arc<TestClock>,
    token: String,
    grant: Arc<Ed25519Signer>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        use std::hash::BuildHasher;
        let suffix = std::hash::RandomState::new().hash_one("inbox-ui");
        let dir =
            std::env::temp_dir().join(format!("sekisho-inbox-ui-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("policy.toml"), POLICY).unwrap();

        let audit = Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]));
        let grant = Arc::new(Ed25519Signer::from_secret_bytes("grant", &[8; 32]));
        let store = Arc::new(Store::open(&dir.join("store.db"), audit).unwrap());
        let clock = Arc::new(TestClock(AtomicI64::new(1_700_000_000)));
        let admin = UserId::try_from("admin").unwrap();
        let token = store
            .add_agent(&AgentId::try_from("claude").unwrap(), &admin, clock.now())
            .unwrap()
            .expose()
            .to_owned();

        let users = Arc::new(InMemoryUsers::default());
        let password_hash = Argon2::default()
            .hash_password(
                b"secret-password",
                &SaltString::encode_b64(b"fixed-test-salt!").unwrap(),
            )
            .unwrap()
            .to_string();
        for (id, role) in [
            ("admin", Role::Admin),
            ("approver", Role::Approver),
            ("viewer", Role::Viewer),
        ] {
            users
                .insert(User {
                    id: UserId::try_from(id).unwrap(),
                    password_hash: password_hash.clone(),
                    totp_secret: Some(vec![1; 20]),
                    roles: [role].into_iter().collect(),
                })
                .unwrap();
        }
        let checks = Arc::new(
            CheckApi::load(
                store.clone(),
                &dir.join("policy.toml"),
                grant.public_key(),
                None,
                &Principal::User(admin),
                clock.now(),
            )
            .unwrap()
            .with_grant_signer(grant.clone())
            .unwrap(),
        );
        let sessions = Arc::new(InMemorySessions::default());
        let state =
            AppState::new_with_agents(users, sessions.clone(), store.clone(), clock.clone(), true)
                .unwrap()
                .with_check_api(checks);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        Self {
            dir,
            base,
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            store,
            sessions,
            clock,
            token,
            grant,
            server,
        }
    }

    fn session(&self, id: &str) -> (String, String) {
        let user = UserId::try_from(id).unwrap();
        let token = self
            .sessions
            .create(&user, self.clock.now(), 43200, None)
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

    async fn get(&self, path: &str, cookie: &str) -> Response {
        self.client
            .get(format!("{}{path}", self.base))
            .header("cookie", cookie)
            .header("accept", "text/html")
            .send()
            .await
            .unwrap()
    }

    async fn post_form(
        &self,
        path: &str,
        cookie: &str,
        csrf: &str,
        form: &[(&str, &str)],
    ) -> Response {
        let mut fields = form.to_vec();
        fields.push(("csrf_token", csrf));
        self.client
            .post(format!("{}{path}", self.base))
            .header("cookie", cookie)
            .header("accept", "text/html")
            .form(&fields)
            .send()
            .await
            .unwrap()
    }

    async fn ask(&self, target: &str, params: Value) -> ApprovalId {
        let response = self
            .client
            .post(format!("{}/v1/check?wait=0", self.base))
            .bearer_auth(&self.token)
            .json(&json!({
                "tool": "git.push",
                "target": target,
                "params": params,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["decision"], "ask");
        ApprovalId::try_from(body["approval_id"].as_str().unwrap()).unwrap()
    }

    fn approval(&self, id: &ApprovalId) -> Approval {
        self.store
            .transact(self.clock.now(), |tx| {
                Ok((tx.get_approval(id)?.unwrap(), vec![]))
            })
            .unwrap()
    }

    async fn decide(
        &self,
        id: &ApprovalId,
        outcome: &str,
        cookie: &str,
        csrf: Option<&str>,
    ) -> Response {
        let mut request = self
            .client
            .post(format!("{}/approvals/{}/{outcome}", self.base, id.as_str()))
            .header("cookie", cookie)
            .header("accept", "text/html");
        if let Some(csrf) = csrf {
            request = request.form(&[("csrf_token", csrf)]);
        }
        request.send().await.unwrap()
    }

    fn approval_digest(&self, target: &str, params: &Value) -> String {
        Action::new(
            AgentId::try_from("claude").unwrap(),
            ToolName::try_from("git.push").unwrap(),
            target.to_owned(),
            params.clone(),
        )
        .unwrap()
        .digest()
        .unwrap()
        .to_string()
    }

    fn audit_count(&self) -> usize {
        self.store.audit_entries(0, 1000).unwrap().len()
    }

    fn issue_grant(&self, id: &str, target: &str) -> GrantId {
        let id = GrantId::try_from(id).unwrap();
        let grant = UnsignedGrant {
            id: id.clone(),
            agent_id: AgentId::try_from("claude").unwrap(),
            tool: ToolName::try_from("git.push").unwrap(),
            target_glob: target.to_owned(),
            params: BTreeMap::from([("force".to_owned(), json!(false))]),
            not_before: self.clock.now(),
            expires_at: Timestamp::from(self.clock.now().as_secs() + 3600),
            max_uses: Some(3),
            issued_by: UserId::try_from("admin").unwrap(),
        }
        .sign(self.grant.as_ref())
        .unwrap();
        self.store.issue_grant(&grant, self.clock.now()).unwrap();
        id
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn flash_cookie(response: &Response, outcome: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().unwrap();
            value
                .starts_with(&format!("sekisho_flash={outcome};"))
                .then(|| value.split(';').next().unwrap().to_owned())
        })
        .unwrap()
}

#[tokio::test]
async fn login_page_is_an_accessible_form() {
    let f = Fixture::new().await;
    let response = f.get("/login", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    for expected in [
        "<!doctype html>",
        "lang=\"en\"",
        "action=\"/login\"",
        "for=\"user_id\"",
        "name=\"password\"",
        "name=\"totp\"",
        "name=\"csrf_token\"",
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
}

#[tokio::test]
async fn browser_login_redirects_to_the_inbox() {
    let f = Fixture::new().await;
    let response = f.get("/login", "").await;
    let prelogin = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = prelogin.split('=').nth(1).unwrap();
    let response = f
        .client
        .post(format!("{}/login", f.base))
        .header("cookie", &prelogin)
        .header("accept", "text/html")
        .form(&[
            ("user_id", "viewer"),
            ("password", "secret-password"),
            ("totp", ""),
            ("csrf_token", csrf),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/");
    let session = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().unwrap();
            value
                .starts_with("sekisho_session=")
                .then(|| value.split(';').next().unwrap().to_owned())
        })
        .unwrap();
    let inbox = f.get("/", &session).await;
    assert_eq!(inbox.status(), StatusCode::OK);
    assert!(inbox.text().await.unwrap().contains("Pending approvals"));
}

#[tokio::test]
async fn unauthenticated_ui_get_redirects_to_login() {
    let f = Fixture::new().await;
    let response = f
        .client
        .get(format!("{}/", f.base))
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/login");

    let response = f
        .client
        .get(format!("{}/", f.base))
        .header("accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn inbox_lists_pending_newest_first_and_refreshes_with_local_htmx() {
    let f = Fixture::new().await;
    let older = f
        .ask(
            "github.com/acme/api:refs/heads/old",
            json!({"force": false}),
        )
        .await;
    f.clock.0.fetch_add(2, Ordering::SeqCst);
    let newer = f
        .ask(
            "github.com/acme/api:refs/heads/new",
            json!({"force": false}),
        )
        .await;
    let (cookie, _) = f.session("approver");
    let response = f.get("/", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    for expected in [
        "Pending approvals",
        "claude",
        "git.push",
        "github.com/acme/api:refs/heads/old",
        "github.com/acme/api:refs/heads/new",
        "main push",
        "15 minutes left",
        "/static/htmx.min.js",
        "hx-trigger=\"every 5s\"",
    ] {
        assert!(body.contains(expected), "missing {expected}");
    }
    assert!(body.find(newer.as_str()).unwrap() < body.find(older.as_str()).unwrap());
    assert!(!body.contains("https://unpkg.com"));
    assert!(!body.contains("cdn."));

    f.clock.0.fetch_add(899, Ordering::SeqCst);
    let body = f.get("/", &cookie).await.text().await.unwrap();
    assert!(!body.contains(older.as_str()));
    assert!(body.contains(newer.as_str()));
    assert!(body.contains("1 second left"));
}

#[tokio::test]
async fn htmx_asset_is_served_locally() {
    let f = Fixture::new().await;
    let response = f.get("/static/htmx.min.js", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/javascript; charset=utf-8"
    );
    assert!(response.text().await.unwrap().contains("var htmx="));
}

#[tokio::test]
async fn approval_detail_renders_every_action_field_and_escaped_json() {
    let f = Fixture::new().await;
    let target = "github.com/acme/api:refs/heads/main";
    let params = json!({"force": false, "note": "<script>alert(1)</script>"});
    let id = f.ask(target, params.clone()).await;
    let digest = f.approval_digest(target, &params);
    let (cookie, csrf) = f.session("approver");
    let response = f.get(&format!("/approvals/{}", id.as_str()), &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    for expected in [
        "Approval detail",
        "Agent",
        "claude",
        "Tool",
        "git.push",
        "Target",
        target,
        "Rule",
        "main push",
        "Action digest",
        &digest,
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "15 minutes left",
        &format!("/approvals/{}/approve", id.as_str()),
        &format!("/approvals/{}/deny", id.as_str()),
        "name=\"csrf_token\"",
        &csrf,
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
    assert!(
        [
            "\"force\": false",
            "&quot;force&quot;: false",
            "&#34;force&#34;: false"
        ]
        .iter()
        .any(|json| body.contains(json))
    );
    assert!(!body.contains("<script>alert(1)</script>"));
}

#[tokio::test]
async fn viewer_sees_no_buttons() {
    let f = Fixture::new().await;
    let id = f
        .ask(
            "github.com/acme/api:refs/heads/main",
            json!({"force": false}),
        )
        .await;
    let (cookie, csrf) = f.session("viewer");
    let response = f.get(&format!("/approvals/{}", id.as_str()), &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(!body.contains(&format!("/approvals/{}/approve", id.as_str())));
    assert!(!body.contains(&format!("/approvals/{}/deny", id.as_str())));
    assert!(!body.contains("Approve action"));
    assert!(!body.contains("Deny action"));

    let response = f.decide(&id, "approve", &cookie, Some(&csrf)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.approval(&id).state(), ApprovalState::Pending);
}

#[tokio::test]
async fn csrf_missing_is_rejected() {
    let f = Fixture::new().await;
    let id = f
        .ask(
            "github.com/acme/api:refs/heads/main",
            json!({"force": false}),
        )
        .await;
    let (cookie, _) = f.session("approver");
    let before = f.audit_count();
    let response = f.decide(&id, "approve", &cookie, None).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.approval(&id).state(), ApprovalState::Pending);
    assert_eq!(f.audit_count(), before);
}

#[tokio::test]
async fn approve_changes_state_writes_audit_and_flashes_once() {
    let f = Fixture::new().await;
    let id = f
        .ask(
            "github.com/acme/api:refs/heads/main",
            json!({"force": false}),
        )
        .await;
    let (cookie, csrf) = f.session("approver");
    let before = f.audit_count();
    let response = f.decide(&id, "approve", &cookie, Some(&csrf)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()["location"].to_str().unwrap(),
        format!("/approvals/{}", id.as_str())
    );
    let flash = flash_cookie(&response, "approved");
    let approval = f.approval(&id);
    assert_eq!(approval.state(), ApprovalState::Approved);
    assert_eq!(
        approval.decided_by(),
        Some(&UserId::try_from("approver").unwrap())
    );
    let entries = f.store.audit_entries(0, 1000).unwrap();
    assert_eq!(entries.len(), before + 1);
    let audit = entries.last().unwrap();
    assert_eq!(audit.kind(), AuditKind::Approved);
    assert_eq!(
        audit.actor(),
        &Principal::User(UserId::try_from("approver").unwrap())
    );
    assert_eq!(audit.subject()["approval_id"], id.as_str());
    assert_eq!(
        audit.subject()["action_digest"],
        approval.action_digest().to_string()
    );

    let combined = format!("{cookie}; {flash}");
    let response = f
        .get(&format!("/approvals/{}", id.as_str()), &combined)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cleared = response.headers().get_all("set-cookie").iter().any(|v| {
        let v = v.to_str().unwrap();
        v.starts_with("sekisho_flash=;") && v.contains("Max-Age=0")
    });
    assert!(cleared);
    let body = response.text().await.unwrap();
    assert!(body.contains("Approval recorded."));
    assert!(!body.contains("Approve action"));

    let body = f
        .get(&format!("/approvals/{}", id.as_str()), &cookie)
        .await
        .text()
        .await
        .unwrap();
    assert!(!body.contains("Approval recorded."));
}

#[tokio::test]
async fn deny_changes_state_writes_audit_and_flashes_once() {
    let f = Fixture::new().await;
    let id = f
        .ask(
            "github.com/acme/api:refs/heads/main",
            json!({"force": false}),
        )
        .await;
    let (cookie, csrf) = f.session("admin");
    let before = f.audit_count();
    let response = f.decide(&id, "deny", &cookie, Some(&csrf)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let flash = flash_cookie(&response, "denied");
    let approval = f.approval(&id);
    assert_eq!(approval.state(), ApprovalState::Denied);
    let entries = f.store.audit_entries(0, 1000).unwrap();
    assert_eq!(entries.len(), before + 1);
    let audit = entries.last().unwrap();
    assert_eq!(audit.kind(), AuditKind::Denied);
    assert_eq!(audit.subject()["approval_id"], id.as_str());

    let combined = format!("{cookie}; {flash}");
    let body = f
        .get(&format!("/approvals/{}", id.as_str()), &combined)
        .await
        .text()
        .await
        .unwrap();
    assert!(body.contains("Denial recorded."));
    assert!(!body.contains("Approve action"));
    assert!(!body.contains("Deny action"));
}

#[tokio::test]
async fn unknown_or_invalid_approval_ids_fail_closed() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("approver");
    let invalid = f.get("/approvals/not-an-id", &cookie).await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let missing = f
        .get("/approvals/apr_0123456789abcdefghijklmnop", &cookie)
        .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn corrupted_approval_rows_fail_closed() {
    let f = Fixture::new().await;
    let id = f
        .ask(
            "github.com/acme/api:refs/heads/main",
            json!({"force": false}),
        )
        .await;
    let connection = rusqlite::Connection::open(f.dir.join("store.db")).unwrap();
    connection
        .execute(
            "UPDATE approvals SET agent_id='mallory' WHERE id=?",
            [id.as_str()],
        )
        .unwrap();
    let (cookie, _) = f.session("approver");
    assert_eq!(
        f.get("/", &cookie).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.get(&format!("/approvals/{}", id.as_str()), &cookie)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

fn issued_agent_token(body: &str) -> &str {
    body.split("<code id=\"agent-token\">")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("issued token is rendered")
}

#[tokio::test]
async fn audit_page_is_paged_newest_first_with_checkpoint_and_raw_json() {
    let f = Fixture::new().await;
    for index in 0..22 {
        let agent = AgentId::try_from(format!("worker-{index:02}").as_str()).unwrap();
        f.store
            .add_agent(&agent, &UserId::try_from("admin").unwrap(), f.clock.now())
            .unwrap();
        f.clock.0.fetch_add(1, Ordering::SeqCst);
    }
    let entries = f.store.audit_entries(0, 1000).unwrap();
    let latest = entries.last().unwrap();
    let oldest_on_page_two = &entries[entries.len() - 21];
    let (cookie, _) = f.session("viewer");

    let response = f.get("/audit", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    for expected in [
        "Audit log",
        "Latest checkpoint",
        &format!("Seq {}", latest.seq()),
        &latest.entry_hash().to_string(),
        "Download export",
        "href=\"/audit/export\"",
        "worker-21",
        &format!("href=\"/audit/{}\"", latest.seq()),
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
    assert!(
        body.find(&format!("/audit/{}", latest.seq())).unwrap()
            < body.find(&format!("/audit/{}", latest.seq() - 1)).unwrap()
    );

    let response = f.get("/audit?page=2", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page_two = response.text().await.unwrap();
    assert!(page_two.contains(&format!("Seq {}", oldest_on_page_two.seq())));
    assert!(page_two.contains("href=\"/audit?page=1\""));

    let response = f.get(&format!("/audit/{}", latest.seq()), &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
    let raw: AuditEntry = response.json().await.unwrap();
    assert_eq!(raw, *latest);

    let response = f.get("/audit", "").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/login");
    let response = f.get("/audit/not-a-sequence", &cookie).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn audit_export_download_returns_the_checked_chain() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("viewer");
    let response = f.get("/audit/export", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/x-ndjson"
    );
    assert!(
        response.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .contains("attachment")
    );
    let body = response.text().await.unwrap();
    let lines: Vec<_> = body.lines().collect();
    assert_eq!(lines.len(), f.audit_count() + 1);
    let trailer: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    let latest = f.store.audit_entries(0, 1000).unwrap().pop().unwrap();
    assert_eq!(trailer["checkpoint"]["seq"], latest.seq());
    assert_eq!(
        trailer["checkpoint"]["entry_hash"],
        latest.entry_hash().to_string()
    );
    assert!(trailer["public_keys"][latest.key_id()].as_str().is_some());

    let response = f.get("/audit/export", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agents_page_lists_agents_and_only_admin_sees_mutations() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("viewer");
    let response = f.get("/agents", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("Agents"));
    assert!(body.contains("claude"));
    assert!(!body.contains("action=\"/agents/add\""));
    assert!(!body.contains("/agents/claude/rotate"));
    assert!(!body.contains("/agents/claude/remove"));

    let (cookie, _) = f.session("admin");
    let body = f.get("/agents", &cookie).await.text().await.unwrap();
    for expected in [
        "action=\"/agents/add\"",
        "/agents/claude/rotate",
        "/agents/claude/remove",
        "name=\"agent_id\"",
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
}

#[tokio::test]
async fn admin_can_add_an_agent_and_the_token_is_shown_once() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("admin");
    let response = f
        .post_form("/agents/add", &cookie, &csrf, &[("agent_id", "zeta")])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("zeta"));
    let token = issued_agent_token(&body).to_owned();
    let agent = AgentId::try_from("zeta").unwrap();
    assert_eq!(
        f.store.authenticate_agent(&token).unwrap(),
        Some(agent.clone())
    );
    assert!(f.store.list_agents().unwrap().contains(&agent));

    let listed = f.get("/agents", &cookie).await.text().await.unwrap();
    assert!(listed.contains("zeta"));
    assert!(!listed.contains(&token));
}

#[tokio::test]
async fn admin_can_rotate_an_agent_and_the_new_token_is_shown_once() {
    let f = Fixture::new().await;
    let old = f.token.clone();
    let (cookie, csrf) = f.session("admin");
    let response = f
        .post_form("/agents/claude/rotate", &cookie, &csrf, &[])
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let new = issued_agent_token(&body).to_owned();
    assert_ne!(new, old);
    assert_eq!(f.store.authenticate_agent(&old).unwrap(), None);
    assert_eq!(
        f.store.authenticate_agent(&new).unwrap(),
        Some(AgentId::try_from("claude").unwrap())
    );
    assert!(
        !f.get("/agents", &cookie)
            .await
            .text()
            .await
            .unwrap()
            .contains(&new)
    );
}

#[tokio::test]
async fn admin_can_remove_an_agent() {
    let f = Fixture::new().await;
    let token = f.token.clone();
    let (cookie, csrf) = f.session("admin");
    let response = f
        .post_form("/agents/claude/remove", &cookie, &csrf, &[])
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/agents");
    assert!(f.store.list_agents().unwrap().is_empty());
    assert_eq!(f.store.authenticate_agent(&token).unwrap(), None);
    assert!(
        !f.get("/agents", &cookie)
            .await
            .text()
            .await
            .unwrap()
            .contains(">/agents/claude/")
    );
}

#[tokio::test]
async fn grants_page_lists_active_and_revoked_grants() {
    let f = Fixture::new().await;
    let active = f.issue_grant(
        "grt_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "github.com/acme/release-*",
    );
    let revoked = f.issue_grant("grt_bbbbbbbbbbbbbbbbbbbbbbbbbb", "github.com/acme/main");
    f.store
        .revoke_grant(&revoked, &UserId::try_from("admin").unwrap(), f.clock.now())
        .unwrap();
    let (cookie, _) = f.session("viewer");
    let body = f.get("/grants", &cookie).await.text().await.unwrap();
    for expected in [
        "Grants",
        active.as_str(),
        revoked.as_str(),
        "active",
        "revoked",
        "github.com/acme/release-*",
        "github.com/acme/main",
        "3 uses",
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
    assert!(!body.contains("action=\"/grants/issue\""));

    let (cookie, _) = f.session("admin");
    let body = f.get("/grants", &cookie).await.text().await.unwrap();
    for expected in [
        "action=\"/grants/issue\"",
        "name=\"agent_id\"",
        "name=\"tool\"",
        "name=\"target_glob\"",
        "name=\"params\"",
        "name=\"expires_in\"",
        "name=\"max_uses\"",
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
}

#[tokio::test]
async fn admin_can_issue_a_signed_grant() {
    let f = Fixture::new().await;
    let (cookie, csrf) = f.session("admin");
    let before = f.audit_count();
    let response = f
        .post_form(
            "/grants/issue",
            &cookie,
            &csrf,
            &[
                ("agent_id", "claude"),
                ("tool", "git.push"),
                ("target_glob", "github.com/acme/release-*"),
                ("params", "{\"force\":false}"),
                ("expires_in", "2h"),
                ("max_uses", "4"),
            ],
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/grants");
    let grants = f.store.list_grants().unwrap();
    let grant = &grants.last().unwrap().grant;
    grant.verify(&f.grant.public_key()).unwrap();
    assert_eq!(grant.agent_id().as_str(), "claude");
    assert_eq!(grant.tool().as_str(), "git.push");
    assert_eq!(grant.target_glob(), "github.com/acme/release-*");
    assert_eq!(grant.params()["force"], json!(false));
    assert_eq!(grant.expires_at().as_secs(), f.clock.now().as_secs() + 7200);
    assert_eq!(grant.max_uses(), Some(4));
    assert_eq!(f.audit_count(), before + 1);

    let body = f.get("/grants", &cookie).await.text().await.unwrap();
    assert!(body.contains(grant.id().as_str()));
    assert!(body.contains("github.com/acme/release-*"));
}

#[tokio::test]
async fn admin_can_revoke_a_grant_and_the_tombstone_is_audited() {
    let f = Fixture::new().await;
    let id = f.issue_grant("grt_cccccccccccccccccccccccccc", "github.com/acme/main");
    let before = f.audit_count();
    let (cookie, csrf) = f.session("admin");
    let response = f
        .post_form(
            &format!("/grants/{}/revoke", id.as_str()),
            &cookie,
            &csrf,
            &[],
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"].to_str().unwrap(), "/grants");
    let grants = f.store.list_grants().unwrap();
    assert!(
        grants
            .iter()
            .any(|view| view.grant.id() == &id && view.revoked)
    );
    let entries = f.store.audit_entries(0, 1000).unwrap();
    assert_eq!(entries.len(), before + 1);
    assert_eq!(entries.last().unwrap().kind(), AuditKind::GrantRevoked);
    assert_eq!(entries.last().unwrap().subject()["grant_id"], id.as_str());
}

#[tokio::test]
async fn viewer_cannot_run_any_admin_action() {
    let f = Fixture::new().await;
    let grant = f.issue_grant("grt_dddddddddddddddddddddddddd", "github.com/acme/main");
    let (cookie, csrf) = f.session("viewer");
    let before = f.audit_count();
    for (path, form) in [
        ("/agents/add", vec![("agent_id", "mallory")]),
        ("/agents/claude/rotate", vec![]),
        ("/agents/claude/remove", vec![]),
        (
            "/grants/issue",
            vec![
                ("agent_id", "claude"),
                ("tool", "git.push"),
                ("target_glob", "github.com/acme/main"),
                ("params", "{}"),
                ("expires_in", "1h"),
                ("max_uses", "1"),
            ],
        ),
    ] {
        let response = f.post_form(path, &cookie, &csrf, &form).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let response = f
        .post_form(
            &format!("/grants/{}/revoke", grant.as_str()),
            &cookie,
            &csrf,
            &[],
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(f.audit_count(), before);
    assert_eq!(
        f.store.list_agents().unwrap(),
        vec![AgentId::try_from("claude").unwrap()]
    );
    let grants = f.store.list_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert!(!grants[0].revoked);
}

#[tokio::test]
async fn policy_page_shows_the_loaded_text_digest_and_time_without_editing() {
    let f = Fixture::new().await;
    let (cookie, _) = f.session("viewer");
    let response = f.get("/policy", &cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let parsed = sekisho_core::Policy::parse(POLICY.as_bytes()).unwrap();
    for expected in [
        "Policy",
        &parsed.sha256.to_string(),
        "Loaded at 1700000000 UTC",
        "main push",
        "tool = \"git.push\"",
        "Read only",
    ] {
        assert!(body.contains(expected), "missing {expected}\n{body}");
    }
    assert!(!body.contains("action=\"/policy"));
    assert!(!body.contains("<textarea"));
}
