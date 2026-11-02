#![allow(clippy::unwrap_used)]

use sekisho::{
    server::{
        AppState, CheckApi, Clock, InMemorySessions, InMemoryUsers, Role, SessionStore, User,
        router,
    },
    store::Store,
};
use sekisho_core::*;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

const POLICY: &str = r#"version = 1
[[rule]]
name = "read"
tool = "git.fetch"
decision = "allow"
budget = { max = 1, per = "1h" }
[[rule]]
name = "push"
tool = "git.push"
decision = "ask"
[[rule]]
name = "blocked"
tool = "git.delete"
decision = "deny"
"#;

struct TestClock(tokio::time::Instant);
impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        (1_700_000_000 + self.0.elapsed().as_secs() as i64).into()
    }
}
struct Fixture {
    dir: PathBuf,
    store: Arc<Store>,
    checks: Arc<CheckApi>,
    clock: Arc<TestClock>,
    client: reqwest::Client,
    base: String,
    token: String,
    cookie: String,
    csrf: String,
    server: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new(ttl: Option<u32>) -> Self {
        Self::build(ttl, POLICY, false).await
    }
    async fn build(ttl: Option<u32>, policy: &str, protect: bool) -> Self {
        use std::hash::BuildHasher;
        let suffix = std::hash::RandomState::new().hash_one("check");
        let dir =
            std::env::temp_dir().join(format!("sekisho-check-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("policy.toml"), policy).unwrap();
        let signer = Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]));
        let store = Arc::new(Store::open(&dir.join("store.db"), signer).unwrap());
        let clock = Arc::new(TestClock(tokio::time::Instant::now()));
        let user = UserId::try_from("admin").unwrap();
        let token = store
            .add_agent(&AgentId::try_from("claude").unwrap(), &user, clock.now())
            .unwrap()
            .expose()
            .to_owned();
        let users = Arc::new(InMemoryUsers::default());
        users
            .insert(User {
                id: user.clone(),
                password_hash: String::new(),
                totp_secret: Some(vec![1; 20]),
                roles: [Role::Approver].into(),
            })
            .unwrap();
        let sessions = Arc::new(InMemorySessions::default());
        let session = sessions
            .create(&user, clock.now(), 43200, Some(1))
            .unwrap()
            .unwrap();
        let csrf = sessions
            .get(&session, clock.now())
            .unwrap()
            .unwrap()
            .csrf_token;
        let cookie = format!("sekisho_session={}", session.expose());
        let mut checks = CheckApi::load(
            store.clone(),
            &dir.join("policy.toml"),
            grant_signer().public_key(),
            ttl,
            &Principal::User(user),
            clock.now(),
        )
        .unwrap();
        if protect {
            checks = checks.with_protected_dir(&dir).unwrap();
        }
        let checks = Arc::new(checks);
        let state = AppState::new_with_agents(users, sessions, store.clone(), clock.clone(), true)
            .unwrap()
            .with_check_api(checks.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        Self {
            dir,
            store,
            checks,
            clock,
            client: reqwest::Client::new(),
            base,
            token,
            cookie,
            csrf,
            server,
        }
    }
    fn check(&self, tool: &str, wait: u64) -> reqwest::RequestBuilder {
        self.client.post(format!("{}/v1/check?wait={wait}", self.base)).bearer_auth(&self.token)
            .header("x-agent-id", "mallory")
            .json(&json!({"agent_id":"mallory", "tool":tool, "target":"repo", "params":{}, "invocations_so_far":0}))
    }
    async fn decision(&self, tool: &str) -> Value {
        let response = self.check(tool, 0).send().await.unwrap();
        assert_eq!(response.status(), 200);
        response.json().await.unwrap()
    }
    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.join("store.db")).unwrap()
    }
    async fn pending(&self) -> ApprovalId {
        for _ in 0..10000 {
            if let Some(id) = self
                .store
                .audit_entries(0, 100)
                .unwrap()
                .iter()
                .find(|e| e.kind() == AuditKind::ApprovalRequested)
                .and_then(|e| e.subject()["approval_id"].as_str())
                .map(str::to_owned)
            {
                // Let the HTTP handler subscribe before advancing the virtual clock.
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                return ApprovalId::try_from(id.as_str()).unwrap();
            }
            tokio::task::yield_now().await;
        }
        panic!("check never created an approval");
    }
    fn approval(&self, id: &ApprovalId) -> Approval {
        self.store
            .transact(self.clock.now(), |tx| {
                Ok((tx.get_approval(id)?.unwrap(), vec![]))
            })
            .unwrap()
    }
    async fn resolve(&self, id: &ApprovalId, outcome: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/approvals/{}/{outcome}", self.base, id.as_str()))
            .header("cookie", &self.cookie)
            .header("X-CSRF-Token", &self.csrf)
            .send()
            .await
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn grant_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes("grant", &[8; 32])
}

#[tokio::test]
async fn agent_id_ignored_in_body() {
    let f = Fixture::new(None).await;
    let result = f.decision("git.push").await;
    assert_eq!(result["decision"], "ask");
    assert_eq!(
        result["expires_at"].as_i64().unwrap(),
        f.clock.now().as_secs() + 900
    );
    let id = ApprovalId::try_from(result["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.approval(&id).action().agent_id().as_str(), "claude");
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .filter(|e| matches!(
                e.kind(),
                AuditKind::ActionRequested | AuditKind::Decided | AuditKind::ApprovalRequested
            ))
            .all(|e| e.actor() == &Principal::Agent(AgentId::try_from("claude").unwrap()))
    );
}

#[tokio::test]
async fn budget_counted_only_on_allow() {
    let f = Fixture::new(None).await;
    assert_eq!(f.decision("git.push").await["decision"], "ask");
    assert_eq!(f.decision("git.delete").await["decision"], "deny");
    assert_eq!(
        f.sql()
            .query_row("SELECT count(*) FROM budget_counters", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(f.decision("git.fetch").await["decision"], "allow");
    for _ in 0..2 {
        let response = f.decision("git.fetch").await;
        assert_eq!(response["decision"], "deny");
        assert_eq!(response["reason"], "budget exhausted");
    }
    assert_eq!(
        f.sql()
            .query_row("SELECT used FROM budget_counters", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn concurrent_checks_cannot_overspend_budget() {
    let f = Fixture::new(None).await;
    let (a, b) = tokio::join!(f.decision("git.fetch"), f.decision("git.fetch"));
    let mut decisions = [
        a["decision"].as_str().unwrap(),
        b["decision"].as_str().unwrap(),
    ];
    decisions.sort();
    assert_eq!(decisions, ["allow", "deny"]);
}

#[tokio::test]
async fn ask_then_approve_wakes_waiter() {
    let f = Fixture::new(None).await;
    let request = f.check("git.push", 600);
    let waiter = tokio::spawn(async move { request.send().await.unwrap() });
    let id = f.pending().await;
    assert!(!waiter.is_finished());
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    let result: Value = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["decision"], "allow");
    assert_eq!(f.approval(&id).state(), ApprovalState::Consumed);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.kind() == AuditKind::Approved)
    );
}

#[tokio::test]
async fn ask_then_deny_wakes_waiter() {
    let f = Fixture::new(None).await;
    let request = f.check("git.push", 600);
    let waiter = tokio::spawn(async move { request.send().await.unwrap() });
    let id = f.pending().await;
    assert_eq!(f.resolve(&id, "deny").await.status(), 200);
    let result: Value = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["decision"], "deny");
    assert_eq!(f.approval(&id).state(), ApprovalState::Denied);
}

#[tokio::test]
async fn expiry_wakes_waiter() {
    let f = Fixture::new(Some(60)).await;
    tokio::time::pause();
    let request = f.check("git.push", 120);
    let waiter = tokio::spawn(async move { request.send().await.unwrap() });
    let id = f.pending().await;
    tokio::time::advance(Duration::from_secs(60)).await;
    let result: Value = waiter.await.unwrap().json().await.unwrap();
    assert_eq!(result["decision"], "expired");
    assert_eq!(f.approval(&id).state(), ApprovalState::Expired);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.kind() == AuditKind::Expired)
    );
}

#[tokio::test]
async fn wait_is_capped() {
    let f = Fixture::new(None).await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let request = f.check("git.push", u64::MAX);
    let waiter = tokio::spawn(async move { request.send().await.unwrap() });
    let id = f.pending().await;
    tokio::time::advance(Duration::from_secs(599)).await;
    assert!(!waiter.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    let result: Value = waiter.await.unwrap().json().await.unwrap();
    assert!(started.elapsed() >= Duration::from_secs(600));
    assert!(started.elapsed() < Duration::from_millis(600100));
    assert_eq!(result["decision"], "ask");
    assert_eq!(f.approval(&id).state(), ApprovalState::Pending);
}

#[tokio::test]
async fn audit_failure_rolls_back_allow_and_ask() {
    let f = Fixture::new(None).await;
    f.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    for tool in ["git.fetch", "git.push", "git.delete"] {
        assert_eq!(f.check(tool, 0).send().await.unwrap().status(), 503);
    }
    for table in ["budget_counters", "approvals"] {
        assert_eq!(
            f.sql()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(f.store.audit_entries(0, 100).unwrap().len(), 2);
}

#[tokio::test]
async fn policy_load_and_reload_are_audited_and_fail_closed() {
    let f = Fixture::new(None).await;
    let actor = Principal::User(UserId::try_from("admin").unwrap());
    let path = f.dir.join("policy.toml");
    let loaded = f.store.audit_entries(0, 100).unwrap();
    assert_eq!(loaded[1].kind(), AuditKind::PolicyLoaded);
    assert_eq!(
        loaded[1].subject()["policy_sha256"],
        Policy::parse(POLICY.as_bytes()).unwrap().sha256.to_string()
    );
    std::fs::write(&path, "invalid").unwrap();
    assert!(
        f.checks
            .reload_policy(&path, &actor, f.clock.now())
            .is_err()
    );
    assert_eq!(f.decision("git.fetch").await["decision"], "allow");
    std::fs::write(&path, "version = 1").unwrap();
    f.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(
        f.checks
            .reload_policy(&path, &actor, f.clock.now())
            .is_err()
    );
    f.sql().execute_batch("DROP TRIGGER fail_audit").unwrap();
    assert_eq!(f.decision("git.push").await["decision"], "ask");
    f.checks
        .reload_policy(&path, &actor, f.clock.now())
        .unwrap();
    assert_eq!(f.decision("git.push").await["decision"], "deny");
    let keys = BTreeMap::from([(
        "audit".into(),
        Ed25519Signer::from_secret_bytes("audit", &[7; 32]).public_key(),
    )]);
    f.store.verify_audit(&keys).unwrap();
}

#[tokio::test]
async fn approval_handlers_enforce_csrf_and_roll_back_on_audit_failure() {
    let f = Fixture::new(None).await;
    let result = f.decision("git.push").await;
    let id = ApprovalId::try_from(result["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(
        f.client
            .post(format!("{}/approvals/{}/approve", f.base, id.as_str()))
            .header("cookie", &f.cookie)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    f.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 503);
    assert_eq!(f.approval(&id).state(), ApprovalState::Pending);
}

#[tokio::test]
async fn grant_allow_records_use_and_deny_still_wins() {
    let f = Fixture::new(None).await;
    for (suffix, tool) in [("a", "git.push"), ("b", "git.delete")] {
        let grant = UnsignedGrant {
            id: GrantId::try_from(format!("grt_{}", suffix.repeat(26)).as_str()).unwrap(),
            agent_id: AgentId::try_from("claude").unwrap(),
            tool: ToolName::try_from(tool).unwrap(),
            target_glob: "repo".into(),
            params: BTreeMap::new(),
            not_before: f.clock.now(),
            expires_at: (f.clock.now().as_secs() + 3600).into(),
            max_uses: Some(1),
            issued_by: UserId::try_from("admin").unwrap(),
        }
        .sign(&grant_signer())
        .unwrap();
        f.store.transact(f.clock.now(), |tx| {
            tx.insert_grant(&grant)?;
            Ok(((), vec![sekisho::store::AuditRecord {
                kind: AuditKind::GrantIssued, actor: Principal::User(grant.issued_by().clone()),
                subject: json!({"grant_id":grant.id().as_str(), "agent_id":grant.agent_id().as_str(), "issued_by":grant.issued_by().as_str(), "expires_at":grant.expires_at()}),
            }]))
        }).unwrap();
    }
    assert_eq!(f.decision("git.push").await["decision"], "allow");
    assert_eq!(f.decision("git.push").await["decision"], "ask");
    assert_eq!(f.decision("git.delete").await["decision"], "deny");
    let uses = f
        .store
        .transact(f.clock.now(), |tx| {
            Ok((
                tx.grant_views_for(&AgentId::try_from("claude").unwrap(), f.clock.now())?,
                vec![],
            ))
        })
        .unwrap();
    assert_eq!(uses[0].uses, 1);
    assert_eq!(uses[1].uses, 0);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.kind() == AuditKind::Consumed
                && e.subject()["grant_id"] == uses[0].grant.id().as_str()
                && e.subject()["uses"] == 1
                && e.subject()["action_digest"].is_string())
    );
    let entries = f.store.audit_entries(0, 100).unwrap();
    assert!(entries.iter().any(|e| e.kind() == AuditKind::Decided
        && e.subject()["grant"] == uses[0].grant.id().as_str()
        && e.subject()["action_digest"].is_string()));
}

#[tokio::test]
async fn invalid_actions_and_queries_never_reach_decision() {
    let f = Fixture::new(None).await;
    for body in [
        json!({"tool":"git.*", "target":"repo", "params":{}}),
        json!({"tool":"git.fetch", "target":"", "params":{}}),
        json!({"tool":"git.fetch", "target":"repo", "params":[]}),
        json!({"tool":"git.fetch", "target":"repo", "params":{"nested":[9007199254740992_u64]}}),
    ] {
        assert_eq!(
            f.client
                .post(format!("{}/v1/check", f.base))
                .bearer_auth(&f.token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            422
        );
    }
    for query in ["-1", "nonsense"] {
        assert_eq!(
            f.client
                .post(format!("{}/v1/check?wait={query}", f.base))
                .bearer_auth(&f.token)
                .json(&json!({"tool":"git.fetch", "target":"repo", "params":{}}))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    assert_eq!(f.store.audit_entries(0, 100).unwrap().len(), 2);
}

#[tokio::test]
async fn recheck_consumes_approved_action_once() {
    let f = Fixture::new(None).await;
    let first = f.decision("git.push").await;
    let id = ApprovalId::try_from(first["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    assert_eq!(f.decision("git.push").await["decision"], "allow");
    assert_eq!(f.approval(&id).state(), ApprovalState::Consumed);
    assert_eq!(f.decision("git.push").await["decision"], "ask");
}

#[tokio::test]
async fn recheck_different_digest_does_not_consume() {
    let f = Fixture::new(None).await;
    let first = f.decision("git.push").await;
    let id = ApprovalId::try_from(first["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    let result: Value = f
        .client
        .post(format!("{}/v1/check", f.base))
        .bearer_auth(&f.token)
        .json(&json!({"tool":"git.push", "target":"other", "params":{}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["decision"], "ask");
    assert_eq!(f.approval(&id).state(), ApprovalState::Approved);
    assert_eq!(f.decision("git.push").await["decision"], "allow");
}

#[tokio::test]
async fn concurrent_rechecks_allow_exactly_once() {
    let f = Fixture::new(None).await;
    let first = f.decision("git.push").await;
    let id = ApprovalId::try_from(first["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    let (a, b) = tokio::join!(f.decision("git.push"), f.decision("git.push"));
    let mut decisions = [
        a["decision"].as_str().unwrap(),
        b["decision"].as_str().unwrap(),
    ];
    decisions.sort();
    assert_eq!(decisions, ["allow", "ask"]);
    assert_eq!(f.approval(&id).state(), ApprovalState::Consumed);
}

#[tokio::test]
async fn recheck_audit_failure_refuses_consumption() {
    let f = Fixture::new(None).await;
    let first = f.decision("git.push").await;
    let id = ApprovalId::try_from(first["approval_id"].as_str().unwrap()).unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    f.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_eq!(f.check("git.push", 0).send().await.unwrap().status(), 503);
    assert_eq!(f.approval(&id).state(), ApprovalState::Approved);
    f.sql().execute_batch("DROP TRIGGER fail_audit").unwrap();
    assert_eq!(f.decision("git.push").await["decision"], "allow");
}

/// SEK-02: hook actions on the Sekisho home are denied by a built-in rule that
/// a permissive policy cannot override, including after a reload.
#[tokio::test]
async fn sekisho_home_is_denied_to_hook_actions_whatever_the_policy() {
    let policy = "version = 1\n[[rule]]\nname = 'all'\ntool_prefix = 'hook:claude-code/'\ndecision = 'allow'\n";
    let f = Fixture::build(None, policy, true).await;
    let real = std::fs::canonicalize(&f.dir).unwrap();
    let check = |target: String| {
        let request = f
            .client
            .post(format!("{}/v1/check", f.base))
            .bearer_auth(&f.token)
            .json(&json!({"tool":"hook:claude-code/read", "target":target, "params":{}}));
        async move {
            let body: Value = request.send().await.unwrap().json().await.unwrap();
            body["decision"].as_str().unwrap().to_owned()
        }
    };
    for home in [f.dir.clone(), real.clone()] {
        let home = home.to_str().unwrap().to_owned();
        assert_eq!(check(format!("{home}/admin.token")).await, "deny");
        assert_eq!(check(home.clone()).await, "deny");
    }
    assert_eq!(check("/tmp/elsewhere".into()).await, "allow");
    f.checks
        .reload_policy(
            &f.dir.join("policy.toml"),
            &Principal::User(UserId::try_from("admin").unwrap()),
            f.clock.now(),
        )
        .unwrap();
    assert_eq!(
        check(format!("{}/keys/grant.ed25519", real.to_str().unwrap())).await,
        "deny"
    );
}

/// SEK-05: a waiting check decides again when its approval arrives, so a deny
/// rule loaded meanwhile wins and the approval is not consumed.
#[tokio::test]
async fn waiting_check_redecides_before_consuming() {
    let f = Fixture::new(None).await;
    let request = f.check("git.push", 600);
    let waiter = tokio::spawn(async move { request.send().await.unwrap() });
    let id = f.pending().await;
    std::fs::write(
        f.dir.join("policy.toml"),
        POLICY.replace(
            "name = \"push\"\ntool = \"git.push\"\ndecision = \"ask\"",
            "name = \"push\"\ntool = \"git.push\"\ndecision = \"deny\"",
        ),
    )
    .unwrap();
    f.checks
        .reload_policy(
            &f.dir.join("policy.toml"),
            &Principal::User(UserId::try_from("admin").unwrap()),
            f.clock.now(),
        )
        .unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    let result: Value = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["decision"], "deny");
    assert_eq!(f.approval(&id).state(), ApprovalState::Approved);
}

/// SEK-05: removing the agent while it waits refuses the approved action.
#[tokio::test]
async fn waiting_check_of_removed_agent_is_denied() {
    let f = Fixture::new(None).await;
    let request = f.check("git.push", 600);
    let waiter = tokio::spawn(async move { request.send().await.unwrap() });
    let id = f.pending().await;
    f.store
        .remove_agent(
            &AgentId::try_from("claude").unwrap(),
            &UserId::try_from("admin").unwrap(),
            f.clock.now(),
        )
        .unwrap();
    assert_eq!(f.resolve(&id, "approve").await.status(), 200);
    let result: Value = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["decision"], "deny");
    assert_eq!(f.approval(&id).state(), ApprovalState::Approved);
}

/// DS-03: an agent cannot hold more than 20 pending approvals; further asks
/// are refused without creating approvals (or notifications).
#[tokio::test]
async fn pending_approvals_per_agent_are_capped() {
    let f = Fixture::new(None).await;
    let mut decisions = Vec::new();
    for _ in 0..25 {
        decisions.push(f.decision("git.push").await);
    }
    assert!(decisions[..20].iter().all(|d| d["decision"] == "ask"));
    for refused in &decisions[20..] {
        assert_eq!(refused["decision"], "deny");
        assert_eq!(refused["reason"], "too many pending approvals");
        assert!(refused["approval_id"].is_null());
    }
    let pending: i64 = f
        .sql()
        .query_row(
            "SELECT count(*) FROM approvals WHERE state='Pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 20);
}

/// DS-03: at most 16 requests per agent wait for approval at once; more get
/// their `ask` answer immediately.
#[tokio::test]
async fn concurrent_waiters_per_agent_are_capped() {
    let f = Fixture::new(None).await;
    let mut waiting = Vec::new();
    for _ in 0..16 {
        let request = f.check("git.push", 600);
        waiting.push(tokio::spawn(async move { request.send().await.unwrap() }));
    }
    // Let all sixteen reach their wait.
    for _ in 0..200 {
        let pending: i64 = f
            .sql()
            .query_row(
                "SELECT count(*) FROM approvals WHERE state='Pending'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if pending == 16 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let extra: Value =
        tokio::time::timeout(Duration::from_secs(2), f.check("git.push", 600).send())
            .await
            .unwrap()
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(extra["decision"], "ask");
    assert!(waiting.iter().all(|w| !w.is_finished()));
    for w in waiting {
        w.abort();
    }
}
