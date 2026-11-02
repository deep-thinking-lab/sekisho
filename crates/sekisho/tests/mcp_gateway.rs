#![allow(clippy::unwrap_used)]

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use sekisho::{
    mcp::{Gateway, UpstreamConfig},
    server::{
        AppState, CheckApi, Clock, InMemorySessions, InMemoryUsers, Role, SessionStore,
        SystemClock, User, router,
    },
    store::Store,
};
use sekisho_core::*;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const SECRET: &str = "private-upstream-bearer-must-not-leak";
const POLICY: &str = r#"version = 1
[[rule]]
name = "read"
tool = "mcp:fake/read"
decision = "allow"
budget = { max = 1, per = "1h" }
[[rule]]
name = "human"
tool = "mcp:fake/write"
decision = "ask"
[[rule]]
name = "blocked"
tool = "mcp:fake/delete"
decision = "deny"
[[rule]]
name = "failure"
tool = "mcp:fake/fail"
decision = "allow"
[[rule]]
name = "timeout"
tool = "mcp:fake/slow"
decision = "allow"
[[rule]]
name = "stdio"
tool = "mcp:stdio/read"
decision = "allow"
"#;

#[derive(Clone, Default)]
struct Backend {
    calls: Arc<Mutex<Vec<Value>>>,
    discovery_fails: Arc<std::sync::atomic::AtomicBool>,
    discoveries: Arc<std::sync::atomic::AtomicUsize>,
    list_mode: Arc<Mutex<String>>,
    wire_mode: Arc<Mutex<String>>,
}
async fn upstream(
    State(backend): State<Backend>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> axum::response::Response {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {SECRET}"))
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"bad credential"})),
        )
            .into_response();
    }
    if backend.wire_mode.lock().unwrap().as_str() == "protocol"
        && request["method"] != "initialize"
        && headers
            .get("MCP-Protocol-Version")
            .and_then(|value| value.to_str().ok())
            != Some("2024-11-05")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let result = match request["method"].as_str().unwrap_or("") {
        "initialize" => {
            let version = if backend.wire_mode.lock().unwrap().as_str() == "protocol" {
                json!("2024-11-05")
            } else {
                request["params"]["protocolVersion"].clone()
            };
            json!({"protocolVersion": version, "capabilities":{"tools":{}}, "serverInfo":{"name":"fake", "version":"1"}})
        }
        "tools/list" => {
            backend
                .discoveries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if backend
                .discovery_fails
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return (StatusCode::BAD_GATEWAY, Json(json!({"error":SECRET}))).into_response();
            }
            let mode = backend.list_mode.lock().unwrap().clone();
            let names = match mode.as_str() {
                "bad" => vec!["read", "Bad", "nested/tool", "", SECRET, "write"],
                "count" => vec!["read"; 1001],
                _ => vec!["read", "write", "delete", "fail", "slow"],
            };
            let mut result = json!({"tools": names.iter().map(|name| json!({"name":name,"description":SECRET,"inputSchema":{"type":"object","properties":{(SECRET):{"type":"string"}}}})).collect::<Vec<_>>()});
            if mode == "pages" {
                result["nextCursor"] = json!("again");
            }
            result
        }
        "tools/call" => {
            backend
                .calls
                .lock()
                .unwrap()
                .push(request["params"].clone());
            match request["params"]["name"].as_str().unwrap() {
                "fail" => {
                    return (StatusCode::BAD_GATEWAY, Json(json!({"error":SECRET})))
                        .into_response();
                }
                "slow" => tokio::time::sleep(Duration::from_secs(10)).await,
                _ => (),
            }
            let text = if request["params"]["arguments"]["oversize"] == true {
                "x".repeat(4 * 1024 * 1024 + 1)
            } else {
                SECRET.to_owned()
            };
            json!({"content":[{"type":"text","text":text}],"isError":false})
        }
        _ => return (StatusCode::ACCEPTED, Json(Value::Null)).into_response(),
    };
    let result = json!({"jsonrpc":"2.0", "id":request["id"], "result":result});
    let mode = backend.wire_mode.lock().unwrap().clone();
    let body = match mode.as_str() {
        "sse" => format!(": keepalive\r\n\r\ndata: {result}\r\n\r\n"),
        "padding" if request["method"] == "tools/call" => {
            format!("{}{result}", " ".repeat(4 * 1024 * 1024))
        }
        _ => result.to_string(),
    };
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(
            "content-type",
            if mode == "sse" {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .body(axum::body::Body::from_stream(
            axum::body::Body::from(body).into_data_stream(),
        ))
        .unwrap()
}

struct Fixture {
    dir: PathBuf,
    store: Arc<Store>,
    backend: Backend,
    client: reqwest::Client,
    base: String,
    token: String,
    cookie: String,
    csrf: String,
    servers: Vec<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn new(wait: u64) -> Self {
        Self::configured(wait, false, json!({})).await
    }
    async fn with_stdio(wait: u64, stdio: bool) -> Self {
        Self::configured(wait, stdio, json!({})).await
    }
    async fn configured(wait: u64, stdio: bool, options: Value) -> Self {
        use std::hash::BuildHasher;
        let suffix = std::hash::RandomState::new().hash_one("mcp");
        let dir = std::env::temp_dir().join(format!("sekisho-mcp-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("policy.toml"), POLICY).unwrap();
        let signer = Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]));
        let store = Arc::new(Store::open(&dir.join("store.db"), signer).unwrap());
        let clock = Arc::new(SystemClock);
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
        let checks = Arc::new(
            CheckApi::load(
                store.clone(),
                &dir.join("policy.toml"),
                Ed25519Signer::from_secret_bytes("grant", &[8; 32]).public_key(),
                None,
                &Principal::User(user),
                clock.now(),
            )
            .unwrap(),
        );
        let backend = Backend::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let app = axum::Router::new()
            .route("/mcp", post(upstream))
            .with_state(backend.clone());
        let upstream = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let secret = dir.join("credential.secret");
        std::fs::write(&secret, SECRET).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut configs = vec![
            serde_json::from_value::<UpstreamConfig>(
                json!({"name":"fake","transport":"http","url":url,"token_file":secret}),
            )
            .unwrap(),
        ];
        if stdio {
            let binary = dir.join("mcp-fake");
            let output = std::process::Command::new("rustc")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/support/mcp_fake.rs"
                ))
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            configs.push(serde_json::from_value(json!({"name":"stdio","transport":"stdio","command":binary,"args":[],"env":{"ONLY_CONFIGURED":"yes"}})).unwrap());
        }
        let gateway = Gateway::load(&dir, configs, Some(wait), Some(3)).unwrap();
        let gateway = gateway
            .with_limits(serde_json::from_value(options).unwrap())
            .unwrap();

        let state = AppState::new_with_agents(users, sessions, store.clone(), clock, true)
            .unwrap()
            .with_check_api(checks)
            .with_mcp_gateway(Arc::new(gateway))
            .with_public_url("https://sekisho.example.test");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gateway =
            tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        Self {
            dir,
            store,
            backend,
            client: reqwest::Client::new(),
            base,
            token,
            cookie,
            csrf,
            servers: vec![upstream, gateway],
        }
    }
    fn request(&self, method: &str, params: Value) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}/mcp", self.base))
            .bearer_auth(&self.token)
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-03-26")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
    }
    async fn rpc(&self, method: &str, params: Value) -> Value {
        let response = self.request(method, params).send().await.unwrap();
        assert!(
            response.status().is_success(),
            "MCP HTTP {}: {}",
            response.status(),
            response.text().await.unwrap()
        );
        decode(&response.text().await.unwrap())
    }
    async fn call(&self, name: &str, args: Value) -> Value {
        self.rpc("tools/call", json!({"name":name,"arguments":args}))
            .await
    }
    fn calls(&self) -> Vec<Value> {
        self.backend
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| json!({"name":call["name"], "arguments":call["arguments"]}))
            .collect()
    }
    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.dir.join("store.db")).unwrap()
    }
    async fn pending(&self) -> ApprovalId {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(id) = self
                    .store
                    .audit_entries(0, 100)
                    .unwrap()
                    .iter()
                    .find(|e| e.kind() == AuditKind::ApprovalRequested)
                    .and_then(|e| e.subject()["approval_id"].as_str())
                    .map(str::to_owned)
                {
                    return ApprovalId::try_from(id.as_str()).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
fn decode(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|_| {
        body.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
            .find(|value| value.get("id").is_some())
            .unwrap_or_else(|| panic!("no JSON-RPC response: {body}"))
    })
}
fn assert_tool_error(response: &Value) {
    assert!(
        response["result"]["isError"] == true || response.get("error").is_some(),
        "expected MCP error, response length {}",
        response.to_string().len()
    );
}

#[tokio::test]
async fn mcp_tools_list_renames_upstream_tools() {
    let f = Fixture::new(0).await;
    let response = f.rpc("tools/list", json!({})).await;
    let names: Vec<_> = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"fake/read"));
    assert!(names.contains(&"fake/write"));
    assert!(names.iter().all(|name| name.starts_with("fake/")));
    assert!(f.calls().is_empty());
}
#[tokio::test]
async fn mcp_call_allowed_forwards() {
    let f = Fixture::new(0).await;
    let args = json!({"nested":{"value":"hello"},"agent_id":"mallory"});
    let response = f.call("fake/read", args.clone()).await;
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(f.calls(), vec![json!({"name":"read","arguments":args})]);
    let entries = f.store.audit_entries(0, 100).unwrap();
    let action = entries
        .iter()
        .find(|e| e.kind() == AuditKind::ActionRequested)
        .unwrap();
    assert_eq!(
        action.actor(),
        &Principal::Agent(AgentId::try_from("claude").unwrap())
    );
    let expected = Action::new(
        AgentId::try_from("claude").unwrap(),
        ToolName::try_from("mcp:fake/read").unwrap(),
        "fake".into(),
        args,
    )
    .unwrap();
    assert_eq!(
        action.subject()["action_digest"],
        expected.digest().unwrap().to_string()
    );
}
#[tokio::test]
async fn mcp_missing_arguments_forward_the_exact_approved_object() {
    let f = Fixture::new(0).await;
    let response = f.rpc("tools/call", json!({"name":"fake/read"})).await;
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(f.calls(), vec![json!({"name":"read", "arguments":{}})]);
}

#[tokio::test]
async fn mcp_call_denied_never_reaches_upstream() {
    let f = Fixture::new(0).await;
    let response = f.call("fake/delete", json!({})).await;
    assert_tool_error(&response);
    assert!(response.to_string().contains("blocked"), "{response}");
    assert!(f.calls().is_empty());
}
#[tokio::test]
async fn mcp_call_ask_then_approve() {
    let f = Arc::new(Fixture::new(5).await);
    let other = f.clone();
    let waiter = tokio::spawn(async move { other.call("fake/write", json!({"value":1})).await });
    let id = f.pending().await;
    assert!(f.calls().is_empty());
    let response = f
        .client
        .post(format!("{}/approvals/{}/approve", f.base, id.as_str()))
        .header("cookie", &f.cookie)
        .header("X-CSRF-Token", &f.csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response = tokio::time::timeout(Duration::from_secs(3), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(f.calls().len(), 1);
    let approval = f
        .store
        .transact(SystemClock.now(), |tx| {
            Ok((tx.get_approval(&id)?.unwrap(), vec![]))
        })
        .unwrap();
    assert_eq!(approval.state(), ApprovalState::Consumed);
}
#[tokio::test]
async fn mcp_upstream_credentials_never_returned() {
    let f = Fixture::new(0).await;
    for response in [
        f.rpc("tools/list", json!({})).await,
        f.call("fake/read", json!({})).await,
        f.call("fake/fail", json!({})).await,
    ] {
        assert!(!response.to_string().contains(SECRET), "{response}");
        assert!(!response.to_string().contains(&f.dir.display().to_string()));
    }
    for entry in f.store.audit_entries(0, 100).unwrap() {
        assert!(!entry.subject().to_string().contains(SECRET));
    }
    assert_eq!(
        f.calls().len(),
        2,
        "the fake requires Sekisho's upstream bearer"
    );
}
#[tokio::test]
async fn mcp_route_rejects_cookie_sessions() {
    let f = Fixture::new(0).await;
    for method in [
        reqwest::Method::GET,
        reqwest::Method::POST,
        reqwest::Method::DELETE,
    ] {
        let response = f
            .client
            .request(method, format!("{}/mcp", f.base))
            .header("cookie", &f.cookie)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }
    assert!(f.calls().is_empty());
}
#[tokio::test]
async fn mcp_upstream_failure_is_audited() {
    let f = Fixture::new(0).await;
    assert_tool_error(&f.call("fake/fail", json!({})).await);
    assert_eq!(f.calls().len(), 1);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "upstream_failed"
                && e.subject()["action_digest"].is_string())
    );
}

#[tokio::test]
async fn mcp_discovery_failure_is_audited() {
    let f = Fixture::new(0).await;
    f.backend
        .discovery_fails
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let response = f.rpc("tools/list", json!({})).await;
    assert!(response.get("error").is_some());
    assert!(!response.to_string().contains(SECRET));
    assert!(f.store.audit_entries(0, 100).unwrap().iter().any(|entry| {
        entry.subject()["outcome"] == "upstream_failed"
            && entry.subject()["operation"] == "tools/list"
    }));
}
#[tokio::test]
async fn mcp_upstream_timeout_is_audited() {
    let f = Fixture::new(0).await;
    let response = tokio::time::timeout(Duration::from_secs(4), f.call("fake/slow", json!({})))
        .await
        .unwrap();
    assert_tool_error(&response);
    assert_eq!(f.calls().len(), 1);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "upstream_failed"
                && e.subject()["action_digest"].is_string())
    );
}
#[tokio::test]
async fn mcp_arguments_reject_unsafe_integers() {
    let f = Fixture::new(0).await;
    assert_tool_error(
        &f.call("fake/read", json!({"nested":[9007199254740992_u64]}))
            .await,
    );
    assert!(f.calls().is_empty());
    assert!(
        !f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.kind() == AuditKind::ActionRequested)
    );
}
#[tokio::test]
async fn mcp_budget_is_counted_server_side() {
    let f = Fixture::new(0).await;
    let (a, b) = tokio::join!(
        f.call("fake/read", json!({"invocations_so_far":0})),
        f.call("fake/read", json!({"invocations_so_far":0}))
    );
    assert_eq!(f.calls().len(), 1);
    assert_eq!(
        [a, b]
            .iter()
            .filter(|r| r["result"]["isError"] == true)
            .count(),
        1
    );
    assert_eq!(
        f.sql()
            .query_row("SELECT used FROM budget_counters", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[tokio::test]
async fn mcp_audit_failure_refuses_execution() {
    let f = Fixture::new(0).await;
    f.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_tool_error(&f.call("fake/read", json!({})).await);
    assert_tool_error(&f.call("fake/write", json!({})).await);
    assert!(f.calls().is_empty());
    for table in ["budget_counters", "approvals"] {
        assert_eq!(
            f.sql()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
#[tokio::test]
async fn mcp_pending_error_names_approval() {
    let f = Fixture::new(0).await;
    let response = f.call("fake/write", json!({})).await;
    assert_tool_error(&response);
    let id = f.pending().await;
    assert!(
        response.to_string().contains(&format!(
            "https://sekisho.example.test/approvals/{}",
            id.as_str()
        )),
        "{response}"
    );
    assert!(f.calls().is_empty());
}
#[tokio::test]
async fn mcp_stdio_has_only_configured_environment() {
    let f = Fixture::with_stdio(0, true).await;
    let tools = f.rpc("tools/list", json!({})).await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "stdio/read")
    );
    let response = f.call("stdio/read", json!({})).await;
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["content"][0]["text"],
        "ONLY_CONFIGURED=yes"
    );
}

#[tokio::test]
async fn mcp_approval_is_bound_to_arguments_and_single_use() {
    let f = Fixture::new(0).await;
    assert_tool_error(&f.call("fake/write", json!({"value":1})).await);
    let id = f.pending().await;
    assert_eq!(
        f.client
            .post(format!("{}/approvals/{}/approve", f.base, id.as_str()))
            .header("cookie", &f.cookie)
            .header("X-CSRF-Token", &f.csrf)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_tool_error(&f.call("fake/write", json!({"value":2})).await);
    assert!(f.calls().is_empty());
    assert_eq!(
        f.call("fake/write", json!({"value":1})).await["result"]["isError"],
        false
    );
    assert_eq!(
        f.calls(),
        vec![json!({"name":"write","arguments":{"value":1}})]
    );
    assert_tool_error(&f.call("fake/write", json!({"value":1})).await);
    assert_eq!(f.calls().len(), 1);
}

#[tokio::test]
async fn tools_list_hides_denied_tools() {
    let f = Fixture::new(0).await;
    let response = f.rpc("tools/list", json!({})).await;
    let tools = response["result"]["tools"].as_array().unwrap();
    assert!(!tools.iter().any(|tool| tool["name"] == "fake/delete"));
    assert!(tools.iter().any(|tool| tool["name"] == "fake/write"));
    assert_eq!(
        f.sql()
            .query_row("SELECT count(*) FROM approvals", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(f.store.audit_entries(0,100).unwrap().iter().any(|e| e.subject()["operation"] == "tools/list" && e.subject()["outcome"] == "listed"));
    f.call("fake/read", json!({})).await;
    let response = f.rpc("tools/list", json!({})).await;
    assert!(
        !response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "fake/read")
    );
}

#[tokio::test]
async fn tools_list_uses_cache() {
    let f = Fixture::new(0).await;
    let (a, b) = tokio::join!(
        f.rpc("tools/list", json!({})),
        f.rpc("tools/list", json!({}))
    );
    assert_eq!(a["result"], b["result"]);
    assert_eq!(
        f.backend
            .discoveries
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn tools_list_cache_expires() {
    let f = Fixture::configured(0, false, json!({"discovery_ttl_seconds":1})).await;
    f.rpc("tools/list", json!({})).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    f.rpc("tools/list", json!({})).await;
    assert_eq!(
        f.backend
            .discoveries
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[tokio::test]
async fn mcp_oversized_request_rejected() {
    for (options, size) in [
        (json!({}), 1024 * 1024 + 1),
        (json!({"request_bytes":512}), 513),
    ] {
        let f = Fixture::configured(0, false, options).await;
        let response = f
            .request(
                "tools/call",
                json!({"name":"fake/read", "arguments":{"text":"x".repeat(size)}}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(f.calls().is_empty());
    }
}

#[tokio::test]
async fn mcp_oversized_http_response_rejected() {
    let f = Fixture::new(0).await;
    assert_tool_error(&f.call("fake/read", json!({"oversize":true})).await);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.subject()["outcome"] == "upstream_failed")
    );
}

#[tokio::test]
async fn mcp_oversized_stdio_response_rejected() {
    let f = Fixture::with_stdio(0, true).await;
    assert_tool_error(&f.call("stdio/read", json!({"oversize":true})).await);
}

#[tokio::test]
async fn bad_tool_name_skipped_others_listed() {
    let f = Fixture::new(0).await;
    *f.backend.list_mode.lock().unwrap() = "bad".into();
    let response = f.rpc("tools/list", json!({})).await;
    let names: Vec<_> = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["fake/read", "fake/write"]);
    assert!(
        f.store
            .audit_entries(0, 100)
            .unwrap()
            .iter()
            .any(|e| e.subject()["skipped_tools"] == 4)
    );
}

#[tokio::test]
async fn one_failing_upstream_does_not_hide_others() {
    let f = Fixture::with_stdio(0, true).await;
    f.backend
        .discovery_fails
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let response = f.rpc("tools/list", json!({})).await;
    assert!(
        response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "stdio/read")
    );
}

#[tokio::test]
async fn discovery_bounds_pages_and_tool_count() {
    for mode in ["count", "pages"] {
        let f = Fixture::new(0).await;
        *f.backend.list_mode.lock().unwrap() = mode.into();
        assert_tool_error(&f.rpc("tools/list", json!({})).await);
        assert!(
            f.backend
                .discoveries
                .load(std::sync::atomic::Ordering::SeqCst)
                <= 100
        );
    }
}

#[tokio::test]
async fn mcp_per_agent_concurrency_is_bounded() {
    let f = Arc::new(Fixture::new(0).await);
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let other = f.clone();
        tasks.push(tokio::spawn(async move {
            other.call("fake/slow", json!({})).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.calls().len() < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let response = f.call("fake/read", json!({})).await;
    assert_tool_error(&response);
    assert!(response.to_string().contains("concurrency"), "{response}");
    assert_eq!(f.calls().len(), 4);
    for task in tasks {
        assert_tool_error(&task.await.unwrap());
    }
    assert_eq!(
        f.call("fake/read", json!({})).await["result"]["isError"],
        false
    );
}

#[tokio::test]
async fn mcp_global_concurrency_is_bounded() {
    let f = Arc::new(Fixture::new(0).await);
    let mut tasks = Vec::new();
    for name in ["one", "two", "three", "four"] {
        let token = f
            .store
            .add_agent(
                &AgentId::try_from(name).unwrap(),
                &UserId::try_from("admin").unwrap(),
                SystemClock.now(),
            )
            .unwrap()
            .expose()
            .to_owned();
        for _ in 0..4 {
            let other = f.clone();
            let token = token.clone();
            tasks.push(tokio::spawn(async move {
                let mut request = other
                    .request("tools/call", json!({"name":"fake/slow", "arguments":{}}))
                    .build()
                    .unwrap();
                request
                    .headers_mut()
                    .insert("authorization", format!("Bearer {token}").parse().unwrap());
                let response = other.client.execute(request).await.unwrap();
                decode(&response.text().await.unwrap())
            }));
        }
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.calls().len() < 16 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let response = f.call("fake/read", json!({})).await;
    assert_tool_error(&response);
    assert!(
        response.to_string().contains("global concurrency"),
        "{response}"
    );
    assert_eq!(f.calls().len(), 16);
    for task in tasks {
        assert_tool_error(&task.await.unwrap());
    }
    assert_eq!(
        f.call("fake/read", json!({})).await["result"]["isError"],
        false
    );
}

#[tokio::test]
async fn upstream_failure_audits_are_rate_limited_without_losing_outcomes() {
    let f = Fixture::new(0).await;
    for _ in 0..3 {
        assert_tool_error(&f.call("fake/fail", json!({})).await);
    }
    let entries = f.store.audit_entries(0, 100).unwrap();
    let failures: Vec<_> = entries
        .iter()
        .filter(|e| e.subject()["outcome"] == "upstream_failed")
        .collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].subject()["server"], "fake");
    assert_eq!(failures[0].subject()["count"], 1);
    assert_eq!(
        entries
            .iter()
            .filter(
                |e| e.subject()["outcome"] == "failed" && e.subject()["action_digest"].is_string()
            )
            .count(),
        3
    );
}

#[tokio::test]
async fn tools_list_success_audit_failure_refuses_response() {
    let f = Fixture::new(0).await;
    f.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert_tool_error(&f.rpc("tools/list", json!({})).await);
}

#[tokio::test]
async fn mcp_chunked_response_bytes_are_capped_before_parsing() {
    let f = Fixture::new(0).await;
    *f.backend.wire_mode.lock().unwrap() = "padding".into();
    assert_tool_error(&f.call("fake/read", json!({})).await);
}

#[tokio::test]
async fn mcp_sse_upstream_responses_work() {
    let f = Fixture::new(0).await;
    *f.backend.wire_mode.lock().unwrap() = "sse".into();
    assert!(f.rpc("tools/list", json!({})).await["result"]["tools"].is_array());
    assert_eq!(
        f.call("fake/read", json!({})).await["result"]["isError"],
        false
    );
}

#[tokio::test]
async fn mcp_response_limit_is_configurable() {
    let f = Fixture::configured(0, false, json!({"response_bytes":512})).await;
    assert_tool_error(&f.rpc("tools/list", json!({})).await);
    assert_eq!(
        f.call("fake/read", json!({})).await["result"]["isError"],
        false
    );
}

#[tokio::test]
async fn mcp_chunked_request_is_bounded() {
    let f = Fixture::configured(0, false, json!({"request_bytes":512})).await;
    let json = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake/read", "arguments":{"text":"x".repeat(513)}}});
    let stream = axum::body::Body::from(json.to_string()).into_data_stream();
    let response = f
        .request("tools/call", json!({}))
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(f.calls().is_empty());
}

#[tokio::test]
async fn mcp_bounded_transport_preserves_protocol_negotiation() {
    let f = Fixture::new(0).await;
    *f.backend.wire_mode.lock().unwrap() = "protocol".into();
    assert_eq!(
        f.call("fake/read", json!({})).await["result"]["isError"],
        false
    );
}
