mod agents;
mod approvals;
mod check;
pub use check::{CheckApi, CheckError};
mod auth;
mod csrf;
mod git;
mod local_admin;
mod mcp;
mod pages;
mod roles;
pub mod routes;
pub(crate) mod session;
mod slack;
mod ui;
pub use agents::{AgentDirectory, InMemoryAgents};
pub use auth::{InMemoryUsers, User, UserDirectory};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{any, get, post},
};
pub use roles::Role;
use sekisho_core::Timestamp;
pub use session::{AuthStoreError, InMemorySessions, Session, SessionStore, SessionToken};
use std::sync::{Arc, Mutex};
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        time::OffsetDateTime::now_utc().unix_timestamp().into()
    }
}
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<dyn UserDirectory>,
    pub sessions: Arc<dyn SessionStore>,
    pub agents: Arc<dyn AgentDirectory>,
    pub clock: Arc<dyn Clock>,
    checks: Option<Arc<CheckApi>>,
    git_proxy: Option<Arc<crate::git::proxy::GitProxy>>,
    mcp_gateway: Option<Arc<crate::mcp::Gateway>>,
    local_admin: Option<Arc<local_admin::LocalAdmin>>,
    slack_integrations: Vec<Arc<crate::notifications::slack::SlackIntegration>>,
    loopback: bool,
    public_url: String,
    attempts: Arc<Mutex<auth::Attempts>>,
    dummy_hash: Arc<String>,
    password_slots: Arc<tokio::sync::Semaphore>,
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
}
impl AppState {
    /// `loopback` must come from the bound address, never a request header.
    pub fn new(
        users: Arc<dyn UserDirectory>,
        sessions: Arc<dyn SessionStore>,
        clock: Arc<dyn Clock>,
        loopback: bool,
    ) -> Result<Self, AuthStoreError> {
        Self::new_with_agents(
            users,
            sessions,
            Arc::new(InMemoryAgents::default()),
            clock,
            loopback,
        )
    }

    pub fn new_with_agents(
        users: Arc<dyn UserDirectory>,
        sessions: Arc<dyn SessionStore>,
        agents: Arc<dyn AgentDirectory>,
        clock: Arc<dyn Clock>,
        loopback: bool,
    ) -> Result<Self, AuthStoreError> {
        Ok(Self {
            users,
            sessions,
            agents,
            clock,
            loopback,
            checks: None,
            git_proxy: None,
            mcp_gateway: None,
            local_admin: None,
            slack_integrations: Vec::new(),
            public_url: "http://127.0.0.1:7470".to_owned(),
            attempts: Arc::new(Mutex::new(auth::Attempts::default())),
            dummy_hash: Arc::new(auth::dummy_hash()?),
            password_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            trusted_proxies: Arc::new(Vec::new()),
        })
    }
    pub fn with_slack_integrations(
        mut self,
        integrations: Vec<Arc<crate::notifications::slack::SlackIntegration>>,
    ) -> Self {
        self.slack_integrations = integrations;
        self
    }
    pub fn with_git_proxy(mut self, proxy: Arc<crate::git::proxy::GitProxy>) -> Self {
        self.git_proxy = Some(proxy);
        self
    }
    pub fn with_mcp_gateway(mut self, gateway: Arc<crate::mcp::Gateway>) -> Self {
        self.mcp_gateway = Some(gateway);
        self
    }
    pub fn with_check_api(mut self, checks: Arc<CheckApi>) -> Self {
        self.checks = Some(checks);
        self
    }
    /// Reverse proxies whose `X-Forwarded-For` names the client for login throttling.
    pub fn with_trusted_proxies(mut self, proxies: Vec<std::net::IpAddr>) -> Self {
        self.trusted_proxies = Arc::new(proxies);
        self
    }
    pub fn with_public_url(mut self, public_url: impl Into<String>) -> Self {
        self.public_url = public_url.into();
        self
    }
    pub(crate) fn approval_url(&self, id: &str) -> String {
        approval_url(&self.public_url, id)
    }
    pub fn with_local_admin(
        mut self,
        token: &str,
        policy_path: std::path::PathBuf,
        actor: sekisho_core::Principal,
    ) -> Self {
        if self.loopback {
            self.local_admin = Some(Arc::new(local_admin::LocalAdmin::new(
                token,
                policy_path,
                actor,
            )));
        }
        self
    }
}

pub(crate) fn approval_url(public_url: &str, id: &str) -> String {
    format!("{public_url}/approvals/{id}")
}
pub fn router(state: AppState) -> Router {
    let mcp_limit = state
        .mcp_gateway
        .as_ref()
        .map_or(1024 * 1024, |gateway| gateway.limits.request_bytes);
    protect(registered_routes(mcp_limit), state)
}
fn registered_routes(mcp_limit: usize) -> Router<AppState> {
    use routes::Handler;
    let mut router = Router::new();
    for spec in routes::ROUTES {
        let handler = match spec.handler {
            Handler::SlackActions => post(slack::actions).layer(DefaultBodyLimit::max(65536)),
            Handler::Health => get(|| async { "ok" }),
            Handler::LoginForm => get(ui::login_page),
            Handler::Login => post(auth::login).layer(DefaultBodyLimit::max(4096)),
            Handler::Logout => post(auth::logout),
            Handler::Static => get(ui::htmx),
            Handler::Git => any(git::proxy),
            Handler::Check => post(check::check),
            Handler::Mcp => any(mcp::handle)
                .layer::<_, std::convert::Infallible>(DefaultBodyLimit::disable())
                .layer(tower_http::limit::RequestBodyLimitLayer::new(mcp_limit)),
            Handler::ReloadPolicy => post(local_admin::reload),
            Handler::ListApprovals => get(local_admin::list_approvals),
            Handler::AdminApprove => post(local_admin::approve),
            Handler::AdminDeny => post(local_admin::deny),
            Handler::Approve => post(approvals::approve),
            Handler::Deny => post(approvals::deny),
            Handler::Home => get(ui::inbox),
            Handler::Approval => get(ui::detail),
            Handler::AuditPage => get(pages::audit),
            Handler::AuditExport => get(pages::audit_export),
            Handler::AuditEntry => get(pages::audit_entry),
            Handler::AgentsPage => get(pages::agents),
            Handler::AddAgent => post(pages::add_agent),
            Handler::RotateAgent => post(pages::rotate_agent),
            Handler::RemoveAgent => post(pages::remove_agent),
            Handler::GrantsPage => get(pages::grants),
            Handler::IssueGrant => post(pages::issue_grant),
            Handler::RevokeGrant => post(pages::revoke_grant),
            Handler::PolicyPage => get(pages::policy),
            Handler::Stub => {
                if spec.method == "GET" {
                    get(|| async { StatusCode::NOT_IMPLEMENTED })
                } else if spec.method == "POST" {
                    post(|| async { StatusCode::NOT_IMPLEMENTED })
                } else {
                    any(|| async { StatusCode::NOT_IMPLEMENTED })
                }
            }
        };
        router = router.route(spec.path, handler);
    }
    router
}
fn protect(router: Router<AppState>, state: AppState) -> Router {
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            roles::authorize,
        ))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{Extension, Json, http::HeaderMap, routing::post};
    use base64::Engine as _;
    use sekisho_core::AgentId;

    #[tokio::test]
    async fn agent_id_comes_from_token() {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
        let agents = Arc::new(InMemoryAgents::default());
        agents
            .insert(AgentId::try_from("claude").unwrap(), &token)
            .unwrap();
        let state = AppState::new_with_agents(
            Arc::new(InMemoryUsers::default()),
            Arc::new(InMemorySessions::default()),
            agents,
            Arc::new(SystemClock),
            true,
        )
        .unwrap();
        let app = protect(
            Router::new().route(
                "/v1/{*path}",
                post(
                    |Extension(agent): Extension<AgentId>,
                     headers: HeaderMap,
                     Json(body): Json<serde_json::Value>| async move {
                        format!(
                            "{}:{}:{}",
                            agent,
                            headers["x-agent-id"].to_str().unwrap_or(""),
                            body["agent_id"].as_str().unwrap_or("")
                        )
                    },
                ),
            ),
            state,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let response = reqwest::Client::new()
            .post(format!("http://{address}/v1/check"))
            .bearer_auth(&token)
            .header("x-agent-id", "mallory")
            .json(&serde_json::json!({"agent_id":"mallory"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.unwrap(),
            "claude:mallory:mallory".to_owned()
        );
        task.abort();
    }

    #[tokio::test]
    async fn every_route_has_a_role() {
        let state = AppState::new(
            Arc::new(InMemoryUsers::default()),
            Arc::new(InMemorySessions::default()),
            Arc::new(SystemClock),
            true,
        )
        .unwrap();
        fn registered_paths(app: &Router) -> std::collections::BTreeSet<String> {
            let debug = format!("{app:?}");
            debug
                .split(", fallback_router:")
                .next()
                .unwrap()
                .split('"')
                .skip(1)
                .step_by(2)
                .filter(|s| s.starts_with('/'))
                .map(str::to_owned)
                .collect()
        }
        let declared = routes::ROUTES
            .iter()
            .map(|spec| spec.path.to_owned())
            .collect();
        assert_eq!(registered_paths(&router(state.clone())), declared);
        let app = protect(
            registered_routes(1024 * 1024).route("/__unclassified", get(|| async { "unexpected" })),
            state,
        );
        assert_ne!(registered_paths(&app), declared);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let response = reqwest::get(format!("http://{address}/__unclassified"))
            .await
            .unwrap();
        task.abort();
        assert_eq!(response.status(), 405);
    }
    #[tokio::test]
    async fn password_verification_is_bounded() {
        let state = AppState::new(
            Arc::new(InMemoryUsers::default()),
            Arc::new(InMemorySessions::default()),
            Arc::new(SystemClock),
            true,
        )
        .unwrap();
        let slots = state.password_slots.clone();
        assert_eq!(slots.available_permits(), 4);
        let held = slots.acquire_many(4).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{address}/login"))
            .send()
            .await
            .unwrap();
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let request = || {
            client
                .post(format!("http://{address}/login"))
                .header("cookie", &cookie)
                .form(&[
                    ("user_id", "unknown"),
                    ("password", "wrong"),
                    ("csrf_token", cookie.split('=').nth(1).unwrap()),
                ])
        };
        let started = std::time::Instant::now();
        let response = request().send().await.unwrap();
        assert_eq!(response.status(), 429);
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(started.elapsed() >= std::time::Duration::from_secs(2));
        drop(held);
        assert_eq!(request().send().await.unwrap().status(), 401);
        task.abort();
    }
}
