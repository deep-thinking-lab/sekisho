use super::AppState;
use crate::store::AuditRecord;
use axum::{
    Extension,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParam, CallToolResult, Content, ListToolsResult, PaginatedRequestParam,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use sekisho_core::{Action, AgentId, AuditKind, DecisionKind, Principal, ToolName};
use serde_json::{Value, json};
use std::sync::Arc;

// Stateless HTTP services bind identity anew on every bearer-authenticated request.
pub(super) async fn handle(
    State(state): State<AppState>,
    Extension(agent): Extension<AgentId>,
    request: Request,
) -> Result<Response, StatusCode> {
    let gateway = state
        .mcp_gateway
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, gateway.limits.request_bytes)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    let service = StreamableHttpService::new(
        move || {
            Ok(Handler {
                state: state.clone(),
                agent: agent.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig {
            stateful_mode: false,
            ..Default::default()
        },
    );
    Ok(service.handle(request).await.into_response())
}

#[derive(Clone)]
struct Handler {
    state: AppState,
    agent: AgentId,
}
fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message)])
}
fn unavailable() -> ErrorData {
    ErrorData::internal_error("Sekisho storage unavailable", None)
}
impl ServerHandler for Handler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let gateway = self.state.mcp_gateway.clone().ok_or_else(unavailable)?;
        let checks = self.state.checks.clone().ok_or_else(unavailable)?;
        let permits = gateway
            .acquire(&self.agent)
            .await
            .map_err(|message| ErrorData::invalid_request(message, None))?;
        let clock = self.state.clock.clone();
        let agent = self.agent.clone();
        let actor = Principal::Agent(agent.clone());
        tokio::spawn(async move {
            let _permits = permits;
            let discoveries = gateway.list_tools().await;
            let mut tools = Vec::new();
            let mut skipped = 0;
            let mut failed = Vec::new();
            let mut errors = Vec::new();
            let mut successful = 0;
            for discovery in discoveries {
                match discovery.result {
                    Ok(catalog) => {
                        successful += 1;
                        skipped += catalog.skipped;
                        for tool in catalog.tools {
                            let name = ToolName::try_from(format!("mcp:{}", tool.name).as_str()).map_err(|_| unavailable())?;
                            let action = Action::new(agent.clone(), name, discovery.server.clone(), json!({})).map_err(|_| unavailable())?;
                            let api = checks.clone();
                            let clock = clock.clone();
                            let decision = tokio::task::spawn_blocking(move || api.precheck(&action, clock.as_ref())).await.map_err(|_| unavailable())?.map_err(|_| unavailable())?;
                            if decision.kind != DecisionKind::Deny { tools.push(tool); }
                        }
                    }
                    Err(class) => {
                        failed.push(discovery.server.clone());
                        if !discovery.cached { errors.push((discovery.server, class)); }
                    }
                }
            }
            let result = ListToolsResult { tools, ..Default::default() };
            let bounded = gateway.check_size(&result).is_ok();
            let subject = json!({"operation":"tools/list", "outcome":if !bounded {"response_limit"} else if successful == 0 && !failed.is_empty() {"discovery_failed"} else {"listed"}, "tool_count":result.tools.len(), "skipped_tools":skipped, "failed_servers":failed});
            audit(&gateway, &checks, clock, actor, subject, errors).await?;
            if !bounded { return Err(ErrorData::internal_error("Sekisho discovery response limit exceeded", None)); }
            if successful == 0 && !failed.is_empty() {
                return Err(ErrorData::internal_error("Sekisho upstream tool discovery failed", None));
            }
            Ok(result)
        }).await.map_err(|_| unavailable())?
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let gateway = self.state.mcp_gateway.clone().ok_or_else(unavailable)?;
        let checks = self.state.checks.clone().ok_or_else(unavailable)?;
        let permits = match gateway.acquire(&self.agent).await {
            Ok(permits) => permits,
            Err(message) => return Ok(tool_error(message)),
        };
        let Some((server, tool)) = request.name.split_once('/') else {
            return Ok(tool_error("Expected <server>/<tool>"));
        };
        if !gateway.has_server(server) || tool.is_empty() || tool.contains('/') {
            return Ok(tool_error("Unknown upstream tool"));
        }
        let Ok(name) = ToolName::try_from(format!("mcp:{server}/{tool}").as_str()) else {
            return Ok(tool_error("Invalid upstream tool name"));
        };
        let params = Value::Object(request.arguments.get_or_insert_default().clone());
        let action = match Action::new(self.agent.clone(), name, server.to_owned(), params) {
            Ok(action) => action,
            Err(_) => {
                return Ok(tool_error(
                    "Invalid tool arguments: integers must be within the safe JSON range",
                ));
            }
        };
        let digest = action.digest().map_err(|_| unavailable())?;
        let decision = checks
            .clone()
            .authorize_action(action, gateway.wait_seconds, self.state.clock.clone())
            .await
            .map_err(|_| unavailable())?;
        if decision.decision != "allow" {
            let mut message = format!(
                "Sekisho {}: {}",
                decision.decision,
                decision.reason.as_deref().unwrap_or("refused")
            );
            if let Some(rule) = decision.rule {
                message.push_str(&format!("; rule: {rule}"));
            }
            if let Some(id) = decision.approval_id {
                message.push_str(&format!(
                    "; approval: {id}, {}",
                    self.state.approval_url(&id)
                ));
            }
            return Ok(tool_error(message));
        }
        let server = server.to_owned();
        request.name = tool.to_owned().into();
        let actor = Principal::Agent(self.agent.clone());
        let clock = self.state.clock.clone();
        // Finish and audit execution even if the requesting agent disconnects.
        tokio::spawn(async move {
            let _permits = permits;
            let result = gateway.call(&server, request).await;
            let failed = result.as_ref().map_or(true, |result| result.is_error == Some(true));
            let class = result.as_ref().err().copied().unwrap_or("tool_error");
            let subject = json!({"operation":"tools/call", "server":server, "action_digest":digest, "outcome":if failed {"failed"} else {"forwarded"}});
            let failures = if failed { vec![(server, class)] } else { vec![] };
            audit(&gateway, &checks, clock, actor, subject, failures).await?;
            Ok(result.unwrap_or_else(|class| tool_error(format!("Sekisho upstream failed: {class}"))))
        }).await.map_err(|_| unavailable())?
    }
}

async fn audit(
    gateway: &crate::mcp::Gateway,
    checks: &Arc<super::CheckApi>,
    clock: Arc<dyn super::Clock>,
    actor: Principal,
    subject: Value,
    failures: Vec<(String, &'static str)>,
) -> Result<(), ErrorData> {
    let mut windows = gateway.failures.lock().await;
    let mut next = windows.clone();
    let mut records = vec![AuditRecord {
        kind: AuditKind::Decided,
        actor: actor.clone(),
        subject: subject.clone(),
    }];
    for (server, class) in failures {
        let window = next.entry(server.clone()).or_default();
        if let Some(count) = window.record() {
            let mut failure = subject.clone();
            failure["server"] = json!(server);
            failure["outcome"] = json!("upstream_failed");
            failure["error_class"] = json!(class);
            failure["count"] = json!(count);
            records.push(AuditRecord {
                kind: AuditKind::Decided,
                actor: actor.clone(),
                subject: failure,
            });
        }
    }
    let store = checks.store.clone();
    tokio::task::spawn_blocking(move || store.transact(clock.now(), |_| Ok(((), records))))
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?;
    *windows = next;
    Ok(())
}
