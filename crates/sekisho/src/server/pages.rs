use super::{AppState, Session, roles::CanAdmin, ui};
use askama::Template;
use axum::{
    Extension, Form, Json,
    body::Body,
    extract::{Path, Query, State},
    http::{
        HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, LOCATION},
    },
    response::{IntoResponse, Response},
};
use rand_core::{OsRng, RngCore};
use sekisho_core::{
    AgentId, AuditEntry, AuditKind, CoreError, Grant, GrantId, Principal, Timestamp, ToolName,
    UnsignedGrant,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

const AUDIT_PAGE_SIZE: u32 = 20;

#[derive(Default, Deserialize)]
pub(super) struct AuditQuery {
    page: Option<u64>,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTemplate {
    user: String,
    rows: Vec<AuditRow>,
    has_checkpoint: bool,
    checkpoint_seq: u64,
    checkpoint_hash: String,
    checkpoint_at: i64,
    page: u64,
    previous: u64,
    has_previous: bool,
    next: u64,
    has_next: bool,
}

struct AuditRow {
    seq: u64,
    kind: String,
    actor: String,
    summary: String,
    at: i64,
}

#[derive(Template)]
#[template(path = "agents.html")]
struct AgentsTemplate {
    user: String,
    rows: Vec<AgentRow>,
    can_admin: bool,
    csrf_token: String,
    show_issued: bool,
    issued_id: String,
    issued_token: String,
}

struct AgentRow {
    id: String,
}

#[derive(Deserialize)]
pub(super) struct AddAgentForm {
    agent_id: String,
}

#[derive(Template)]
#[template(path = "grants.html")]
struct GrantsTemplate {
    user: String,
    rows: Vec<GrantRow>,
    can_admin: bool,
    csrf_token: String,
}

struct GrantRow {
    id: String,
    agent: String,
    tool: String,
    target_glob: String,
    params: String,
    uses: String,
    expires_at: i64,
    status: String,
}

#[derive(Deserialize)]
pub(super) struct IssueGrantForm {
    agent_id: String,
    tool: String,
    target_glob: String,
    params: String,
    expires_in: String,
    #[serde(default)]
    max_uses: String,
}

#[derive(Template)]
#[template(path = "policy.html")]
struct PolicyTemplate {
    user: String,
    path: String,
    text: String,
    sha256: String,
    loaded_at: String,
}

pub(super) async fn audit(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Query(query): Query<AuditQuery>,
) -> Result<Response, StatusCode> {
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let page = query.page.unwrap_or(1).max(1);
    let store = api.store();
    let (entries, total, checkpoint) = tokio::task::spawn_blocking(move || {
        let (entries, total) = store.audit_page(page, AUDIT_PAGE_SIZE)?;
        let checkpoint = store.audit_checkpoint()?;
        Ok::<_, crate::store::StoreError>((entries, total, checkpoint))
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let rows = entries
        .iter()
        .map(audit_row)
        .collect::<Result<Vec<_>, _>>()?;
    let (checkpoint_seq, checkpoint_hash, checkpoint_at, has_checkpoint) = checkpoint
        .as_ref()
        .map_or((0, String::new(), 0, false), |checkpoint| {
            (
                checkpoint.seq,
                checkpoint.entry_hash.to_string(),
                checkpoint.at.as_secs(),
                true,
            )
        });
    let next = u64::from(AUDIT_PAGE_SIZE)
        .checked_mul(page)
        .is_some_and(|seen| seen < total);
    ui::render(AuditTemplate {
        user: session.user.to_string(),
        rows,
        has_checkpoint,
        checkpoint_seq,
        checkpoint_hash,
        checkpoint_at,
        page,
        previous: page.saturating_sub(1),
        has_previous: page > 1,
        next: page.saturating_add(1),
        has_next: next,
    })
}

pub(super) async fn audit_entry(
    State(state): State<AppState>,
    Path(raw_seq): Path<String>,
) -> Result<Response, StatusCode> {
    let seq = raw_seq
        .parse::<u64>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let entry = tokio::task::spawn_blocking(move || store.audit_entry(seq))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut response = Json(entry).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(super) async fn audit_export(State(state): State<AppState>) -> Result<Response, StatusCode> {
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let at = state.clock.now();
    let body = tokio::task::spawn_blocking(move || {
        let export = store.audit_export(at, 0)?;
        export.jsonl()
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"sekisho-audit.jsonl\""),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(super) async fn agents(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Extension(can_admin): Extension<CanAdmin>,
) -> Result<Response, StatusCode> {
    let template = agents_template(&state, &session, can_admin.0, None).await?;
    ui::render(template)
}

pub(super) async fn add_agent(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Form(form): Form<AddAgentForm>,
) -> Result<Response, StatusCode> {
    let id = AgentId::try_from(form.agent_id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let actor = session.user.clone();
    let now = state.clock.now();
    let token = tokio::task::spawn_blocking(move || store.add_agent(&id, &actor, now))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(store_error)?;
    let id = form.agent_id;
    let issued = Some((id, token.expose().to_owned()));
    let template = agents_template(&state, &session, true, issued).await?;
    ui::render(template)
}

pub(super) async fn rotate_agent(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(raw_id): Path<String>,
) -> Result<Response, StatusCode> {
    let id = AgentId::try_from(raw_id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let actor = session.user.clone();
    let now = state.clock.now();
    let token = tokio::task::spawn_blocking(move || store.rotate_agent(&id, &actor, now))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(store_error)?;
    let template = agents_template(
        &state,
        &session,
        true,
        Some((raw_id, token.expose().to_owned())),
    )
    .await?;
    ui::render(template)
}

pub(super) async fn remove_agent(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(raw_id): Path<String>,
) -> Result<Response, StatusCode> {
    let id = AgentId::try_from(raw_id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let actor = session.user.clone();
    let now = state.clock.now();
    tokio::task::spawn_blocking(move || store.remove_agent(&id, &actor, now))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(store_error)?;
    Ok(redirect("/agents"))
}

pub(super) async fn grants(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Extension(can_admin): Extension<CanAdmin>,
) -> Result<Response, StatusCode> {
    let template = grants_template(&state, &session, can_admin.0).await?;
    ui::render(template)
}

pub(super) async fn issue_grant(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Form(form): Form<IssueGrantForm>,
) -> Result<Response, StatusCode> {
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let signer = api.grant_signer().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let agent_id =
        AgentId::try_from(form.agent_id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let tool = ToolName::try_from(form.tool.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let params = parse_params(&form.params)?;
    let now = state.clock.now();
    let expires_at = now
        .as_secs()
        .checked_add(parse_duration(&form.expires_in)?)
        .ok_or(StatusCode::BAD_REQUEST)?
        .into();
    let max_uses = parse_max_uses(&form.max_uses)?;
    let grant: Grant = UnsignedGrant {
        id: random_grant_id()?,
        agent_id,
        tool,
        target_glob: form.target_glob,
        params,
        not_before: now,
        expires_at,
        max_uses,
        issued_by: session.user.clone(),
    }
    .sign(signer.as_ref())
    .map_err(core_error)?;
    let store = api.store();
    tokio::task::spawn_blocking(move || store.issue_grant(&grant, now))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(store_error)?;
    Ok(redirect("/grants"))
}

pub(super) async fn revoke_grant(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(raw_id): Path<String>,
) -> Result<Response, StatusCode> {
    let id = GrantId::try_from(raw_id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let actor = session.user.clone();
    let now = state.clock.now();
    tokio::task::spawn_blocking(move || store.revoke_grant(&id, &actor, now))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(store_error)?;
    Ok(redirect("/grants"))
}

pub(super) async fn policy(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Response, StatusCode> {
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let policy = api
        .policy_view()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    ui::render(PolicyTemplate {
        user: session.user.to_string(),
        path: policy.path.display().to_string(),
        text: escape_text(&policy.text),
        sha256: policy.sha256.to_string(),
        loaded_at: format!("Loaded at {} UTC", policy.loaded_at.as_secs()),
    })
}

async fn agents_template(
    state: &AppState,
    session: &Session,
    can_admin: bool,
    issued: Option<(String, String)>,
) -> Result<AgentsTemplate, StatusCode> {
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let agents = tokio::task::spawn_blocking(move || store.list_agents())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let (show_issued, issued_id, issued_token) = issued.map_or_else(
        || (false, String::new(), String::new()),
        |(id, token)| (true, id, token),
    );
    Ok(AgentsTemplate {
        user: session.user.to_string(),
        rows: agents
            .into_iter()
            .map(|id| AgentRow { id: id.to_string() })
            .collect(),
        can_admin,
        csrf_token: session.csrf_token.clone(),
        show_issued,
        issued_id,
        issued_token,
    })
}

async fn grants_template(
    state: &AppState,
    session: &Session,
    can_admin: bool,
) -> Result<GrantsTemplate, StatusCode> {
    let api = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let store = api.store();
    let grants = tokio::task::spawn_blocking(move || store.list_grants())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let now = state.clock.now();
    let rows = grants
        .into_iter()
        .map(|view| grant_row(view, now))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GrantsTemplate {
        user: session.user.to_string(),
        rows,
        can_admin,
        csrf_token: session.csrf_token.clone(),
    })
}

fn audit_row(entry: &AuditEntry) -> Result<AuditRow, StatusCode> {
    let summary =
        serde_json::to_string(entry.subject()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(AuditRow {
        seq: entry.seq(),
        kind: audit_kind(entry.kind()).to_owned(),
        actor: principal(entry.actor()),
        summary: truncate(summary, 240),
        at: entry.at().as_secs(),
    })
}

fn audit_kind(kind: AuditKind) -> &'static str {
    match kind {
        AuditKind::ActionRequested => "Action requested",
        AuditKind::Decided => "Decided",
        AuditKind::ApprovalRequested => "Approval requested",
        AuditKind::Approved => "Approved",
        AuditKind::Denied => "Denied",
        AuditKind::Expired => "Expired",
        AuditKind::Consumed => "Consumed",
        AuditKind::GrantIssued => "Grant issued",
        AuditKind::GrantRevoked => "Grant revoked",
        AuditKind::PolicyLoaded => "Policy loaded",
        AuditKind::UserLogin => "User login",
        AuditKind::AgentAdded => "Agent changed",
        AuditKind::KeyRotated => "Key rotated",
        AuditKind::AnchorSent => "Anchor sent",
        AuditKind::AnchorFailed => "Anchor failed",
        AuditKind::NotifySent => "Notify sent",
        AuditKind::NotifyFailed => "Notify failed",
    }
}

fn principal(principal: &Principal) -> String {
    match principal {
        Principal::User(user) => format!("User {user}"),
        Principal::Agent(agent) => format!("Agent {agent}"),
    }
}

fn truncate(mut value: String, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value;
    }
    let byte = value
        .char_indices()
        .nth(limit)
        .map_or(value.len(), |(index, _)| index);
    value.truncate(byte);
    value.push_str("...");
    value
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn grant_row(view: crate::store::GrantView, now: Timestamp) -> Result<GrantRow, StatusCode> {
    let grant = view.grant;
    let status = if view.revoked {
        "revoked"
    } else if now >= grant.expires_at() {
        "expired"
    } else if now < grant.not_before() {
        "pending"
    } else if grant.max_uses().is_some_and(|max| view.uses >= max) {
        "exhausted"
    } else {
        "active"
    };
    let uses = grant.max_uses().map_or_else(
        || format!("{} uses", view.uses),
        |max| format!("{} / {} uses", view.uses, max),
    );
    let params =
        serde_json::to_string(grant.params()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(GrantRow {
        id: grant.id().to_string(),
        agent: grant.agent_id().to_string(),
        tool: grant.tool().to_string(),
        target_glob: grant.target_glob().to_owned(),
        params,
        uses,
        expires_at: grant.expires_at().as_secs(),
        status: status.to_owned(),
    })
}

fn parse_params(text: &str) -> Result<BTreeMap<String, Value>, StatusCode> {
    if text.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let value: Value = serde_json::from_str(text).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !value.is_object() {
        return Err(StatusCode::BAD_REQUEST);
    }
    serde_json::from_value(value).map_err(|_| StatusCode::BAD_REQUEST)
}

fn parse_duration(value: &str) -> Result<i64, StatusCode> {
    let (index, unit) = value
        .char_indices()
        .next_back()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let number = &value[..index];
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    number
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|seconds| *seconds > 0)
        .ok_or(StatusCode::BAD_REQUEST)
}

fn parse_max_uses(value: &str) -> Result<Option<u32>, StatusCode> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    value
        .parse::<u32>()
        .map(Some)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

fn random_grant_id() -> Result<GrantId, StatusCode> {
    let mut bytes = [0; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut number = u128::from_be_bytes(bytes);
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut suffix = String::with_capacity(26);
    for _ in 0..26 {
        suffix.push(char::from(alphabet[(number & 31) as usize]));
        number >>= 5;
    }
    GrantId::try_from(format!("grt_{suffix}").as_str())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn core_error(error: CoreError) -> StatusCode {
    match error {
        CoreError::Signing => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn store_error(error: crate::store::StoreError) -> StatusCode {
    use crate::store::StoreError;
    match error {
        StoreError::AgentAlreadyExists => StatusCode::CONFLICT,
        StoreError::AgentNotFound | StoreError::GrantNotFound => StatusCode::NOT_FOUND,
        StoreError::InvalidAgent | StoreError::InvalidGrant | StoreError::Core(_) => {
            StatusCode::BAD_REQUEST
        }
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn redirect(location: &'static str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static(location));
    response
}
