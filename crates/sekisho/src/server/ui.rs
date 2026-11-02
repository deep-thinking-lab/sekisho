use super::{AppState, Session, auth, csrf, roles::CanApprove, session::random_token};
use askama::Template;
use axum::{
    Extension,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{Html, IntoResponse, Response},
};
use sekisho_core::{Approval, ApprovalId, ApprovalState, Timestamp};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    csrf_token: String,
    error: String,
}

#[derive(Template)]
#[template(path = "inbox.html")]
struct InboxTemplate {
    user: String,
    rows: Vec<InboxRow>,
}

struct InboxRow {
    id: String,
    agent: String,
    tool: String,
    target: String,
    rule: String,
    time_left: String,
}

#[derive(Template)]
#[template(path = "approval.html")]
struct ApprovalTemplate {
    user: String,
    id: String,
    agent: String,
    tool: String,
    target: String,
    params: String,
    digest: String,
    rule: String,
    state: String,
    time_left: String,
    csrf_token: String,
    show_forms: bool,
    flash: String,
}

pub(super) fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().starts_with("text/html"))
        })
}

pub(super) fn render(template: impl Template) -> Result<Response, StatusCode> {
    let body = template
        .render()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut response = Html(body).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(super) async fn login_page(State(state): State<AppState>) -> Result<Response, StatusCode> {
    let token = random_token().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut response = render(LoginTemplate {
        csrf_token: token.clone(),
        error: String::new(),
    })?;
    auth::add_cookie(
        &mut response,
        csrf::set_cookie("sekisho_prelogin", &token, "/login", 600, state.loopback),
    )?;
    Ok(response)
}

pub(super) fn login_error(csrf_token: &str) -> Result<Response, StatusCode> {
    let mut response = render(LoginTemplate {
        csrf_token: csrf_token.to_owned(),
        error: "The user ID, password, or verification code was not accepted.".to_owned(),
    })?;
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    Ok(response)
}

pub(super) async fn inbox(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Response, StatusCode> {
    let now = state.clock.now();
    let approvals = if let Some(api) = state.checks.clone() {
        let store = api.store.clone();
        tokio::task::spawn_blocking(move || store.pending_approvals(now))
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    } else {
        Vec::new()
    };
    let rows = approvals
        .into_iter()
        .map(|approval| inbox_row(&approval, now))
        .collect();
    render(InboxTemplate {
        user: session.user.to_string(),
        rows,
    })
}

pub(super) async fn detail(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Extension(can_approve): Extension<CanApprove>,
    Path(raw_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let id = ApprovalId::try_from(raw_id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let lookup = id.clone();
    let store = api.store.clone();
    let approval = tokio::task::spawn_blocking(move || store.approval(&lookup))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let now = state.clock.now();
    let params = serde_json::to_string_pretty(approval.action().params())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let flash_cookie = csrf::cookie(&headers, "sekisho_flash").map(str::to_owned);
    let flash = flash_message(flash_cookie.as_deref(), &approval, &session);
    let mut response = render(ApprovalTemplate {
        user: session.user.to_string(),
        id: id.as_str().to_owned(),
        agent: approval.action().agent_id().to_string(),
        tool: approval.action().tool().to_string(),
        target: approval.action().target().to_owned(),
        params,
        digest: approval.action_digest().to_string(),
        rule: approval.rule().to_owned(),
        state: display_state(&approval, now).to_owned(),
        time_left: time_left(approval.expires_at(), now),
        csrf_token: session.csrf_token.clone(),
        show_forms: can_approve.0
            && approval.state() == ApprovalState::Pending
            && now < approval.expires_at(),
        flash: flash.unwrap_or_default().to_owned(),
    })?;
    if flash_cookie.is_some() {
        auth::add_cookie(
            &mut response,
            csrf::set_cookie(
                "sekisho_flash",
                "",
                &format!("/approvals/{}", id.as_str()),
                0,
                state.loopback,
            ),
        )?;
    }
    Ok(response)
}

pub(super) async fn htmx() -> Result<Response, StatusCode> {
    let mut response = Response::new(Body::from(
        include_bytes!("../../static/htmx.min.js").as_slice(),
    ));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000"),
    );
    Ok(response)
}

fn inbox_row(approval: &Approval, now: Timestamp) -> InboxRow {
    InboxRow {
        id: approval.id().as_str().to_owned(),
        agent: approval.action().agent_id().to_string(),
        tool: approval.action().tool().to_string(),
        target: approval.action().target().to_owned(),
        rule: approval.rule().to_owned(),
        time_left: time_left(approval.expires_at(), now),
    }
}

fn flash_message(
    cookie: Option<&str>,
    approval: &Approval,
    session: &Session,
) -> Option<&'static str> {
    if approval.decided_by() != Some(&session.user) {
        return None;
    }
    match (cookie, approval.state()) {
        (Some("approved"), ApprovalState::Approved | ApprovalState::Consumed) => {
            Some("Approval recorded.")
        }
        (Some("denied"), ApprovalState::Denied) => Some("Denial recorded."),
        _ => None,
    }
}

fn display_state(approval: &Approval, now: Timestamp) -> &'static str {
    match approval.state() {
        ApprovalState::Pending if now >= approval.expires_at() => "Expired",
        ApprovalState::Pending => "Pending",
        ApprovalState::Approved => "Approved",
        ApprovalState::Denied => "Denied",
        ApprovalState::Expired => "Expired",
        ApprovalState::Consumed => "Consumed",
    }
}

fn time_left(expires_at: Timestamp, now: Timestamp) -> String {
    let seconds = expires_at.as_secs().saturating_sub(now.as_secs());
    match seconds {
        0 => "Expired".to_owned(),
        1 => "1 second left".to_owned(),
        2..=59 => format!("{seconds} seconds left"),
        60..=119 => "1 minute left".to_owned(),
        _ => {
            let minutes = seconds.saturating_add(59) / 60;
            format!("{minutes} minutes left")
        }
    }
}
