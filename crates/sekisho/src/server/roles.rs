use super::{
    AppState, Session, SessionToken, csrf,
    routes::{Access, Handler, ROUTES},
};
use axum::{
    extract::{FromRequest, MatchedPath, Request, State},
    http::{StatusCode, header::LOCATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Role {
    Admin,
    Approver,
    Viewer,
}

#[derive(Clone, Copy)]
pub(super) struct CanApprove(pub(super) bool);

#[derive(Clone, Copy)]
pub(super) struct CanAdmin(pub(super) bool);

impl Role {
    pub fn satisfies(self, required: Self) -> bool {
        self <= required
    }
}

pub(super) async fn authorize(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(path) = request.extensions().get::<MatchedPath>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(spec) = ROUTES.iter().find(|r| {
        r.path == path.as_str()
            && (r.method == "*"
                || r.method == request.method().as_str()
                || (r.method == "GET" && request.method() == "HEAD"))
    }) else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    if matches!(spec.access, Access::Integration) {
        if request.headers().contains_key("cookie")
            || request.headers().contains_key("authorization")
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        return next.run(request).await;
    }
    if matches!(spec.access, Access::LocalAdmin) {
        let Some(admin) = state.local_admin.as_ref().filter(|_| state.loopback) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if request.headers().contains_key("cookie") {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let token = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if !token.is_some_and(|token| admin.authenticates(token)) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        return next.run(request).await;
    }
    if matches!(spec.access, Access::Agent | Access::GitAgent) {
        let basic = if matches!(spec.access, Access::GitAgent) {
            crate::git::proxy::basic_token(request.headers())
        } else {
            None
        };
        let Some(token) = basic.as_deref().or_else(|| {
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .filter(|v| !v.is_empty())
                .filter(|_| matches!(spec.access, Access::Agent))
        }) else {
            return if matches!(spec.access, Access::GitAgent) {
                (
                    StatusCode::UNAUTHORIZED,
                    [("www-authenticate", "Basic realm=\"Sekisho\"")],
                )
                    .into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            };
        };
        if csrf::cookie(request.headers(), "sekisho_session").is_some() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        match state.agents.resolve_token(token) {
            Ok(Some(agent)) => {
                request.extensions_mut().insert(agent);
            }
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
        return next.run(request).await;
    }
    let needs_session =
        matches!(spec.access, Access::Human(_)) || request.uri().path() == "/logout";
    if needs_session {
        let Some(raw) = csrf::cookie(request.headers(), "sekisho_session") else {
            if redirects_to_login(spec, &request) {
                return (StatusCode::SEE_OTHER, [(LOCATION, "/login")]).into_response();
            }
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let token = SessionToken::from_cookie(raw);
        let session = match state.sessions.get(&token, state.clock.now()) {
            Ok(Some(s)) => s,
            Ok(None) if redirects_to_login(spec, &request) => {
                return (StatusCode::SEE_OTHER, [(LOCATION, "/login")]).into_response();
            }
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        if let Access::Human(role) = spec.access {
            let user = match state.users.find(&session.user) {
                Ok(Some(u)) => u,
                Ok(None) if redirects_to_login(spec, &request) => {
                    return (StatusCode::SEE_OTHER, [(LOCATION, "/login")]).into_response();
                }
                Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            if !user.roles.iter().any(|actual| actual.satisfies(role)) {
                return StatusCode::FORBIDDEN.into_response();
            }
            request.extensions_mut().insert(CanApprove(
                user.roles
                    .iter()
                    .any(|actual| actual.satisfies(Role::Approver)),
            ));
            request.extensions_mut().insert(CanAdmin(
                user.roles.iter().any(|actual| *actual == Role::Admin),
            ));
        }
        if !matches!(request.method().as_str(), "GET" | "HEAD" | "OPTIONS") {
            let header = request
                .headers()
                .get("X-CSRF-Token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let supplied = if let Some(header) = header {
                header
            } else {
                if !request
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
                {
                    return StatusCode::FORBIDDEN.into_response();
                }
                let (parts, body) = request.into_parts();
                let Ok(bytes) = axum::body::to_bytes(body, 16384).await else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                let mut form_request = Request::new(axum::body::Body::from(bytes.clone()));
                *form_request.method_mut() = axum::http::Method::POST;
                form_request.headers_mut().insert(
                    "content-type",
                    axum::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
                let form =
                    axum::Form::<super::auth::CsrfForm>::from_request(form_request, &()).await;
                request = Request::from_parts(parts, axum::body::Body::from(bytes));
                match form {
                    Ok(form) => form.0.csrf_token,
                    Err(_) => return StatusCode::FORBIDDEN.into_response(),
                }
            };
            if !csrf::matches(&session.csrf_token, &supplied) {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        request.extensions_mut().insert(token);
        request.extensions_mut().insert::<Session>(session);
    }
    next.run(request).await
}

fn redirects_to_login(spec: &super::routes::RouteSpec, request: &Request) -> bool {
    matches!(
        spec.handler,
        Handler::Home
            | Handler::Approval
            | Handler::AuditPage
            | Handler::AgentsPage
            | Handler::GrantsPage
            | Handler::PolicyPage
    ) && matches!(request.method().as_str(), "GET" | "HEAD")
        && super::ui::wants_html(request.headers())
}
