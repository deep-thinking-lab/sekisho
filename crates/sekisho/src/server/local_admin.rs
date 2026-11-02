use super::{AppState, CheckError};
use argon2::password_hash::Output;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use sekisho_core::{ApprovalId, Principal, UserId};
use sha2::{Digest as _, Sha256};
use std::{path::PathBuf, sync::Mutex};

pub(super) struct LocalAdmin {
    token_hash: [u8; 32],
    policy_path: PathBuf,
    actor: Principal,
    /// Separate from the web login limiter, so a token holder guessing codes
    /// cannot lock the admin out of the browser.
    attempts: Mutex<super::auth::Attempts>,
}

impl LocalAdmin {
    pub(super) fn new(token: &str, policy_path: PathBuf, actor: Principal) -> Self {
        Self {
            token_hash: Sha256::digest(token.as_bytes()).into(),
            policy_path,
            actor,
            attempts: Mutex::new(super::auth::Attempts::default()),
        }
    }

    pub(super) fn authenticates(&self, token: &str) -> bool {
        let presented = Sha256::digest(token.as_bytes());
        // password_hash::Output uses a constant-time equality implementation.
        match (Output::new(&self.token_hash), Output::new(&presented)) {
            (Ok(stored), Ok(presented)) => stored == presented,
            _ => false,
        }
    }
}

/// Every local admin route that changes state needs the bootstrap admin's TOTP
/// code as well as the local admin token. The token is a file in the Sekisho
/// home, which an agent running as the same OS user can read; the code is not.
/// The code's step is consumed in the same transaction as the change.
pub(super) async fn reload(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let unavailable = (StatusCode::SERVICE_UNAVAILABLE, "policy reload unavailable");
    let (admin, user, step) = verify_totp(&state, &body)
        .await
        .map_err(|status| (status, "a valid, unused TOTP code is required"))?;
    let api = state.checks.clone().ok_or(unavailable)?;
    let actor = user.clone();
    let limiter = admin.clone();
    tokio::task::spawn_blocking(move || {
        api.reload_policy_with_totp(
            &admin.policy_path,
            &admin.actor,
            state.clock.now(),
            Some((&user, step)),
        )
    })
    .await
    .map_err(|_| unavailable)?
    .map_err(|error| match error {
        CheckError::Policy(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid policy"),
        CheckError::Io(_) => (StatusCode::UNPROCESSABLE_ENTITY, "policy file refused"),
        CheckError::Store(crate::store::StoreError::TotpReplay) => (
            StatusCode::UNAUTHORIZED,
            "a valid, unused TOTP code is required",
        ),
        _ => unavailable,
    })?;
    accepted(&limiter, &actor).map_err(|status| (status, "policy reloaded"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpBody {
    totp: String,
}

/// Check the code against the bootstrap admin's secret without consuming it.
/// Every call counts as an attempt until the change that consumes the step
/// succeeds. Attempts are limited separately from the web login, so a token
/// holder guessing codes cannot lock the admin out of the browser.
async fn verify_totp(
    state: &AppState,
    body: &[u8],
) -> Result<(std::sync::Arc<LocalAdmin>, UserId, u64), StatusCode> {
    let admin = state
        .local_admin
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let Principal::User(actor) = admin.actor.clone() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let code = serde_json::from_slice::<TotpBody>(body)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .totp;
    let now = state.clock.now();
    if !admin
        .attempts
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .reserve(Some(actor.clone()), now)
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let users = state.users.clone();
    let user = actor.clone();
    let step = tokio::task::spawn_blocking(move || {
        Ok::<_, super::AuthStoreError>(
            users
                .find(&user)?
                .and_then(|u| u.totp_secret)
                .and_then(|secret| super::auth::totp_step(&secret, &code, now)),
        )
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok((admin, actor, step))
}

/// Reset the attempt limiter only after a change consumed the step. A valid
/// but already used code stays a failed attempt.
fn accepted(admin: &LocalAdmin, actor: &UserId) -> Result<(), StatusCode> {
    admin
        .attempts
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .accept(actor);
    Ok(())
}

#[derive(serde::Serialize)]
pub(super) struct ApprovalSummary {
    id: String,
    agent_id: String,
    tool: String,
    target: String,
    rule: String,
    expires_at: i64,
}

pub(super) async fn list_approvals(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApprovalSummary>>, StatusCode> {
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let now = state.clock.now();
    let approvals = tokio::task::spawn_blocking(move || api.store().pending_approvals(now))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        approvals
            .into_iter()
            .map(|approval| ApprovalSummary {
                id: approval.id().as_str().to_owned(),
                agent_id: approval.action().agent_id().to_string(),
                tool: approval.action().tool().to_string(),
                target: approval.action().target().to_owned(),
                rule: approval.rule().to_owned(),
                expires_at: approval.expires_at().as_secs(),
            })
            .collect(),
    ))
}

pub(super) async fn approve(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<StatusCode, StatusCode> {
    resolve(state, id, true, &body).await
}

pub(super) async fn deny(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<StatusCode, StatusCode> {
    resolve(state, id, false, &body).await
}

async fn resolve(
    state: AppState,
    id: String,
    approve: bool,
    body: &[u8],
) -> Result<StatusCode, StatusCode> {
    let id = ApprovalId::try_from(id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let (admin, actor, step) = verify_totp(&state, body).await?;
    super::approvals::transition_with_totp(state, actor.clone(), id, approve, step).await?;
    accepted(&admin, &actor)?;
    Ok(StatusCode::NO_CONTENT)
}
