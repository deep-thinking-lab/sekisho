use super::{AppState, Session, check::approval_record};
use axum::{
    Extension,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use sekisho_core::{ApprovalId, Principal, UserId};

pub(super) async fn approve(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    resolve(state, session, id, true, super::ui::wants_html(&headers)).await
}
pub(super) async fn deny(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    resolve(state, session, id, false, super::ui::wants_html(&headers)).await
}

async fn resolve(
    state: AppState,
    session: Session,
    id: String,
    approve: bool,
    html: bool,
) -> Result<Response, StatusCode> {
    state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let id = ApprovalId::try_from(id.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let location = html
        .then(|| {
            HeaderValue::from_str(&format!("/approvals/{}", id.as_str()))
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
        })
        .transpose()?;
    let flash_cookie = html
        .then(|| {
            super::csrf::set_cookie(
                "sekisho_flash",
                if approve { "approved" } else { "denied" },
                &format!("/approvals/{}", id.as_str()),
                30,
                state.loopback,
            )
            .parse::<HeaderValue>()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
        })
        .transpose()?;
    transition(state, session.user, id.clone(), approve).await?;
    let mut response = location.map_or_else(
        || StatusCode::OK.into_response(),
        |location| {
            let mut response = StatusCode::SEE_OTHER.into_response();
            response.headers_mut().insert(LOCATION, location);
            response
        },
    );
    if let Some(cookie) = flash_cookie {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    Ok(response)
}

pub(super) async fn transition(
    state: AppState,
    actor: UserId,
    id: ApprovalId,
    approve: bool,
) -> Result<(), StatusCode> {
    transition_with_channel(state, actor, id, approve, None).await
}

/// Local admin decision: the TOTP step is consumed in the same transaction as
/// the approval change, so one code decides at most one approval.
pub(super) async fn transition_with_totp(
    state: AppState,
    actor: UserId,
    id: ApprovalId,
    approve: bool,
    step: u64,
) -> Result<(), StatusCode> {
    decide(state, actor, id, approve, None, Some(step)).await
}

pub(super) async fn transition_with_channel(
    state: AppState,
    actor: UserId,
    id: ApprovalId,
    approve: bool,
    channel: Option<&'static str>,
) -> Result<(), StatusCode> {
    decide(state, actor, id, approve, channel, None).await
}

async fn decide(
    state: AppState,
    actor: UserId,
    id: ApprovalId,
    approve: bool,
    channel: Option<&'static str>,
    totp_step: Option<u64>,
) -> Result<(), StatusCode> {
    let api = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let clock = state.clock;
    let notify_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let store = api.store();
        store.transact_with_time(
            || clock.now(),
            |tx, now| {
                if let Some(step) = totp_step {
                    tx.consume_totp_step(&actor, step)?;
                }
                let old = tx
                    .get_approval(&id)?
                    .ok_or(crate::store::StoreError::InvalidApproval)?;
                let actor = Principal::User(actor);
                let next = if approve {
                    old.approve(&actor, now)?
                } else {
                    old.deny(&actor, now)?
                };
                tx.update_approval(&next)?;
                let mut record = approval_record(&next, actor);
                if let Some(channel) = channel {
                    record.subject["channel"] = serde_json::json!(channel);
                }
                Ok(((), vec![record]))
            },
        )?;
        api.notify(&notify_id);
        Ok::<_, crate::store::StoreError>(())
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|error| match error {
        crate::store::StoreError::Transition(_) => StatusCode::CONFLICT,
        crate::store::StoreError::InvalidApproval => StatusCode::NOT_FOUND,
        crate::store::StoreError::TotpReplay => StatusCode::UNAUTHORIZED,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    })?;
    Ok(())
}
