use super::{AppState, Role, approvals};
use axum::{
    Form,
    body::{Body, Bytes},
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode},
};
use sekisho_core::ApprovalId;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct SlackForm {
    payload: String,
}
#[derive(Deserialize)]
struct Payload {
    #[serde(rename = "type")]
    kind: String,
    user: SlackUser,
    actions: Vec<Action>,
    response_url: String,
}
#[derive(Deserialize)]
struct SlackUser {
    id: String,
}
#[derive(Deserialize)]
struct Action {
    action_id: String,
    value: String,
}

pub(super) async fn actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let mut matching = state
        .slack_integrations
        .iter()
        .filter(|integration| integration.verifies(&headers, &body, state.clock.now()));
    let integration = matching.next().ok_or(StatusCode::UNAUTHORIZED)?;
    // Ambiguous signing keys must never select a different app's identity or TOTP setting.
    if matching.next().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut request = Request::new(Body::from(body));
    *request.method_mut() = axum::http::Method::POST;
    *request.headers_mut() = headers;
    let Form(form) = Form::<SlackForm>::from_request(request, &())
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let payload: Payload =
        serde_json::from_str(&form.payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    if payload.kind != "block_actions" || payload.actions.len() != 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let action = &payload.actions[0];
    let approve = match action.action_id.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let id = ApprovalId::try_from(action.value.as_str()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let response_url = integration
        .response_url(&payload.response_url)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let integration = integration.clone();
    tokio::spawn(async move {
        let message = resolve_action(state, integration, payload.user.id, id, approve).await
            .unwrap_or_else(|_| ephemeral("Sekisho could not record this decision. The action was refused. Try again in the web inbox."));
        send_reply(response_url, message).await;
    });
    Ok(StatusCode::OK)
}

async fn resolve_action(
    state: AppState,
    integration: std::sync::Arc<crate::notifications::slack::SlackIntegration>,
    slack_user: String,
    id: ApprovalId,
    approve: bool,
) -> Result<Value, StatusCode> {
    let message = if let Some(user_id) = integration.users.get(&slack_user) {
        let users = state.users.clone();
        let user_id = user_id.clone();
        let user = tokio::task::spawn_blocking(move || users.find(&user_id))
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if let Some(user) = user {
            if !user.roles.iter().any(|role| role.satisfies(Role::Approver)) {
                ephemeral("Your Sekisho user does not have the Approver role.")
            } else if integration.requires_totp
                || (approve && !integration.one_click())
                || (approve && !one_click_approvable(&state, &id).await?)
            {
                ephemeral(&format!(
                    "TOTP is required. Open {} to approve or deny in Sekisho.",
                    state.approval_url(id.as_str())
                ))
            } else {
                match approvals::transition_with_channel(
                    state.clone(),
                    user.id.clone(),
                    id.clone(),
                    approve,
                    Some("slack"),
                )
                .await
                {
                    Ok(()) => {
                        json!({"replace_original":true, "text":format!("{} {} by {}.",if approve { "Approved" } else { "Denied" },id.as_str(),user.id)})
                    }
                    Err(StatusCode::CONFLICT) => ephemeral(
                        "Cannot decide your own approval, or the approval has already been decided or expired.",
                    ),
                    Err(StatusCode::NOT_FOUND) => ephemeral("This approval no longer exists."),
                    Err(error) => return Err(error),
                }
            }
        } else {
            ephemeral("Your Slack user is not mapped to an existing Sekisho user.")
        }
    } else {
        ephemeral("Your Slack user is not mapped to a Sekisho user.")
    };
    Ok(message)
}

/// Whether a one-click Slack approval may decide this approval. A missing
/// approval falls through to the transition, which reports it.
async fn one_click_approvable(state: &AppState, id: &ApprovalId) -> Result<bool, StatusCode> {
    let api = state
        .checks
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let id = id.clone();
    let now = state.clock.now();
    let approval = tokio::task::spawn_blocking(move || {
        api.store()
            .transact(now, |tx| Ok((tx.get_approval(&id)?, vec![])))
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(approval
        .is_none_or(|approval| crate::notifications::one_click_approvable(approval.action())))
}

fn ephemeral(text: &str) -> Value {
    json!({"response_type":"ephemeral", "replace_original":false, "text":text})
}

async fn send_reply(url: reqwest::Url, message: Value) {
    let Ok(client) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
    else {
        return;
    };
    for attempt in 0..3 {
        if client
            .post(url.clone())
            .json(&message)
            .send()
            .await
            .is_ok_and(|reply| reply.status().is_success())
        {
            return;
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
        }
    }
    tracing::warn!("Slack interaction reply failed");
}
