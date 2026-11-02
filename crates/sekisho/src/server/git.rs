use super::AppState;
use crate::git::{
    pack::{Ancestry, HashKind},
    pktline::{Encoding, ObjectId},
    proxy::{GitProxy, PushBody, Remote, component, response_body},
};
use crate::store::AuditRecord;
use axum::{
    Extension,
    body::Body,
    extract::{Path, Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use sekisho_core::{Action, AgentId, AuditKind, DecisionKind, Principal, ToolName};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) async fn proxy(
    State(state): State<AppState>,
    Extension(agent): Extension<AgentId>,
    Path(path): Path<String>,
    request: Request,
) -> Response {
    let Some(proxy) = state.git_proxy.as_ref() else {
        return git_error(StatusCode::SERVICE_UNAVAILABLE, "Git proxy unavailable");
    };
    let slot = if path.ends_with("/git-receive-pack") {
        match proxy.push_slots.clone().try_acquire_owned() {
            Ok(slot) => Some(slot),
            Err(_) => {
                return git_error(StatusCode::SERVICE_UNAVAILABLE, "Git push capacity reached");
            }
        }
    } else {
        None
    };
    let deadline = Instant::now() + proxy.push_timeout;
    let cancel = Arc::new(AtomicBool::new(false));
    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let _cancel = Cancel(cancel.clone());
    match execute(&state, agent, &path, request, deadline, cancel, slot).await {
        Ok(response) => response,
        Err(status) => git_error(status, "Sekisho refused the git request"),
    }
}
fn git_error(status: StatusCode, message: &str) -> Response {
    let payload = format!("ERR {message}\n");
    (
        status,
        [("content-type", "application/x-git-receive-pack-result")],
        format!("{:04x}{payload}0000", payload.len() + 4),
    )
        .into_response()
}
async fn execute(
    state: &AppState,
    agent: AgentId,
    path: &str,
    request: Request,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Response, StatusCode> {
    let proxy = state
        .git_proxy
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let checks = state
        .checks
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let segments: Vec<_> = path.split('/').collect();
    let [remote_name, owner, repo_git, tail @ ..] = segments.as_slice() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let repo = repo_git
        .strip_suffix(".git")
        .filter(|v| component(v))
        .ok_or(StatusCode::NOT_FOUND)?;
    if !component(remote_name) || !component(owner) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let remote = proxy
        .remotes
        .get(*remote_name)
        .ok_or(StatusCode::NOT_FOUND)?;
    let owner = if remote.case_insensitive {
        owner.to_ascii_lowercase()
    } else {
        (*owner).to_owned()
    };
    let repo = if remote.case_insensitive {
        repo.to_ascii_lowercase()
    } else {
        repo.to_owned()
    };
    let endpoint = tail.join("/");
    let push = match (request.method(), endpoint.as_str()) {
        (&Method::GET, "info/refs") => {
            if !matches!(
                request.uri().query(),
                Some("service=git-upload-pack" | "service=git-receive-pack")
            ) {
                return Err(StatusCode::BAD_REQUEST);
            }
            false
        }
        (&Method::POST, "git-upload-pack") => false,
        (&Method::POST, "git-receive-pack") => true,
        _ => return Err(StatusCode::METHOD_NOT_ALLOWED),
    };
    let encoding = match request.headers().get("content-encoding") {
        None => Encoding::Identity,
        Some(v) if v == "identity" => Encoding::Identity,
        Some(v) if v == "gzip" => Encoding::Gzip,
        _ => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
    };
    let mut url = remote
        .base
        .join(&format!("{owner}/{repo}.git/{endpoint}"))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    url.set_query(request.uri().query());
    let (parts, body) = request.into_parts();
    let mut outgoing = remote.authenticate(proxy.client.request(parts.method, url));
    for name in ["content-type", "accept", "git-protocol"] {
        if let Some(value) = parts.headers.get(name) {
            outgoing = outgoing.header(name, value);
        }
    }
    let target = format!("{}/{owner}/{repo}", remote.host);
    let mut bodies = None;
    let actions = if push {
        let runtime = tokio::runtime::Handle::current();
        let limit = proxy.body_limit;
        let mut parsed = tokio::task::spawn_blocking(move || {
            PushBody::parse(body, encoding, limit, runtime, deadline, cancel)
        })
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut actions = Vec::new();
        let mut unresolved = Vec::new();
        for (index, update) in parsed.commands.updates.iter().enumerate() {
            let old = object_id(&update.old);
            let new = object_id(&update.new);
            let delete = new.bytes().all(|b| b == b'0');
            let create = old.bytes().all(|b| b == b'0');
            if !(create || delete) {
                unresolved.push(index);
            }
            // An update is forced unless Sekisho proves it is a fast-forward below.
            actions.push(action(
                agent.clone(),
                "git.push",
                format!("{target}:{}", update.refname),
                json!({"old":old,"new":new,"delete":delete,"force":!(create || delete)}),
            )?);
        }
        // Store work runs off the async workers, like every other route.
        let (depends, denied) = {
            let checks = checks.clone();
            let clock = state.clock.clone();
            let probes = actions.clone();
            tokio::task::spawn_blocking(move || {
                let mut depends = Vec::new();
                let mut denied = false;
                for action in &probes {
                    let mut params = action.params().clone();
                    let mut decisions = Vec::new();
                    for force in [false, true] {
                        params["force"] = json!(force);
                        let probe = Action::new(
                            action.agent_id().clone(),
                            action.tool().clone(),
                            action.target().to_owned(),
                            params.clone(),
                        )
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                        decisions.push(
                            checks
                                .precheck(&probe, clock.as_ref())
                                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
                        );
                    }
                    denied |= decisions.iter().all(|d| d.kind == DecisionKind::Deny);
                    depends.push(decisions[0] != decisions[1]);
                }
                Ok::<_, StatusCode>((depends, denied))
            })
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)??
        };
        if !denied && !unresolved.is_empty() {
            let kind = match parsed.commands.updates[unresolved[0]].old {
                ObjectId::Sha1(_) => HashKind::Sha1,
                ObjectId::Sha256(_) => HashKind::Sha256,
            };
            let mut walks = Vec::new();
            for &index in &unresolved {
                let param = |key: &str| {
                    actions[index].params()[key]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(StatusCode::BAD_REQUEST)
                };
                walks.push((index, param("old")?, param("new")?));
            }
            // Scanning and the ancestry walks are CPU work over up to 64 MiB of
            // commits: run them off the async workers, bounded by the push
            // deadline. A walk that runs out of time stays unproven (forced).
            let walk_deadline = deadline.min(Instant::now() + Duration::from_secs(30));
            let (body, walked) = tokio::task::spawn_blocking(move || {
                let walked = parsed.scan(kind, deadline).map(|graph| {
                    let mut memo = std::collections::HashMap::new();
                    walks
                        .into_iter()
                        .map(|(index, old, new)| {
                            let ancestry = memo
                                .entry((old.clone(), new.clone()))
                                .or_insert_with(|| {
                                    graph.ancestry_until(&old, &new, Some(walk_deadline))
                                })
                                .clone();
                            (index, old, ancestry)
                        })
                        .collect::<Vec<_>>()
                });
                (parsed, walked)
            })
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            parsed = body;
            let walked = walked.map_err(|_| StatusCode::BAD_REQUEST)?;
            // Each distinct (old, boundary commit) pair is asked once per push,
            // and at most MAX_COMPARES pairs in total. Unasked pairs stay unproven.
            let mut pending = Vec::new();
            let mut pairs = std::collections::BTreeSet::new();
            for (index, old, ancestry) in walked {
                match ancestry {
                    Some(Ancestry::FastForward) => {
                        actions[index] = with_force(&actions[index], false)?;
                    }
                    // Not a fast-forward, or the walk ran out of time: forced.
                    Some(Ancestry::NotFastForward) | None => {}
                    // Unproven stays forced when the decision does not depend on it.
                    Some(Ancestry::Upstream(_)) if !depends[index] => {}
                    Some(Ancestry::Upstream(frontier)) => {
                        let frontier: Vec<_> = frontier
                            .into_iter()
                            .take(MAX_FRONTIER)
                            .map(|commit| (old.clone(), commit))
                            .collect();
                        for pair in &frontier {
                            if pairs.len() < MAX_COMPARES {
                                pairs.insert(pair.clone());
                            }
                        }
                        pending.push((index, frontier));
                    }
                }
            }
            let mut compares = tokio::task::JoinSet::new();
            for (old, commit) in pairs {
                let proxy = proxy.clone();
                let remote_name = (*remote_name).to_owned();
                let owner = owner.clone();
                let repo = repo.clone();
                compares.spawn(async move {
                    let ancestor = match proxy.remotes.get(&remote_name) {
                        Some(remote) => {
                            compare(&proxy, remote, &owner, &repo, &old, &commit).await
                                == Some(true)
                        }
                        None => false,
                    };
                    ((old, commit), ancestor)
                });
            }
            let compare_deadline = tokio::time::Instant::from_std(
                deadline.min(Instant::now() + Duration::from_secs(15)),
            );
            let mut ancestors = std::collections::BTreeSet::new();
            while let Ok(Some(result)) =
                tokio::time::timeout_at(compare_deadline, compares.join_next()).await
            {
                let (pair, ancestor) = result.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                if ancestor {
                    ancestors.insert(pair);
                }
            }
            compares.abort_all();
            for (index, frontier) in pending {
                if frontier.iter().any(|pair| ancestors.contains(pair)) {
                    actions[index] = with_force(&actions[index], false)?;
                }
            }
        }
        bodies = Some(parsed);
        actions
    } else {
        // Fetch bodies contain no push commands and can be forwarded directly.
        if let Some(value) = parts.headers.get("content-encoding") {
            outgoing = outgoing.header("content-encoding", value);
        }
        outgoing = outgoing.body(reqwest::Body::wrap_stream(body.into_data_stream()));
        vec![action(agent.clone(), "git.fetch", target, json!({}))?]
    };
    let mut refused = false;
    let mut approvals = Vec::new();
    let digests = actions
        .iter()
        .map(Action::digest)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let results = {
        let checks = checks.clone();
        let clock = state.clock.clone();
        let agent = agent.clone();
        tokio::task::spawn_blocking(move || checks.check_all(agent, actions, clock.as_ref()))
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    };
    for result in results {
        if result.decision != "allow" {
            refused = true;
            if let Some(id) = result.approval_id {
                approvals.push(format!("{id}: {}", state.approval_url(&id)));
            }
        }
    }
    if refused {
        let message = if approvals.is_empty() {
            "Sekisho denied this git action".to_owned()
        } else {
            format!("Sekisho approval required: {}", approvals.join(", "))
        };
        if let Some(body) = &bodies {
            let sideband = body
                .commands
                .capabilities
                .iter()
                .any(|c| c == "side-band-64k" || c == "side-band");
            if sideband {
                let payload = format!("\x03{message}\n");
                return Ok((
                    StatusCode::OK,
                    [("content-type", "application/x-git-receive-pack-result")],
                    format!("{:04x}{payload}0000", payload.len() + 4),
                )
                    .into_response());
            }
            return Ok(git_error(StatusCode::OK, &message));
        }
        return Ok(git_error(StatusCode::FORBIDDEN, &message));
    }
    if let Some(body) = bodies {
        let request = outgoing.build().map_err(|_| StatusCode::BAD_GATEWAY)?;
        let body = body.forward();
        let sent = tokio::task::spawn_blocking(move || {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let client = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .timeout(remaining.max(Duration::from_millis(1)))
                .build()?;
            client
                .request(request.method().clone(), request.url().clone())
                .headers(request.headers().clone())
                .timeout(remaining.max(Duration::from_millis(1)))
                .body(body)
                .send()
        })
        .await;
        let subject = match &sent {
            Ok(Ok(response)) => {
                json!({"outcome":"forwarded", "status":response.status().as_u16(), "action_digests":digests})
            }
            Ok(Err(error)) => {
                json!({"outcome":"upstream_failed", "error_class":if error.is_timeout() {"timeout"} else if error.is_connect() {"connect"} else if error.is_body() {"body"} else {"transport"}, "action_digests":digests})
            }
            Err(_) => {
                json!({"outcome":"upstream_failed", "error_class":"worker", "action_digests":digests})
            }
        };
        checks
            .store
            .transact(state.clock.now(), |_| {
                Ok((
                    (),
                    vec![AuditRecord {
                        kind: AuditKind::Decided,
                        actor: Principal::Agent(agent.clone()),
                        subject,
                    }],
                ))
            })
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let response = sent
            .map_err(|_| StatusCode::BAD_GATEWAY)?
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let mut result = Response::builder().status(response.status());
        for name in [
            "content-type",
            "content-length",
            "cache-control",
            "expires",
            "pragma",
        ] {
            if let Some(value) = response.headers().get(name) {
                result = result.header(name, value);
            }
        }
        return result
            .body(response_body(response, slot, deadline, {
                let checks = checks.clone();
                let clock = state.clock.clone();
                move || checks.store.transact(clock.now(), |_| Ok(((), vec![AuditRecord {
                    kind: AuditKind::Decided, actor: Principal::Agent(agent),
                    subject: json!({"outcome":"upstream_failed", "error_class":"response_body", "action_digests":digests}),
                }]))).map_err(std::io::Error::other)
            }).await.map_err(|_| StatusCode::BAD_GATEWAY)?)
            .map_err(|_| StatusCode::BAD_GATEWAY);
    }
    let response = outgoing.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut result = Response::builder().status(response.status());
    for name in ["content-type", "cache-control", "expires", "pragma"] {
        if let Some(value) = response.headers().get(name) {
            result = result.header(name, value);
        }
    }
    result
        .body(Body::from_stream(response.bytes_stream()))
        .map_err(|_| StatusCode::BAD_GATEWAY)
}

fn action(
    agent: AgentId,
    tool: &str,
    target: String,
    params: serde_json::Value,
) -> Result<Action, StatusCode> {
    let tool = ToolName::try_from(tool).map_err(|_| StatusCode::BAD_REQUEST)?;
    Action::new(agent, tool, target, params).map_err(|_| StatusCode::BAD_REQUEST)
}
fn object_id(id: &ObjectId) -> String {
    match id {
        ObjectId::Sha1(bytes) => hex_string(bytes),
        ObjectId::Sha256(bytes) => hex_string(bytes),
    }
}
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn with_force(original: &Action, force: bool) -> Result<Action, StatusCode> {
    let mut params = original.params().clone();
    params["force"] = json!(force);
    action(
        original.agent_id().clone(),
        "git.push",
        original.target().to_owned(),
        params,
    )
}
/// Frontier commits checked upstream per update. Beyond this the update stays forced.
const MAX_FRONTIER: usize = 16;
/// Distinct compare API calls per push, so one push cannot drain the
/// upstream token's rate limit. Updates left unproven stay forced.
const MAX_COMPARES: usize = 32;
/// Whether the upstream says `old` is an ancestor of `commit`. `None` when it
/// cannot say, which callers treat as "not proven".
async fn compare(
    proxy: &GitProxy,
    remote: &Remote,
    owner: &str,
    repo: &str,
    old: &str,
    commit: &str,
) -> Option<bool> {
    let path = format!("repos/{owner}/{repo}/compare/{old}...{commit}");
    let url = remote.api.as_ref()?.join(&path).ok()?;
    let response = remote
        .authenticate(
            proxy
                .client
                .get(url)
                .header("user-agent", "sekisho")
                .timeout(std::time::Duration::from_secs(10)),
        )
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let value: serde_json::Value = response.json().await.ok()?;
    match value.get("status")?.as_str()? {
        "ahead" | "identical" => Some(true),
        "behind" | "diverged" => Some(false),
        _ => None,
    }
}
