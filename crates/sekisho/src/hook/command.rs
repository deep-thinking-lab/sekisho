use super::claude_code::{HookDecision, action_from_hook, hook_output};
use crate::up;
use anyhow::{Context, Result, anyhow, bail, ensure};
use reqwest::{Client, Url};
use sekisho_core::{Action, AgentId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{self, Read, Write},
    time::Duration,
};

const CHECK_WAIT_SECONDS: u64 = 120;
const HOOK_TIMEOUT_SECONDS: u64 = CHECK_WAIT_SECONDS + 10;
const DEFAULT_SERVER: &str = "http://127.0.0.1:7470";
const MAPPING_AGENT: &str = "claude-code";

pub async fn run_claude_code() -> Result<()> {
    let decision = match check_claude_code().await {
        Ok(decision) => decision,
        Err(error) => HookDecision::Deny {
            reason: format!("Sekisho refused the action: {error:#}"),
        },
    };
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &hook_output(&decision))?;
    writeln!(stdout)?;
    Ok(())
}

async fn check_claude_code() -> Result<HookDecision> {
    let mut hook_json = Vec::new();
    io::stdin().lock().read_to_end(&mut hook_json)?;
    let agent = AgentId::try_from(MAPPING_AGENT)?;
    let action = action_from_hook(&agent, &hook_json)?;
    if let Some(reason) = state_dir_refusal(&action) {
        return Ok(HookDecision::Deny { reason });
    }
    let token = read_token()?;
    let server = server_url()?;
    let response = request_decision(&server, &action, &token).await?;
    Ok(response.into_hook_decision(&server))
}

/// Built-in refusal for actions on the Sekisho home, before any server call.
/// The server denies `hook:` targets inside its home with a built-in rule too.
/// For Bash this is a tripwire on the command text, not a boundary: a shell can
/// always build the path at run time. Run Sekisho as a separate OS user.
fn state_dir_refusal(action: &Action) -> Option<String> {
    let tool = action.tool().as_str().strip_prefix("hook:claude-code/")?;
    let mut homes = vec!["/.sekisho".to_owned()];
    if let Ok(home) = up::home(None) {
        if home.is_absolute() {
            homes.extend(home.to_str().map(str::to_owned));
        }
        if let Ok(real) = fs::canonicalize(&home) {
            homes.extend(real.to_str().map(str::to_owned));
        }
    }
    let target = action.target();
    let target = target.strip_prefix("cwd:").unwrap_or(target);
    let inside = homes
        .iter()
        .filter(|home| home.as_str() != "/.sekisho")
        .any(|home| {
            let home = home.trim_end_matches('/');
            target == home || target.starts_with(&format!("{home}/"))
        });
    let inside = inside || home_by_inode(target);
    let mentioned = tool == "bash"
        && action.params()["command"]
            .as_str()
            .is_some_and(|command| homes.iter().any(|home| command.contains(home.as_str())));
    (inside || mentioned).then(|| {
        "Sekisho refused the action: the Sekisho state directory is off limits to agents".to_owned()
    })
}

/// Whether `target` is the Sekisho home, inside it, or a directory containing
/// it, compared by (device, inode) so no path spelling (firmlink, bind mount,
/// alias) can hide it. A target that does not exist yet is judged by its
/// nearest existing ancestor.
fn home_by_inode(target: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(home) = up::home(None) else {
        return false;
    };
    let id = |path: &std::path::Path| fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
    let Some(home_id) = id(&home) else {
        return false;
    };
    let trimmed = target.trim_end_matches('/');
    let target = std::path::Path::new(if trimmed.is_empty() { "/" } else { trimmed });
    if target
        .ancestors()
        .filter_map(&id)
        .any(|ancestor| ancestor == home_id)
    {
        return true;
    }
    // A directory that contains the home: a search rooted there reaches it.
    let target_id = fs::metadata(target)
        .ok()
        .filter(|m| m.is_dir())
        .map(|m| (m.dev(), m.ino()));
    // Ancestors under both spellings of the home, from the same helper as the
    // server's built-in rule, so the two checks cannot drift.
    target_id.is_some_and(|target_id| {
        fs::canonicalize(&home)
            .ok()
            .and_then(|home| home.to_str().map(sekisho_core::protected_ancestors))
            .unwrap_or_default()
            .iter()
            .filter_map(|ancestor| id(std::path::Path::new(ancestor)))
            .any(|ancestor| ancestor == target_id)
    })
}

fn server_url() -> Result<Url> {
    let raw = env::var("SEKISHO_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_owned());
    let url = Url::parse(&raw).context("SEKISHO_SERVER must be an absolute HTTP or HTTPS URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "SEKISHO_SERVER must use HTTP or HTTPS"
    );
    Ok(url)
}

fn read_token() -> Result<String> {
    if let Ok(token) = env::var("SEKISHO_TOKEN") {
        let token = token.trim();
        ensure!(!token.is_empty(), "SEKISHO_TOKEN is empty");
        return Ok(token.to_owned());
    }
    let path = up::home(None)?.join("agent-token");
    up::check_mode(&path, false)
        .with_context(|| format!("cannot read agent token from {}", path.display()))?;
    let token = fs::read_to_string(&path)
        .with_context(|| format!("cannot read agent token from {}", path.display()))?;
    let token = token.trim();
    ensure!(!token.is_empty(), "agent token file is empty");
    Ok(token.to_owned())
}

async fn request_decision(server: &Url, action: &Action, token: &str) -> Result<CheckResponse> {
    let mut url = server.clone();
    url.set_path("/v1/check");
    url.set_query(Some(&format!("wait={CHECK_WAIT_SECONDS}")));
    url.set_fragment(None);
    let client = Client::builder()
        .timeout(Duration::from_secs(HOOK_TIMEOUT_SECONDS))
        .build()
        .context("cannot create the Sekisho HTTP client")?;
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&CheckRequest {
            tool: action.tool().as_str(),
            target: action.target(),
            params: action.params(),
        })
        .send()
        .await
        .map_err(request_error)?;
    let status = response.status();
    if !status.is_success() {
        bail!("Sekisho server returned HTTP {}", status.as_u16());
    }
    response
        .json()
        .await
        .context("Sekisho server returned an invalid response")
}

fn request_error(error: reqwest::Error) -> anyhow::Error {
    if error.is_timeout() {
        anyhow!("Sekisho server did not respond before the hook deadline")
    } else if error.is_connect() {
        anyhow!("Sekisho server is unreachable")
    } else {
        anyhow!("Sekisho check request failed")
    }
}

#[derive(Serialize)]
struct CheckRequest<'a> {
    tool: &'a str,
    target: &'a str,
    params: &'a Value,
}

#[derive(Deserialize)]
struct CheckResponse {
    decision: ServerDecision,
    reason: Option<String>,
    approval_id: Option<String>,
}

impl CheckResponse {
    fn into_hook_decision(self, server: &Url) -> HookDecision {
        match self.decision {
            ServerDecision::Allow => HookDecision::Allow,
            ServerDecision::Deny => HookDecision::Deny {
                reason: self.reason.unwrap_or_else(|| "denied by policy".to_owned()),
            },
            ServerDecision::Ask => pending_decision(self.approval_id.as_deref(), server),
            ServerDecision::Expired => HookDecision::Deny {
                reason: approval_reason("approval expired", self.approval_id.as_deref(), server),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ServerDecision {
    Allow,
    Ask,
    Deny,
    Expired,
}

fn pending_decision(approval_id: Option<&str>, server: &Url) -> HookDecision {
    HookDecision::Deny {
        reason: approval_reason("approval still pending", approval_id, server),
    }
}

fn approval_reason(prefix: &str, approval_id: Option<&str>, server: &Url) -> String {
    let Some(approval_id) = approval_id else {
        return format!("{prefix}; Sekisho did not return an approval id");
    };
    let mut link = server.clone();
    link.set_path(&format!("/approvals/{approval_id}"));
    link.set_query(None);
    link.set_fragment(None);
    format!("{prefix}: {approval_id}. Open {link} to approve or deny.")
}

pub fn claude_code_config() -> Value {
    json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": "sekisho hook claude-code",
                    "timeout": HOOK_TIMEOUT_SECONDS
                }]
            }]
        }
    })
}
