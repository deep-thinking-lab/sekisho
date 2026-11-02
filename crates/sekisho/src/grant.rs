use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use rand_core::{OsRng, RngCore};
use sekisho_core::{AgentId, Ed25519Signer, GrantId, Timestamp, ToolName, UnsignedGrant};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Subcommand)]
pub enum Command {
    /// Issue a signed grant.
    Add(Add),
    /// List grants and their use status.
    List,
    /// Revoke a grant and write its tombstone.
    Revoke {
        /// Grant id to revoke.
        id: String,
    },
}

#[derive(Args)]
pub struct Add {
    /// Agent allowed by the grant.
    #[arg(long)]
    agent: String,
    /// Tool allowed by the grant.
    #[arg(long)]
    tool: String,
    /// Target glob allowed by the grant.
    #[arg(long)]
    target: String,
    /// Exact top-level parameter constraint as key=value.
    #[arg(long = "param")]
    params: Vec<String>,
    /// Grant lifetime, such as 30m, 2h or 1d.
    #[arg(long)]
    expires: String,
    /// Maximum number of grant uses.
    #[arg(long)]
    max_uses: Option<u32>,
}

pub fn run(command: Command) -> Result<()> {
    let home = crate::up::home(None)?;
    let store = crate::up::open_store(&home)?;
    let actor = store
        .bootstrap_admin()?
        .context("home is not initialized; run sekisho up first")?;
    let now: Timestamp = time::OffsetDateTime::now_utc().unix_timestamp().into();
    match command {
        Command::Add(options) => {
            let expires_at = now
                .as_secs()
                .checked_add(duration(&options.expires)?)
                .context("grant expiry overflow")?
                .into();
            let key = crate::up::key(&home.join("keys/grant.ed25519"), false)?;
            let grant = UnsignedGrant {
                id: random_id()?,
                agent_id: AgentId::try_from(options.agent.as_str())?,
                tool: ToolName::try_from(options.tool.as_str())?,
                target_glob: options.target,
                params: params(options.params)?,
                not_before: now,
                expires_at,
                max_uses: options.max_uses,
                issued_by: actor,
            }
            .sign(&Ed25519Signer::from_secret_bytes("grant", &key))?;
            store.issue_grant(&grant, now)?;
            println!("{}", grant.id());
        }
        Command::List => {
            println!("ID\tAGENT\tTOOL\tTARGET\tUSES/MAX\tEXPIRES\tSTATUS");
            for view in store.list_grants()? {
                let grant = &view.grant;
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
                let max = grant
                    .max_uses()
                    .map(|max| max.to_string())
                    .unwrap_or_else(|| "unlimited".into());
                println!(
                    "{}\t{}\t{}\t{}\t{}/{}\t{}\t{}",
                    grant.id(),
                    grant.agent_id(),
                    grant.tool(),
                    serde_json::to_string(grant.target_glob())?,
                    view.uses,
                    max,
                    grant.expires_at().as_secs(),
                    status
                );
            }
        }
        Command::Revoke { id } => {
            store.revoke_grant(&GrantId::try_from(id.as_str())?, &actor, now)?;
        }
    }
    Ok(())
}

fn params(arguments: Vec<String>) -> Result<BTreeMap<String, Value>> {
    let mut params = BTreeMap::new();
    for argument in arguments {
        let (key, value) = argument.split_once('=').context("--param requires k=v")?;
        ensure!(!key.is_empty(), "--param key must not be empty");
        let value = match serde_json::from_str::<Value>(value) {
            Ok(value) if !value.is_array() && !value.is_object() => value,
            _ => Value::String(value.to_owned()),
        };
        ensure!(
            params.insert(key.to_owned(), value).is_none(),
            "duplicate --param key"
        );
    }
    Ok(params)
}

fn duration(value: &str) -> Result<i64> {
    let (index, unit) = value
        .char_indices()
        .next_back()
        .context("--expires requires a duration")?;
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => anyhow::bail!("--expires requires s, m, h or d"),
    };
    let number = &value[..index];
    ensure!(
        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
        "--expires requires a positive duration"
    );
    number
        .parse::<i64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|seconds| *seconds > 0)
        .context("--expires must be a positive duration that fits a timestamp")
}

fn random_id() -> Result<GrantId> {
    let mut bytes = [0; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
    let mut number = u128::from_be_bytes(bytes);
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut suffix = String::with_capacity(26);
    for _ in 0..26 {
        suffix.push(char::from(alphabet[(number & 31) as usize]));
        number >>= 5;
    }
    Ok(GrantId::try_from(format!("grt_{suffix}").as_str())?)
}
