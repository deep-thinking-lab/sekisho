use anyhow::{Context, Result};
use clap::Subcommand;
use sekisho_core::{DecisionKind, Policy, ToolMatch};
use serde_json::json;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum Command {
    /// Validate a policy file without loading it.
    Check {
        /// Policy file to validate.
        file: PathBuf,
        /// Print every parsed rule as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reload the running server's policy file. Reads the admin's TOTP code from a terminal prompt or stdin.
    Reload,
}

pub async fn run(command: Command) -> Result<()> {
    match command {
        Command::Check {
            file,
            json: print_json,
        } => {
            let policy = Policy::parse(&std::fs::read(file)?)?;
            if !print_json {
                println!("ok: {} rules", policy.rules.len());
                return Ok(());
            }
            for rule in policy.rules {
                let mut output = json!({
                    "name": rule.name,
                    "target": rule.target_pattern,
                    "params": rule.params,
                    "decision": match rule.decision {
                        DecisionKind::Allow => "allow",
                        DecisionKind::Ask => "ask",
                        DecisionKind::Deny => "deny",
                    },
                    "budget": rule.budget.map(|b| json!({"max": b.max, "per_seconds": b.per_seconds})),
                    "approvers": rule.approvers,
                });
                match rule.tool {
                    ToolMatch::Exact(tool) => output["tool"] = json!(tool),
                    ToolMatch::Prefix(prefix) => output["tool_prefix"] = json!(prefix),
                }
                println!("{}", serde_json::to_string(&output)?);
            }
        }
        Command::Reload => {
            let home = crate::up::home(None)?;
            let totp = crate::local_admin_client::read_totp()?;
            let response = crate::local_admin_client::request_with(
                &home,
                reqwest::Method::POST,
                "/admin/policy/reload",
                Some(&serde_json::json!({ "totp": totp })),
            )
            .await?;
            let status = response.status();
            if status != reqwest::StatusCode::NO_CONTENT {
                let error = response.text().await.context("cannot read server error")?;
                anyhow::bail!("policy reload failed ({status}): {error}");
            }
        }
    }
    Ok(())
}
