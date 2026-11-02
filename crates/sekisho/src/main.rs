use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use hook::command::claude_code_config;
use sekisho_core::AgentId;
use std::process::ExitCode;

mod anchor;
mod approvals;
mod audit_cli;
mod grant;
mod hook;
mod local_admin_client;
mod policy;
mod up;

#[derive(Parser)]
#[command(name = "sekisho", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Set up a private home and start the Sekisho server.
    Up(up::Options),
    /// Export or verify the signed audit chain.
    Audit {
        /// Audit command to run.
        #[command(subcommand)]
        command: audit_cli::AuditCommand,
    },
    /// Add, list, rotate or remove agents.
    Agent {
        /// Agent command to run.
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Validate or reload the policy.
    Policy {
        /// Policy command to run.
        #[command(subcommand)]
        command: policy::Command,
    },
    /// Issue, list or revoke grants.
    Grant {
        /// Grant command to run.
        #[command(subcommand)]
        command: grant::Command,
    },
    /// Run the Claude Code hook.
    Hook {
        /// Hook integration to run.
        #[command(subcommand)]
        command: HookCommand,
    },
    /// List, approve or deny pending approvals.
    Approvals {
        /// Approval command to run.
        #[command(subcommand)]
        command: approvals::Command,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Add an agent and print its token.
    Add {
        /// Agent id to add.
        name: String,
        /// Print an integration configuration for the agent.
        #[arg(long, value_enum)]
        print_config: Option<PrintConfig>,
    },
    /// List configured agents.
    List,
    /// Rotate an agent token.
    Rotate {
        /// Agent id whose token to rotate.
        name: String,
    },
    /// Remove an agent.
    Remove {
        /// Agent id to remove.
        name: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum PrintConfig {
    /// Print Claude Code hook and MCP configuration.
    ClaudeCode,
}

#[derive(Subcommand)]
enum HookCommand {
    /// Run the Claude Code PreToolUse hook.
    ClaudeCode,
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Some(Command::Up(options)) => finish(up::run(options).await),
        Some(Command::Audit { command }) => finish_audit(audit_cli::run(command)),
        Some(Command::Agent { command }) => finish(run_agent(command)),
        Some(Command::Policy { command }) => finish(policy::run(command).await),
        Some(Command::Grant { command }) => finish(grant::run(command)),
        Some(Command::Hook { command }) => match command {
            HookCommand::ClaudeCode => finish(hook::command::run_claude_code().await),
        },
        Some(Command::Approvals { command }) => finish(approvals::run(command).await),
        None => finish(up::run(up::Options::default()).await),
    }
}

fn finish(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn finish_audit(result: Result<(), audit_cli::AuditCliError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run_agent(command: AgentCommand) -> Result<()> {
    let home = up::home(None)?;
    let store = up::open_store(&home)?;
    let actor = store
        .bootstrap_admin()?
        .context("home is not initialized; run sekisho up first")?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp().into();
    match command {
        AgentCommand::Add { name, print_config } => {
            let token = store.add_agent(&AgentId::try_from(name.as_str())?, &actor, now)?;
            println!("{}", token.expose());
            if let Some(PrintConfig::ClaudeCode) = print_config {
                println!();
                println!("Token setup:");
                println!("export SEKISHO_TOKEN='{}'", token.expose());
                println!();
                println!(".claude/settings.json:");
                println!("{}", serde_json::to_string_pretty(&claude_code_config())?);
                println!(".mcp.json:");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "mcpServers": {"sekisho": {"type":"http", "url":"http://127.0.0.1:7470/mcp",
                            "headers":{"Authorization":"Bearer ${SEKISHO_TOKEN}"}}}
                    }))?
                );
            }
        }
        AgentCommand::List => {
            for agent in store.list_agents()? {
                println!("{agent}");
            }
        }
        AgentCommand::Rotate { name } => {
            let token = store.rotate_agent(&AgentId::try_from(name.as_str())?, &actor, now)?;
            println!("{}", token.expose());
        }
        AgentCommand::Remove { name } => {
            store.remove_agent(&AgentId::try_from(name.as_str())?, &actor, now)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod help_tests {
    use super::*;
    use clap::CommandFactory;

    fn walk(command: &clap::Command, path: &str) {
        for subcommand in command.get_subcommands() {
            let name = format!("{path} {}", subcommand.get_name());
            assert!(
                subcommand
                    .get_about()
                    .is_some_and(|about| !about.to_string().is_empty()),
                "{name} needs a description"
            );
            walk(subcommand, &name);
        }
        for arg in command.get_arguments().filter(|arg| !arg.is_hide_set()) {
            assert!(
                arg.get_help()
                    .is_some_and(|help| !help.to_string().is_empty()),
                "{path} {} needs a description",
                arg.get_id()
            );
        }
    }

    #[test]
    fn every_subcommand_and_flag_has_a_description() {
        walk(&Cli::command(), "sekisho");
    }
}
