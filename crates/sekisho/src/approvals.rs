use crate::{local_admin_client, up};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use sekisho_core::ApprovalId;
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List pending approvals.
    List {
        /// Print the raw approval list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Approve one pending approval. Reads the admin's TOTP code from a terminal prompt or stdin.
    Approve {
        /// Approval id shown by the held action.
        id: String,
    },
    /// Deny one pending approval. Reads the admin's TOTP code from a terminal prompt or stdin.
    Deny {
        /// Approval id shown by the held action.
        id: String,
    },
}

#[derive(Deserialize)]
struct ApprovalRow {
    id: String,
    agent_id: String,
    tool: String,
    target: String,
    rule: String,
    expires_at: i64,
}

pub(crate) async fn run(command: Command) -> Result<()> {
    let home = up::home(None)?;
    match command {
        Command::List { json } => {
            let response =
                local_admin_client::request(&home, reqwest::Method::GET, "/admin/approvals")
                    .await?;
            let status = response.status();
            ensure!(
                status == reqwest::StatusCode::OK,
                "approval list failed ({status})"
            );
            let body = response.text().await.context("invalid approval list")?;
            if json {
                println!("{body}");
                return Ok(());
            }
            let rows: Vec<ApprovalRow> =
                serde_json::from_str(&body).context("invalid approval list")?;
            let now = OffsetDateTime::now_utc().unix_timestamp();
            println!("ID\tAGENT\tTOOL\tTARGET\tRULE\tEXPIRES");
            for row in rows {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    row.id,
                    row.agent_id,
                    row.tool,
                    row.target,
                    row.rule,
                    format_expiry(row.expires_at, now)?
                );
            }
        }
        Command::Approve { id } => decide(&home, id, true).await?,
        Command::Deny { id } => decide(&home, id, false).await?,
    }
    Ok(())
}

fn format_expiry(expires_at: i64, now: i64) -> Result<String> {
    let expires = OffsetDateTime::from_unix_timestamp(expires_at)
        .context("invalid approval expiry")?
        .format(&Rfc3339)
        .context("cannot format approval expiry")?;
    Ok(format!(
        "{expires} ({})",
        relative_time(expires_at.saturating_sub(now))
    ))
}

fn relative_time(seconds: i64) -> String {
    if seconds <= 0 {
        "expired".to_owned()
    } else if seconds < 60 {
        format!("in {seconds}s")
    } else if seconds < 3600 {
        format!("in {}m", seconds / 60)
    } else {
        let hours = seconds / 3600;
        let minutes = seconds % 3600 / 60;
        if minutes == 0 {
            format!("in {hours}h")
        } else {
            format!("in {hours}h {minutes}m")
        }
    }
}

async fn decide(home: &std::path::Path, id: String, approve: bool) -> Result<()> {
    let id = ApprovalId::try_from(id.as_str())?;
    let totp = local_admin_client::read_totp()?;
    let (action, outcome) = if approve {
        ("approve", "approved")
    } else {
        ("deny", "denied")
    };
    let response = local_admin_client::request_with(
        home,
        reqwest::Method::POST,
        &format!("/admin/approvals/{}/{action}", id.as_str()),
        Some(&serde_json::json!({ "totp": totp })),
    )
    .await?;
    let status = response.status();
    ensure!(
        status != reqwest::StatusCode::UNAUTHORIZED,
        "approval {action} failed: invalid or reused TOTP code"
    );
    ensure!(
        status == reqwest::StatusCode::NO_CONTENT,
        "approval {action} failed ({status})"
    );
    println!("{outcome} {}", id.as_str());
    Ok(())
}
