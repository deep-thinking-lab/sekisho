use super::StoreError;
use rusqlite::{Connection, TransactionBehavior};

const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE users (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL, body TEXT NOT NULL);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE agents (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE grants (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, expires_at INTEGER NOT NULL, body TEXT NOT NULL);
CREATE INDEX grants_agent ON grants(agent_id, expires_at);
CREATE TABLE grant_tombstones (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE approvals (id TEXT PRIMARY KEY, state TEXT NOT NULL, agent_id TEXT NOT NULL, expires_at INTEGER NOT NULL, action_digest TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX approvals_lookup ON approvals(agent_id, state, expires_at);
CREATE TABLE budget_counters (agent_id TEXT NOT NULL, rule TEXT NOT NULL, window_start INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(agent_id, rule, window_start));
CREATE TABLE audit (seq INTEGER PRIMARY KEY CHECK(seq >= 0), body TEXT NOT NULL);
"#,
    r#"
ALTER TABLE grants ADD COLUMN uses INTEGER NOT NULL DEFAULT 0 CHECK(uses >= 0);
"#,
    r#"
ALTER TABLE budget_counters RENAME COLUMN rule TO rule_name;
ALTER TABLE budget_counters DROP COLUMN body;
ALTER TABLE budget_counters ADD COLUMN used INTEGER NOT NULL DEFAULT 0;
"#,
    r#"
ALTER TABLE users ADD COLUMN last_totp_step INTEGER CHECK(last_totp_step >= 0);
"#,
    r#"
ALTER TABLE agents ADD COLUMN token_hash BLOB NOT NULL DEFAULT X'';
"#,
];

#[doc(hidden)]
pub fn migrations() -> &'static [&'static str] {
    MIGRATIONS
}

pub(super) fn apply(connection: &mut Connection) -> Result<(), StoreError> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS meta (version INTEGER PRIMARY KEY);")?;
    let version: usize = tx.query_row("SELECT coalesce(max(version), 0) FROM meta", [], |r| {
        r.get(0)
    })?;
    let migrations = migrations();
    if version > migrations.len() {
        return Err(StoreError::SchemaVersion);
    }
    for (index, sql) in migrations.iter().enumerate().skip(version) {
        tx.execute_batch(sql)?;
        tx.execute("INSERT INTO meta(version) VALUES (?)", [index + 1])?;
    }
    tx.commit()?;
    Ok(())
}
