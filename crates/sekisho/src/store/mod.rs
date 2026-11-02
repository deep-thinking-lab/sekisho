//! SQLite state and audit writes share one immediate transaction.
mod agents;
mod approvals;
mod audit;
mod auth;
mod budgets;
mod grants;
mod migrations;

#[doc(hidden)]
pub use migrations::migrations;

use rusqlite::{Connection, Transaction, TransactionBehavior};
use sekisho_core::{
    AuditKind, ChainError, CoreError, Principal, PublicKey, Signer, Timestamp, TransitionError,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

pub use agents::AgentToken;
pub use approvals::ConsumeError;
pub use audit::AuditExport;
pub use grants::GrantView;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("invalid stored JSON")]
    Json(#[from] serde_json::Error),
    #[error("core operation failed")]
    Core(#[from] CoreError),
    #[error("invalid approval transition")]
    Transition(#[from] TransitionError),
    #[error("audit verification failed")]
    Chain(#[from] ChainError),
    #[error("store mutex poisoned")]
    Poisoned,
    #[error("SQLite pragma {0} was not applied")]
    Pragma(&'static str),
    #[error("TOTP step already used")]
    TotpReplay,
    #[error("invalid approval data or predecessor")]
    InvalidApproval,
    #[error("invalid grant data")]
    InvalidGrant,
    #[error("agent already exists")]
    AgentAlreadyExists,
    #[error("agent not found")]
    AgentNotFound,
    #[error("invalid agent data or token")]
    InvalidAgent,
    #[error("could not generate an agent token")]
    TokenGeneration,
    #[error("grant not found")]
    GrantNotFound,
    #[error("state change lacks a matching audit record")]
    MissingAudit,
    #[error("a transaction operation failed")]
    TransactionFailed,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("invalid budget configuration")]
    InvalidBudget,
    #[error("invalid stored budget counter")]
    InvalidBudgetCounter,
    #[error("invalid audit export: {0}")]
    InvalidAuditExport(String),
}

pub struct Store {
    connection: Mutex<Connection>,
    signer: Arc<dyn Signer + Send + Sync>,
    audit_keys: BTreeMap<String, PublicKey>,
}

pub struct AuditRecord {
    pub kind: AuditKind,
    pub actor: Principal,
    pub subject: serde_json::Value,
}

pub struct Tx<'a> {
    sql: Transaction<'a>,
    now: Timestamp,
    changes: RefCell<Vec<serde_json::Value>>,
    failed: Cell<bool>,
}

impl Store {
    pub fn open(path: &Path, signer: Arc<dyn Signer + Send + Sync>) -> Result<Self, StoreError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode != "wal" {
            return Err(StoreError::Pragma("journal_mode"));
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let foreign_keys: i64 =
            connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        if foreign_keys != 1 {
            return Err(StoreError::Pragma("foreign_keys"));
        }
        let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        if synchronous != 2 {
            return Err(StoreError::Pragma("synchronous"));
        }
        migrations::apply(&mut connection)?;
        let audit_keys = BTreeMap::from([(signer.key_id().to_owned(), signer.public_key())]);
        Ok(Self {
            connection: Mutex::new(connection),
            signer,
            audit_keys,
        })
    }

    pub fn with_audit_keys(mut self, mut keys: BTreeMap<String, PublicKey>) -> Self {
        keys.insert(self.signer.key_id().to_owned(), self.signer.public_key());
        self.audit_keys = keys;
        self
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn transact<T>(
        &self,
        now: Timestamp,
        f: impl FnOnce(&Tx<'_>) -> Result<(T, Vec<AuditRecord>), StoreError>,
    ) -> Result<T, StoreError> {
        self.transact_with_time(|| now, |tx, _| f(tx))
    }

    /// Sample authoritative time after acquiring both the mutex and the SQLite write lock.
    pub fn transact_with_time<T>(
        &self,
        now: impl FnOnce() -> Timestamp,
        f: impl FnOnce(&Tx<'_>, Timestamp) -> Result<(T, Vec<AuditRecord>), StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = self.lock();
        let sql = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now();
        let tx = Tx {
            sql,
            now,
            changes: RefCell::new(Vec::new()),
            failed: Cell::new(false),
        };
        let (result, records) = f(&tx, now)?;
        if tx.failed.get() {
            return Err(StoreError::TransactionFailed);
        }
        agents::check_records(&tx.changes.borrow(), &records)?;
        approvals::check_records(&tx.changes.borrow(), &records)?;
        grants::check_records(&tx.changes.borrow(), &records)?;
        audit::append(&tx.sql, now, records, self.signer.as_ref())?;
        tx.sql.commit()?;
        Ok(result)
    }
}

impl Tx<'_> {
    fn checked<T>(
        &self,
        operation: impl FnOnce() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let result = operation();
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }
}
