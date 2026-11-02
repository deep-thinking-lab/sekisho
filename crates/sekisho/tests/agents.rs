#![allow(clippy::unwrap_used)]

use sekisho::server::AgentDirectory;
use sekisho::store::{Store, StoreError};
use sekisho_core::{
    AgentId, AuditKind, CoreError, Ed25519Signer, PublicKey, Signature, Signer, UserId,
};
use sha2::{Digest, Sha256};
use std::{hash::BuildHasher, path::PathBuf, sync::Arc};

struct Db {
    dir: PathBuf,
    path: PathBuf,
}

impl Db {
    fn new(name: &str) -> Self {
        let suffix = std::hash::RandomState::new().hash_one(name);
        let dir =
            std::env::temp_dir().join(format!("sekisho-{name}-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("store.db");
        Self { dir, path }
    }

    fn open(&self) -> Arc<Store> {
        let signer = Ed25519Signer::from_secret_bytes("audit", &[7; 32]);
        Arc::new(Store::open(&self.path, Arc::new(signer)).unwrap())
    }

    fn read_storage(&self) -> Vec<u8> {
        let mut bytes = std::fs::read(&self.path).unwrap();
        let wal = self.path.with_extension("db-wal");
        if wal.exists() {
            bytes.extend(std::fs::read(wal).unwrap());
        }
        bytes
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn admin() -> UserId {
    UserId::try_from("admin").unwrap()
}

fn claude() -> AgentId {
    AgentId::try_from("claude").unwrap()
}

struct FailingSigner;

impl Signer for FailingSigner {
    fn key_id(&self) -> &str {
        "audit"
    }

    fn public_key(&self) -> PublicKey {
        Ed25519Signer::from_secret_bytes("audit", &[7; 32]).public_key()
    }

    fn sign(&self, _: &[u8]) -> Result<Signature, CoreError> {
        Err(CoreError::SignatureVerification)
    }
}

#[test]
fn rotated_token_invalidates_old() {
    let db = Db::new("rotate-agent");
    let store = db.open();
    let old = store.add_agent(&claude(), &admin(), 100.into()).unwrap();
    let directory: &dyn AgentDirectory = store.as_ref();
    assert_eq!(
        directory.resolve_token(old.expose()).unwrap(),
        Some(claude())
    );

    let new = store.rotate_agent(&claude(), &admin(), 101.into()).unwrap();
    assert_ne!(old.expose(), new.expose());
    assert_eq!(directory.resolve_token(old.expose()).unwrap(), None);
    assert_eq!(
        directory.resolve_token(new.expose()).unwrap(),
        Some(claude())
    );
    assert_eq!(store.list_agents().unwrap(), vec![claude()]);
    assert_eq!(store.audit_entries(0, 10).unwrap().len(), 2);
}

#[test]
fn removed_agent_cannot_authenticate() {
    let db = Db::new("remove-agent");
    let store = db.open();
    let token = store.add_agent(&claude(), &admin(), 100.into()).unwrap();
    store.remove_agent(&claude(), &admin(), 101.into()).unwrap();

    let directory: &dyn AgentDirectory = store.as_ref();
    assert_eq!(directory.resolve_token(token.expose()).unwrap(), None);
    assert!(store.list_agents().unwrap().is_empty());
    let entries = store.audit_entries(0, 10).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].kind(), AuditKind::AgentAdded);
    assert_eq!(entries[0].subject()["agent_event"], "added");
    assert_eq!(entries[1].subject()["agent_event"], "removed");
}

#[test]
fn token_never_stored_in_plaintext() {
    let db = Db::new("agent-token-storage");
    let store = db.open();
    let token = store.add_agent(&claude(), &admin(), 100.into()).unwrap();

    let storage = db.read_storage();
    assert!(
        !storage
            .windows(token.expose().len())
            .any(|window| window == token.expose().as_bytes()),
        "agent token appeared in the database or its WAL"
    );

    let connection = rusqlite::Connection::open(&db.path).unwrap();
    let (hash, body): (Vec<u8>, String) = connection
        .query_row(
            "SELECT token_hash, body FROM agents WHERE id='claude'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(hash, Sha256::digest(token.expose().as_bytes()).as_slice());
    assert!(!body.contains(token.expose()));
}

#[test]
fn list_rejects_malformed_token_hash() {
    let db = Db::new("agent-malformed-hash");
    let store = db.open();
    store.add_agent(&claude(), &admin(), 100.into()).unwrap();
    rusqlite::Connection::open(&db.path)
        .unwrap()
        .execute("UPDATE agents SET token_hash=X'01' WHERE id='claude'", [])
        .unwrap();

    assert!(matches!(store.list_agents(), Err(StoreError::InvalidAgent)));
}

#[test]
fn audit_signing_failure_rolls_back_add() {
    let db = Db::new("agent-signing-failure");
    let signer: Arc<dyn Signer + Send + Sync> = Arc::new(FailingSigner);
    let store = Store::open(&db.path, signer).unwrap();

    assert!(store.add_agent(&claude(), &admin(), 100.into()).is_err());

    let connection = rusqlite::Connection::open(&db.path).unwrap();
    let agents: i64 = connection
        .query_row("SELECT count(*) FROM agents", [], |row| row.get(0))
        .unwrap();
    let audit: i64 = connection
        .query_row("SELECT count(*) FROM audit", [], |row| row.get(0))
        .unwrap();
    assert_eq!((agents, audit), (0, 0));
}
