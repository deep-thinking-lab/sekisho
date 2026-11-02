//! Pure construction and offline verification of signed audit chains.

use crate::action::validate_integers;
use crate::{CoreError, Digest, Principal, PublicKey, Signature, Signer, Timestamp, verify};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    ActionRequested,
    Decided,
    ApprovalRequested,
    Approved,
    Denied,
    Expired,
    Consumed,
    GrantIssued,
    GrantRevoked,
    PolicyLoaded,
    UserLogin,
    AgentAdded,
    KeyRotated,
    AnchorSent,
    AnchorFailed,
    NotifySent,
    NotifyFailed,
}

/// Deserialized entries are untrusted until verified with the caller's trusted keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    seq: u64,
    at: Timestamp,
    kind: AuditKind,
    actor: Principal,
    subject: Value,
    prev_hash: Digest,
    entry_hash: Digest,
    signature: Signature,
    key_id: String,
}

impl AuditEntry {
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn at(&self) -> Timestamp {
        self.at
    }
    pub fn kind(&self) -> AuditKind {
        self.kind
    }
    pub fn actor(&self) -> &Principal {
        &self.actor
    }
    pub fn subject(&self) -> &Value {
        &self.subject
    }
    pub fn prev_hash(&self) -> Digest {
        self.prev_hash
    }
    pub fn entry_hash(&self) -> Digest {
        self.entry_hash
    }
    pub fn signature(&self) -> Signature {
        self.signature
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub entry_hash: Digest,
    pub at: Timestamp,
    pub key_id: String,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSummary {
    pub count: u64,
    pub last_seq: u64,
    pub entry_hash: Digest,
    pub at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("empty audit chain")]
    Empty,
    #[error("sequence gap at {0}")]
    GapAt(u64),
    #[error("bad previous hash at {0}")]
    BadPrevHash(u64),
    #[error("bad entry hash at {0}")]
    BadEntryHash(u64),
    #[error("bad signature at {0}")]
    BadSignature(u64),
    #[error("unknown key {1} at {0}")]
    UnknownKey(u64, String),
    #[error("nonmonotonic time at {0}")]
    NonMonotonicTime(u64),
    #[error("chain ends at {last_seq} before checkpoint {checkpoint_seq}")]
    TruncatedBefore { checkpoint_seq: u64, last_seq: u64 },
    #[error("checkpoint does not match chain")]
    CheckpointMismatch,
    #[error("bad checkpoint signature")]
    BadCheckpointSignature,
}

fn canonical(value: &Value) -> Result<Vec<u8>, CoreError> {
    validate_integers(value, "")?;
    serde_jcs::to_vec(value).map_err(|e| CoreError::Canonicalization(e.to_string()))
}

fn hash_entry(
    seq: u64,
    at: Timestamp,
    kind: AuditKind,
    actor: &Principal,
    subject: &Value,
    key_id: &str,
    prev_hash: Digest,
) -> Result<Digest, CoreError> {
    let bytes = canonical(&json!({"v":1,"seq":seq,"at":at,"kind":kind,"actor":actor,
        "subject":subject,"key_id":key_id}))?;
    Ok(Digest::from(<[u8; 32]>::from(
        Sha256::new()
            .chain_update(prev_hash.as_bytes())
            .chain_update(bytes)
            .finalize(),
    )))
}

fn entry_message(entry_hash: Digest) -> Result<Vec<u8>, CoreError> {
    canonical(&json!({"v":1,"kind":"audit-entry","entry_hash":entry_hash}))
}

fn checkpoint_message(
    seq: u64,
    entry_hash: Digest,
    at: Timestamp,
    key_id: &str,
) -> Result<Vec<u8>, CoreError> {
    canonical(
        &json!({"v":1,"kind":"audit-checkpoint","seq":seq,"entry_hash":entry_hash,
        "at":at,"key_id":key_id}),
    )
}

/// Build the next entry. Times must not decrease and signed integers must be JCS-safe.
pub fn next_entry(
    prev: Option<&AuditEntry>,
    at: Timestamp,
    kind: AuditKind,
    actor: Principal,
    subject: Value,
    signer: &dyn Signer,
) -> Result<AuditEntry, CoreError> {
    let (seq, prev_hash) = match prev {
        Some(prev) => {
            if at < prev.at {
                return Err(CoreError::NonMonotonicAuditTime);
            }
            (
                prev.seq
                    .checked_add(1)
                    .ok_or(CoreError::AuditSequenceOverflow)?,
                prev.entry_hash,
            )
        }
        None => (0, Digest::from([0; 32])),
    };
    let key_id = signer.key_id().to_owned();
    let entry_hash = hash_entry(seq, at, kind, &actor, &subject, &key_id, prev_hash)?;
    let signature = signer.sign(&entry_message(entry_hash)?)?;
    Ok(AuditEntry {
        seq,
        at,
        kind,
        actor,
        subject,
        prev_hash,
        entry_hash,
        signature,
        key_id,
    })
}

/// Sign an anchor at or after the last entry's time, using the supplied signer.
pub fn checkpoint(
    last: &AuditEntry,
    at: Timestamp,
    signer: &dyn Signer,
) -> Result<Checkpoint, CoreError> {
    if at < last.at {
        return Err(CoreError::NonMonotonicAuditTime);
    }
    let key_id = signer.key_id().to_owned();
    let message = checkpoint_message(last.seq, last.entry_hash, at, &key_id)?;
    Ok(Checkpoint {
        seq: last.seq,
        entry_hash: last.entry_hash,
        at,
        key_id,
        signature: signer.sign(&message)?,
    })
}

fn verify_entries(
    entries: &[AuditEntry],
    keys: &BTreeMap<String, PublicKey>,
    start_seq: u64,
    start_hash: Digest,
) -> Result<ChainSummary, ChainError> {
    let last = entries.last().ok_or(ChainError::Empty)?;
    let mut prev_hash = start_hash;
    let mut prev_time: Option<Timestamp> = None;
    let mut expected_seq = start_seq;
    let mut count = 0_u64;
    let mut iter = entries.iter().peekable();
    while let Some(entry) = iter.next() {
        if entry.seq != expected_seq {
            return Err(ChainError::GapAt(expected_seq));
        }
        if entry.prev_hash != prev_hash {
            return Err(ChainError::BadPrevHash(expected_seq));
        }
        if prev_time.is_some_and(|at| entry.at < at) {
            return Err(ChainError::NonMonotonicTime(expected_seq));
        }
        let hash = hash_entry(
            entry.seq,
            entry.at,
            entry.kind,
            &entry.actor,
            &entry.subject,
            &entry.key_id,
            entry.prev_hash,
        )
        .map_err(|_| ChainError::BadEntryHash(expected_seq))?;
        if hash != entry.entry_hash {
            return Err(ChainError::BadEntryHash(expected_seq));
        }
        let key = keys
            .get(&entry.key_id)
            .ok_or_else(|| ChainError::UnknownKey(expected_seq, entry.key_id.clone()))?;
        let message = entry_message(hash).map_err(|_| ChainError::BadEntryHash(expected_seq))?;
        verify(key, &message, &entry.signature)
            .map_err(|_| ChainError::BadSignature(expected_seq))?;
        prev_hash = hash;
        prev_time = Some(entry.at);
        count = count.checked_add(1).ok_or(ChainError::GapAt(entry.seq))?;
        if iter.peek().is_some() {
            expected_seq = entry
                .seq
                .checked_add(1)
                .ok_or(ChainError::GapAt(entry.seq))?;
        }
    }
    Ok(ChainSummary {
        count,
        last_seq: last.seq,
        entry_hash: last.entry_hash,
        at: last.at,
    })
}

/// Verify from genesis. Key rotation records never add to the caller's trust map.
pub fn verify_chain(
    entries: &[AuditEntry],
    keys: &BTreeMap<String, PublicKey>,
) -> Result<ChainSummary, ChainError> {
    verify_entries(entries, keys, 0, Digest::from([0; 32]))
}

fn verify_checkpoint_signature(
    checkpoint: &Checkpoint,
    keys: &BTreeMap<String, PublicKey>,
) -> Result<(), ChainError> {
    let message = checkpoint_message(
        checkpoint.seq,
        checkpoint.entry_hash,
        checkpoint.at,
        &checkpoint.key_id,
    )
    .map_err(|_| ChainError::BadCheckpointSignature)?;
    let key = keys
        .get(&checkpoint.key_id)
        .ok_or(ChainError::BadCheckpointSignature)?;
    verify(key, &message, &checkpoint.signature).map_err(|_| ChainError::BadCheckpointSignature)
}

/// Authenticate a checkpoint signature against external trust anchors.
pub fn verify_checkpoint(
    checkpoint: &Checkpoint,
    keys: &BTreeMap<String, PublicKey>,
) -> Result<(), ChainError> {
    verify_checkpoint_signature(checkpoint, keys)
}

/// Verify a contiguous suffix whose first entry links to the supplied checkpoint.
pub fn verify_chain_from_checkpoint(
    entries: &[AuditEntry],
    keys: &BTreeMap<String, PublicKey>,
    checkpoint: &Checkpoint,
) -> Result<ChainSummary, ChainError> {
    verify_checkpoint_signature(checkpoint, keys)?;
    let first = entries.first().ok_or(ChainError::Empty)?;
    let expected_first_seq = checkpoint
        .seq
        .checked_add(1)
        .ok_or(ChainError::CheckpointMismatch)?;
    if first.seq != expected_first_seq {
        return Err(ChainError::GapAt(expected_first_seq));
    }
    verify_entries(entries, keys, expected_first_seq, checkpoint.entry_hash)
}

/// Authenticate the checkpoint and require its entry to occur in the verified chain.
pub fn verify_against_checkpoint(
    entries: &[AuditEntry],
    keys: &BTreeMap<String, PublicKey>,
    cp: &Checkpoint,
) -> Result<(), ChainError> {
    verify_checkpoint_signature(cp, keys)?;
    let summary = verify_chain(entries, keys)?;
    if summary.last_seq < cp.seq {
        return Err(ChainError::TruncatedBefore {
            checkpoint_seq: cp.seq,
            last_seq: summary.last_seq,
        });
    }
    let anchored = entries
        .iter()
        .find(|entry| entry.seq == cp.seq)
        .ok_or(ChainError::CheckpointMismatch)?;
    if anchored.entry_hash != cp.entry_hash || cp.at < anchored.at {
        return Err(ChainError::CheckpointMismatch);
    }
    Ok(())
}
