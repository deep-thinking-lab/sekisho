use super::{AuditRecord, Store, StoreError};
use rusqlite::{Connection, OptionalExtension, Transaction};
use sekisho_core::{
    AuditEntry, ChainError, ChainSummary, Checkpoint, PublicKey, Signer, Timestamp, checkpoint,
    next_entry, verify_against_checkpoint, verify_chain, verify_chain_from_checkpoint,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const AUDIT_PAGE_SIZE: u32 = 1_000;

enum ExportAnchor {
    Full(Checkpoint),
    Start(Checkpoint),
}

pub struct AuditExport {
    entries: Vec<AuditEntry>,
    anchor: ExportAnchor,
    public_keys: BTreeMap<String, PublicKey>,
}

#[derive(Serialize)]
struct ExportTrailer<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint: Option<&'a Checkpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_checkpoint: Option<&'a Checkpoint>,
    public_keys: &'a BTreeMap<String, PublicKey>,
}

impl AuditExport {
    pub fn jsonl(&self) -> Result<String, StoreError> {
        let mut contents = String::new();
        for entry in &self.entries {
            contents.push_str(&serde_json::to_string(entry)?);
            contents.push('\n');
        }
        let (checkpoint, start_checkpoint) = match &self.anchor {
            ExportAnchor::Full(checkpoint) => (Some(checkpoint), None),
            ExportAnchor::Start(checkpoint) => (None, Some(checkpoint)),
        };
        contents.push_str(&serde_json::to_string(&ExportTrailer {
            checkpoint,
            start_checkpoint,
            public_keys: &self.public_keys,
        })?);
        contents.push('\n');
        Ok(contents)
    }
}

fn decode_entry(seq: u64, body: &str) -> Result<AuditEntry, StoreError> {
    let entry: AuditEntry = serde_json::from_str(body)?;
    if entry.seq() != seq {
        return Err(ChainError::GapAt(seq).into());
    }
    Ok(entry)
}

pub(super) fn entries(
    connection: &Connection,
    from_seq: u64,
    limit: u32,
) -> Result<Vec<AuditEntry>, StoreError> {
    let Ok(from_seq) = i64::try_from(from_seq) else {
        return Ok(Vec::new());
    };
    let mut query =
        connection.prepare("SELECT seq, body FROM audit WHERE seq >= ? ORDER BY seq LIMIT ?")?;
    let rows = query.query_map((from_seq, limit), |r| {
        Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (seq, body) = row?;
        decode_entry(seq, &body)
    })
    .collect()
}

fn snapshot(connection: &Connection) -> Result<Vec<AuditEntry>, StoreError> {
    let mut all = Vec::new();
    let mut from_seq = 0;
    loop {
        let page = entries(connection, from_seq, AUDIT_PAGE_SIZE)?;
        let page_len = page.len();
        let last_seq = page.last().map(AuditEntry::seq).unwrap_or(from_seq);
        all.extend(page);
        if page_len < AUDIT_PAGE_SIZE as usize {
            return Ok(all);
        }
        from_seq = last_seq
            .checked_add(1)
            .ok_or(StoreError::Chain(ChainError::GapAt(last_seq)))?;
    }
}

pub(super) fn append(
    tx: &Transaction<'_>,
    now: Timestamp,
    records: Vec<AuditRecord>,
    signer: &dyn Signer,
) -> Result<(), StoreError> {
    let body: Option<String> = tx
        .query_row(
            "SELECT body FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let mut previous: Option<AuditEntry> = body.map(|b| serde_json::from_str(&b)).transpose()?;
    for record in records {
        let entry = next_entry(
            previous.as_ref(),
            now,
            record.kind,
            record.actor,
            record.subject,
            signer,
        )?;
        let body = serde_jcs::to_string(&entry)?;
        tx.execute(
            "INSERT INTO audit(seq, body) VALUES (?, ?)",
            (entry.seq(), body),
        )?;
        previous = Some(entry);
    }
    Ok(())
}

impl Store {
    pub fn audit_entries(&self, from_seq: u64, limit: u32) -> Result<Vec<AuditEntry>, StoreError> {
        entries(&self.lock(), from_seq, limit)
    }
    pub fn audit_snapshot(&self) -> Result<Vec<AuditEntry>, StoreError> {
        snapshot(&self.lock())
    }
    pub fn audit_page(
        &self,
        page: u64,
        page_size: u32,
    ) -> Result<(Vec<AuditEntry>, u64), StoreError> {
        let connection = self.lock();
        let total: u64 =
            connection.query_row("SELECT count(*) FROM audit", [], |row| row.get(0))?;
        if page_size == 0 {
            return Ok((Vec::new(), total));
        }
        let offset = page.saturating_sub(1).saturating_mul(u64::from(page_size));
        let Ok(offset) = i64::try_from(offset) else {
            return Ok((Vec::new(), total));
        };
        let mut query =
            connection.prepare("SELECT seq, body FROM audit ORDER BY seq DESC LIMIT ? OFFSET ?")?;
        let rows = query.query_map((page_size, offset), |row| {
            Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
        })?;
        let entries = rows
            .map(|row| {
                let (seq, body) = row?;
                decode_entry(seq, &body)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok((entries, total))
    }
    pub fn audit_entry(&self, seq: u64) -> Result<Option<AuditEntry>, StoreError> {
        let connection = self.lock();
        let body: Option<String> = connection
            .query_row("SELECT body FROM audit WHERE seq=?", [seq], |row| {
                row.get(0)
            })
            .optional()?;
        body.as_deref()
            .map(|body| decode_entry(seq, body))
            .transpose()
    }
    pub fn audit_latest_entry(&self) -> Result<Option<AuditEntry>, StoreError> {
        let connection = self.lock();
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        body.map(|body| serde_json::from_str(&body).map_err(StoreError::from))
            .transpose()
    }
    pub fn audit_latest_anchor_attempt(&self) -> Result<Option<AuditEntry>, StoreError> {
        let connection = self.lock();
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM audit WHERE json_extract(body, '$.kind') IN ('AnchorSent', 'AnchorFailed') ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        body.map(|body| serde_json::from_str(&body).map_err(StoreError::from))
            .transpose()
    }
    pub fn audit_checkpoint(&self) -> Result<Option<Checkpoint>, StoreError> {
        let connection = self.lock();
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(body) = body else {
            return Ok(None);
        };
        let last: AuditEntry = serde_json::from_str(&body)?;
        checkpoint(&last, last.at(), self.signer.as_ref())
            .map(Some)
            .map_err(StoreError::from)
    }
    pub fn audit_checkpoint_at(&self, at: Timestamp) -> Result<Option<Checkpoint>, StoreError> {
        let connection = self.lock();
        let body: Option<String> = connection
            .query_row(
                "SELECT body FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(body) = body else {
            return Ok(None);
        };
        let last: AuditEntry = serde_json::from_str(&body)?;
        checkpoint(&last, at.max(last.at()), self.signer.as_ref())
            .map(Some)
            .map_err(StoreError::from)
    }
    pub fn audit_export(&self, at: Timestamp, from_seq: u64) -> Result<AuditExport, StoreError> {
        let connection = self.lock();
        let all = snapshot(&connection)?;
        let last = all.last().ok_or(StoreError::Chain(ChainError::Empty))?;
        for entry in &all {
            if !self.audit_keys.contains_key(entry.key_id()) {
                return Err(StoreError::Chain(ChainError::UnknownKey(
                    entry.seq(),
                    entry.key_id().to_owned(),
                )));
            }
        }
        verify_chain(&all, &self.audit_keys)?;
        let start = all.partition_point(|entry| entry.seq() < from_seq);
        if start == all.len() {
            return Err(StoreError::InvalidAuditExport(
                "requested start is after the last audit entry".to_owned(),
            ));
        }
        let entries = all[start..].to_vec();
        let checkpoint = if start == 0 {
            checkpoint(last, at.max(last.at()), self.signer.as_ref())?
        } else {
            let previous = &all[start - 1];
            checkpoint(previous, at.max(previous.at()), self.signer.as_ref())?
        };
        let used = entries
            .iter()
            .map(|entry| entry.key_id().to_owned())
            .chain(std::iter::once(checkpoint.key_id.clone()))
            .collect::<BTreeSet<_>>();
        let public_keys = self
            .audit_keys
            .iter()
            .filter(|(key_id, _)| used.contains(*key_id))
            .map(|(key_id, key)| (key_id.clone(), *key))
            .collect::<BTreeMap<_, _>>();
        let anchor = if start == 0 {
            verify_against_checkpoint(&all, &public_keys, &checkpoint)?;
            ExportAnchor::Full(checkpoint)
        } else {
            verify_chain_from_checkpoint(&entries, &public_keys, &checkpoint)?;
            ExportAnchor::Start(checkpoint)
        };
        Ok(AuditExport {
            entries,
            anchor,
            public_keys,
        })
    }
    pub(super) fn verified_audit_entries(
        &self,
        keys: &BTreeMap<String, PublicKey>,
    ) -> Result<(Vec<AuditEntry>, ChainSummary), StoreError> {
        let mut all = Vec::new();
        let mut from_seq = 0;
        let mut last_summary = None;
        loop {
            let page = self.audit_entries(from_seq, AUDIT_PAGE_SIZE)?;
            if page.is_empty() {
                return last_summary
                    .map(|summary| (all, summary))
                    .ok_or(StoreError::Chain(ChainError::Empty));
            }
            let page_len = page.len();
            let last_seq = page.last().map(AuditEntry::seq).unwrap_or(from_seq);
            all.extend(page);
            let summary = verify_chain(&all, keys)?;
            if page_len < AUDIT_PAGE_SIZE as usize {
                return Ok((all, summary));
            }
            last_summary = Some(summary);
            from_seq = last_seq
                .checked_add(1)
                .ok_or(StoreError::Chain(ChainError::GapAt(last_seq)))?;
        }
    }
    pub fn verify_audit(
        &self,
        keys: &BTreeMap<String, PublicKey>,
    ) -> Result<ChainSummary, StoreError> {
        self.verified_audit_entries(keys)
            .map(|(_, summary)| summary)
    }
}
