use super::{AuditRecord, Store, StoreError, Tx};
use rusqlite::OptionalExtension;
use sekisho_core::{
    Approval, ApprovalId, ApprovalState, AuditKind, Digest, Principal, PublicKey, Timestamp,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn state(a: &Approval) -> &'static str {
    match a.state() {
        ApprovalState::Pending => "Pending",
        ApprovalState::Approved => "Approved",
        ApprovalState::Denied => "Denied",
        ApprovalState::Expired => "Expired",
        ApprovalState::Consumed => "Consumed",
    }
}

fn body(a: &Approval) -> Value {
    json!({"id":a.id().as_str(), "action":a.action(), "action_digest":a.action_digest(),
        "rule":a.rule(), "requested_at":a.requested_at(), "expires_at":a.expires_at(),
        "state":state(a), "decided_by":a.decided_by(), "decided_at":a.decided_at(),
        "consumed_at":a.consumed_at()})
}
fn encode(a: &Approval) -> Result<String, StoreError> {
    let value = body(a);
    let encoded = serde_jcs::to_string(&value)?;
    let decoded: Value = serde_json::from_str(&encoded)?;
    for field in ["requested_at", "expires_at", "decided_at", "consumed_at"] {
        if value[field] != decoded[field] {
            return Err(StoreError::InvalidApproval);
        }
    }
    Ok(encoded)
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, StoreError> {
    v[key].as_str().ok_or(StoreError::InvalidApproval)
}
fn time(v: &Value, key: &str) -> Result<Timestamp, StoreError> {
    Ok(v[key].as_i64().ok_or(StoreError::InvalidApproval)?.into())
}

fn decode(v: &Value) -> Result<Approval, StoreError> {
    let requested = time(v, "requested_at")?;
    let ttl = time(v, "expires_at")?
        .as_secs()
        .checked_sub(requested.as_secs())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(StoreError::InvalidApproval)?;
    let mut a = Approval::request(
        ApprovalId::try_from(text(v, "id")?)?,
        serde_json::from_value(v["action"].clone())?,
        text(v, "rule")?.to_owned(),
        requested,
        ttl,
    )?;
    let target = text(v, "state")?;
    if !v["decided_by"].is_null() {
        let actor = Principal::User(serde_json::from_value(v["decided_by"].clone())?);
        let at = time(v, "decided_at")?;
        a = if target == "Denied" {
            a.deny(&actor, at)?
        } else {
            a.approve(&actor, at)?
        };
    }
    a = match target {
        "Pending" | "Approved" | "Denied" => a,
        "Expired" => a.expire(a.expires_at())?,
        "Consumed" => a.consume(a.action_digest(), time(v, "consumed_at")?)?,
        _ => return Err(StoreError::InvalidApproval),
    };
    if body(&a) != *v {
        return Err(StoreError::InvalidApproval);
    }
    Ok(a)
}

type ApprovalColumns = (String, String, String, i64, String);

fn columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalColumns> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn checked(
    expected: Option<&ApprovalId>,
    (encoded, stored_state, agent, expires, digest): ApprovalColumns,
) -> Result<Approval, StoreError> {
    let approval = decode(&serde_json::from_str(&encoded)?)?;
    if expected.is_some_and(|id| approval.id() != id)
        || state(&approval) != stored_state
        || approval.action().agent_id().as_str() != agent
        || approval.expires_at().as_secs() != expires
        || approval.action_digest().to_string() != digest
    {
        return Err(StoreError::InvalidApproval);
    }
    Ok(approval)
}

fn advance(old: &Approval, new: &Approval, now: Timestamp) -> Result<Approval, StoreError> {
    Ok(match new.state() {
        ApprovalState::Approved | ApprovalState::Denied => {
            let by = Principal::User(new.decided_by().ok_or(StoreError::InvalidApproval)?.clone());
            if new.state() == ApprovalState::Approved {
                old.approve(&by, now)?
            } else {
                old.deny(&by, now)?
            }
        }
        ApprovalState::Expired => old.expire(now)?,
        ApprovalState::Consumed => old.consume(new.action_digest(), now)?,
        ApprovalState::Pending => return Err(StoreError::InvalidApproval),
    })
}

/// Consumption failures include refused transitions and rolled-back storage/audit failures.
pub type ConsumeError = StoreError;

impl Tx<'_> {
    pub(crate) fn approved_for_digest(
        &self,
        digest: &Digest,
    ) -> Result<Option<ApprovalId>, StoreError> {
        self.checked(|| {
            let id: Option<String> = self.sql.query_row(
                "SELECT id FROM approvals WHERE state='Approved' AND action_digest=? AND expires_at>? ORDER BY id LIMIT 1",
                (digest.to_string(), self.now.as_secs()), |r| r.get(0),
            ).optional()?;
            id.map(|id| ApprovalId::try_from(id.as_str()).map_err(StoreError::from)).transpose()
        })
    }

    pub(crate) fn consume_approval(
        &self,
        id: &ApprovalId,
        digest: &Digest,
    ) -> Result<(Approval, AuditRecord), ConsumeError> {
        self.checked(|| {
            let old = self.get_approval(id)?.ok_or(StoreError::InvalidApproval)?;
            let changed = self.sql.execute(
                "UPDATE approvals SET state='Consumed' WHERE id=? AND state='Approved' AND action_digest=? AND expires_at>?",
                (id.as_str(), digest.to_string(), self.now.as_secs()),
            )?;
            if changed != 1 { return Err(StoreError::InvalidApproval); }
            let consumed = old.consume(digest, self.now)?;
            self.sql.execute("UPDATE approvals SET body=? WHERE id=?", (encode(&consumed)?, id.as_str()))?;
            self.changes.borrow_mut().push(body(&consumed));
            let record = AuditRecord {
                kind: AuditKind::Consumed,
                actor: Principal::Agent(consumed.action().agent_id().clone()),
                subject: json!({"approval_id":id.as_str(), "action_digest":digest, "state":"Consumed"}),
            };
            Ok((consumed, record))
        })
    }

    /// Live pending approvals requested by `agent`.
    pub(crate) fn pending_count(&self, agent: &sekisho_core::AgentId) -> Result<u32, StoreError> {
        self.checked(|| {
            Ok(self.sql.query_row(
                "SELECT count(*) FROM approvals WHERE agent_id=? AND state='Pending' AND expires_at>?",
                (agent.as_str(), self.now.as_secs()),
                |r| r.get(0),
            )?)
        })
    }

    pub fn insert_approval(&self, a: &Approval) -> Result<(), StoreError> {
        self.checked(|| {
            if a.state() != ApprovalState::Pending || a.requested_at() != self.now {
                return Err(StoreError::InvalidApproval);
            }
            self.sql.execute(
                "INSERT INTO approvals(id,state,agent_id,expires_at,action_digest,body) VALUES (?,?,?,?,?,?)",
                (
                    a.id().as_str(),
                    state(a),
                    a.action().agent_id().as_str(),
                    a.expires_at().as_secs(),
                    a.action_digest().to_string(),
                    encode(a)?,
                ),
            )?;
            self.changes.borrow_mut().push(body(a));
            Ok(())
        })
    }
    pub fn update_approval(&self, a: &Approval) -> Result<(), StoreError> {
        self.checked(|| {
            let old = self
                .get_approval(a.id())?
                .ok_or(StoreError::InvalidApproval)?;
            if encode(&advance(&old, a, self.now)?)? != encode(a)? {
                return Err(StoreError::InvalidApproval);
            }
            if a.state() == ApprovalState::Consumed {
                let (consumed, _) = self.consume_approval(a.id(), a.action_digest())?;
                if consumed != *a {
                    return Err(StoreError::InvalidApproval);
                }
                return Ok(());
            }
            let changed = self.sql.execute(
                "UPDATE approvals SET state=?, body=? WHERE id=? AND state=? AND action_digest=?",
                (
                    state(a),
                    encode(a)?,
                    a.id().as_str(),
                    state(&old),
                    a.action_digest().to_string(),
                ),
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidApproval);
            }
            self.changes.borrow_mut().push(body(a));
            Ok(())
        })
    }
    pub fn get_approval(&self, id: &ApprovalId) -> Result<Option<Approval>, StoreError> {
        self.checked(|| {
            let row = self
                .sql
                .query_row(
                    "SELECT body,state,agent_id,expires_at,action_digest FROM approvals WHERE id=?",
                    [id.as_str()],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, i64>(3)?,
                            r.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()?;
            row.map(|(encoded, stored_state, agent, expires, digest)| {
                checked(Some(id), (encoded, stored_state, agent, expires, digest))
            })
            .transpose()
        })
    }
}

impl Store {
    pub(crate) fn approval(&self, id: &ApprovalId) -> Result<Option<Approval>, StoreError> {
        let row = self
            .lock()
            .query_row(
                "SELECT body,state,agent_id,expires_at,action_digest FROM approvals WHERE id=?",
                [id.as_str()],
                columns,
            )
            .optional()?;
        row.map(|row| checked(Some(id), row)).transpose()
    }

    pub(crate) fn pending_approvals(&self, now: Timestamp) -> Result<Vec<Approval>, StoreError> {
        let connection = self.lock();
        let mut query = connection.prepare(
            "SELECT body,state,agent_id,expires_at,action_digest
             FROM approvals WHERE state='Pending' AND expires_at>?",
        )?;
        let rows = query
            .query_map([now.as_secs()], columns)?
            .collect::<Result<Vec<_>, _>>()?;
        drop(query);
        let mut approvals = rows
            .into_iter()
            .map(|row| checked(None, row))
            .collect::<Result<Vec<_>, _>>()?;
        approvals.retain(|approval| {
            approval.state() == ApprovalState::Pending && now < approval.expires_at()
        });
        approvals.sort_by(|left, right| {
            right
                .requested_at()
                .as_secs()
                .cmp(&left.requested_at().as_secs())
                .then_with(|| left.id().as_str().cmp(right.id().as_str()))
        });
        Ok(approvals)
    }
}

pub(super) fn check_records(changes: &[Value], records: &[AuditRecord]) -> Result<(), StoreError> {
    let approval_changes: Vec<_> = changes
        .iter()
        .filter(|change| change.get("action_digest").is_some())
        .collect();
    let approvals: Vec<_> = records
        .iter()
        .filter(|r| r.subject.get("approval_id").is_some())
        .collect();
    if approvals.len() != approval_changes.len() {
        return Err(StoreError::MissingAudit);
    }
    for (change, record) in approval_changes.into_iter().zip(approvals) {
        let kind = match text(change, "state")? {
            "Pending" => AuditKind::ApprovalRequested,
            "Approved" => AuditKind::Approved,
            "Denied" => AuditKind::Denied,
            "Expired" => AuditKind::Expired,
            "Consumed" => AuditKind::Consumed,
            _ => return Err(StoreError::InvalidApproval),
        };
        if record.kind != kind
            || record.subject["approval_id"] != change["id"]
            || record.subject["state"] != change["state"]
            || record.subject["action_digest"] != change["action_digest"]
        {
            return Err(StoreError::MissingAudit);
        }
    }
    Ok(())
}

impl Store {
    /// Consume exactly once, bound to the action about to run, with a signed audit entry.
    pub fn consume_approval(
        &self,
        id: &ApprovalId,
        digest: &Digest,
        now: Timestamp,
    ) -> Result<Approval, ConsumeError> {
        self.transact(now, |tx| {
            let (approval, record) = tx.consume_approval(id, digest)?;
            Ok((approval, vec![record]))
        })
    }

    /// Compare stored approvals with their latest state in an authenticated chain.
    pub fn check_approval_consistency(
        &self,
        keys: &BTreeMap<String, PublicKey>,
    ) -> Result<Vec<ApprovalId>, StoreError> {
        let (entries, _) = self.verified_audit_entries(keys)?;
        let mut latest = BTreeMap::new();
        for entry in entries {
            if let Some(id) = entry.subject()["approval_id"].as_str() {
                latest.insert(id.to_owned(), entry.subject().clone());
            }
        }
        let connection = self.lock();
        let mut query = connection
            .prepare("SELECT id,state,action_digest,body,agent_id,expires_at FROM approvals")?;
        let rows = query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut mismatches = Vec::new();
        for row in rows {
            let (id, stored_state, digest, encoded, agent, expires) = row?;
            let subject = latest.remove(&id);
            let a = serde_json::from_str(&encoded)
                .map_err(StoreError::from)
                .and_then(|v| decode(&v));
            let valid = a.is_ok_and(|a| {
                a.id().as_str() == id
                    && state(&a) == stored_state
                    && a.action_digest().to_string() == digest
                    && a.action().agent_id().as_str() == agent
                    && a.expires_at().as_secs() == expires
            });
            if !valid
                || !subject
                    .is_some_and(|v| v["state"] == stored_state && v["action_digest"] == digest)
            {
                mismatches.push(ApprovalId::try_from(id.as_str())?);
            }
        }
        for id in latest.keys() {
            mismatches.push(ApprovalId::try_from(id.as_str())?);
        }
        mismatches.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(mismatches)
    }
}
