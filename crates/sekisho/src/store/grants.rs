use super::{AuditKind, AuditRecord, Principal, Store, StoreError, Tx};
use sekisho_core::{AgentId, Grant, GrantId, Timestamp, UserId};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct GrantView {
    pub grant: Grant,
    pub uses: u32,
    pub revoked: bool,
}

fn issued_subject(grant: &Grant) -> Value {
    json!({
        "grant_id": grant.id().as_str(),
        "agent_id": grant.agent_id().as_str(),
        "issued_by": grant.issued_by().as_str(),
        "expires_at": grant.expires_at(),
    })
}

fn revoked_subject(id: &GrantId, by: &UserId, now: Timestamp) -> Value {
    json!({
        "grant_id": id.as_str(),
        "revoked_by": by.as_str(),
        "revoked_at": now,
    })
}

fn encode(value: &Value) -> Result<String, StoreError> {
    Ok(serde_jcs::to_string(value)?)
}

fn decode_row(
    id: String,
    agent_id: String,
    expires_at: i64,
    uses: i64,
    body: String,
    revoked: bool,
) -> Result<GrantView, StoreError> {
    let grant: Grant = serde_json::from_str(&body)?;
    if encode(&serde_json::to_value(&grant)?)? != body {
        return Err(StoreError::InvalidGrant);
    }
    let uses = u32::try_from(uses).map_err(|_| StoreError::InvalidGrant)?;
    if grant.id().as_str() != id
        || grant.agent_id().as_str() != agent_id
        || grant.expires_at().as_secs() != expires_at
    {
        return Err(StoreError::InvalidGrant);
    }
    Ok(GrantView {
        grant,
        uses,
        revoked,
    })
}

impl Tx<'_> {
    pub fn insert_grant(&self, grant: &Grant) -> Result<(), StoreError> {
        self.checked(|| {
            let subject = issued_subject(grant);
            self.sql.execute(
                "INSERT INTO grants(id,agent_id,expires_at,uses,body) VALUES (?,?,?,0,?)",
                (
                    grant.id().as_str(),
                    grant.agent_id().as_str(),
                    grant.expires_at().as_secs(),
                    encode(&serde_json::to_value(grant)?)?,
                ),
            )?;
            self.changes.borrow_mut().push(subject);
            Ok(())
        })
    }

    pub fn revoke_grant(
        &self,
        id: &GrantId,
        by: &UserId,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        self.checked(|| {
            if now != self.now {
                return Err(StoreError::InvalidGrant);
            }
            let exists: bool = self.sql.query_row(
                "SELECT EXISTS(SELECT 1 FROM grants WHERE id=?)",
                [id.as_str()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(StoreError::GrantNotFound);
            }
            let subject = revoked_subject(id, by, now);
            self.sql.execute(
                "INSERT INTO grant_tombstones(id,body) VALUES (?,?)",
                (id.as_str(), encode(&subject)?),
            )?;
            self.changes.borrow_mut().push(subject);
            Ok(())
        })
    }

    pub fn grant_views_for(
        &self,
        agent: &AgentId,
        now: Timestamp,
    ) -> Result<Vec<GrantView>, StoreError> {
        self.checked(|| {
            let mut query = self.sql.prepare(
                "SELECT g.id,g.agent_id,g.expires_at,g.uses,g.body,t.id IS NOT NULL \
                 FROM grants g LEFT JOIN grant_tombstones t ON t.id=g.id \
                 WHERE g.agent_id=? AND g.expires_at>? ORDER BY g.id",
            )?;
            let rows = query.query_map((agent.as_str(), now.as_secs()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })?;
            let mut views = Vec::new();
            for row in rows {
                let (id, agent_id, expires_at, uses, body, revoked) = row?;
                let view = decode_row(id, agent_id, expires_at, uses, body, revoked)?;
                if view.grant.not_before() <= now {
                    views.push(view);
                }
            }
            Ok(views)
        })
    }

    pub fn record_grant_use(&self, id: &GrantId) -> Result<(), StoreError> {
        self.checked(|| {
            let changed = self.sql.execute(
                "UPDATE grants SET uses=uses+1 WHERE id=? AND uses<4294967295 \
                 AND NOT EXISTS(SELECT 1 FROM grant_tombstones WHERE id=?)",
                (id.as_str(), id.as_str()),
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidGrant);
            }
            let uses: u32 =
                self.sql
                    .query_row("SELECT uses FROM grants WHERE id=?", [id.as_str()], |r| {
                        r.get(0)
                    })?;
            self.changes
                .borrow_mut()
                .push(json!({"grant_id":id.as_str(), "uses":uses}));
            Ok(())
        })
    }
}

impl Store {
    pub fn issue_grant(&self, grant: &Grant, now: Timestamp) -> Result<(), StoreError> {
        self.transact(now, |tx| {
            tx.insert_grant(grant)?;
            Ok((
                (),
                vec![AuditRecord {
                    kind: AuditKind::GrantIssued,
                    actor: Principal::User(grant.issued_by().clone()),
                    subject: issued_subject(grant),
                }],
            ))
        })
    }

    pub fn revoke_grant(
        &self,
        id: &GrantId,
        by: &UserId,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        self.transact(now, |tx| {
            tx.revoke_grant(id, by, now)?;
            Ok((
                (),
                vec![AuditRecord {
                    kind: AuditKind::GrantRevoked,
                    actor: Principal::User(by.clone()),
                    subject: revoked_subject(id, by, now),
                }],
            ))
        })
    }

    pub fn list_grants(&self) -> Result<Vec<GrantView>, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut query = connection.prepare(
            "SELECT g.id,g.agent_id,g.expires_at,g.uses,g.body,t.id IS NOT NULL \
             FROM grants g LEFT JOIN grant_tombstones t ON t.id=g.id ORDER BY g.id",
        )?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?;
        rows.map(|row| {
            let (id, agent_id, expires_at, uses, body, revoked) = row?;
            decode_row(id, agent_id, expires_at, uses, body, revoked)
        })
        .collect()
    }
}

pub(super) fn check_records(changes: &[Value], records: &[AuditRecord]) -> Result<(), StoreError> {
    let grant_changes: Vec<_> = changes
        .iter()
        .filter(|change| change.get("grant_id").is_some())
        .collect();
    let grant_records: Vec<_> = records
        .iter()
        .filter(|record| record.subject.get("grant_id").is_some())
        .collect();
    if grant_changes.len() != grant_records.len() {
        return Err(StoreError::MissingAudit);
    }
    for (change, record) in grant_changes.into_iter().zip(grant_records) {
        if change.get("uses").is_some() {
            if record.kind != AuditKind::Consumed
                || record.subject["grant_id"] != change["grant_id"]
                || record.subject["uses"] != change["uses"]
                || serde_json::from_value::<sekisho_core::Digest>(
                    record.subject["action_digest"].clone(),
                )
                .is_err()
            {
                return Err(StoreError::MissingAudit);
            }
            continue;
        }
        let (kind, user) = if let Some(by) = change["revoked_by"].as_str() {
            (AuditKind::GrantRevoked, by)
        } else {
            let by = change["issued_by"]
                .as_str()
                .ok_or(StoreError::InvalidGrant)?;
            (AuditKind::GrantIssued, by)
        };
        let user = UserId::try_from(user)?;
        if record.kind != kind || record.subject != *change || record.actor != Principal::User(user)
        {
            return Err(StoreError::MissingAudit);
        }
    }
    Ok(())
}
