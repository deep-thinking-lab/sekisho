use super::{AuditKind, AuditRecord, Principal, Store, StoreError, Tx};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sekisho_core::{AgentId, Timestamp, UserId};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const TOKEN_BYTES: usize = 32;

/// Secret bearer token. It intentionally has no `Debug` implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentToken(String);

impl AgentToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Store {
    pub fn add_agent(
        &self,
        id: &AgentId,
        actor: &UserId,
        now: Timestamp,
    ) -> Result<AgentToken, StoreError> {
        let token = generate_token()?;
        let hash = token_hash(token.expose());
        self.transact(now, |tx| {
            tx.insert_agent(id, &hash, actor)?;
            Ok(((), vec![agent_record(id, actor, "added")]))
        })?;
        Ok(token)
    }

    pub fn rotate_agent(
        &self,
        id: &AgentId,
        actor: &UserId,
        now: Timestamp,
    ) -> Result<AgentToken, StoreError> {
        let token = generate_token()?;
        let hash = token_hash(token.expose());
        self.transact(now, |tx| {
            tx.rotate_agent(id, &hash, actor)?;
            Ok(((), vec![agent_record(id, actor, "rotated")]))
        })?;
        Ok(token)
    }

    pub fn remove_agent(
        &self,
        id: &AgentId,
        actor: &UserId,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        self.transact(now, |tx| {
            tx.remove_agent(id, actor)?;
            Ok(((), vec![agent_record(id, actor, "removed")]))
        })
    }

    pub fn list_agents(&self) -> Result<Vec<AgentId>, StoreError> {
        let connection = self.lock();
        let mut query =
            connection.prepare("SELECT id, body, token_hash FROM agents ORDER BY id")?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut agents = Vec::new();
        for row in rows {
            let (id, body, stored) = row?;
            if stored.len() != TOKEN_BYTES {
                return Err(StoreError::InvalidAgent);
            }
            agents.push(decode_agent(&id, &body)?);
        }
        Ok(agents)
    }

    pub fn authenticate_agent(&self, token: &str) -> Result<Option<AgentId>, StoreError> {
        if !valid_token(token) {
            return Ok(None);
        }
        let presented = token_hash(token);
        let connection = self.lock();
        let mut query =
            connection.prepare("SELECT id, body, token_hash FROM agents ORDER BY id")?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut found = None;
        for row in rows {
            let (id, body, stored) = row?;
            let id = decode_agent(&id, &body)?;
            if stored.len() != TOKEN_BYTES {
                return Err(StoreError::InvalidAgent);
            }
            if constant_time_eq(&presented, &stored) {
                if found.is_some() {
                    return Err(StoreError::InvalidAgent);
                }
                found = Some(id);
            }
        }
        Ok(found)
    }
}

impl Tx<'_> {
    fn insert_agent(
        &self,
        id: &AgentId,
        hash: &[u8; TOKEN_BYTES],
        actor: &UserId,
    ) -> Result<(), StoreError> {
        self.checked(|| {
            let exists: bool = self.sql.query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE id=?)",
                [id.as_str()],
                |row| row.get(0),
            )?;
            if exists {
                return Err(StoreError::AgentAlreadyExists);
            }
            self.sql.execute(
                "INSERT INTO agents(id, body, token_hash) VALUES (?, ?, ?)",
                (id.as_str(), agent_body(id)?, hash.as_slice()),
            )?;
            self.changes
                .borrow_mut()
                .push(agent_change(id, actor, "added"));
            Ok(())
        })
    }

    fn rotate_agent(
        &self,
        id: &AgentId,
        hash: &[u8; TOKEN_BYTES],
        actor: &UserId,
    ) -> Result<(), StoreError> {
        self.checked(|| {
            let changed = self.sql.execute(
                "UPDATE agents SET token_hash=? WHERE id=?",
                (hash.as_slice(), id.as_str()),
            )?;
            if changed != 1 {
                return Err(StoreError::AgentNotFound);
            }
            self.changes
                .borrow_mut()
                .push(agent_change(id, actor, "rotated"));
            Ok(())
        })
    }

    fn remove_agent(&self, id: &AgentId, actor: &UserId) -> Result<(), StoreError> {
        self.checked(|| {
            let changed = self
                .sql
                .execute("DELETE FROM agents WHERE id=?", [id.as_str()])?;
            if changed != 1 {
                return Err(StoreError::AgentNotFound);
            }
            self.changes
                .borrow_mut()
                .push(agent_change(id, actor, "removed"));
            Ok(())
        })
    }
}

fn generate_token() -> Result<AgentToken, StoreError> {
    let mut bytes = [0; TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StoreError::TokenGeneration)?;
    Ok(AgentToken(URL_SAFE_NO_PAD.encode(bytes)))
}

fn valid_token(token: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(token)
        .is_ok_and(|bytes| bytes.len() == TOKEN_BYTES)
}

fn token_hash(token: &str) -> [u8; TOKEN_BYTES] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn agent_body(id: &AgentId) -> Result<String, StoreError> {
    Ok(serde_jcs::to_string(&json!({"agent_id": id.as_str()}))?)
}

fn decode_agent(id: &str, body: &str) -> Result<AgentId, StoreError> {
    let value: Value = serde_json::from_str(body)?;
    let agent = AgentId::try_from(id)?;
    if value != json!({"agent_id": id}) || serde_jcs::to_string(&value)? != body {
        return Err(StoreError::InvalidAgent);
    }
    Ok(agent)
}

fn agent_change(id: &AgentId, actor: &UserId, event: &str) -> Value {
    json!({
        "agent_id": id.as_str(),
        "agent_event": event,
        "actor_id": actor.as_str(),
    })
}

fn agent_record(id: &AgentId, actor: &UserId, event: &str) -> AuditRecord {
    AuditRecord {
        kind: AuditKind::AgentAdded,
        actor: Principal::User(actor.clone()),
        subject: agent_change(id, actor, event),
    }
}

pub(super) fn check_records(changes: &[Value], records: &[AuditRecord]) -> Result<(), StoreError> {
    let changes: Vec<_> = changes
        .iter()
        .filter(|change| change.get("agent_event").is_some())
        .collect();
    let records: Vec<_> = records
        .iter()
        .filter(|record| record.subject.get("agent_event").is_some())
        .collect();
    if changes.len() != records.len() {
        return Err(StoreError::MissingAudit);
    }
    for (change, record) in changes.into_iter().zip(records) {
        let actor = change["actor_id"]
            .as_str()
            .ok_or(StoreError::InvalidAgent)?;
        if record.kind != AuditKind::AgentAdded
            || record.subject != *change
            || record.actor != Principal::User(UserId::try_from(actor)?)
        {
            return Err(StoreError::MissingAudit);
        }
    }
    Ok(())
}
