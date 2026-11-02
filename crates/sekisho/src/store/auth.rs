use super::{AuditRecord, Store};
use crate::server::{
    AuthStoreError, Session, SessionStore, SessionToken, User, UserDirectory, session::random_token,
};
use rusqlite::OptionalExtension;
use sekisho_core::{AuditKind, Digest, Principal, Timestamp, UserId};
use serde_json::json;
use sha2::{Digest as _, Sha256};

fn token_hash(token: &SessionToken) -> String {
    Digest::from(<[u8; 32]>::from(Sha256::digest(token.expose().as_bytes()))).to_string()
}
fn record(user: &UserId, operation: &str) -> AuditRecord {
    AuditRecord {
        kind: AuditKind::UserLogin,
        actor: Principal::User(user.clone()),
        subject: json!({"user_id": user, "operation": operation}),
    }
}
impl UserDirectory for Store {
    fn find(&self, id: &UserId) -> Result<Option<User>, AuthStoreError> {
        let body: Option<String> = self
            .lock()
            .query_row("SELECT body FROM users WHERE id=?", [id.as_str()], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|_| AuthStoreError)?;
        body.map(|body| {
            let user: User = serde_json::from_str(&body).map_err(|_| AuthStoreError)?;
            if user.id != *id {
                return Err(AuthStoreError);
            }
            Ok(user)
        })
        .transpose()
    }
}
impl SessionStore for Store {
    fn create(
        &self,
        user: &UserId,
        now: Timestamp,
        ttl_seconds: u32,
        totp_step: Option<u64>,
    ) -> Result<Option<SessionToken>, AuthStoreError> {
        let token = SessionToken::from_cookie(&random_token()?);
        let session = Session {
            user: user.clone(),
            csrf_token: random_token()?,
            expires_at: now
                .as_secs()
                .checked_add(i64::from(ttl_seconds))
                .ok_or(AuthStoreError)?
                .into(),
        };
        let step = totp_step
            .map(i64::try_from)
            .transpose()
            .map_err(|_| AuthStoreError)?;
        self.transact(now, |tx| {
            if let Some(step) = step {
                let changed = tx.sql.execute(
                    "UPDATE users SET last_totp_step=? WHERE id=? AND (last_totp_step IS NULL OR last_totp_step < ?)",
                    (step, user.as_str(), step),
                )?;
                if changed != 1 { return Ok((None, vec![])); }
            }
            tx.sql.execute(
                "INSERT INTO sessions(id,user_id,expires_at,body) VALUES (?,?,?,?)",
                (token_hash(&token), user.as_str(), session.expires_at.as_secs(), serde_json::to_string(&session)?),
            )?;
            Ok((Some(token), vec![record(user, "login")]))
        }).map_err(|_| AuthStoreError)
    }
    fn get(&self, token: &SessionToken, now: Timestamp) -> Result<Option<Session>, AuthStoreError> {
        let row = self
            .lock()
            .query_row(
                "SELECT user_id,expires_at,body FROM sessions WHERE id=? AND expires_at>?",
                (token_hash(token), now.as_secs()),
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthStoreError)?;
        row.map(|(user, expires, body)| {
            let session: Session = serde_json::from_str(&body).map_err(|_| AuthStoreError)?;
            if session.user.as_str() != user || session.expires_at.as_secs() != expires {
                return Err(AuthStoreError);
            }
            Ok(session)
        })
        .transpose()
    }
    fn accept_totp_step(
        &self,
        user: &UserId,
        step: u64,
        now: Timestamp,
    ) -> Result<bool, AuthStoreError> {
        match self.transact(now, |tx| {
            tx.consume_totp_step(user, step).map(|()| (true, vec![]))
        }) {
            Ok(accepted) => Ok(accepted),
            Err(super::StoreError::TotpReplay) => Ok(false),
            Err(_) => Err(AuthStoreError),
        }
    }
    fn revoke(&self, token: &SessionToken, now: Timestamp) -> Result<(), AuthStoreError> {
        self.transact(now, |tx| {
            let hash = token_hash(token);
            let user: Option<String> = tx
                .sql
                .query_row("SELECT user_id FROM sessions WHERE id=?", [&hash], |r| {
                    r.get(0)
                })
                .optional()?;
            let Some(user) = user else {
                return Ok(((), vec![]));
            };
            let user = UserId::try_from(user.as_str())?;
            tx.sql.execute("DELETE FROM sessions WHERE id=?", [&hash])?;
            Ok(((), vec![record(&user, "logout")]))
        })
        .map_err(|_| AuthStoreError)
    }
}

impl Store {
    /// `totp` is consumed in the same transaction; a used step refuses the load.
    pub fn record_policy_load(
        &self,
        policy_sha256: Digest,
        actor: &Principal,
        now: Timestamp,
        totp: Option<(&UserId, u64)>,
    ) -> Result<(), super::StoreError> {
        self.transact(now, |tx| {
            // Reload must refuse poisoned state even though ordinary transactions can recover.
            if self.connection.is_poisoned() {
                return Err(super::StoreError::Poisoned);
            }
            if let Some((user, step)) = totp {
                tx.consume_totp_step(user, step)?;
            }
            Ok((
                (),
                vec![AuditRecord {
                    kind: AuditKind::PolicyLoaded,
                    actor: actor.clone(),
                    subject: json!({"policy_sha256": policy_sha256}),
                }],
            ))
        })
    }

    pub fn bootstrap_admin(&self) -> Result<Option<UserId>, super::StoreError> {
        let entries = self.audit_entries(0, 1)?;
        let Some(entry) = entries.first() else {
            return Ok(None);
        };
        if entry.kind() != AuditKind::UserLogin || entry.subject()["operation"] != "bootstrap_admin"
        {
            return Ok(None);
        }
        let Principal::User(id) = entry.actor() else {
            return Ok(None);
        };
        if entry.subject()["user_id"] != id.as_str() {
            return Ok(None);
        }
        Ok(Some(id.clone()))
    }

    pub fn has_users(&self) -> Result<bool, super::StoreError> {
        Ok(self
            .lock()
            .query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |r| r.get(0))?)
    }

    /// Bootstrap credentials and the policy load are audited atomically.
    pub fn startup(
        &self,
        admin: Option<&User>,
        policy_sha256: Digest,
        now: Timestamp,
    ) -> Result<(), super::StoreError> {
        if let Some(admin) = admin {
            admin.id.ensure_human()?;
        }
        self.transact(now, |tx| {
            let mut records = Vec::new();
            let actor = if let Some(admin) = admin {
                let changed = tx.sql.execute(
                    "INSERT INTO users(id,body) SELECT ?,? WHERE NOT EXISTS(SELECT 1 FROM users)",
                    (admin.id.as_str(), serde_json::to_string(admin)?),
                )?;
                if changed != 1 {
                    return Err(super::StoreError::TransactionFailed);
                }
                records.push(record(&admin.id, "bootstrap_admin"));
                admin.id.clone()
            } else {
                let id: String =
                    tx.sql
                        .query_row("SELECT id FROM users ORDER BY id LIMIT 1", [], |r| r.get(0))?;
                UserId::try_from(id.as_str())?
            };
            records.push(AuditRecord {
                kind: AuditKind::PolicyLoaded,
                actor: Principal::User(actor),
                subject: json!({"policy_sha256": policy_sha256}),
            });
            Ok(((), records))
        })
    }
}

impl super::Tx<'_> {
    /// Advance the user's last accepted TOTP step, or fail with `TotpReplay`.
    pub(crate) fn consume_totp_step(
        &self,
        user: &UserId,
        step: u64,
    ) -> Result<(), super::StoreError> {
        let step = i64::try_from(step).map_err(|_| super::StoreError::TotpReplay)?;
        let changed = self.sql.execute(
            "UPDATE users SET last_totp_step=? WHERE id=? AND (last_totp_step IS NULL OR last_totp_step < ?)",
            (step, user.as_str(), step),
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(super::StoreError::TotpReplay)
        }
    }
}
