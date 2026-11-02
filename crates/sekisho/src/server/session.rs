use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use sekisho_core::{Timestamp, UserId};
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Debug, thiserror::Error)]
#[error("authentication storage unavailable")]
pub struct AuthStoreError;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionToken(String);
impl SessionToken {
    pub fn from_cookie(value: &str) -> Self {
        Self(value.to_owned())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub user: UserId,
    pub csrf_token: String,
    pub expires_at: Timestamp,
}
/// Persistent implementations commit mutations, TOTP advancement, and audit atomically.
/// Creation returns `None` when the supplied TOTP step has already been accepted.
pub trait SessionStore: Send + Sync {
    fn create(
        &self,
        user: &UserId,
        now: Timestamp,
        ttl_seconds: u32,
        totp_step: Option<u64>,
    ) -> Result<Option<SessionToken>, AuthStoreError>;
    fn get(&self, token: &SessionToken, now: Timestamp) -> Result<Option<Session>, AuthStoreError>;
    fn revoke(&self, token: &SessionToken, now: Timestamp) -> Result<(), AuthStoreError>;
    /// Record a TOTP step used outside login. `false` when it was already used.
    fn accept_totp_step(
        &self,
        user: &UserId,
        step: u64,
        now: Timestamp,
    ) -> Result<bool, AuthStoreError>;
}
#[derive(Default)]
struct SessionState {
    sessions: HashMap<SessionToken, Session>,
    last_steps: HashMap<UserId, u64>,
}
#[derive(Default)]
pub struct InMemorySessions {
    state: Mutex<SessionState>,
    failing: AtomicBool,
    revoke_failing: AtomicBool,
}
impl InMemorySessions {
    pub fn set_revoke_failing(&self, failing: bool) {
        self.revoke_failing.store(failing, Ordering::SeqCst);
    }
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
    fn check(&self) -> Result<(), AuthStoreError> {
        if self.failing.load(Ordering::SeqCst) {
            Err(AuthStoreError)
        } else {
            Ok(())
        }
    }
}
impl SessionStore for InMemorySessions {
    fn create(
        &self,
        user: &UserId,
        now: Timestamp,
        ttl_seconds: u32,
        totp_step: Option<u64>,
    ) -> Result<Option<SessionToken>, AuthStoreError> {
        self.check()?;
        let token = SessionToken(random_token()?);
        let session = Session {
            user: user.clone(),
            csrf_token: random_token()?,
            expires_at: now
                .as_secs()
                .checked_add(i64::from(ttl_seconds))
                .ok_or(AuthStoreError)?
                .into(),
        };
        let mut state = self.state.lock().map_err(|_| AuthStoreError)?;
        if let Some(step) = totp_step {
            if state.last_steps.get(user).is_some_and(|last| step <= *last) {
                return Ok(None);
            }
            state.last_steps.insert(user.clone(), step);
        }
        state.sessions.insert(token.clone(), session);
        Ok(Some(token))
    }
    fn get(&self, token: &SessionToken, now: Timestamp) -> Result<Option<Session>, AuthStoreError> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| AuthStoreError)?
            .sessions
            .get(token)
            .filter(|s| now < s.expires_at)
            .cloned())
    }
    fn accept_totp_step(
        &self,
        user: &UserId,
        step: u64,
        _now: Timestamp,
    ) -> Result<bool, AuthStoreError> {
        self.check()?;
        let mut state = self.state.lock().map_err(|_| AuthStoreError)?;
        if state.last_steps.get(user).is_some_and(|last| step <= *last) {
            return Ok(false);
        }
        state.last_steps.insert(user.clone(), step);
        Ok(true)
    }
    fn revoke(&self, token: &SessionToken, _now: Timestamp) -> Result<(), AuthStoreError> {
        self.check()?;
        if self.revoke_failing.load(Ordering::SeqCst) {
            return Err(AuthStoreError);
        }
        self.state
            .lock()
            .map_err(|_| AuthStoreError)?
            .sessions
            .remove(token);
        Ok(())
    }
}
pub(crate) fn random_token() -> Result<String, AuthStoreError> {
    let mut bytes = [0; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AuthStoreError)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
