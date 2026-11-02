use super::AuthStoreError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sekisho_core::AgentId;
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

pub trait AgentDirectory: Send + Sync {
    fn resolve_token(&self, token: &str) -> Result<Option<AgentId>, AuthStoreError>;
}

impl AgentDirectory for crate::store::Store {
    fn resolve_token(&self, token: &str) -> Result<Option<AgentId>, AuthStoreError> {
        self.authenticate_agent(token).map_err(|_| AuthStoreError)
    }
}

#[derive(Default)]
pub struct InMemoryAgents {
    agents: Mutex<HashMap<AgentId, [u8; 32]>>,
}

impl InMemoryAgents {
    pub fn insert(&self, id: AgentId, token: &str) -> Result<(), AuthStoreError> {
        let hash = token_hash(token).ok_or(AuthStoreError)?;
        self.lock().insert(id, hash);
        Ok(())
    }

    pub fn rotate(&self, id: &AgentId, token: &str) -> Result<(), AuthStoreError> {
        let hash = token_hash(token).ok_or(AuthStoreError)?;
        let mut agents = self.lock();
        let stored = agents.get_mut(id).ok_or(AuthStoreError)?;
        *stored = hash;
        Ok(())
    }

    pub fn remove(&self, id: &AgentId) -> bool {
        self.lock().remove(id).is_some()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<AgentId, [u8; 32]>> {
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AgentDirectory for InMemoryAgents {
    fn resolve_token(&self, token: &str) -> Result<Option<AgentId>, AuthStoreError> {
        let Some(presented) = token_hash(token) else {
            return Ok(None);
        };
        let agents = self.lock();
        let mut found = None;
        for (id, stored) in agents.iter() {
            if constant_time_eq(&presented, stored) {
                if found.is_some() {
                    return Err(AuthStoreError);
                }
                found = Some(id.clone());
            }
        }
        Ok(found)
    }
}

fn token_hash(token: &str) -> Option<[u8; 32]> {
    let valid = URL_SAFE_NO_PAD
        .decode(token)
        .is_ok_and(|bytes| bytes.len() == 32);
    valid.then(|| Sha256::digest(token.as_bytes()).into())
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
