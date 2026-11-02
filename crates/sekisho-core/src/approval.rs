use crate::{Action, AgentId, CoreError, Digest, Timestamp, UserId};

/// Caller-supplied approval identifier. Core never generates identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalId(String);

impl ApprovalId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ApprovalId {
    type Error = CoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let valid = value.strip_prefix("apr_").is_some_and(|suffix| {
            suffix.len() == 26
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        });
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(CoreError::InvalidApprovalId(value.to_owned()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Principal {
    User(UserId),
    Agent(AgentId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    #[error("cannot {event} an approval in state {from:?}")]
    NotAllowed {
        from: ApprovalState,
        event: &'static str,
    },
    #[error("agents cannot approve or deny")]
    AgentCannotDecide,
    #[error("requesters cannot decide their own approvals")]
    SelfApproval,
    #[error("approval has expired")]
    Expired,
    #[error("action digest does not match approval")]
    DigestMismatch,
}

/// A digest-bound approval. Transitions return a new value without mutating the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    id: ApprovalId,
    action: Action,
    action_digest: Digest,
    rule: String,
    requested_at: Timestamp,
    expires_at: Timestamp,
    state: ApprovalState,
    decided_by: Option<UserId>,
    decided_at: Option<Timestamp>,
    consumed_at: Option<Timestamp>,
}

impl Approval {
    pub fn request(
        id: ApprovalId,
        action: Action,
        rule: String,
        now: Timestamp,
        ttl_seconds: u32,
    ) -> Result<Self, CoreError> {
        if !(60..=86400).contains(&ttl_seconds) {
            return Err(CoreError::InvalidApprovalTtl(ttl_seconds));
        }
        let expires_at = now
            .as_secs()
            .checked_add(i64::from(ttl_seconds))
            .ok_or(CoreError::ApprovalExpiryOverflow)?;
        let action_digest = action.digest()?;
        Ok(Self {
            id,
            action,
            action_digest,
            rule,
            requested_at: now,
            expires_at: expires_at.into(),
            state: ApprovalState::Pending,
            decided_by: None,
            decided_at: None,
            consumed_at: None,
        })
    }

    pub fn approve(&self, by: &Principal, now: Timestamp) -> Result<Self, TransitionError> {
        let user = self.deciding_user(by)?;
        self.require_state(ApprovalState::Pending, "approve")?;
        if now >= self.expires_at {
            return Err(TransitionError::Expired);
        }
        let mut next = self.clone();
        next.state = ApprovalState::Approved;
        next.decided_by = Some(user.clone());
        next.decided_at = Some(now);
        Ok(next)
    }

    pub fn deny(&self, by: &Principal, now: Timestamp) -> Result<Self, TransitionError> {
        let user = self.deciding_user(by)?;
        self.require_state(ApprovalState::Pending, "deny")?;
        let mut next = self.clone();
        next.state = ApprovalState::Denied;
        next.decided_by = Some(user.clone());
        next.decided_at = Some(now);
        Ok(next)
    }

    pub fn expire(&self, now: Timestamp) -> Result<Self, TransitionError> {
        if !matches!(self.state, ApprovalState::Pending | ApprovalState::Approved)
            || now < self.expires_at
        {
            return Err(self.not_allowed("expire"));
        }
        let mut next = self.clone();
        next.state = ApprovalState::Expired;
        Ok(next)
    }

    pub fn consume(
        &self,
        digest_of_action_about_to_run: &Digest,
        now: Timestamp,
    ) -> Result<Self, TransitionError> {
        self.require_state(ApprovalState::Approved, "consume")?;
        if now >= self.expires_at {
            return Err(TransitionError::Expired);
        }
        if digest_of_action_about_to_run != &self.action_digest {
            return Err(TransitionError::DigestMismatch);
        }
        let mut next = self.clone();
        next.state = ApprovalState::Consumed;
        next.consumed_at = Some(now);
        Ok(next)
    }

    fn deciding_user<'a>(&self, by: &'a Principal) -> Result<&'a UserId, TransitionError> {
        match by {
            Principal::Agent(_) => Err(TransitionError::AgentCannotDecide),
            Principal::User(user) if user.as_str() == self.action.agent_id().as_str() => {
                Err(TransitionError::SelfApproval)
            }
            Principal::User(user) => Ok(user),
        }
    }

    fn require_state(
        &self,
        state: ApprovalState,
        event: &'static str,
    ) -> Result<(), TransitionError> {
        if self.state == state {
            Ok(())
        } else {
            Err(self.not_allowed(event))
        }
    }

    fn not_allowed(&self, event: &'static str) -> TransitionError {
        TransitionError::NotAllowed {
            from: self.state,
            event,
        }
    }

    pub fn id(&self) -> &ApprovalId {
        &self.id
    }
    pub fn action(&self) -> &Action {
        &self.action
    }
    pub fn action_digest(&self) -> &Digest {
        &self.action_digest
    }
    pub fn rule(&self) -> &str {
        &self.rule
    }
    pub fn requested_at(&self) -> Timestamp {
        self.requested_at
    }
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
    pub fn state(&self) -> ApprovalState {
        self.state
    }
    pub fn decided_by(&self) -> Option<&UserId> {
        self.decided_by.as_ref()
    }
    pub fn decided_at(&self) -> Option<Timestamp> {
        self.decided_at
    }
    pub fn consumed_at(&self) -> Option<Timestamp> {
        self.consumed_at
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ToolName;
    use proptest::prelude::*;
    use serde_json::json;

    fn human() -> Principal {
        Principal::User(UserId::try_from("admin").unwrap())
    }

    fn action(force: bool) -> Action {
        Action::new(
            AgentId::try_from("claude").unwrap(),
            ToolName::try_from("git.push").unwrap(),
            "repo:main".into(),
            json!({"force": force}),
        )
        .unwrap()
    }

    fn pending() -> Approval {
        Approval::request(
            ApprovalId::try_from("apr_0123456789abcdefghijklmnop").unwrap(),
            action(false),
            "main".into(),
            100.into(),
            60,
        )
        .unwrap()
    }

    #[test]
    fn every_state_event_pair() {
        use ApprovalState::*;
        let pending = pending();
        let approved = pending.approve(&human(), 110.into()).unwrap();
        let states = [
            pending.clone(),
            approved.clone(),
            pending.deny(&human(), 110.into()).unwrap(),
            pending.expire(160.into()).unwrap(),
            approved
                .consume(approved.action_digest(), 120.into())
                .unwrap(),
        ];
        let expected = [
            [Some(Approved), Some(Denied), Some(Expired), None],
            [None, None, Some(Expired), Some(Consumed)],
            [None, None, None, None],
            [None, None, None, None],
            [None, None, None, None],
        ];
        for (approval, row) in states.iter().zip(expected) {
            let events = [
                ("approve", approval.approve(&human(), 130.into())),
                ("deny", approval.deny(&human(), 130.into())),
                ("expire", approval.expire(160.into())),
                (
                    "consume",
                    approval.consume(approval.action_digest(), 130.into()),
                ),
            ];
            for ((event, result), state) in events.into_iter().zip(row) {
                match state {
                    Some(state) => assert_eq!(result.unwrap().state(), state),
                    None => assert_eq!(
                        result,
                        Err(TransitionError::NotAllowed {
                            from: approval.state(),
                            event,
                        })
                    ),
                }
            }
        }
    }

    #[test]
    fn consume_requires_matching_digest() {
        let approved = pending().approve(&human(), 110.into()).unwrap();
        assert_eq!(
            approved.consume(&action(true).digest().unwrap(), 120.into()),
            Err(TransitionError::DigestMismatch)
        );
    }

    #[test]
    fn transitions_do_not_mutate_original() {
        let original = pending();
        let snapshot = original.clone();
        let approved = original.approve(&human(), 110.into()).unwrap();
        assert_eq!(original, snapshot);
        assert_eq!(original.state(), ApprovalState::Pending);
        assert_eq!(original.decided_by(), None);
        assert_eq!(original.decided_at(), None);
        assert_eq!(original.consumed_at(), None);
        assert_eq!(
            approved.decided_by(),
            Some(&UserId::try_from("admin").unwrap())
        );
        assert_eq!(approved.decided_at(), Some(110.into()));
        let consumed = approved
            .consume(approved.action_digest(), 120.into())
            .unwrap();
        assert_eq!(approved.state(), ApprovalState::Approved);
        assert_eq!(approved.consumed_at(), None);
        assert_eq!(consumed.consumed_at(), Some(120.into()));
        assert_eq!(consumed.decided_by(), approved.decided_by());
        assert_eq!(consumed.decided_at(), approved.decided_at());
        let denied = original.deny(&human(), 160.into()).unwrap();
        assert_eq!(denied.decided_by(), approved.decided_by());
        assert_eq!(denied.decided_at(), Some(160.into()));
        assert_eq!(denied.consumed_at(), None);
        let expired = approved.expire(160.into()).unwrap();
        assert_eq!(expired.decided_by(), approved.decided_by());
        assert_eq!(expired.decided_at(), approved.decided_at());
        assert_eq!(expired.consumed_at(), None);
    }

    #[test]
    fn request_validates_id_ttl_and_timestamp_overflow() {
        let valid = "apr_0123456789abcdefghijklmnop";
        assert_eq!(ApprovalId::try_from(valid).unwrap().as_str(), valid);
        for invalid in [
            "".to_owned(),
            valid.to_uppercase(),
            valid[1..].to_owned(),
            format!("{valid}0"),
            "apr_0123456789abcdefghijklmno_".into(),
            "apr_0123456789abcdefghijklmné".into(),
        ] {
            assert!(ApprovalId::try_from(invalid.as_str()).is_err(), "{invalid}");
        }
        for ttl in [0, 59, 86401, u32::MAX] {
            assert!(
                Approval::request(
                    pending().id().clone(),
                    action(false),
                    "main".into(),
                    100.into(),
                    ttl
                )
                .is_err()
            );
        }
        for ttl in [60, 86400] {
            for now in [i64::MIN, 0, i64::MAX - i64::from(ttl)] {
                let request = Approval::request(
                    pending().id().clone(),
                    action(false),
                    "main".into(),
                    now.into(),
                    ttl,
                )
                .unwrap();
                assert_eq!(request.requested_at(), now.into());
                assert_eq!(request.expires_at(), (now + i64::from(ttl)).into());
                assert_eq!(request.action(), &action(false));
                assert_eq!(request.action_digest(), &action(false).digest().unwrap());
                assert_eq!(request.rule(), "main");
            }
            assert!(
                Approval::request(
                    pending().id().clone(),
                    action(false),
                    "main".into(),
                    i64::MAX.into(),
                    ttl
                )
                .is_err()
            );
        }
    }

    #[test]
    fn cannot_expire_early() {
        let pending = pending();
        let approved = pending.approve(&human(), 110.into()).unwrap();
        for approval in [pending, approved] {
            assert_eq!(
                approval.expire(159.into()),
                Err(TransitionError::NotAllowed {
                    from: approval.state(),
                    event: "expire",
                })
            );
        }
    }

    proptest! {
        #[test]
        fn consume_is_single_use(first in 110i64..160, again in any::<i64>(), bytes in any::<[u8; 32]>()) {
            let approved = pending().approve(&human(), 110.into()).unwrap();
            let consumed = approved.consume(approved.action_digest(), first.into()).unwrap();
            for digest in [*consumed.action_digest(), Digest::from(bytes)] {
                prop_assert_eq!(consumed.consume(&digest, again.into()), Err(TransitionError::NotAllowed {
                    from: ApprovalState::Consumed, event: "consume",
                }));
            }
        }
    }
}
