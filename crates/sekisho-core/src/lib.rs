//! Pure domain logic for Sekisho. No I/O, no async, no clock reads.

mod action;
mod approval;
mod audit;
mod decide;
mod digest;
mod error;
mod grant;
mod ids;
mod policy;
mod signing;

pub use action::Action;
pub use approval::{Approval, ApprovalId, ApprovalState, Principal, TransitionError};
pub use decide::{BudgetView, Decision, GrantView, decide};
pub use digest::Digest;
pub use error::CoreError;
pub use grant::{Grant, GrantId, GrantInvalid, UnsignedGrant};
pub use ids::{AgentId, Timestamp, ToolName, UserId};

pub use audit::{
    AuditEntry, AuditKind, ChainError, ChainSummary, Checkpoint, checkpoint, next_entry,
    verify_against_checkpoint, verify_chain, verify_chain_from_checkpoint, verify_checkpoint,
};
pub use policy::{
    Budget, DATA_VOLUME_ROOT, DecisionKind, PATH_ALIAS_PREFIXES, PROTECTED_DIR_RULE, Policy,
    PolicyError, Rule, ToolMatch, protected_ancestors, without_data_volume,
};
pub use signing::{Ed25519Signer, PublicKey, Signature, Signer, verify};
