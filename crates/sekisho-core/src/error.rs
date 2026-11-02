/// Invalid domain input or a failure to canonicalize an action.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("invalid public key encoding")]
    InvalidPublicKey,
    #[error("invalid signature")]
    BadSignature,
    #[error("audit sequence overflows")]
    AuditSequenceOverflow,
    #[error("audit time must not decrease")]
    NonMonotonicAuditTime,
    #[error("signature verification failed")]
    SignatureVerification,
    #[error("signing failed")]
    Signing,
    #[error("invalid grant id: {0}")]
    InvalidGrantId(String),
    #[error("grant expiry must be after not_before")]
    InvalidGrantWindow,
    #[error("invalid grant target glob: {0}")]
    InvalidGrantGlob(String),
    #[error("invalid approval id: {0}")]
    InvalidApprovalId(String),
    #[error("approval TTL must be between 60 and 86400 seconds: {0}")]
    InvalidApprovalTtl(u32),
    #[error("approval expiry overflows timestamp")]
    ApprovalExpiryOverflow,
    #[error("invalid tool name: {0}")]
    InvalidToolName(String),
    #[error("invalid agent id: {0}")]
    InvalidAgentId(String),
    #[error("invalid user id: {0}")]
    InvalidUserId(String),
    #[error("user id is reserved: {0}")]
    ReservedUserId(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("params must be a JSON object")]
    ParamsNotObject,
    #[error("unsafe integer at {0}")]
    UnsafeInteger(String),
    #[error("number at {0} is a float with an integer value or negative zero; send an integer")]
    AmbiguousNumber(String),
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    #[error("action canonicalization failed: {0}")]
    Canonicalization(String),
}
