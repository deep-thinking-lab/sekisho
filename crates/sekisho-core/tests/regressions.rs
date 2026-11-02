//! Regression tests named in DESIGN §10.
//!
//! Each test stays ignored until the task named in its doc comment implements
//! the guard. The full list is visible with `cargo test -- --ignored --list`.

#![allow(clippy::unwrap_used)]

use sekisho_core::{
    Action, AgentId, Approval, ApprovalId, AuditEntry, AuditKind, BudgetView, ChainError,
    DecisionKind, Ed25519Signer, Grant, GrantId, GrantView, Policy, Principal, Signer, Timestamp,
    ToolName, TransitionError, UnsignedGrant, UserId, checkpoint, decide, next_entry,
    verify_against_checkpoint, verify_chain,
};
use serde_json::json;
use std::collections::BTreeMap;

fn pending_approval() -> Approval {
    Approval::request(
        ApprovalId::try_from("apr_0123456789abcdefghijklmnop").unwrap(),
        Action::new(
            AgentId::try_from("claude").unwrap(),
            ToolName::try_from("git.push").unwrap(),
            "repo:main".into(),
            json!({"force": false}),
        )
        .unwrap(),
        "main needs approval".into(),
        100.into(),
        60,
    )
    .unwrap()
}

fn human(name: &str) -> Principal {
    Principal::User(UserId::try_from(name).unwrap())
}

/// Old defect: "Ultra trusted `invocations_so_far` and `cost_so_far_cents` from the request body."
///
/// Implemented by tasks 103 and 203.
#[test]
fn budget_is_counted_server_side() {
    let policy = Policy::parse(
        b"version = 1\n\n[[rule]]\nname = \"limited\"\n\
          tool = \"git.push\"\ndecision = \"allow\"\n\
          budget = { max = 2, per = \"1h\" }\n",
    )
    .unwrap();
    let action = Action::new(
        AgentId::try_from("claude").unwrap(),
        ToolName::try_from("git.push").unwrap(),
        "repo:main".into(),
        json!({"invocations_so_far": 1_000_000, "used": 1_000_000}),
    )
    .unwrap();
    let signer = Ed25519Signer::from_secret_bytes("grant", &[7; 32]);
    let allowed = decide(
        &action,
        &policy,
        &[],
        &signer.public_key(),
        &BudgetView { used: &|_| 1 },
        Timestamp::from(100),
    );
    assert_eq!(allowed.kind, DecisionKind::Allow);

    let denied = decide(
        &action,
        &policy,
        &[],
        &signer.public_key(),
        &BudgetView { used: &|_| 2 },
        Timestamp::from(100),
    );
    assert_eq!(denied.kind, DecisionKind::Deny);
    assert_eq!(denied.reason, "budget exhausted");
}

/// Old defect: "Ultra envelopes stored only mission and action string."
///
/// Implemented by task 302.
#[test]
#[ignore = "implemented in crates/sekisho/tests/store.rs::approval_is_bound_to_digest"]
fn approval_is_bound_to_digest() {
    unimplemented!("enabled by task 302")
}

/// Old defect: "Nothing consumed a granted envelope."
///
/// Implemented by task 302.
#[test]
#[ignore = "implemented in crates/sekisho/tests/store.rs::approval_is_single_use"]
fn approval_is_single_use() {
    unimplemented!("enabled by task 302")
}

/// Old defect: "Envelopes never expired."
///
/// Implemented by task 105.
#[test]
fn approval_expires() {
    let pending = pending_approval();
    let approved = pending.approve(&human("admin"), 159.into()).unwrap();
    assert!(
        approved
            .consume(approved.action_digest(), 159.into())
            .is_ok()
    );
    for now in [160, 161, i64::MAX] {
        assert_eq!(
            pending.approve(&human("admin"), now.into()),
            Err(TransitionError::Expired)
        );
        assert_eq!(
            approved.consume(approved.action_digest(), now.into()),
            Err(TransitionError::Expired)
        );
    }
}

/// Old defect: "One shared operator token, no self-approval check."
///
/// Implemented by task 205.
#[test]
#[ignore = "implemented in crates/sekisho/tests/server.rs::agent_cannot_approve"]
fn agent_cannot_approve() {
    unimplemented!("enabled by task 205")
}

/// Old defect: "One shared operator token, no self-approval check."
///
/// Implemented by task 105.
#[test]
fn approver_is_not_requester() {
    let pending = pending_approval();
    let agent = Principal::Agent(AgentId::try_from("other-agent").unwrap());
    for now in [100, 160] {
        assert_eq!(
            pending.approve(&agent, now.into()),
            Err(TransitionError::AgentCannotDecide)
        );
        assert_eq!(
            pending.deny(&agent, now.into()),
            Err(TransitionError::AgentCannotDecide)
        );
        assert_eq!(
            pending.approve(&human("claude"), now.into()),
            Err(TransitionError::SelfApproval)
        );
        assert_eq!(
            pending.deny(&human("claude"), now.into()),
            Err(TransitionError::SelfApproval)
        );
    }
}

/// Old defect: "Ultra removed grants from memory even if the journal delete failed."
///
/// Implemented by task 202.
#[test]
#[ignore = "implemented in crates/sekisho/tests/store.rs"]
fn revocation_is_durable_before_effect() {
    unimplemented!("enabled by task 202")
}

/// Old defect: "Ultra and Kizuna continued when audit or signing failed."
///
/// Implemented by task 201.
#[test]
#[ignore = "implemented in crates/sekisho/tests/store.rs"]
fn audit_write_failure_refuses_action() {
    unimplemented!("enabled by task 201")
}

/// Old defect: "Ultra's chain was unkeyed and unanchored."
///
/// Implemented by task 106.
#[test]
fn audit_chain_detects_edit() {
    let (mut entries, keys) = audit_fixture();
    let mut raw = serde_json::to_value(&entries[0]).unwrap();
    raw["subject"]["approved"] = json!(true);
    entries[0] = serde_json::from_value(raw).unwrap();
    assert_eq!(
        verify_chain(&entries, &keys),
        Err(ChainError::BadEntryHash(0))
    );
}

/// Old defect: "Ultra's chain was unkeyed and unanchored."
///
/// Implemented by task 106.
#[test]
fn audit_chain_detects_truncation_against_checkpoint() {
    let (entries, keys) = audit_fixture();
    let cp = checkpoint(
        &entries[1],
        102.into(),
        &Ed25519Signer::from_secret_bytes("audit", &[1; 32]),
    )
    .unwrap();
    assert_eq!(
        verify_against_checkpoint(&entries[..1], &keys, &cp),
        Err(ChainError::TruncatedBefore {
            checkpoint_seq: 1,
            last_seq: 0
        })
    );
}

/// Old defect: "Ultra's chain was unkeyed and unanchored."
///
/// Implemented by task 106.
#[test]
fn audit_chain_is_signed() {
    let (entries, mut keys) = audit_fixture();
    assert!(verify_chain(&entries, &keys).is_ok());
    keys.insert(
        "audit".into(),
        Ed25519Signer::from_secret_bytes("audit", &[2; 32]).public_key(),
    );
    assert_eq!(
        verify_chain(&entries, &keys),
        Err(ChainError::BadSignature(0))
    );
}

/// Old defect: "Ultra envelopes were not chained, so a row could be flipped to granted."
///
/// Implemented by task 201.
#[test]
#[ignore = "implemented in crates/sekisho/tests/store.rs"]
fn approval_state_is_in_chain() {
    unimplemented!("enabled by task 201")
}

/// Old defect: "Grant precedence was unclear."
///
/// Implemented by task 103.
#[test]
fn deny_beats_grant() {
    let policy = Policy::parse(
        b"version = 1\n\n[[rule]]\nname = \"deny main\"\n\
          tool = \"git.push\"\ntarget = \"repo:main\"\ndecision = \"deny\"\n",
    )
    .unwrap();
    let signer = Ed25519Signer::from_secret_bytes("grant", &[7; 32]);
    let grant = matching_grant(&signer);
    let grants = [GrantView {
        grant: &grant,
        uses: 0,
        revoked: false,
    }];
    let action = Action::new(
        AgentId::try_from("claude").unwrap(),
        ToolName::try_from("git.push").unwrap(),
        "repo:main".into(),
        json!({}),
    )
    .unwrap();
    let decision = decide(
        &action,
        &policy,
        &grants,
        &signer.public_key(),
        &BudgetView { used: &|_| 0 },
        Timestamp::from(150),
    );
    assert_eq!(decision.kind, DecisionKind::Deny);
    assert_eq!(decision.rule.as_deref(), Some("deny main"));
    assert!(decision.grant.is_none());
}

/// Old defect: "Tenant and caller identity came from client headers."
///
/// Implemented by task 206.
#[test]
#[ignore = "implemented in crates/sekisho/src/server/mod.rs::tests::agent_id_comes_from_token"]
fn agent_id_comes_from_token() {
    unimplemented!("enabled by task 206")
}

/// Old defect: "Several services leaked version and licence state."
///
/// Implemented by task 205.
#[test]
#[ignore = "implemented in crates/sekisho/tests/server.rs::healthz_leaks_nothing"]
fn healthz_leaks_nothing() {
    unimplemented!("enabled by task 205")
}

fn audit_fixture() -> (
    Vec<AuditEntry>,
    std::collections::BTreeMap<String, sekisho_core::PublicKey>,
) {
    let signer = Ed25519Signer::from_secret_bytes("audit", &[1; 32]);
    let first = next_entry(
        None,
        100.into(),
        AuditKind::Approved,
        human("admin"),
        json!({"approved":false}),
        &signer,
    )
    .unwrap();
    let second = next_entry(
        Some(&first),
        101.into(),
        AuditKind::Consumed,
        human("admin"),
        json!({}),
        &signer,
    )
    .unwrap();
    (
        vec![first, second],
        std::collections::BTreeMap::from([("audit".into(), signer.public_key())]),
    )
}

fn matching_grant(signer: &Ed25519Signer) -> Grant {
    UnsignedGrant {
        id: GrantId::try_from("grt_00000000000000000000000000").unwrap(),
        agent_id: AgentId::try_from("claude").unwrap(),
        tool: ToolName::try_from("git.push").unwrap(),
        target_glob: "repo:*".into(),
        params: BTreeMap::new(),
        not_before: 100.into(),
        expires_at: 200.into(),
        max_uses: Some(1),
        issued_by: UserId::try_from("admin").unwrap(),
    }
    .sign(signer)
    .unwrap()
}
