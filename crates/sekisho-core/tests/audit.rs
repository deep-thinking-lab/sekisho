#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use sekisho_core::{
    AgentId, AuditEntry, AuditKind, ChainError, CoreError, Digest, Ed25519Signer, GrantId,
    Principal, PublicKey, Signature, Signer, Timestamp, ToolName, UnsignedGrant, UserId,
    checkpoint, next_entry, verify, verify_against_checkpoint, verify_chain,
    verify_chain_from_checkpoint,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes("audit-a", &[7; 32])
}
fn actor() -> Principal {
    Principal::User(UserId::try_from("admin").unwrap())
}
fn keys(signer: &dyn Signer) -> BTreeMap<String, PublicKey> {
    BTreeMap::from([(signer.key_id().into(), signer.public_key())])
}
fn chain(len: usize) -> Vec<AuditEntry> {
    let signer = signer();
    let mut entries = Vec::new();
    for i in 0..len {
        entries.push(
            next_entry(
                entries.last(),
                (100 + i as i64).into(),
                AuditKind::Approved,
                actor(),
                json!({"value": "abcdefgh", "n": i}),
                &signer,
            )
            .unwrap(),
        );
    }
    entries
}
fn change(entry: &AuditEntry, field: &str, value: Value) -> AuditEntry {
    let mut raw = serde_json::to_value(entry).unwrap();
    raw[field] = value;
    serde_json::from_value(raw).unwrap()
}
fn flip_hex(value: &str, index: usize) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let i = index % bytes.len();
    bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}
fn flip_name(value: &str, index: usize) -> String {
    let mut bytes = value.as_bytes().to_vec();
    let i = index % bytes.len();
    bytes[i] = if bytes[i] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).unwrap()
}
fn error_seq(error: ChainError) -> u64 {
    match error {
        ChainError::GapAt(s)
        | ChainError::BadPrevHash(s)
        | ChainError::BadEntryHash(s)
        | ChainError::BadSignature(s)
        | ChainError::UnknownKey(s, _)
        | ChainError::NonMonotonicTime(s) => s,
        other => panic!("unexpected error {other:?}"),
    }
}

#[test]
fn dropping_the_tail_passes_chain_but_fails_checkpoint() {
    let entries = chain(3);
    let cp = checkpoint(&entries[2], 200.into(), &signer()).unwrap();
    let keys = keys(&signer());
    assert!(verify_chain(&entries[..2], &keys).is_ok());
    assert_eq!(
        verify_against_checkpoint(&entries[..2], &keys, &cp),
        Err(ChainError::TruncatedBefore {
            checkpoint_seq: 2,
            last_seq: 1
        })
    );
    assert!(verify_against_checkpoint(&entries, &keys, &cp).is_ok());
}

#[test]
fn reordering_fails() {
    let mut entries = chain(3);
    entries.swap(1, 2);
    assert_eq!(
        verify_chain(&entries, &keys(&signer())),
        Err(ChainError::GapAt(1))
    );
}

#[test]
fn gap_fails() {
    let mut entries = chain(3);
    entries.remove(1);
    assert_eq!(
        verify_chain(&entries, &keys(&signer())),
        Err(ChainError::GapAt(1))
    );
}

#[test]
fn suffix_with_wrong_checkpoint_fails() {
    let entries = chain(4);
    let s = signer();
    let trusted = keys(&s);
    let cp = checkpoint(&entries[1], 102.into(), &s).unwrap();
    assert!(verify_chain_from_checkpoint(&entries[2..], &trusted, &cp).is_ok());

    let mut foreign = Vec::new();
    for i in 0..2 {
        foreign.push(
            next_entry(
                foreign.last(),
                (300 + i).into(),
                AuditKind::Approved,
                actor(),
                json!({"foreign": i}),
                &s,
            )
            .unwrap(),
        );
    }
    let wrong_chain = checkpoint(&foreign[1], 302.into(), &s).unwrap();
    assert_eq!(
        verify_chain_from_checkpoint(&entries[2..], &trusted, &wrong_chain),
        Err(ChainError::BadPrevHash(2))
    );

    let mut raw = serde_json::to_value(&cp).unwrap();
    raw["signature"] = json!(flip_hex(raw["signature"].as_str().unwrap(), 0));
    let bad_signature: sekisho_core::Checkpoint = serde_json::from_value(raw).unwrap();
    assert_eq!(
        verify_chain_from_checkpoint(&entries[2..], &trusted, &bad_signature),
        Err(ChainError::BadCheckpointSignature)
    );

    let attacker = Ed25519Signer::from_secret_bytes("audit-b", &[8; 32]);
    let unknown_key = checkpoint(&entries[1], 102.into(), &attacker).unwrap();
    assert_eq!(
        verify_chain_from_checkpoint(&entries[2..], &trusted, &unknown_key),
        Err(ChainError::BadCheckpointSignature)
    );
}

#[test]
fn suffix_gap_fails() {
    let entries = chain(5);
    let s = signer();
    let cp = checkpoint(&entries[1], 102.into(), &s).unwrap();
    let suffix = [entries[2].clone(), entries[4].clone()];
    assert_eq!(
        verify_chain_from_checkpoint(&suffix, &keys(&s), &cp),
        Err(ChainError::GapAt(3))
    );
}

#[test]
fn unknown_key_fails() {
    assert_eq!(
        verify_chain(&chain(1), &BTreeMap::new()),
        Err(ChainError::UnknownKey(0, "audit-a".into()))
    );
}

#[test]
fn rotated_key_verifies_with_both_keys() {
    let a = signer();
    let b = Ed25519Signer::from_secret_bytes("audit-b", &[8; 32]);
    let mut entries = chain(1);
    entries.push(
        next_entry(
            entries.last(),
            101.into(),
            AuditKind::KeyRotated,
            actor(),
            json!({"key_id":"audit-b"}),
            &b,
        )
        .unwrap(),
    );
    let mut trusted = keys(&a);
    assert_eq!(
        verify_chain(&entries, &trusted),
        Err(ChainError::UnknownKey(1, "audit-b".into()))
    );
    trusted.insert(b.key_id().into(), b.public_key());
    assert!(verify_chain(&entries, &trusted).is_ok());
    let cp = checkpoint(&entries[0], 102.into(), &b).unwrap();
    assert!(verify_against_checkpoint(&entries, &trusted, &cp).is_ok());
}

#[test]
fn grant_signature_is_not_an_audit_signature() {
    let s = signer();
    let entries = chain(1);
    let grant = UnsignedGrant {
        id: GrantId::try_from("grt_0123456789abcdefghijklmnop").unwrap(),
        agent_id: AgentId::try_from("claude").unwrap(),
        tool: ToolName::try_from("git.push").unwrap(),
        target_glob: "repo:release/*".into(),
        params: BTreeMap::new(),
        not_before: 100.into(),
        expires_at: 200.into(),
        max_uses: Some(3),
        issued_by: UserId::try_from("admin").unwrap(),
    }
    .sign(&s)
    .unwrap();
    grant.verify(&s.public_key()).unwrap();
    let forged = change(&entries[0], "signature", json!(grant.signature()));
    assert_eq!(
        verify_chain(&[forged], &keys(&s)),
        Err(ChainError::BadSignature(0))
    );
    let mut cp = checkpoint(&entries[0], 101.into(), &s).unwrap();
    cp.signature = *grant.signature();
    assert_eq!(
        verify_against_checkpoint(&entries, &keys(&s), &cp),
        Err(ChainError::BadCheckpointSignature)
    );
}

#[test]
fn exact_wire_hash_and_signing_preimages() {
    let s = signer();
    let entry = next_entry(
        None,
        100.into(),
        AuditKind::Approved,
        actor(),
        json!({"b": 1.0, "a": -0.0}),
        &s,
    )
    .unwrap();
    let literal = br#"{"actor":{"User":"admin"},"at":100,"key_id":"audit-a","kind":"Approved","seq":0,"subject":{"a":0,"b":1},"v":1}"#;
    let expected = Digest::from(<[u8; 32]>::from(
        Sha256::new()
            .chain_update([0; 32])
            .chain_update(literal)
            .finalize(),
    ));
    assert_eq!(entry.prev_hash(), Digest::from([0; 32]));
    assert_eq!(entry.entry_hash(), expected);
    let msg = format!("{{\"entry_hash\":\"{expected}\",\"kind\":\"audit-entry\",\"v\":1}}");
    assert!(verify(&s.public_key(), msg.as_bytes(), &entry.signature()).is_ok());
    assert!(
        verify(
            &s.public_key(),
            expected.to_string().as_bytes(),
            &entry.signature()
        )
        .is_err()
    );
    let cp = checkpoint(&entry, 101.into(), &s).unwrap();
    let cpmsg = format!(
        "{{\"at\":101,\"entry_hash\":\"{expected}\",\"key_id\":\"audit-a\",\"kind\":\"audit-checkpoint\",\"seq\":0,\"v\":1}}"
    );
    assert!(verify(&s.public_key(), cpmsg.as_bytes(), &cp.signature).is_ok());
    // Independent Ed25519 fixture computed from the literal preimage with OpenSSL.
    assert_eq!(
        cp.signature.to_string(),
        concat!(
            "46e3bbab9803afaca356923379390cc55d5edcdb9deb0a8e17e5d77509b4ec997",
            "2c7b07f2f383051afaf8dd098e22d625932682d47c87e46b5f9650af5195604"
        )
    );
    let second = next_entry(
        Some(&entry),
        100.into(),
        AuditKind::Approved,
        actor(),
        json!(null),
        &s,
    )
    .unwrap();
    let second_literal = br#"{"actor":{"User":"admin"},"at":100,"key_id":"audit-a","kind":"Approved","seq":1,"subject":null,"v":1}"#;
    let raw_prev = hex::decode(expected.to_string()).unwrap();
    let hash = Digest::from(<[u8; 32]>::from(
        Sha256::new()
            .chain_update(raw_prev)
            .chain_update(second_literal)
            .finalize(),
    ));
    assert_eq!(second.entry_hash(), hash);
    let encoded = serde_json::to_value(&second).unwrap();
    assert_eq!(
        serde_json::from_value::<AuditEntry>(encoded).unwrap(),
        second
    );
    let summary = verify_chain(&[entry, second], &keys(&s)).unwrap();
    assert_eq!(summary.last_seq, 1);
    assert_eq!(summary.entry_hash, hash);
    assert_eq!(summary.at, Timestamp::from(100));
    assert_eq!(summary.count, 2);
}

#[test]
fn checkpoint_checks_every_field_and_historical_inclusion() {
    let entries = chain(3);
    let s = signer();
    let trusted = keys(&s);
    let cp = checkpoint(&entries[1], 200.into(), &s).unwrap();
    assert!(verify_against_checkpoint(&entries, &trusted, &cp).is_ok());
    for field in ["seq", "entry_hash", "at", "signature", "key_id"] {
        let mut raw = serde_json::to_value(&cp).unwrap();
        raw[field] = match field {
            "seq" => json!(2),
            "at" => json!(201),
            "key_id" => json!("unknown"),
            _ => json!(flip_hex(raw[field].as_str().unwrap(), 0)),
        };
        let bad = serde_json::from_value(raw).unwrap();
        assert!(
            verify_against_checkpoint(&entries, &trusted, &bad).is_err(),
            "{field}"
        );
    }
    let mut wrong = cp.clone();
    wrong.entry_hash = entries[0].entry_hash();
    let msg = serde_jcs::to_vec(&json!({"v":1,"kind":"audit-checkpoint","seq":wrong.seq,
        "at":wrong.at,"entry_hash":wrong.entry_hash,"key_id":wrong.key_id}))
    .unwrap();
    wrong.signature = s.sign(&msg).unwrap();
    assert_eq!(
        verify_against_checkpoint(&entries, &trusted, &wrong),
        Err(ChainError::CheckpointMismatch)
    );
}

#[test]
fn checkpoint_key_label_is_authenticated() {
    let entries = chain(3);
    let s = signer();
    let trusted = keys(&s);
    let cp = checkpoint(&entries[1], 200.into(), &s).unwrap();
    assert!(verify_against_checkpoint(&entries, &trusted, &cp).is_ok());
    let mut aliased = trusted.clone();
    aliased.insert("other-id".into(), s.public_key());
    let mut equivalent_key = cp.clone();
    equivalent_key.key_id = "other-id".into();
    assert_eq!(
        verify_against_checkpoint(&entries, &aliased, &equivalent_key),
        Err(ChainError::BadCheckpointSignature)
    );
}

struct FailingSigner;
impl Signer for FailingSigner {
    fn key_id(&self) -> &str {
        "failing"
    }
    fn public_key(&self) -> PublicKey {
        signer().public_key()
    }
    fn sign(&self, _: &[u8]) -> Result<Signature, CoreError> {
        Err(CoreError::Signing)
    }
}

#[test]
fn empty_time_boundaries_safe_integers_and_signing_failure() {
    let s = signer();
    assert_eq!(verify_chain(&[], &keys(&s)), Err(ChainError::Empty));
    let entry = chain(1).remove(0);
    assert!(
        next_entry(
            Some(&entry),
            99.into(),
            AuditKind::Approved,
            actor(),
            json!({}),
            &s
        )
        .is_err()
    );
    assert!(checkpoint(&entry, 99.into(), &s).is_err());
    assert_eq!(
        next_entry(
            None,
            100.into(),
            AuditKind::Approved,
            actor(),
            json!({}),
            &FailingSigner
        ),
        Err(CoreError::Signing)
    );
    assert_eq!(
        checkpoint(&entry, 101.into(), &FailingSigner),
        Err(CoreError::Signing)
    );
    for at in [i64::MIN, i64::MAX, -9007199254740992, 9007199254740992] {
        assert!(next_entry(None, at.into(), AuditKind::Approved, actor(), json!({}), &s).is_err());
        assert!(checkpoint(&entry, at.into(), &s).is_err());
    }
    for at in [-9007199254740991_i64, 9007199254740991] {
        let e = next_entry(
            None,
            at.into(),
            AuditKind::Approved,
            actor(),
            json!(null),
            &s,
        )
        .unwrap();
        assert!(verify_chain(&[e], &keys(&s)).is_ok());
    }
    for subject in [
        json!({"a/b~": [9007199254740992_u64]}),
        json!(-9007199254740992_i64),
        json!([u64::MAX]),
    ] {
        assert!(matches!(
            next_entry(
                None,
                100.into(),
                AuditKind::Approved,
                actor(),
                subject.clone(),
                &s
            ),
            Err(CoreError::UnsafeInteger(_))
        ));
        let bad = change(&entry, "subject", subject);
        assert_eq!(
            verify_chain(&[bad], &keys(&s)),
            Err(ChainError::BadEntryHash(0))
        );
    }
    let last = change(&entry, "seq", json!(u64::MAX));
    assert!(
        next_entry(
            Some(&last),
            101.into(),
            AuditKind::Approved,
            actor(),
            json!({}),
            &s
        )
        .is_err()
    );
    let last_safe = change(&entry, "seq", json!(9007199254740991_u64));
    assert!(
        next_entry(
            Some(&last_safe),
            101.into(),
            AuditKind::Approved,
            actor(),
            json!({}),
            &s
        )
        .is_err()
    );
    let backwards = change(&chain(2)[1], "at", json!(99));
    assert_eq!(
        verify_chain(&[entry, backwards], &keys(&s)),
        Err(ChainError::NonMonotonicTime(1))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn changing_any_field_names_the_entry(
        len in 1usize..=50, chosen in any::<usize>(), byte in any::<usize>(), seed in any::<u64>()
    ) {
        let mut entries = chain(len);
        let index = chosen % len;
        // Randomize the subject and rebuild the suffix so the baseline is fully authentic.
        for i in 0..len {
            entries[i] = next_entry(if i == 0 { None } else { Some(&entries[i-1]) },
                (100 + i as i64).into(), AuditKind::Approved, actor(),
                json!({"value": format!("{seed:016x}"), "n": i}), &signer()).unwrap();
        }
        prop_assert!(verify_chain(&entries, &keys(&signer())).is_ok());
        let original = entries[index].clone();
        let raw = serde_json::to_value(&original).unwrap();
        for field in ["seq", "at", "kind", "actor", "subject", "prev_hash", "entry_hash", "signature", "key_id"] {
            let value = match field {
                "seq" => json!(original.seq() ^ (1_u64 << ((byte % 6) * 8))),
                "at" => json!(original.at().as_secs() ^ (1_i64 << ((byte % 6) * 8))),
                "kind" => json!([
                    AuditKind::ActionRequested, AuditKind::Decided, AuditKind::ApprovalRequested,
                    AuditKind::Denied, AuditKind::Expired, AuditKind::Consumed, AuditKind::GrantIssued,
                    AuditKind::GrantRevoked, AuditKind::PolicyLoaded, AuditKind::UserLogin,
                    AuditKind::AgentAdded, AuditKind::KeyRotated, AuditKind::AnchorSent,
                    AuditKind::AnchorFailed, AuditKind::NotifySent, AuditKind::NotifyFailed,
                ][byte % 16]),
                "actor" => json!({"User":flip_name("admin", byte)}),
                "subject" => json!({"value": flip_hex(raw["subject"]["value"].as_str().unwrap(), byte), "n": index}),
                "key_id" => json!(flip_name("audit-a", byte)),
                _ => json!(flip_hex(raw[field].as_str().unwrap(), byte)),
            };
            entries[index] = change(&original, field, value);
            let error = verify_chain(&entries, &keys(&signer())).unwrap_err();
            prop_assert_eq!(error_seq(error), index as u64, "field {}", field);
        }
    }
}

#[test]
fn actor_type_and_entry_key_label_are_authenticated() {
    let s = signer();
    let entries = chain(1);
    let mut trusted = keys(&s);
    trusted.insert("other".into(), s.public_key());
    for (field, value) in [
        ("actor", json!({"Agent":"admin"})),
        ("key_id", json!("other")),
    ] {
        let bad = change(&entries[0], field, value);
        assert_eq!(
            verify_chain(&[bad], &trusted),
            Err(ChainError::BadEntryHash(0))
        );
    }
}

#[test]
fn independently_signed_invalid_time_and_unsafe_numbers_are_refused() {
    let s = signer();
    let mut entries = chain(2);
    let original = entries[1].clone();
    for (field, value, expected) in [
        ("at", json!(99), ChainError::NonMonotonicTime(1)),
        (
            "at",
            json!(9007199254740992_i64),
            ChainError::BadEntryHash(1),
        ),
        (
            "subject",
            json!({"nested":[9007199254740992_u64]}),
            ChainError::BadEntryHash(1),
        ),
    ] {
        let mut raw = serde_json::to_value(&original).unwrap();
        raw[field] = value;
        let fields = json!({"v":1,"seq":raw["seq"],"at":raw["at"],"kind":raw["kind"],
            "actor":raw["actor"],"subject":raw["subject"],"key_id":raw["key_id"]});
        let prev = hex::decode(raw["prev_hash"].as_str().unwrap()).unwrap();
        let hash = hex::encode(
            Sha256::new()
                .chain_update(prev)
                .chain_update(serde_jcs::to_vec(&fields).unwrap())
                .finalize(),
        );
        let message =
            serde_jcs::to_vec(&json!({"v":1,"kind":"audit-entry","entry_hash":hash})).unwrap();
        raw["entry_hash"] = json!(hash);
        raw["signature"] = json!(s.sign(&message).unwrap());
        entries[1] = serde_json::from_value(raw).unwrap();
        assert_eq!(verify_chain(&entries, &keys(&s)), Err(expected));
    }
    let mut cp = checkpoint(&entries[0], 100.into(), &s).unwrap();
    for (at, seq, expected) in [
        (99_i64, 0_u64, ChainError::CheckpointMismatch),
        (9007199254740992, 0, ChainError::BadCheckpointSignature),
        (100, 9007199254740992, ChainError::BadCheckpointSignature),
    ] {
        cp.at = at.into();
        cp.seq = seq;
        let message = serde_jcs::to_vec(&json!({"v":1,"kind":"audit-checkpoint","seq":cp.seq,
            "entry_hash":cp.entry_hash,"at":cp.at,"key_id":cp.key_id}))
        .unwrap();
        cp.signature = s.sign(&message).unwrap();
        assert_eq!(
            verify_against_checkpoint(&entries[..1], &keys(&s), &cp),
            Err(expected)
        );
    }
    let cp = checkpoint(&entries[0], 100.into(), &s).unwrap();
    assert_eq!(
        verify_against_checkpoint(&[], &keys(&s), &cp),
        Err(ChainError::Empty)
    );
}

#[test]
fn every_audit_kind_and_principal_round_trips_and_verifies() {
    let s = signer();
    let mut entries = Vec::new();
    for (i, kind) in [
        AuditKind::ActionRequested,
        AuditKind::Decided,
        AuditKind::ApprovalRequested,
        AuditKind::Approved,
        AuditKind::Denied,
        AuditKind::Expired,
        AuditKind::Consumed,
        AuditKind::GrantIssued,
        AuditKind::GrantRevoked,
        AuditKind::PolicyLoaded,
        AuditKind::UserLogin,
        AuditKind::AgentAdded,
        AuditKind::KeyRotated,
        AuditKind::AnchorSent,
        AuditKind::AnchorFailed,
        AuditKind::NotifySent,
        AuditKind::NotifyFailed,
    ]
    .into_iter()
    .enumerate()
    {
        let principal = if i % 2 == 0 {
            actor()
        } else {
            Principal::Agent(sekisho_core::AgentId::try_from("claude").unwrap())
        };
        let entry = next_entry(
            entries.last(),
            100.into(),
            kind,
            principal.clone(),
            json!({}),
            &s,
        )
        .unwrap();
        assert_eq!(entry.kind(), kind);
        assert_eq!(entry.actor(), &principal);
        assert_eq!(entry.key_id(), "audit-a");
        assert_eq!(entry.subject(), &json!({}));
        let wire = serde_json::to_vec(&entry).unwrap();
        entries.push(serde_json::from_slice::<AuditEntry>(&wire).unwrap());
    }
    assert!(verify_chain(&entries, &keys(&s)).is_ok());
}

#[test]
fn broken_links_hashes_and_signatures_report_exact_errors() {
    let s = signer();
    let original = chain(2);
    for index in [0, 1] {
        for (field, expected) in [
            ("prev_hash", ChainError::BadPrevHash(index as u64)),
            ("entry_hash", ChainError::BadEntryHash(index as u64)),
            ("signature", ChainError::BadSignature(index as u64)),
        ] {
            let mut entries = original.clone();
            let raw = serde_json::to_value(&entries[index]).unwrap();
            entries[index] = change(
                &entries[index],
                field,
                json!(flip_hex(raw[field].as_str().unwrap(), 0)),
            );
            assert_eq!(verify_chain(&entries, &keys(&s)), Err(expected));
        }
    }
}
