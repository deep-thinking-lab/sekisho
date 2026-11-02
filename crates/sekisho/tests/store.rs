#![allow(clippy::unwrap_used)]

use sekisho::{
    server::{Role, User, UserDirectory},
    store::{AuditRecord, Store, StoreError, migrations},
};
use sekisho_core::*;
use serde_json::json;
use std::hash::BuildHasher;
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::Arc,
};

struct Db(PathBuf);
impl Db {
    fn new(name: &str) -> Self {
        let suffix = std::hash::RandomState::new().hash_one(name);
        let dir =
            std::env::temp_dir().join(format!("sekisho-{name}-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir.join("store.db"))
    }
    fn open(&self) -> Store {
        Store::open(&self.0, signer()).unwrap()
    }
    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.0).unwrap()
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.0.parent().unwrap()).unwrap();
    }
}
fn signer() -> Arc<dyn Signer + Send + Sync> {
    Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]))
}
fn keys() -> BTreeMap<String, PublicKey> {
    BTreeMap::from([("audit".into(), signer().public_key())])
}
fn actor() -> Principal {
    Principal::User(UserId::try_from("admin").unwrap())
}
fn pending() -> Approval {
    Approval::request(
        ApprovalId::try_from("apr_0123456789abcdefghijklmnop").unwrap(),
        Action::new(
            AgentId::try_from("claude").unwrap(),
            ToolName::try_from("git.push").unwrap(),
            "repo:main".into(),
            json!({}),
        )
        .unwrap(),
        "main".into(),
        100.into(),
        60,
    )
    .unwrap()
}
fn grant_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes("grant", &[8; 32])
}
fn grant() -> Grant {
    UnsignedGrant {
        id: GrantId::try_from("grt_0123456789abcdefghijklmnop").unwrap(),
        agent_id: AgentId::try_from("claude").unwrap(),
        tool: ToolName::try_from("git.push").unwrap(),
        target_glob: "repo:release/*".into(),
        params: BTreeMap::from([("force".into(), json!(false))]),
        not_before: 100.into(),
        expires_at: 200.into(),
        max_uses: Some(3),
        issued_by: UserId::try_from("admin").unwrap(),
    }
    .sign(&grant_signer())
    .unwrap()
}
fn issued_record(g: &Grant) -> AuditRecord {
    AuditRecord {
        kind: AuditKind::GrantIssued,
        actor: Principal::User(g.issued_by().clone()),
        subject: json!({
            "grant_id": g.id().as_str(),
            "agent_id": g.agent_id().as_str(),
            "issued_by": g.issued_by().as_str(),
            "expires_at": g.expires_at(),
        }),
    }
}
fn revoked_record(g: &Grant, by: &UserId, now: i64) -> AuditRecord {
    AuditRecord {
        kind: AuditKind::GrantRevoked,
        actor: Principal::User(by.clone()),
        subject: json!({
            "grant_id": g.id().as_str(),
            "revoked_by": by.as_str(),
            "revoked_at": now,
        }),
    }
}
fn save_grant(store: &Store, g: &Grant) -> Result<(), StoreError> {
    store.transact(100.into(), |tx| {
        tx.insert_grant(g)?;
        Ok(((), vec![issued_record(g)]))
    })
}
fn revoke_grant(store: &Store, g: &Grant, by: &UserId, now: i64) -> Result<(), StoreError> {
    store.transact(now.into(), |tx| {
        tx.revoke_grant(g.id(), by, now.into())?;
        Ok(((), vec![revoked_record(g, by, now)]))
    })
}
fn record(a: &Approval) -> AuditRecord {
    AuditRecord {
        kind: match a.state() {
            ApprovalState::Pending => AuditKind::ApprovalRequested,
            ApprovalState::Approved => AuditKind::Approved,
            ApprovalState::Denied => AuditKind::Denied,
            ApprovalState::Expired => AuditKind::Expired,
            ApprovalState::Consumed => AuditKind::Consumed,
        },
        actor: actor(),
        subject: json!({"approval_id": a.id().as_str(), "state": format!("{:?}", a.state()), "action_digest": a.action_digest()}),
    }
}
fn append(store: &Store) {
    store
        .transact(100.into(), |_| {
            Ok((
                (),
                vec![AuditRecord {
                    kind: AuditKind::PolicyLoaded,
                    actor: actor(),
                    subject: json!({"policy_sha256":"test"}),
                }],
            ))
        })
        .unwrap();
}
fn save(store: &Store, a: &Approval, now: i64, insert: bool) -> Result<(), StoreError> {
    store.transact(now.into(), |tx| {
        if insert {
            tx.insert_approval(a)?;
        } else {
            tx.update_approval(a)?;
        }
        Ok(((), vec![record(a)]))
    })
}
fn assert_empty(db: &Db, store: &Store) {
    assert_eq!(
        db.sql()
            .query_row("SELECT count(*) FROM approvals", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(store.audit_entries(0, 100).unwrap().is_empty());
}

#[test]
fn pragmas_are_applied_and_verified() {
    let db = Db::new("pragmas");
    let _store = db.open();
    let connection = db.sql();
    assert_eq!(
        connection
            .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        connection
            .query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn panic_in_transact_rolls_back_and_store_stays_usable() {
    let db = Db::new("panic-recovery");
    let store = db.open();
    let p = pending();
    let panicked = catch_unwind(AssertUnwindSafe(|| {
        store.transact(
            100.into(),
            |tx| -> Result<((), Vec<AuditRecord>), StoreError> {
                tx.insert_approval(&p)?;
                panic!("test transaction panic");
            },
        )
    }));
    assert!(panicked.is_err());
    assert_empty(&db, &store);

    save(&store, &p, 100, true).unwrap();
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 1);
    assert!(
        store
            .check_approval_consistency(&keys())
            .unwrap()
            .is_empty()
    );
}

struct FailingSigner;
impl Signer for FailingSigner {
    fn key_id(&self) -> &str {
        "audit"
    }
    fn public_key(&self) -> PublicKey {
        signer().public_key()
    }
    fn sign(&self, _: &[u8]) -> Result<Signature, CoreError> {
        Err(CoreError::SignatureVerification)
    }
}
#[test]
fn audit_write_failure_refuses_action() {
    let db = Db::new("sign-failure");
    let store = Store::open(&db.0, Arc::new(FailingSigner)).unwrap();
    assert!(save(&store, &pending(), 100, true).is_err());
    assert_empty(&db, &store);
}
#[test]
fn approval_state_is_in_chain() {
    let db = Db::new("approval-chain");
    let store = db.open();
    let p = pending();
    let approved = p.approve(&actor(), 110.into()).unwrap();
    let consumed = approved
        .consume(approved.action_digest(), 120.into())
        .unwrap();
    let mut approved_body = String::new();
    for (a, now, insert) in [
        (&p, 100, true),
        (&approved, 110, false),
        (&consumed, 120, false),
    ] {
        save(&store, a, now, insert).unwrap();
        if a.state() == ApprovalState::Approved {
            approved_body = db
                .sql()
                .query_row("SELECT body FROM approvals", [], |r| r.get(0))
                .unwrap();
        }
        store
            .transact(now.into(), |tx| {
                assert_eq!(tx.get_approval(a.id())?.as_ref(), Some(a));
                Ok(((), vec![]))
            })
            .unwrap();
    }
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 3);
    assert!(
        store
            .check_approval_consistency(&keys())
            .unwrap()
            .is_empty()
    );
    db.sql()
        .execute(
            "UPDATE approvals SET state='Approved', body=?",
            [&approved_body],
        )
        .unwrap();
    assert_eq!(
        store.check_approval_consistency(&keys()).unwrap(),
        vec![p.id().clone()]
    );
}
#[test]
fn migrations_are_idempotent() {
    let db = Db::new("migrations");
    let first = db.open();
    append(&first);
    let conn = db.sql();
    let before: i64 = conn
        .query_row("SELECT count(*) FROM meta", [], |r| r.get(0))
        .unwrap();
    assert!(before > 0);
    drop(first);
    let second = db.open();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    for table in [
        "users",
        "sessions",
        "agents",
        "grants",
        "grant_tombstones",
        "approvals",
        "budget_counters",
        "audit",
        "meta",
    ] {
        conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
    }
    assert_eq!(second.verify_audit(&keys()).unwrap().count, 1);
}

#[test]
fn every_historical_version_upgrades_to_current() {
    let migrations = migrations();
    for version in 1..migrations.len() {
        let db = Db::new(&format!("historical-migration-{version}"));
        let conn = db.sql();
        conn.execute_batch("CREATE TABLE IF NOT EXISTS meta (version INTEGER PRIMARY KEY);")
            .unwrap();
        for (index, migration) in migrations[..version].iter().enumerate() {
            conn.execute_batch(migration).unwrap();
            conn.execute("INSERT INTO meta(version) VALUES (?)", [index + 1])
                .unwrap();
        }

        let approval = pending();
        let approval_body = serde_jcs::to_string(&json!({
            "id": approval.id().as_str(),
            "action": approval.action(),
            "action_digest": approval.action_digest(),
            "rule": approval.rule(),
            "requested_at": approval.requested_at(),
            "expires_at": approval.expires_at(),
            "state": "Pending",
            "decided_by": null,
            "decided_at": null,
            "consumed_at": null,
        }))
        .unwrap();
        conn.execute(
            "INSERT INTO approvals(id,state,agent_id,expires_at,action_digest,body) \
             VALUES (?,?,?,?,?,?)",
            (
                approval.id().as_str(),
                "Pending",
                approval.action().agent_id().as_str(),
                approval.expires_at().as_secs(),
                approval.action_digest().to_string(),
                approval_body,
            ),
        )
        .unwrap();

        let grant = grant();
        let grant_body = serde_jcs::to_string(&serde_json::to_value(&grant).unwrap()).unwrap();
        if version >= 2 {
            conn.execute(
                "INSERT INTO grants(id,agent_id,expires_at,uses,body) VALUES (?,?,?,?,?)",
                (
                    grant.id().as_str(),
                    grant.agent_id().as_str(),
                    grant.expires_at().as_secs(),
                    2,
                    grant_body,
                ),
            )
            .unwrap();
        } else {
            conn.execute(
                "INSERT INTO grants(id,agent_id,expires_at,body) VALUES (?,?,?,?)",
                (
                    grant.id().as_str(),
                    grant.agent_id().as_str(),
                    grant.expires_at().as_secs(),
                    grant_body,
                ),
            )
            .unwrap();
        }

        if version >= 3 {
            conn.execute(
                "INSERT INTO budget_counters(agent_id,rule_name,window_start,used) \
                 VALUES (?,?,?,?)",
                ("claude", "legacy", 0, 4),
            )
            .unwrap();
        } else {
            conn.execute(
                "INSERT INTO budget_counters(agent_id,rule,window_start,body) VALUES (?,?,?,?)",
                ("claude", "legacy", 0, "{}"),
            )
            .unwrap();
        }

        let user = User {
            id: UserId::try_from("admin").unwrap(),
            password_hash: "historical-password-hash".into(),
            totp_secret: None,
            roles: BTreeSet::from([Role::Admin]),
        };
        conn.execute(
            "INSERT INTO users(id,body) VALUES (?,?)",
            ("admin", serde_json::to_string(&user).unwrap()),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agents(id,body) VALUES (?,?)",
            ("claude", r#"{"agent_id":"claude"}"#),
        )
        .unwrap();

        let audit = next_entry(
            None,
            50.into(),
            AuditKind::UserLogin,
            actor(),
            json!({"user_id": "admin", "operation": "historical"}),
            signer().as_ref(),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit(seq,body) VALUES (?,?)",
            (audit.seq(), serde_jcs::to_string(&audit).unwrap()),
        )
        .unwrap();
        drop(conn);

        let store = db.open();
        assert_eq!(
            db.sql()
                .query_row("SELECT max(version) FROM meta", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            migrations.len() as i64,
            "version {version} did not migrate to current"
        );
        assert_eq!(
            store
                .transact(100.into(), |tx| {
                    Ok((tx.get_approval(approval.id())?, vec![]))
                })
                .unwrap(),
            Some(approval.clone()),
            "approval did not survive version {version}"
        );
        let views = store
            .transact(150.into(), |tx| {
                Ok((tx.grant_views_for(grant.agent_id(), 150.into())?, vec![]))
            })
            .unwrap();
        assert_eq!(views.len(), 1, "grant did not survive version {version}");
        assert_eq!(views[0].grant.id(), grant.id());
        assert_eq!(
            views[0].uses,
            if version >= 2 { 2 } else { 0 },
            "grant uses default changed at version {version}"
        );
        let used = store
            .transact(0.into(), |tx| {
                Ok((
                    tx.budget_used(
                        &grant.agent_id().clone(),
                        "legacy",
                        budget(10, 60),
                        0.into(),
                    )?,
                    vec![],
                ))
            })
            .unwrap();
        assert_eq!(
            used,
            if version >= 3 { 4 } else { 0 },
            "budget default changed at version {version}"
        );
        let stored_user = store.find(&user.id).unwrap().unwrap();
        assert_eq!(stored_user.password_hash, user.password_hash);
        assert_eq!(stored_user.roles, user.roles);
        assert_eq!(
            db.sql()
                .query_row(
                    "SELECT last_totp_step FROM users WHERE id='admin'",
                    [],
                    |r| { r.get::<_, Option<i64>>(0) }
                )
                .unwrap(),
            None,
            "last_totp_step default changed at version {version}"
        );
        let (agent_body, token_hash): (String, Vec<u8>) = db
            .sql()
            .query_row(
                "SELECT body,token_hash FROM agents WHERE id='claude'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(agent_body, r#"{"agent_id":"claude"}"#);
        assert!(
            token_hash.is_empty(),
            "token_hash default changed at version {version}"
        );
        assert_eq!(
            store.verify_audit(&keys()).unwrap().count,
            1,
            "audit chain did not survive version {version}"
        );
    }
}

#[test]
fn audit_seq_is_gapless_across_reopen() {
    let db = Db::new("reopen");
    {
        let s = db.open();
        append(&s);
        append(&s);
    }
    let s = db.open();
    append(&s);
    assert_eq!(
        s.audit_entries(0, 100)
            .unwrap()
            .iter()
            .map(AuditEntry::seq)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(s.audit_entries(1, 1).unwrap()[0].seq(), 1);
    assert_eq!(s.verify_audit(&keys()).unwrap().count, 3);
}
#[test]
fn concurrent_transacts_serialize() {
    let db = Db::new("concurrency");
    let store = Arc::new(db.open());
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let s = Arc::clone(&store);
            scope.spawn(move || {
                for _ in 0..100 {
                    append(&s);
                }
            });
        }
    });
    let entries = store.audit_entries(0, 1000).unwrap();
    assert_eq!(
        entries.iter().map(AuditEntry::seq).collect::<Vec<_>>(),
        (0..200).collect::<Vec<_>>()
    );
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 200);
}
#[test]
fn missing_or_wrong_approval_audit_rolls_back() {
    for wrong in [false, true] {
        let db = Db::new("missing-audit");
        let s = db.open();
        let p = pending();
        assert!(
            s.transact(100.into(), |tx| {
                tx.insert_approval(&p)?;
                let mut records = vec![];
                if wrong {
                    let mut r = record(&p);
                    r.subject["action_digest"] = json!("wrong");
                    records.push(r);
                }
                Ok(((), records))
            })
            .is_err()
        );
        assert_empty(&db, &s);
    }
}
#[test]
fn callback_and_sql_audit_failures_roll_back() {
    let db = Db::new("write-failure");
    let s = db.open();
    let p = pending();
    let failed: Result<(), StoreError> = s.transact(100.into(), |tx| {
        tx.insert_approval(&p)?;
        tx.insert_approval(&p)?;
        Ok(((), vec![record(&p)]))
    });
    assert!(failed.is_err());
    assert_empty(&db, &s);
    db.sql().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(save(&s, &p, 100, true).is_err());
    assert_empty(&db, &s);
}
#[test]
fn stale_or_invalid_approval_updates_refuse() {
    let db = Db::new("transitions");
    let s = db.open();
    let p = pending();
    let a = p.approve(&actor(), 110.into()).unwrap();
    assert!(save(&s, &a, 110, true).is_err());
    save(&s, &p, 100, true).unwrap();
    assert!(save(&s, &p, 101, false).is_err());
    let c = a.consume(a.action_digest(), 120.into()).unwrap();
    assert!(save(&s, &c, 120, false).is_err());
    save(&s, &a, 110, false).unwrap();
    assert!(save(&s, &a, 110, false).is_err());
    assert!(save(&s, &c, 160, false).is_err());
    save(&s, &c, 120, false).unwrap();
    assert!(save(&s, &c, 120, false).is_err());
    assert_eq!(s.verify_audit(&keys()).unwrap().count, 3);
}

#[test]
fn ignored_transaction_error_still_rolls_back() {
    let db = Db::new("ignored-error");
    let s = db.open();
    let p = pending();
    assert!(
        s.transact(100.into(), |tx| {
            tx.insert_approval(&p)?;
            assert!(tx.insert_approval(&p).is_err());
            Ok(((), vec![record(&p)]))
        })
        .is_err()
    );
    assert_empty(&db, &s);
}
#[test]
fn audit_build_failure_rolls_back() {
    let db = Db::new("build-failure");
    let s = db.open();
    append(&s);
    let p = pending();
    assert!(
        s.transact(99.into(), |tx| {
            let p = Approval::request(
                p.id().clone(),
                p.action().clone(),
                p.rule().into(),
                99.into(),
                60,
            )
            .unwrap();
            tx.insert_approval(&p)?;
            Ok(((), vec![record(&p)]))
        })
        .is_err()
    );
    assert_eq!(s.verify_audit(&keys()).unwrap().count, 1);
    assert_eq!(
        db.sql()
            .query_row("SELECT count(*) FROM approvals", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn independent_connections_serialize() {
    let db = Db::new("connections");
    let a = db.open();
    let b = db.open();
    std::thread::scope(|scope| {
        for s in [&a, &b] {
            scope.spawn(move || {
                for _ in 0..100 {
                    append(s);
                }
            });
        }
    });
    assert_eq!(a.verify_audit(&keys()).unwrap().count, 200);
}
#[test]
fn denied_and_expired_approvals_round_trip() {
    for approved_first in [false, true] {
        for expire in [false, true] {
            if approved_first && !expire {
                continue;
            }
            let db = Db::new("round-trip");
            let s = db.open();
            let mut a = pending();
            save(&s, &a, 100, true).unwrap();
            if approved_first {
                a = a.approve(&actor(), 110.into()).unwrap();
                save(&s, &a, 110, false).unwrap();
            }
            let (a, now) = if expire {
                (a.expire(160.into()).unwrap(), 160)
            } else {
                (a.deny(&actor(), 110.into()).unwrap(), 110)
            };
            save(&s, &a, now, false).unwrap();
            drop(s);
            db.open()
                .transact(now.into(), |tx| {
                    assert_eq!(tx.get_approval(a.id())?, Some(a.clone()));
                    Ok(((), vec![]))
                })
                .unwrap();
        }
    }
}
#[test]
fn consistency_detects_body_tamper_and_deleted_row() {
    let db = Db::new("tamper-body");
    let s = db.open();
    let p = pending();
    save(&s, &p, 100, true).unwrap();
    db.sql()
        .execute(
            "UPDATE approvals SET body=json_set(body,'$.state','Approved')",
            [],
        )
        .unwrap();
    assert_eq!(
        s.check_approval_consistency(&keys()).unwrap(),
        vec![p.id().clone()]
    );
    db.sql().execute("DELETE FROM approvals", []).unwrap();
    assert_eq!(
        s.check_approval_consistency(&keys()).unwrap(),
        vec![p.id().clone()]
    );
}

#[test]
fn consistency_check_rejects_unsigned_forged_audit_row() {
    let db = Db::new("forged-audit");
    let store = db.open();
    let pending = pending();
    save(&store, &pending, 100, true).unwrap();

    let approved = pending.approve(&actor(), 110.into()).unwrap();
    save(&store, &approved, 110, false).unwrap();
    let approved_body: String = db
        .sql()
        .query_row("SELECT body FROM approvals", [], |r| r.get(0))
        .unwrap();
    db.sql()
        .execute("DELETE FROM audit WHERE seq=1", [])
        .unwrap();
    let mut forged: serde_json::Value = db
        .sql()
        .query_row("SELECT body FROM audit WHERE seq=0", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap()
        .parse()
        .unwrap();
    forged["seq"] = json!(1);
    forged["subject"]["state"] = json!("Approved");
    db.sql()
        .execute(
            "INSERT INTO audit(seq,body) VALUES (1,?)",
            [serde_jcs::to_string(&forged).unwrap()],
        )
        .unwrap();
    db.sql()
        .execute(
            "UPDATE approvals SET state='Approved', body=?",
            [approved_body],
        )
        .unwrap();

    assert!(matches!(
        store.check_approval_consistency(&keys()),
        Err(StoreError::Chain(_))
    ));
}

#[test]
fn audit_verification_reads_more_than_one_page() {
    let db = Db::new("audit-pages");
    let store = db.open();
    for _ in 0..1_001 {
        append(&store);
    }
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 1_001);
}

#[test]
fn lossy_canonical_approval_body_refuses_write() {
    let db = Db::new("lossy-body");
    let s = db.open();
    let template = pending();
    let now = 9_007_199_254_740_931;
    let a = Approval::request(
        template.id().clone(),
        template.action().clone(),
        "main".into(),
        now.into(),
        62,
    )
    .unwrap();
    assert!(save(&s, &a, now, true).is_err());
    assert_empty(&db, &s);
}

#[test]
fn canonical_action_numbers_survive_approval_transition() {
    let db = Db::new("canonical-numbers");
    let s = db.open();
    let p = pending();
    let action = Action::new(
        p.action().agent_id().clone(),
        p.action().tool().clone(),
        "repo:main".into(),
        // Integral floats and -0.0 are refused at construction (DS-01).
        json!({"a":0.5,"b":1e30,"c":-2.5}),
    )
    .unwrap();
    let p = Approval::request(p.id().clone(), action, "main".into(), 100.into(), 60).unwrap();
    save(&s, &p, 100, true).unwrap();
    let a = p.approve(&actor(), 110.into()).unwrap();
    save(&s, &a, 110, false).unwrap();
    s.transact(110.into(), |tx| {
        let stored = tx.get_approval(a.id())?.unwrap();
        assert_eq!(stored.action_digest(), a.action_digest());
        assert_eq!(stored.state(), ApprovalState::Approved);
        Ok(((), vec![]))
    })
    .unwrap();
}

fn budget(max: u32, per_seconds: u32) -> Budget {
    Budget { max, per_seconds }
}

fn budget_used(store: &Store, agent: &AgentId, rule: &str, configured: Budget, now: i64) -> u32 {
    store
        .transact(now.into(), |tx| {
            Ok((tx.budget_used(agent, rule, configured, now.into())?, vec![]))
        })
        .unwrap()
}

fn execute_with_budget(store: &Store, agent: &AgentId, rule: &str, configured: Budget, now: i64) {
    store
        .transact(now.into(), |tx| {
            tx.record_budget_use(agent, rule, configured, now.into())?;
            Ok((
                (),
                vec![AuditRecord {
                    kind: AuditKind::Decided,
                    actor: Principal::Agent(agent.clone()),
                    subject: json!({"rule": rule, "executed": true}),
                }],
            ))
        })
        .unwrap();
}

#[test]
fn counter_increments_only_on_execution() {
    let db = Db::new("budget-execution");
    let store = db.open();
    let agent = AgentId::try_from("claude").unwrap();
    let configured = budget(2, 60);

    assert_eq!(budget_used(&store, &agent, "main", configured, 100), 0);
    assert_eq!(budget_used(&store, &agent, "main", configured, 100), 0);

    execute_with_budget(&store, &agent, "main", configured, 100);
    assert_eq!(budget_used(&store, &agent, "main", configured, 100), 1);
}

#[test]
fn window_rolls_over() {
    let db = Db::new("budget-window");
    let store = db.open();
    let agent = AgentId::try_from("claude").unwrap();
    let configured = budget(2, 60);

    execute_with_budget(&store, &agent, "main", configured, 100);
    assert_eq!(budget_used(&store, &agent, "main", configured, 119), 1);
    assert_eq!(budget_used(&store, &agent, "main", configured, 120), 0);

    execute_with_budget(&store, &agent, "main", configured, 120);
    assert_eq!(budget_used(&store, &agent, "main", configured, 179), 1);
    assert_eq!(budget_used(&store, &agent, "main", configured, 180), 0);
}

#[test]
fn budgets_are_per_agent_and_rule() {
    let db = Db::new("budget-isolation");
    let store = db.open();
    let claude = AgentId::try_from("claude").unwrap();
    let codex = AgentId::try_from("codex").unwrap();
    let configured = budget(2, 60);

    execute_with_budget(&store, &claude, "main", configured, 100);
    execute_with_budget(&store, &claude, "main", configured, 101);
    execute_with_budget(&store, &claude, "release", configured, 102);
    execute_with_budget(&store, &codex, "main", configured, 103);

    assert_eq!(budget_used(&store, &claude, "main", configured, 104), 2);
    assert_eq!(budget_used(&store, &claude, "release", configured, 104), 1);
    assert_eq!(budget_used(&store, &codex, "main", configured, 104), 1);
}

#[test]
fn budget_is_counted_server_side() {
    let db = Db::new("budget-server-side");
    let agent = AgentId::try_from("claude").unwrap();
    let configured = budget(5, 60);
    {
        let store = db.open();
        execute_with_budget(&store, &agent, "main", configured, 100);
        execute_with_budget(&store, &agent, "main", configured, 101);
    }

    let reopened = db.open();
    assert_eq!(budget_used(&reopened, &agent, "main", configured, 102), 2);
    assert_eq!(
        db.sql()
            .query_row(
                "SELECT used FROM budget_counters WHERE agent_id=? AND rule_name=? AND window_start=?",
                ("claude", "main", 60),
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
}

#[test]
fn revocation_is_durable_before_effect() {
    let db = Db::new("grant-revoke-failure");
    let store = db.open();
    let g = grant();
    let by = UserId::try_from("admin").unwrap();
    save_grant(&store, &g).unwrap();
    db.sql()
        .execute_batch(
            "CREATE TRIGGER fail_tombstone BEFORE INSERT ON grant_tombstones \
             BEGIN SELECT RAISE(ABORT,'injected'); END;",
        )
        .unwrap();

    assert!(revoke_grant(&store, &g, &by, 150).is_err());

    let views = store
        .transact(150.into(), |tx| {
            Ok((tx.grant_views_for(g.agent_id(), 150.into())?, vec![]))
        })
        .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].uses, 0);
    assert!(!views[0].revoked);
    assert_eq!(
        g.is_valid_at(
            &grant_signer().public_key(),
            150.into(),
            views[0].uses,
            views[0].revoked,
        ),
        Ok(())
    );
    assert_eq!(
        db.sql()
            .query_row("SELECT count(*) FROM grant_tombstones", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 1);
}

#[test]
fn revoked_grant_never_reloads_valid_after_reopen() {
    let db = Db::new("grant-revoke-reopen");
    let g = grant();
    let by = UserId::try_from("admin").unwrap();
    {
        let store = db.open();
        save_grant(&store, &g).unwrap();
        revoke_grant(&store, &g, &by, 150).unwrap();
    }

    let store = db.open();
    let views = store
        .transact(150.into(), |tx| {
            Ok((tx.grant_views_for(g.agent_id(), 150.into())?, vec![]))
        })
        .unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].grant.id(), g.id());
    assert!(views[0].revoked);
    assert_eq!(
        g.is_valid_at(
            &grant_signer().public_key(),
            150.into(),
            views[0].uses,
            views[0].revoked,
        ),
        Err(GrantInvalid::Revoked)
    );
    assert!(matches!(
        store.transact(150.into(), |tx| {
            tx.record_grant_use(g.id())?;
            Ok(((), vec![]))
        }),
        Err(StoreError::InvalidGrant)
    ));
    let entries = store.audit_entries(0, 10).unwrap();
    assert_eq!(entries[1].kind(), AuditKind::GrantRevoked);
    assert_eq!(entries[1].subject()["grant_id"], g.id().as_str());
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 2);
}

#[test]
fn grant_uses_counted_server_side() {
    let db = Db::new("grant-uses");
    let g = grant();
    {
        let store = db.open();
        save_grant(&store, &g).unwrap();
        for now in [110, 120, 130] {
            store
                .transact(now.into(), |tx| {
                    tx.record_grant_use(g.id())?;
                    Ok(((), vec![used_record(&g, ((now - 100) / 10) as u32)]))
                })
                .unwrap();
        }
        let views = store
            .transact(150.into(), |tx| {
                Ok((tx.grant_views_for(g.agent_id(), 150.into())?, vec![]))
            })
            .unwrap();
        assert_eq!(views[0].uses, 3);
    }

    let store = db.open();
    let views = store
        .transact(150.into(), |tx| {
            Ok((tx.grant_views_for(g.agent_id(), 150.into())?, vec![]))
        })
        .unwrap();
    assert_eq!(views[0].uses, 3);
    assert_eq!(
        g.is_valid_at(
            &grant_signer().public_key(),
            150.into(),
            views[0].uses,
            views[0].revoked,
        ),
        Err(GrantInvalid::Exhausted)
    );
}

#[test]
fn grant_state_changes_require_matching_audit() {
    for wrong in [false, true] {
        let db = Db::new("grant-missing-audit");
        let store = db.open();
        let g = grant();
        let result = store.transact(100.into(), |tx| {
            tx.insert_grant(&g)?;
            let records = if wrong {
                let mut record = issued_record(&g);
                record.subject["grant_id"] = json!("grt_zzzzzzzzzzzzzzzzzzzzzzzzzz");
                vec![record]
            } else {
                vec![]
            };
            Ok(((), records))
        });
        assert!(result.is_err());
        assert_eq!(
            db.sql()
                .query_row("SELECT count(*) FROM grants", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(store.audit_entries(0, 10).unwrap().is_empty());
    }

    let db = Db::new("grant-revoke-missing-audit");
    let store = db.open();
    let g = grant();
    let by = UserId::try_from("admin").unwrap();
    save_grant(&store, &g).unwrap();
    assert!(matches!(
        store.transact(150.into(), |tx| {
            tx.revoke_grant(g.id(), &by, 140.into())?;
            Ok(((), vec![revoked_record(&g, &by, 140)]))
        }),
        Err(StoreError::InvalidGrant)
    ));
    assert!(
        store
            .transact(150.into(), |tx| {
                tx.revoke_grant(g.id(), &by, 150.into())?;
                Ok(((), vec![]))
            })
            .is_err()
    );
    let views = store
        .transact(150.into(), |tx| {
            Ok((tx.grant_views_for(g.agent_id(), 150.into())?, vec![]))
        })
        .unwrap();
    assert_eq!(views.len(), 1);
    assert!(!views[0].revoked);
    assert_eq!(store.verify_audit(&keys()).unwrap().count, 1);
}

fn saved_approved(store: &Store) -> Approval {
    let p = pending();
    save(store, &p, 100, true).unwrap();
    let a = p.approve(&actor(), 110.into()).unwrap();
    save(store, &a, 110, false).unwrap();
    a
}

#[test]
fn approval_is_bound_to_digest() {
    let db = Db::new("consume-digest");
    let store = db.open();
    let a = saved_approved(&store);
    let changed = Action::new(
        a.action().agent_id().clone(),
        a.action().tool().clone(),
        "other".into(),
        json!({}),
    )
    .unwrap();
    assert!(
        store
            .consume_approval(a.id(), &changed.digest().unwrap(), 120.into())
            .is_err()
    );
    assert_eq!(store.audit_entries(0, 10).unwrap().len(), 2);
    let consumed = store
        .consume_approval(a.id(), a.action_digest(), 120.into())
        .unwrap();
    assert_eq!(consumed.state(), ApprovalState::Consumed);
    assert_eq!(consumed.consumed_at(), Some(120.into()));
    assert!(
        store
            .check_approval_consistency(&keys())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn approval_is_single_use() {
    let db = Db::new("consume-concurrent");
    let store = db.open();
    let a = saved_approved(&store);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let store = db.open();
            let a = a.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .consume_approval(a.id(), a.action_digest(), 120.into())
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .filter_map(|w| w.join().unwrap().then_some(()))
            .count(),
        1
    );
    assert_eq!(
        store
            .audit_entries(0, 10)
            .unwrap()
            .iter()
            .filter(|e| e.kind() == AuditKind::Consumed)
            .count(),
        1
    );
    assert!(
        store
            .consume_approval(a.id(), a.action_digest(), 121.into())
            .is_err()
    );
    store.verify_audit(&keys()).unwrap();
}

#[test]
fn expired_approval_not_consumable() {
    let db = Db::new("consume-expired");
    let store = db.open();
    let a = saved_approved(&store);
    for now in [160, 161] {
        assert!(
            store
                .consume_approval(a.id(), a.action_digest(), now.into())
                .is_err()
        );
    }
    assert_eq!(store.audit_entries(0, 10).unwrap().len(), 2);
}

#[test]
fn denied_approval_not_consumable() {
    let db = Db::new("consume-denied");
    let store = db.open();
    let p = pending();
    save(&store, &p, 100, true).unwrap();
    assert!(
        store
            .consume_approval(p.id(), p.action_digest(), 105.into())
            .is_err()
    );
    let a = p.deny(&actor(), 110.into()).unwrap();
    save(&store, &a, 110, false).unwrap();
    assert!(
        store
            .consume_approval(a.id(), a.action_digest(), 120.into())
            .is_err()
    );
    assert_eq!(store.audit_entries(0, 10).unwrap().len(), 2);
}

#[test]
fn consumption_audit_failure_rolls_back() {
    let db = Db::new("consume-audit-fail");
    let store = db.open();
    let a = saved_approved(&store);
    db.sql().execute_batch("CREATE TRIGGER fail_consume BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(
        store
            .consume_approval(a.id(), a.action_digest(), 120.into())
            .is_err()
    );
    assert_eq!(
        store
            .transact(120.into(), |tx| Ok((tx.get_approval(a.id())?, vec![])))
            .unwrap(),
        Some(a.clone())
    );
    db.sql().execute_batch("DROP TRIGGER fail_consume").unwrap();
    store
        .consume_approval(a.id(), a.action_digest(), 120.into())
        .unwrap();
}

fn used_record(g: &Grant, uses: u32) -> AuditRecord {
    AuditRecord {
        kind: AuditKind::Consumed,
        actor: Principal::Agent(g.agent_id().clone()),
        subject: json!({"grant_id": g.id().as_str(), "uses": uses, "action_digest": pending().action_digest()}),
    }
}

#[test]
fn grant_use_without_audit_is_refused() {
    let db = Db::new("grant-use-audit");
    let store = db.open();
    let g = grant();
    save_grant(&store, &g).unwrap();
    assert!(matches!(
        store.transact(110.into(), |tx| {
            tx.record_grant_use(g.id())?;
            Ok(((), vec![]))
        }),
        Err(StoreError::MissingAudit)
    ));
    assert_eq!(
        store
            .transact(110.into(), |tx| Ok((
                tx.grant_views_for(g.agent_id(), 110.into())?,
                vec![]
            )))
            .unwrap()[0]
            .uses,
        0
    );
}

#[test]
fn grant_use_count_is_in_chain() {
    let db = Db::new("grant-use-chain");
    let store = db.open();
    let g = grant();
    save_grant(&store, &g).unwrap();
    for uses in 1..=2 {
        store
            .transact(110.into(), |tx| {
                tx.record_grant_use(g.id())?;
                Ok(((), vec![used_record(&g, uses)]))
            })
            .unwrap();
    }
    let entries = store.audit_entries(0, 10).unwrap();
    for (e, uses) in entries[1..].iter().zip(1..=2) {
        assert_eq!(e.kind(), AuditKind::Consumed);
        assert_eq!(e.subject()["uses"], uses);
        assert_eq!(
            e.subject()["action_digest"],
            pending().action_digest().to_string()
        );
    }
    store.verify_audit(&keys()).unwrap();
}

#[test]
fn grant_use_wrong_audit_rolls_back() {
    let db = Db::new("grant-use-wrong-audit");
    let store = db.open();
    let g = grant();
    save_grant(&store, &g).unwrap();
    for wrong in 0..5 {
        let mut record = used_record(&g, 1);
        match wrong {
            0 => record.kind = AuditKind::Decided,
            1 => record.subject["uses"] = json!(2),
            2 => record.subject["grant_id"] = json!("grt_bbbbbbbbbbbbbbbbbbbbbbbbbb"),
            3 => {
                record
                    .subject
                    .as_object_mut()
                    .unwrap()
                    .remove("action_digest");
            }
            _ => record.subject["action_digest"] = json!("invalid"),
        }
        assert!(matches!(
            store.transact(110.into(), |tx| {
                tx.record_grant_use(g.id())?;
                Ok(((), vec![record]))
            }),
            Err(StoreError::MissingAudit)
        ));
    }
    assert_eq!(
        store
            .transact(110.into(), |tx| Ok((
                tx.grant_views_for(g.agent_id(), 110.into())?,
                vec![]
            )))
            .unwrap()[0]
            .uses,
        0
    );
    assert_eq!(store.audit_entries(0, 10).unwrap().len(), 1);
}

#[test]
fn consumption_signing_failure_rolls_back() {
    let db = Db::new("consume-signing-fail");
    let store = db.open();
    let a = saved_approved(&store);
    let failing = Store::open(&db.0, Arc::new(FailingSigner)).unwrap();
    assert!(
        failing
            .consume_approval(a.id(), a.action_digest(), 120.into())
            .is_err()
    );
    assert_eq!(
        store
            .transact(120.into(), |tx| Ok((tx.get_approval(a.id())?, vec![])))
            .unwrap(),
        Some(a.clone())
    );
    assert_eq!(store.audit_entries(0, 10).unwrap().len(), 2);
    store
        .consume_approval(a.id(), a.action_digest(), 120.into())
        .unwrap();
}
