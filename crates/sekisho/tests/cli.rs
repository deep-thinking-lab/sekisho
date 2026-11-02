#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use sekisho::store::{AuditRecord, Store};
use sekisho_core::{
    AuditEntry, AuditKind, Ed25519Signer, Principal, PublicKey, Signer, Timestamp, UserId,
    checkpoint, next_entry, verify_chain,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    hash::BuildHasher,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let suffix = std::hash::RandomState::new().hash_one(name);
        let path =
            std::env::temp_dir().join(format!("sekisho-{name}-{}-{suffix}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes("audit", &[seed; 32])
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn home_with_entries(name: &str, times: &[i64]) -> (TempDir, PathBuf) {
    let home = TempDir::new(name);
    let sekisho_home = home.path().join(".sekisho");
    fs::create_dir(&sekisho_home).unwrap();
    set_mode(&sekisho_home, 0o700);
    let keys = sekisho_home.join("keys");
    fs::create_dir(&keys).unwrap();
    set_mode(&keys, 0o700);
    let audit_key = keys.join("audit.ed25519");
    fs::write(&audit_key, [7_u8; 32]).unwrap();
    set_mode(&audit_key, 0o600);
    let grant_key = keys.join("grant.ed25519");
    fs::write(&grant_key, [8_u8; 32]).unwrap();
    set_mode(&grant_key, 0o600);
    let store = Store::open(&sekisho_home.join("sekisho.db"), Arc::new(signer(7))).unwrap();
    set_mode(&sekisho_home.join("sekisho.db"), 0o600);
    for at in times {
        store
            .transact(Timestamp::from(*at), |_| {
                Ok((
                    (),
                    vec![AuditRecord {
                        kind: AuditKind::PolicyLoaded,
                        actor: Principal::User(UserId::try_from("admin").unwrap()),
                        subject: json!({"policy_sha256": format!("policy-{at}")}),
                    }],
                ))
            })
            .unwrap();
    }
    let export = home.path().join("audit.jsonl");
    (home, export)
}

fn sekisho() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sekisho"))
}

fn run_export(home: &Path, out: &Path, extra: &[&str]) -> Output {
    let mut command = sekisho();
    command
        .env("HOME", home)
        .args(["audit", "export", "--out"])
        .arg(out)
        .args(extra)
        .output()
        .expect("audit export should run")
}

fn run_verify(file: &Path, extra: &[&str]) -> Output {
    sekisho()
        .args(["audit", "verify"])
        .arg(file)
        .args(extra)
        .output()
        .expect("audit verify should run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be UTF-8")
}

fn exported_key_argument(output: &Output) -> String {
    let stderr = stderr(output);
    let lines: Vec<_> = stderr.lines().collect();
    assert_eq!(lines.len(), 1, "unexpected export stderr: {stderr}");
    let argument = lines[0]
        .strip_prefix("--pubkey ")
        .expect("export should print a --pubkey argument");
    let encoded = argument
        .strip_prefix("audit=")
        .expect("exported key id should be audit");
    let key = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("exported public key should be base64");
    assert_eq!(key.len(), 32);
    argument.to_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        stderr(output)
    );
}

fn assert_invalid(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {} stderr: {}",
        stdout(output),
        stderr(output)
    );
}

fn assert_unauthenticated(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout: {} stderr: {}",
        stdout(output),
        stderr(output)
    );
    assert_eq!(
        stderr(output),
        "UNAUTHENTICATED: signatures checked only against keys inside the file; pass --pubkey to authenticate\n"
    );
}

fn rewrite_with_signer(
    source: &Path,
    out: &Path,
    signer: &Ed25519Signer,
    embedded: &BTreeMap<String, PublicKey>,
) {
    let source = fs::read_to_string(source).unwrap();
    let lines: Vec<_> = source.lines().collect();
    let original = lines[..lines.len() - 1]
        .iter()
        .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap())
        .collect::<Vec<_>>();
    let mut entries = Vec::new();
    for entry in original {
        entries.push(
            next_entry(
                entries.last(),
                entry.at(),
                entry.kind(),
                entry.actor().clone(),
                entry.subject().clone(),
                signer,
            )
            .unwrap(),
        );
    }
    let last = entries.last().unwrap();
    let anchor = checkpoint(last, last.at(), signer).unwrap();
    let mut contents = entries
        .iter()
        .map(|entry| serde_json::to_string(entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    contents.push('\n');
    contents.push_str(
        &serde_json::to_string(&json!({
            "checkpoint": anchor,
            "public_keys": embedded,
        }))
        .unwrap(),
    );
    contents.push('\n');
    fs::write(out, contents).unwrap();
}

#[test]
fn version_flag_prints_name_and_version() {
    let output = sekisho()
        .arg("--version")
        .output()
        .expect("sekisho --version should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("version output should be UTF-8");
    let version = stdout
        .strip_prefix("sekisho ")
        .expect("output should start with the binary name")
        .trim_end();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn round_trip_verifies() {
    let (home, export) = home_with_entries("round-trip", &[100, 101, 102]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let key_argument = exported_key_argument(&exported);

    let lines = fs::read_to_string(&export).unwrap();
    let lines: Vec<_> = lines.lines().collect();
    assert_eq!(lines.len(), 4);
    let trailer: Value = serde_json::from_str(lines[3]).unwrap();
    assert!(trailer["checkpoint"].is_object());
    assert_eq!(
        trailer["public_keys"]["audit"],
        signer(7).public_key().to_string()
    );

    let unauthenticated = run_verify(&export, &[]);
    assert_unauthenticated(&unauthenticated);
    assert_eq!(
        stdout(&unauthenticated),
        "valid: entries=3 first_seq=0 last_seq=2 time_range=100..102 keys=audit\n"
    );

    let verified = run_verify(&export, &["--pubkey", &key_argument]);
    assert_success(&verified);
    assert_eq!(
        stdout(&verified),
        "valid: entries=3 first_seq=0 last_seq=2 time_range=100..102 keys=audit\n"
    );

    let partial = home.path().join("partial.jsonl");
    let exported = run_export(home.path(), &partial, &["--from", "1"]);
    assert_success(&exported);
    let key_argument = exported_key_argument(&exported);
    let verified = run_verify(&partial, &["--pubkey", &key_argument]);
    assert_success(&verified);
    assert_eq!(
        stdout(&verified),
        "valid: entries=2 first_seq=1 last_seq=2 time_range=101..102 keys=audit\n"
    );
}

#[test]
fn edited_export_fails_with_seq() {
    let (home, export) = home_with_entries("edited", &[100, 101, 102]);
    assert_success(&run_export(home.path(), &export, &[]));

    let mut lines: Vec<Value> = fs::read_to_string(&export)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines[1]["subject"] = json!({"policy_sha256": "tampered"});
    let edited = lines
        .iter()
        .map(|line| serde_json::to_string(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&export, edited).unwrap();

    let verified = run_verify(&export, &[]);
    assert_invalid(&verified);
    let error = stderr(&verified);
    assert!(error.contains("seq 1"), "{error}");
    assert!(error.contains("bad entry hash"), "{error}");
}

#[test]
fn truncated_export_fails_against_checkpoint() {
    let (home, export) = home_with_entries("truncated", &[100, 101, 102]);
    assert_success(&run_export(home.path(), &export, &[]));

    let mut lines: Vec<String> = fs::read_to_string(&export)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    lines.remove(2);
    fs::write(&export, lines.join("\n") + "\n").unwrap();

    let verified = run_verify(&export, &[]);
    assert_invalid(&verified);
    let error = stderr(&verified);
    assert!(error.contains("seq 2"), "{error}");
    assert!(error.contains("before checkpoint 2"), "{error}");
}

#[test]
fn suffix_export_is_smaller_and_verifies() {
    let (home, full) = home_with_entries("suffix", &[100, 101, 102, 103]);
    let full_export = run_export(home.path(), &full, &[]);
    assert_success(&full_export);
    let key_argument = exported_key_argument(&full_export);

    let suffix = home.path().join("suffix.jsonl");
    let exported = run_export(home.path(), &suffix, &["--from", "2"]);
    assert_success(&exported);
    assert!(
        fs::metadata(&suffix).unwrap().len() < fs::metadata(&full).unwrap().len(),
        "suffix export should be smaller"
    );

    let contents = fs::read_to_string(&suffix).unwrap();
    let lines: Vec<_> = contents.lines().collect();
    assert_eq!(lines.len(), 3);
    let first: AuditEntry = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first.seq(), 2);
    let trailer: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(trailer["start_checkpoint"]["seq"], 1);
    assert!(trailer.get("checkpoint").is_none());
    assert!(trailer.get("verified_prefix").is_none());

    let verified = run_verify(&suffix, &["--pubkey", &key_argument]);
    assert_success(&verified);
    assert_eq!(
        stdout(&verified),
        "valid: entries=2 first_seq=2 last_seq=3 time_range=102..103 keys=audit\n"
    );
}

#[test]
fn full_export_still_verifies() {
    let (home, export) = home_with_entries("full-format", &[100, 101, 102]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let key_argument = exported_key_argument(&exported);

    let contents = fs::read_to_string(&export).unwrap();
    let lines: Vec<_> = contents.lines().collect();
    assert_eq!(lines.len(), 4);
    let trailer: Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(trailer["checkpoint"]["seq"], 2);
    assert!(trailer.get("start_checkpoint").is_none());

    let verified = run_verify(&export, &["--pubkey", &key_argument]);
    assert_success(&verified);
    assert_eq!(
        stdout(&verified),
        "valid: entries=3 first_seq=0 last_seq=2 time_range=100..102 keys=audit\n"
    );
}

#[test]
fn verify_needs_no_database() {
    let (home, export) = home_with_entries("offline", &[100, 101]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let key_argument = exported_key_argument(&exported);
    let saved = TempDir::new("offline-saved");
    let saved_export = saved.path().join("audit.jsonl");
    fs::copy(&export, &saved_export).unwrap();
    fs::remove_dir_all(home.path()).unwrap();

    let verified = sekisho()
        .current_dir(saved.path())
        .env("HOME", saved.path().join("missing-home"))
        .args(["audit", "verify"])
        .arg(&saved_export)
        .args(["--pubkey", &key_argument])
        .output()
        .unwrap();
    assert_success(&verified);
    assert!(stdout(&verified).contains("entries=2 first_seq=0 last_seq=1"));
}

#[test]
fn external_pubkey_overrides_embedded() {
    let (home, export) = home_with_entries("external-key", &[100]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let authentic_override = exported_key_argument(&exported);
    assert_success(&run_verify(&export, &["--pubkey", &authentic_override]));

    let wrong = signer(8).public_key();
    let wrong_override = format!(
        "audit={}",
        base64::engine::general_purpose::STANDARD.encode(wrong.to_bytes())
    );
    assert_invalid(&run_verify(&export, &["--pubkey", &wrong_override]));

    let mut lines: Vec<Value> = fs::read_to_string(&export)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let last = lines.len() - 1;
    lines[last]["public_keys"]["audit"] = json!(wrong.to_string());
    let replaced = lines
        .iter()
        .map(|line| serde_json::to_string(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&export, replaced).unwrap();

    assert_invalid(&run_verify(&export, &[]));
    assert_success(&run_verify(&export, &["--pubkey", &authentic_override]));
}

#[test]
fn embedded_key_substitution_is_unauthenticated() {
    let (home, export) = home_with_entries("substituted", &[100, 101, 102]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let authentic_override = exported_key_argument(&exported);

    let attacker = Ed25519Signer::from_secret_bytes("attacker", &[9; 32]);
    let substituted = home.path().join("substituted.jsonl");
    let embedded = BTreeMap::from([
        ("audit".to_owned(), signer(7).public_key()),
        ("attacker".to_owned(), attacker.public_key()),
    ]);
    rewrite_with_signer(&export, &substituted, &attacker, &embedded);

    let unauthenticated = run_verify(&substituted, &[]);
    assert_unauthenticated(&unauthenticated);
    assert!(stdout(&unauthenticated).starts_with("valid: entries=3"));

    let authenticated = run_verify(&substituted, &["--pubkey", &authentic_override]);
    assert_invalid(&authenticated);
    let error = stderr(&authenticated);
    assert!(error.contains("seq 0"), "{error}");
    assert!(error.contains("unknown key attacker"), "{error}");

    let source = fs::read_to_string(&export).unwrap();
    let lines: Vec<_> = source.lines().collect();
    let entries = lines[..lines.len() - 1]
        .iter()
        .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap())
        .collect::<Vec<_>>();
    let last = entries.last().unwrap();
    let attacker_anchor = checkpoint(last, last.at(), &attacker).unwrap();
    let attacker_checkpoint = home.path().join("attacker-checkpoint.jsonl");
    let mut contents = lines[..lines.len() - 1].join("\n");
    contents.push('\n');
    contents.push_str(
        &serde_json::to_string(&json!({
            "checkpoint": attacker_anchor,
            "public_keys": embedded,
        }))
        .unwrap(),
    );
    contents.push('\n');
    fs::write(&attacker_checkpoint, contents).unwrap();

    let authenticated = run_verify(&attacker_checkpoint, &["--pubkey", &authentic_override]);
    assert_invalid(&authenticated);
    let error = stderr(&authenticated);
    assert!(error.contains("seq 2"), "{error}");
    assert!(error.contains("unknown key attacker"), "{error}");
}

#[test]
fn extra_embedded_key_is_ignored_when_pubkey_given() {
    let (home, export) = home_with_entries("extra-embedded", &[100, 101]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let authentic_override = exported_key_argument(&exported);

    let attacker = Ed25519Signer::from_secret_bytes("attacker", &[9; 32]);
    let substituted = home.path().join("extra-embedded.jsonl");
    let embedded = BTreeMap::from([
        ("audit".to_owned(), signer(7).public_key()),
        ("attacker".to_owned(), attacker.public_key()),
    ]);
    rewrite_with_signer(&export, &substituted, &attacker, &embedded);

    let authenticated = run_verify(&substituted, &["--pubkey", &authentic_override]);
    assert_invalid(&authenticated);
    let error = stderr(&authenticated);
    assert!(error.contains("seq 0"), "{error}");
    assert!(error.contains("unknown key attacker"), "{error}");
}

#[test]
fn pubkey_file_trust_anchor() {
    let (home, export) = home_with_entries("pubkey-file", &[100, 101]);
    let exported = run_export(home.path(), &export, &[]);
    assert_success(&exported);
    let authentic_override = exported_key_argument(&exported);
    let authentic_line = authentic_override.replacen('=', " ", 1);
    let authentic_file = home.path().join("authentic.pub");
    fs::write(&authentic_file, authentic_line + "\n").unwrap();

    let verified = run_verify(
        &export,
        &["--pubkey-file", authentic_file.to_str().unwrap()],
    );
    assert_success(&verified);

    let wrong_line = format!(
        "audit {}",
        base64::engine::general_purpose::STANDARD.encode(signer(8).public_key().to_bytes())
    );
    let wrong_file = home.path().join("wrong.pub");
    fs::write(&wrong_file, wrong_line + "\n").unwrap();

    let rejected = run_verify(&export, &["--pubkey-file", wrong_file.to_str().unwrap()]);
    assert_invalid(&rejected);
}

fn audit_keys(home: &Path) -> BTreeMap<String, (PathBuf, PublicKey)> {
    let directory = home.join("keys/audit");
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700,
        "{} should be private",
        directory.display()
    );
    fs::read_dir(&directory)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{} should be private",
                path.display()
            );
            let key_id = path
                .file_stem()
                .and_then(|name| name.to_str())
                .expect("key id should be UTF-8")
                .to_owned();
            let encoded = fs::read_to_string(&path).unwrap();
            let bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .unwrap()
                .try_into()
                .expect("registry key should be 32 bytes");
            (key_id, (path, PublicKey::from(bytes)))
        })
        .collect()
}

fn persisted_audit(home: &Path) -> Vec<AuditEntry> {
    let connection = rusqlite::Connection::open(home.join("sekisho.db")).unwrap();
    connection
        .prepare("SELECT body FROM audit ORDER BY seq")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(|body| serde_json::from_str(&body.unwrap()).unwrap())
        .collect()
}

fn rotated_key_id(home: &Path) -> String {
    persisted_audit(home)
        .into_iter()
        .find(|entry| entry.kind() == AuditKind::KeyRotated)
        .and_then(|entry| entry.subject()["key_id"].as_str().map(str::to_owned))
        .expect("rotation should name the new key")
}

fn write_key_file(path: &Path, keys: impl IntoIterator<Item = (String, PublicKey)>) {
    let contents = keys
        .into_iter()
        .map(|(key_id, key)| {
            format!(
                "{key_id} {}\n",
                base64::engine::general_purpose::STANDARD.encode(key.to_bytes())
            )
        })
        .collect::<String>();
    fs::write(path, contents).unwrap();
}

#[test]
fn rotation_writes_signed_rotation_entry() {
    let home = temp_home("rotation-entry");
    let before = audit_keys(&home);
    assert_eq!(before.len(), 1);
    assert!(before.contains_key("audit"));
    let old_secret = fs::read(home.join("keys/audit.ed25519")).unwrap();

    let output = run(&home, &["audit", "rotate-key"]);
    assert_success(&output);

    let entries = persisted_audit(&home);
    let rotation = entries.last().expect("rotation entry should be present");
    assert_eq!(rotation.kind(), AuditKind::KeyRotated);
    assert_eq!(rotation.key_id(), "audit");
    let new_key_id = rotation.subject()["key_id"]
        .as_str()
        .expect("rotation should name the new key");
    assert_ne!(new_key_id, "audit");
    assert!(stdout(&output).starts_with(&format!("--pubkey {new_key_id}=")));
    assert_ne!(
        fs::read(home.join("keys/audit.ed25519")).unwrap(),
        old_secret
    );

    let after = audit_keys(&home);
    assert!(after.contains_key("audit"));
    assert!(after.contains_key(new_key_id));
    verify_chain(
        &entries,
        &after
            .iter()
            .map(|(key_id, (_, key))| (key_id.clone(), *key))
            .collect(),
    )
    .unwrap();
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn export_after_rotation_includes_both_keys() {
    let home = temp_home("rotation-export");
    assert_success(&run(&home, &["audit", "rotate-key"]));
    let new_key_id = rotated_key_id(&home);
    let export = home.join("rotated.jsonl");
    let output = run(
        &home,
        &["audit", "export", "--out", export.to_str().unwrap()],
    );
    assert_success(&output);

    let trailer: Value = fs::read_to_string(&export)
        .unwrap()
        .lines()
        .last()
        .map(|line| serde_json::from_str(line).unwrap())
        .expect("export should have a trailer");
    let keys = trailer["public_keys"]
        .as_object()
        .expect("export should embed public keys");
    assert!(keys.contains_key("audit"));
    assert!(keys.contains_key(&new_key_id));
    assert_eq!(trailer["checkpoint"]["key_id"], new_key_id);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn verify_after_rotation_with_both_anchors() {
    let home = temp_home("rotation-both-anchors");
    assert_success(&run(&home, &["audit", "rotate-key"]));
    let export = home.join("rotated.jsonl");
    assert_success(&run(
        &home,
        &["audit", "export", "--out", export.to_str().unwrap()],
    ));
    let anchors = home.join("both.pub");
    write_key_file(
        &anchors,
        audit_keys(&home)
            .into_iter()
            .map(|(key_id, (_, key))| (key_id, key)),
    );

    let verified = run_verify(&export, &["--pubkey-file", anchors.to_str().unwrap()]);
    assert_success(&verified);
    assert!(stdout(&verified).contains("keys=audit,"));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn verify_with_only_new_anchor_fails_for_old_entries() {
    let home = temp_home("rotation-new-anchor");
    assert_success(&run(&home, &["audit", "rotate-key"]));
    let new_key_id = rotated_key_id(&home);
    let export = home.join("rotated.jsonl");
    assert_success(&run(
        &home,
        &["audit", "export", "--out", export.to_str().unwrap()],
    ));
    let anchors = home.join("new.pub");
    let new_key = audit_keys(&home).remove(&new_key_id).unwrap().1;
    write_key_file(&anchors, [(new_key_id, new_key)]);

    let rejected = run_verify(&export, &["--pubkey-file", anchors.to_str().unwrap()]);
    assert_invalid(&rejected);
    let error = stderr(&rejected);
    assert!(error.contains("unknown key audit"), "{error}");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn suffix_export_after_rotation_verifies() {
    let home = temp_home("rotation-suffix");
    assert_success(&run(&home, &["audit", "rotate-key"]));
    assert_success(&run(&home, &["audit", "rotate-key"]));

    let entries = persisted_audit(&home);
    let last = entries.last().expect("rotation entries should be present");
    let entry_key = last.key_id().to_owned();
    let checkpoint_key = last.subject()["key_id"]
        .as_str()
        .expect("rotation should name the next key")
        .to_owned();
    assert_ne!(entry_key, checkpoint_key);

    let export = home.join("rotation-suffix.jsonl");
    let from = last.seq().to_string();
    assert_success(&run(
        &home,
        &[
            "audit",
            "export",
            "--out",
            export.to_str().unwrap(),
            "--from",
            &from,
        ],
    ));

    let contents = fs::read_to_string(&export).unwrap();
    let lines: Vec<_> = contents.lines().collect();
    assert_eq!(lines.len(), 2);
    let trailer: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(trailer["start_checkpoint"]["seq"], last.seq() - 1);
    let embedded = trailer["public_keys"]
        .as_object()
        .expect("suffix should embed public keys");
    let mut embedded_ids = embedded.keys().cloned().collect::<Vec<_>>();
    let mut used_ids = vec![entry_key.clone(), checkpoint_key.clone()];
    embedded_ids.sort();
    used_ids.sort();
    assert_eq!(embedded_ids, used_ids);

    let registry = audit_keys(&home);
    let anchors = home.join("suffix-anchors.pub");
    write_key_file(
        &anchors,
        used_ids.into_iter().map(|key_id| {
            let key = registry
                .get(&key_id)
                .expect("embedded key should exist in the registry")
                .1;
            (key_id, key)
        }),
    );
    let verified = run_verify(&export, &["--pubkey-file", anchors.to_str().unwrap()]);
    assert_success(&verified);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn verify_help_documents_exit_codes() {
    let output = sekisho()
        .args(["audit", "verify", "--help"])
        .output()
        .expect("verify help should run");
    assert_success(&output);
    let help = stdout(&output);
    for expected in ["0 valid", "1 invalid", "2 usage", "3 unauthenticated"] {
        assert!(
            help.contains(expected),
            "help did not contain {expected:?}:\n{help}"
        );
    }
}

#[test]
fn malformed_pubkey_is_usage_error() {
    let output = run_verify(Path::new("unused.jsonl"), &["--pubkey", "not-a-key"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn export_uses_shared_home_and_permission_checks() {
    let (home, export) = home_with_entries("shared-home", &[100]);
    let sekisho_home = home.path().join(".sekisho");
    let mut command = sekisho();
    command
        .env("SEKISHO_HOME", &sekisho_home)
        .env("HOME", home.path().join("ignored-home"))
        .args(["audit", "export", "--out"])
        .arg(&export);
    let exported = command.output().unwrap();
    assert_success(&exported);

    set_mode(&sekisho_home.join("sekisho.db"), 0o644);
    let mut command = sekisho();
    command
        .env("SEKISHO_HOME", &sekisho_home)
        .env("HOME", home.path().join("ignored-home"))
        .args(["audit", "export", "--out"])
        .arg(&export);
    let rejected = command.output().unwrap();
    assert_invalid(&rejected);
    let error = stderr(&rejected);
    assert!(error.contains("0644"), "{error}");
}

fn temp_home(name: &str) -> PathBuf {
    let suffix = std::hash::RandomState::new().hash_one(name);
    let home = std::env::temp_dir().join(format!("sekisho-{name}-{}-{suffix}", std::process::id()));
    let mut child = Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .args(["up", "--home"])
        .arg(&home)
        .args(["--bind", "127.0.0.1:0", "--admin-password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("setup should start");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"operator\npassword\npassword\n")
        .unwrap();
    let mut ready = false;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        if line.unwrap().starts_with("Listening on ") {
            ready = true;
            break;
        }
    }
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(ready, "setup should initialize the home");
    home
}

fn run(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sekisho"))
        .env("SEKISHO_HOME", home)
        .args(args)
        .output()
        .expect("sekisho agent command should run")
}

#[test]
fn agent_cli_add_list_rotate_remove() {
    let home = temp_home("agent-cli");
    let added = run(&home, &["agent", "add", "claude"]);
    assert!(added.status.success(), "{:?}", added.stderr);
    let first = String::from_utf8(added.stdout).expect("token should be UTF-8");
    let first = first.trim();
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(first)
            .expect("token should be base64url")
            .len(),
        32
    );

    let listed = run(&home, &["agent", "list"]);
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8(listed.stdout).expect("list should be UTF-8"),
        "claude\n"
    );

    let rotated = run(&home, &["agent", "rotate", "claude"]);
    assert!(rotated.status.success(), "{:?}", rotated.stderr);
    let second = String::from_utf8(rotated.stdout).expect("token should be UTF-8");
    let second = second.trim();
    assert_ne!(first, second);

    let removed = run(&home, &["agent", "remove", "claude"]);
    assert!(removed.status.success(), "{:?}", removed.stderr);
    let listed = run(&home, &["agent", "list"]);
    assert!(listed.status.success());
    assert!(listed.stdout.is_empty());

    let connection = rusqlite::Connection::open(home.join("sekisho.db")).unwrap();
    let audit: Vec<String> = connection
        .prepare("SELECT body FROM audit ORDER BY seq")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(audit.len(), 5);
    let audit = &audit[2..];
    assert_eq!(audit.len(), 3);
    assert!(audit.iter().all(|entry| entry.contains("AgentAdded")));
    std::fs::remove_dir_all(home).unwrap();
}
