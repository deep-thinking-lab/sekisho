use crate::up;
use anyhow::Context as _;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand_core::{OsRng, RngCore};
use sekisho::store::{AuditRecord, StoreError};
use sekisho_core::{
    AuditEntry, AuditKind, ChainError, Checkpoint, CoreError, Ed25519Signer, Principal, PublicKey,
    Signer, Timestamp, verify_against_checkpoint, verify_chain, verify_chain_from_checkpoint,
    verify_checkpoint,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub(crate) struct KeyOverride {
    key_id: String,
    public_key: PublicKey,
}

impl FromStr for KeyOverride {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (key_id, public_key) = value
            .split_once('=')
            .ok_or_else(|| "expected KEYID=BASE64".to_owned())?;
        if key_id.is_empty() {
            return Err("public key id must not be empty".to_owned());
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            public_key: parse_public_key(public_key)?,
        })
    }
}

fn parse_public_key(value: &str) -> Result<PublicKey, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| "public key must be base64 for exactly 32 bytes".to_owned())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "public key must be base64 for exactly 32 bytes".to_owned())?;
    Ok(PublicKey::from(bytes))
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum AuditCommand {
    /// Export the signed audit chain to JSONL.
    Export {
        /// Path to write the JSONL export.
        #[arg(long)]
        out: PathBuf,
        /// First audit sequence number to include.
        #[arg(long)]
        from: Option<u64>,
    },
    /// Verify an audit export and its checkpoint.
    #[command(after_help = "Exit codes:\n  0 valid\n  1 invalid\n  2 usage\n  3 unauthenticated")]
    Verify {
        /// Audit export file to verify.
        file: PathBuf,
        /// External trust key as KEYID=BASE64.
        #[arg(long = "pubkey", value_name = "KEYID=BASE64")]
        public_keys: Vec<KeyOverride>,
        /// File containing external trust keys.
        #[arg(long = "pubkey-file", value_name = "PATH")]
        public_key_file: Option<PathBuf>,
        /// Saved anchor checkpoint to verify the chain against.
        #[arg(long, value_name = "PATH")]
        against_checkpoint: Option<PathBuf>,
    },
    /// Rotate the audit signing key and record the rotation in the audit trail.
    RotateKey,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportTrailer {
    #[serde(default)]
    checkpoint: Option<Checkpoint>,
    #[serde(default)]
    start_checkpoint: Option<Checkpoint>,
    public_keys: BTreeMap<String, PublicKey>,
    #[serde(default)]
    verified_prefix: Vec<AuditEntry>,
}

enum ParsedCheckpoint {
    Full(Checkpoint),
    Start(Checkpoint),
}

struct ParsedAuditExport {
    entries: Vec<AuditEntry>,
    checkpoint: ParsedCheckpoint,
    public_keys: BTreeMap<String, PublicKey>,
    verified_prefix: Vec<AuditEntry>,
}

enum AuditInput {
    Export(ParsedAuditExport),
    Chain(Vec<AuditEntry>),
}

enum TrustAnchors {
    Authenticated(BTreeMap<String, PublicKey>),
    Embedded(BTreeMap<String, PublicKey>),
}

impl TrustAnchors {
    fn keys(&self) -> &BTreeMap<String, PublicKey> {
        match self {
            Self::Authenticated(keys) | Self::Embedded(keys) => keys,
        }
    }

    fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuditCliError {
    #[error("{0:#}")]
    Setup(#[from] anyhow::Error),
    #[error("cannot read export {path}: {source}")]
    ReadExport {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot write export {path}: {source}")]
    WriteExport {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot read public key file {path}: {source}")]
    ReadPubkeyFile {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot read checkpoint {path}: {source}")]
    ReadCheckpoint {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid checkpoint {path}: {reason}")]
    InvalidCheckpoint { path: String, reason: String },
    #[error("{0}")]
    Usage(String),
    #[error("store operation failed: {0}")]
    Store(#[from] StoreError),
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("core operation failed: {0}")]
    Core(#[from] CoreError),
    #[error("invalid export at line {line}: {reason}")]
    InvalidLine { line: usize, reason: String },
    #[error("invalid export at seq {seq}: {reason}")]
    InvalidSeq { seq: u64, reason: String },
    #[error(
        "UNAUTHENTICATED: signatures checked only against keys inside the file; pass --pubkey to authenticate"
    )]
    Unauthenticated,
}

impl AuditCliError {
    fn invalid_line(line: usize, reason: impl Into<String>) -> Self {
        Self::InvalidLine {
            line,
            reason: reason.into(),
        }
    }

    fn invalid_seq(seq: u64, reason: impl Into<String>) -> Self {
        Self::InvalidSeq {
            seq,
            reason: reason.into(),
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Unauthenticated => 3,
            Self::Setup(_)
            | Self::ReadExport { .. }
            | Self::WriteExport { .. }
            | Self::ReadPubkeyFile { .. }
            | Self::ReadCheckpoint { .. }
            | Self::InvalidCheckpoint { .. }
            | Self::Store(_)
            | Self::Json(_)
            | Self::Core(_)
            | Self::InvalidLine { .. }
            | Self::InvalidSeq { .. } => 1,
        }
    }
}

pub(crate) fn run(command: AuditCommand) -> Result<(), AuditCliError> {
    match command {
        AuditCommand::Export { out, from } => export(&out, from),
        AuditCommand::Verify {
            file,
            public_keys,
            public_key_file,
            against_checkpoint,
        } => verify(
            &file,
            public_keys,
            public_key_file.as_deref(),
            against_checkpoint.as_deref(),
        ),
        AuditCommand::RotateKey => rotate_key(),
    }
}

fn rotate_key() -> Result<(), AuditCliError> {
    let home = up::home(None)?;
    let (store, old_signer) = up::open_store_and_signer(&home)?;
    let actor = store
        .bootstrap_admin()?
        .context("home is not initialized; run sekisho up first")?;
    let mut secret = [0; 32];
    let mut id_bytes = [0; 16];
    OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
    OsRng
        .try_fill_bytes(&mut id_bytes)
        .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
    let key_id = format!("audit-{}", URL_SAFE_NO_PAD.encode(id_bytes));
    let new_signer = Ed25519Signer::from_secret_bytes(&key_id, &secret);
    let staged = up::stage_audit_private_key(&home, &secret)?;
    let public_key_path = match up::write_audit_public_key(&home, &key_id, new_signer.public_key())
    {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_file(&staged);
            return Err(error.into());
        }
    };
    let now = Timestamp::from(OffsetDateTime::now_utc().unix_timestamp().max(0));
    if let Err(error) = store.transact(now, |_| {
        Ok((
            (),
            vec![AuditRecord {
                kind: AuditKind::KeyRotated,
                actor: Principal::User(actor.clone()),
                subject: serde_json::json!({
                    "key_id": key_id.clone(),
                    "old_key_id": old_signer.key_id(),
                }),
            }],
        ))
    }) {
        let _ = fs::remove_file(&staged);
        let _ = fs::remove_file(public_key_path);
        return Err(error.into());
    }
    up::activate_audit_private_key(&home, &staged)?;
    println!(
        "--pubkey {}={}",
        new_signer.key_id(),
        STANDARD.encode(new_signer.public_key().to_bytes())
    );
    Ok(())
}

fn export(out: &Path, from: Option<u64>) -> Result<(), AuditCliError> {
    let home = up::home(None)?;
    let (store, signer) = up::open_store_and_signer(&home)?;
    let now = OffsetDateTime::now_utc().unix_timestamp().max(0);
    let start_seq = from.unwrap_or(0);
    let export = store
        .audit_export(Timestamp::from(now), start_seq)
        .map_err(|error| match error {
            StoreError::InvalidAuditExport(reason) => AuditCliError::invalid_seq(start_seq, reason),
            error => AuditCliError::Store(error),
        })?;
    fs::write(out, export.jsonl()?).map_err(|source| AuditCliError::WriteExport {
        path: out.display().to_string(),
        source,
    })?;
    eprintln!(
        "--pubkey {}={}",
        signer.key_id(),
        STANDARD.encode(signer.public_key().to_bytes())
    );
    Ok(())
}

fn verify(
    file: &Path,
    overrides: Vec<KeyOverride>,
    public_key_file: Option<&Path>,
    against_checkpoint: Option<&Path>,
) -> Result<(), AuditCliError> {
    let bytes = fs::read(file).map_err(|source| AuditCliError::ReadExport {
        path: file.display().to_string(),
        source,
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|_| AuditCliError::invalid_line(1, "export is not UTF-8"))?;
    let input = parse_audit_input(&text, against_checkpoint.is_some())?;
    let saved_anchor = against_checkpoint.map(read_checkpoint).transpose()?;
    let trust = match &input {
        AuditInput::Export(export) => external_trust(overrides, public_key_file)?
            .unwrap_or_else(|| TrustAnchors::Embedded(export.public_keys.clone())),
        AuditInput::Chain(_) => external_trust(overrides, public_key_file)?.ok_or_else(|| {
            AuditCliError::Usage("chain verification requires --pubkey or --pubkey-file".to_owned())
        })?,
    };
    let keys = trust.keys();
    let (display_entries, used_keys, verified_prefix) = match input {
        AuditInput::Export(export) => {
            verify_export(&export, keys)?;
            let (checkpoint, is_start) = match &export.checkpoint {
                ParsedCheckpoint::Full(checkpoint) => (checkpoint, false),
                ParsedCheckpoint::Start(checkpoint) => (checkpoint, true),
            };
            let mut chain_entries = export.verified_prefix.clone();
            chain_entries.extend(export.entries.iter().cloned());
            if let Some(anchor) = &saved_anchor {
                verify_saved_anchor(
                    &chain_entries,
                    &export.entries,
                    is_start.then_some(checkpoint),
                    anchor,
                    keys,
                )?;
            }
            let used = if is_start {
                &export.entries
            } else {
                &chain_entries
            }
            .iter()
            .map(|entry| entry.key_id().to_owned())
            .chain(std::iter::once(checkpoint.key_id.clone()))
            .chain(saved_anchor.iter().map(|anchor| anchor.key_id.clone()))
            .collect::<BTreeSet<_>>();
            let display = if is_start {
                export.entries
            } else {
                chain_entries
            };
            (display, used, export.verified_prefix.len())
        }
        AuditInput::Chain(entries) => {
            verify_chain(&entries, keys).map_err(|error| chain_error(&error, 0))?;
            let anchor = saved_anchor
                .as_ref()
                .ok_or_else(|| AuditCliError::Usage("missing --against-checkpoint".to_owned()))?;
            verify_against_checkpoint(&entries, keys, anchor)
                .map_err(|error| chain_error(&error, anchor.seq))?;
            let used = entries
                .iter()
                .map(|entry| entry.key_id().to_owned())
                .chain(std::iter::once(anchor.key_id.clone()))
                .collect();
            (entries, used, 0)
        }
    };
    print_valid(&display_entries, &used_keys, verified_prefix);
    if trust.is_authenticated() {
        Ok(())
    } else {
        Err(AuditCliError::Unauthenticated)
    }
}

fn verify_export(
    export: &ParsedAuditExport,
    keys: &BTreeMap<String, PublicKey>,
) -> Result<(), AuditCliError> {
    if export.entries.is_empty() {
        return Err(AuditCliError::invalid_seq(0, "empty audit chain"));
    }
    let (checkpoint, is_start) = match &export.checkpoint {
        ParsedCheckpoint::Full(checkpoint) => (checkpoint, false),
        ParsedCheckpoint::Start(checkpoint) => (checkpoint, true),
    };
    let mut chain_entries = export.verified_prefix.clone();
    chain_entries.extend(export.entries.iter().cloned());
    if is_start {
        if !keys.contains_key(&checkpoint.key_id) {
            return Err(chain_error(
                &ChainError::UnknownKey(checkpoint.seq, checkpoint.key_id.clone()),
                checkpoint.seq,
            ));
        }
        verify_chain_from_checkpoint(&export.entries, keys, checkpoint)
            .map_err(|error| chain_error(&error, checkpoint.seq))?;
    } else {
        let summary = verify_chain(&chain_entries, keys)
            .map_err(|error| chain_error(&error, checkpoint.seq))?;
        if !keys.contains_key(&checkpoint.key_id) {
            return Err(chain_error(
                &ChainError::UnknownKey(checkpoint.seq, checkpoint.key_id.clone()),
                checkpoint.seq,
            ));
        }
        verify_against_checkpoint(&chain_entries, keys, checkpoint)
            .map_err(|error| chain_error(&error, checkpoint.seq))?;
        if checkpoint.seq != summary.last_seq {
            return Err(AuditCliError::invalid_seq(
                checkpoint.seq,
                "checkpoint does not anchor the final entry",
            ));
        }
    }
    Ok(())
}

fn verify_saved_anchor(
    chain_entries: &[AuditEntry],
    exported_entries: &[AuditEntry],
    start_checkpoint: Option<&Checkpoint>,
    anchor: &Checkpoint,
    keys: &BTreeMap<String, PublicKey>,
) -> Result<(), AuditCliError> {
    let Some(start_checkpoint) = start_checkpoint else {
        verify_against_checkpoint(chain_entries, keys, anchor)
            .map_err(|error| chain_error(&error, anchor.seq))?;
        return Ok(());
    };
    verify_checkpoint(anchor, keys).map_err(|error| chain_error(&error, anchor.seq))?;
    let last_seq = exported_entries
        .last()
        .ok_or_else(|| AuditCliError::invalid_seq(0, "empty audit chain"))?
        .seq();
    if last_seq < anchor.seq {
        return Err(chain_error(
            &ChainError::TruncatedBefore {
                checkpoint_seq: anchor.seq,
                last_seq,
            },
            anchor.seq,
        ));
    }
    if anchor.seq == start_checkpoint.seq {
        if anchor.entry_hash != start_checkpoint.entry_hash {
            return Err(chain_error(&ChainError::CheckpointMismatch, anchor.seq));
        }
        return Ok(());
    }
    if anchor.seq < start_checkpoint.seq {
        return Err(chain_error(&ChainError::CheckpointMismatch, anchor.seq));
    }
    let entry = exported_entries
        .iter()
        .find(|entry| entry.seq() == anchor.seq)
        .ok_or_else(|| chain_error(&ChainError::CheckpointMismatch, anchor.seq))?;
    if entry.entry_hash() != anchor.entry_hash || anchor.at < entry.at() {
        return Err(chain_error(&ChainError::CheckpointMismatch, anchor.seq));
    }
    Ok(())
}

fn print_valid(entries: &[AuditEntry], keys: &BTreeSet<String>, verified_prefix: usize) {
    let Some(first) = entries.first() else {
        return;
    };
    let Some(last) = entries.last() else {
        return;
    };
    let used = keys.iter().cloned().collect::<Vec<_>>().join(",");
    let prefix = if verified_prefix == 0 {
        String::new()
    } else {
        format!(" verified_prefix={verified_prefix}")
    };
    println!(
        "valid: entries={} first_seq={} last_seq={} time_range={}..{} keys={used}{prefix}",
        entries.len(),
        first.seq(),
        last.seq(),
        first.at().as_secs(),
        last.at().as_secs(),
    );
}

fn external_trust(
    overrides: Vec<KeyOverride>,
    public_key_file: Option<&Path>,
) -> Result<Option<TrustAnchors>, AuditCliError> {
    if overrides.is_empty() && public_key_file.is_none() {
        return Ok(None);
    }
    let mut keys = BTreeMap::new();
    for key in overrides {
        insert_trust_key(&mut keys, key.key_id, key.public_key)?;
    }
    if let Some(path) = public_key_file {
        let contents =
            fs::read_to_string(path).map_err(|source| AuditCliError::ReadPubkeyFile {
                path: path.display().to_string(),
                source,
            })?;
        for (index, line) in contents.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let key_id = fields.next().ok_or_else(|| {
                AuditCliError::Usage(format!(
                    "invalid public key file {}:{}: expected KEYID BASE64",
                    path.display(),
                    index + 1
                ))
            })?;
            let encoded = fields.next().ok_or_else(|| {
                AuditCliError::Usage(format!(
                    "invalid public key file {}:{}: expected KEYID BASE64",
                    path.display(),
                    index + 1
                ))
            })?;
            if fields.next().is_some() {
                return Err(AuditCliError::Usage(format!(
                    "invalid public key file {}:{}: expected KEYID BASE64",
                    path.display(),
                    index + 1
                )));
            }
            let public_key = parse_public_key(encoded).map_err(|reason| {
                AuditCliError::Usage(format!(
                    "invalid public key file {}:{}: {reason}",
                    path.display(),
                    index + 1
                ))
            })?;
            insert_trust_key(&mut keys, key_id.to_owned(), public_key)?;
        }
    }
    Ok(Some(TrustAnchors::Authenticated(keys)))
}

fn insert_trust_key(
    keys: &mut BTreeMap<String, PublicKey>,
    key_id: String,
    public_key: PublicKey,
) -> Result<(), AuditCliError> {
    if key_id.is_empty() {
        return Err(AuditCliError::Usage(
            "public key id must not be empty".to_owned(),
        ));
    }
    if keys.contains_key(&key_id) {
        return Err(AuditCliError::Usage(format!(
            "duplicate public key id {key_id}"
        )));
    }
    keys.insert(key_id, public_key);
    Ok(())
}

fn read_checkpoint(path: &Path) -> Result<Checkpoint, AuditCliError> {
    let contents = fs::read_to_string(path).map_err(|source| AuditCliError::ReadCheckpoint {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&contents).map_err(|error| AuditCliError::InvalidCheckpoint {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

fn parse_audit_input(text: &str, allow_chain: bool) -> Result<AuditInput, AuditCliError> {
    let lines = text.lines().collect::<Vec<_>>();
    let Some(last) = lines.last() else {
        return Err(AuditCliError::invalid_line(1, "missing checkpoint footer"));
    };
    let last_value: Value = serde_json::from_str(last)
        .map_err(|error| AuditCliError::invalid_line(lines.len(), error.to_string()))?;
    let has_trailer =
        last_value.get("checkpoint").is_some() || last_value.get("start_checkpoint").is_some();
    if has_trailer || !allow_chain {
        return parse_export(text).map(AuditInput::Export);
    }
    if lines.iter().any(|line| line.trim().is_empty()) {
        let line = lines
            .iter()
            .position(|line| line.trim().is_empty())
            .map_or(1, |index| index + 1);
        return Err(AuditCliError::invalid_line(line, "blank JSONL line"));
    }
    let entries = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str::<AuditEntry>(line)
                .map_err(|error| AuditCliError::invalid_line(index + 1, error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if entries.is_empty() {
        return Err(AuditCliError::invalid_seq(0, "empty audit chain"));
    }
    Ok(AuditInput::Chain(entries))
}

fn parse_export(text: &str) -> Result<ParsedAuditExport, AuditCliError> {
    let lines = text.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return Err(AuditCliError::invalid_line(1, "missing checkpoint footer"));
    }
    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            return Err(AuditCliError::invalid_line(index + 1, "blank JSONL line"));
        }
    }

    let trailer_line = lines.len();
    let trailer_value: Value = serde_json::from_str(lines[trailer_line - 1])
        .map_err(|error| AuditCliError::invalid_line(trailer_line, error.to_string()))?;
    if trailer_value.get("checkpoint").is_none() && trailer_value.get("start_checkpoint").is_none()
    {
        return Err(AuditCliError::invalid_line(
            trailer_line,
            "missing checkpoint footer",
        ));
    }
    let trailer: ExportTrailer = serde_json::from_value(trailer_value)
        .map_err(|error| AuditCliError::invalid_line(trailer_line, error.to_string()))?;
    let checkpoint = match (trailer.checkpoint, trailer.start_checkpoint) {
        (Some(checkpoint), None) => ParsedCheckpoint::Full(checkpoint),
        (None, Some(checkpoint)) => {
            if !trailer.verified_prefix.is_empty() {
                return Err(AuditCliError::invalid_line(
                    trailer_line,
                    "start checkpoint cannot include a verified prefix",
                ));
            }
            ParsedCheckpoint::Start(checkpoint)
        }
        _ => {
            return Err(AuditCliError::invalid_line(
                trailer_line,
                "expected exactly one checkpoint footer",
            ));
        }
    };
    let entries = lines[..trailer_line - 1]
        .iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str::<AuditEntry>(line)
                .map_err(|error| AuditCliError::invalid_line(index + 1, error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedAuditExport {
        entries,
        checkpoint,
        public_keys: trailer.public_keys,
        verified_prefix: trailer.verified_prefix,
    })
}

fn chain_error(error: &ChainError, checkpoint_seq: u64) -> AuditCliError {
    let seq = match error {
        ChainError::GapAt(seq)
        | ChainError::BadPrevHash(seq)
        | ChainError::BadEntryHash(seq)
        | ChainError::BadSignature(seq)
        | ChainError::NonMonotonicTime(seq) => *seq,
        ChainError::UnknownKey(seq, _) => *seq,
        ChainError::TruncatedBefore { checkpoint_seq, .. } => *checkpoint_seq,
        ChainError::Empty => 0,
        ChainError::CheckpointMismatch | ChainError::BadCheckpointSignature => checkpoint_seq,
    };
    AuditCliError::invalid_seq(seq, error.to_string())
}
