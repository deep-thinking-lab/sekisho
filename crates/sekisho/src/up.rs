use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use clap::Args;
use rand_core::{OsRng, RngCore};
use sekisho::{
    notifications::{NotificationChannel, Notifications},
    server::{AppState, CheckApi, Clock, Role, SystemClock, User, router},
    store::Store,
};
use sekisho_core::{Ed25519Signer, Principal, PublicKey, Signer, UserId};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, BufRead, IsTerminal, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

#[derive(Args)]
pub struct Options {
    /// Private home directory to use.
    #[arg(long)]
    home: Option<PathBuf>,
    /// Address for the Sekisho server to bind.
    #[arg(long, default_value = "127.0.0.1:7470")]
    bind: SocketAddr,
    /// Read the admin id, password and confirmation as three lines on stdin.
    #[arg(long)]
    admin_password_stdin: bool,
    /// Allow an unencrypted non-loopback bind.
    #[arg(long)]
    insecure_bind: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            home: None,
            bind: SocketAddr::from(([127, 0, 0, 1], 7470)),
            admin_password_stdin: false,
            insecure_bind: false,
        }
    }
}

pub fn home(explicit: Option<PathBuf>) -> Result<PathBuf> {
    explicit
        .or_else(|| std::env::var_os("SEKISHO_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".sekisho")))
        .context("SEKISHO_HOME and HOME are not set; use --home")
}

pub fn open_store(home: &Path) -> Result<Store> {
    open_store_and_signer(home).map(|(store, _)| store)
}

pub fn open_store_and_signer(home: &Path) -> Result<(Store, Arc<Ed25519Signer>)> {
    for (path, directory) in [
        (home.to_owned(), true),
        (home.join("keys"), true),
        (home.join("keys/audit.ed25519"), false),
        (home.join("keys/grant.ed25519"), false),
        (home.join("sekisho.db"), false),
    ] {
        ensure!(
            path.try_exists()?,
            "{} is not initialized; run sekisho up first",
            path.display()
        );
        check_mode(&path, directory)?;
    }
    let registry = home.join("keys/audit");
    private_dir(&registry)?;
    let audit = key(&home.join("keys/audit.ed25519"), false)?;
    let _grant = key(&home.join("keys/grant.ed25519"), false)?;
    let current = Ed25519Signer::from_secret_bytes("audit", &audit);
    let (key_id, public_keys) = ensure_audit_key_registry(home, current.public_key())?;
    let signer = Arc::new(Ed25519Signer::from_secret_bytes(&key_id, &audit));
    let store = Store::open(&home.join("sekisho.db"), signer.clone())?.with_audit_keys(public_keys);
    Ok((store, signer))
}

fn audit_registry_dir(home: &Path) -> PathBuf {
    home.join("keys/audit")
}

fn load_audit_public_keys(home: &Path) -> Result<BTreeMap<String, PublicKey>> {
    let directory = audit_registry_dir(home);
    if !directory.try_exists()? {
        return Ok(BTreeMap::new());
    }
    check_mode(&directory, true)?;
    let mut keys = BTreeMap::new();
    for entry in
        fs::read_dir(&directory).with_context(|| format!("cannot read {}", directory.display()))?
    {
        let path = entry?.path();
        check_mode(&path, false)?;
        ensure!(
            path.extension().is_some_and(|extension| extension == "pub"),
            "{} must be a .pub file",
            path.display()
        );
        let key_id = path
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .context("audit key filename must contain a key id")?;
        ensure!(
            key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "invalid audit key id {}",
            path.display()
        );
        let encoded =
            fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let bytes = STANDARD
            .decode(encoded.trim())
            .with_context(|| format!("invalid public key in {}", path.display()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!("{} must contain one 32-byte public key", path.display())
        })?;
        ensure!(
            keys.insert(key_id.to_owned(), PublicKey::from(bytes))
                .is_none(),
            "duplicate audit key id {key_id}"
        );
    }
    Ok(keys)
}

pub(crate) fn write_audit_public_key(
    home: &Path,
    key_id: &str,
    public_key: PublicKey,
) -> Result<PathBuf> {
    ensure!(
        !key_id.is_empty()
            && key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid audit key id"
    );
    let directory = audit_registry_dir(home);
    private_dir(&directory)?;
    let path = directory.join(format!("{key_id}.pub"));
    let encoded = STANDARD.encode(public_key.to_bytes());
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = fs::read_to_string(&path)?;
            ensure!(
                existing.trim() == encoded,
                "audit key id {key_id} already names a different public key"
            );
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot create {}", path.display()));
        }
    }
    check_mode(&path, false)?;
    Ok(path)
}

fn ensure_audit_key_registry(
    home: &Path,
    active_public_key: PublicKey,
) -> Result<(String, BTreeMap<String, PublicKey>)> {
    let mut keys = load_audit_public_keys(home)?;
    if keys.is_empty() {
        write_audit_public_key(home, "audit", active_public_key)?;
        keys.insert("audit".to_owned(), active_public_key);
    }
    let matching = keys
        .iter()
        .filter(|(_, key)| **key == active_public_key)
        .map(|(key_id, _)| key_id.clone())
        .collect::<Vec<_>>();
    let key_id = match matching.as_slice() {
        [key_id] => key_id.clone(),
        [] => anyhow::bail!("active audit key is missing from keys/audit"),
        _ => anyhow::bail!("active audit key has more than one registry id"),
    };
    Ok((key_id, keys))
}

pub(crate) fn stage_audit_private_key(home: &Path, secret: &[u8; 32]) -> Result<PathBuf> {
    let path = home.join("keys/audit.ed25519.next");
    ensure!(!path.try_exists()?, "pending audit key already exists");
    private_file(&path, secret)?;
    Ok(path)
}

pub(crate) fn activate_audit_private_key(home: &Path, staged: &Path) -> Result<()> {
    let active = home.join("keys/audit.ed25519");
    fs::rename(staged, &active).with_context(|| format!("cannot replace {}", active.display()))?;
    check_mode(&active, false)
}

const SAMPLE_POLICY: &str = r#"version = 1

[[rule]]
name = "agents may push to their own branches"
tool = "git.push"
target = "github.com/example/*:refs/heads/agent/**"
params = { force = false }
decision = "allow"
budget = { max = 50, per = "1h" }

[[rule]]
name = "pushes to main need a human"
tool = "git.push"
target = "github.com/example/*:refs/heads/main"
decision = "ask"
approvers = 1

[[rule]]
name = "read-only MCP tools"
tool_prefix = "mcp:github/get_"
decision = "allow"
"#;

#[derive(Default, serde::Deserialize)]
struct Config {
    approval_ttl_seconds: Option<u32>,
    public_url: Option<String>,
    /// Reverse proxies trusted to name the client in `X-Forwarded-For`.
    #[serde(default)]
    trusted_proxies: Vec<std::net::IpAddr>,
    #[serde(default)]
    remote: Vec<sekisho::git::proxy::RemoteConfig>,
    git_body_limit_bytes: Option<usize>,
    git_push_timeout_seconds: Option<u64>,
    git_max_concurrent_pushes: Option<usize>,
    #[serde(default)]
    mcp: Vec<sekisho::mcp::UpstreamConfig>,
    mcp_wait_seconds: Option<u64>,
    mcp_timeout_seconds: Option<u64>,
    #[serde(default)]
    mcp_limits: sekisho::mcp::Limits,
    anchor: Option<crate::anchor::AnchorConfig>,
    #[serde(default)]
    notify: Vec<NotifyConfig>,
}

#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum NotifyConfig {
    Webhook {
        url: String,
        token_file: Option<PathBuf>,
        #[serde(default)]
        include_params: bool,
    },
    Slack {
        webhook_url_file: PathBuf,
        #[serde(default)]
        interactive: bool,
        signing_secret_file: Option<PathBuf>,
        #[serde(default)]
        slack_users: std::collections::BTreeMap<String, String>,
        slack_requires_totp: Option<bool>,
        #[serde(default)]
        include_params: bool,
    },
}

pub async fn run(options: Options) -> Result<()> {
    ensure!(
        options.bind.ip().is_loopback() || options.insecure_bind,
        "non-loopback binding without TLS requires --insecure-bind"
    );
    if !options.bind.ip().is_loopback() {
        eprintln!("WARNING: --insecure-bind exposes Sekisho over unencrypted HTTP");
    }
    let home = home(options.home)?;
    private_dir(&home)?;
    let keys = home.join("keys");
    private_dir(&keys)?;
    private_dir(&keys.join("audit"))?;
    let db = home.join("sekisho.db");
    let existing_db = db.try_exists()?;
    let _audit = key(&keys.join("audit.ed25519"), !existing_db)?;
    let grant = key(&keys.join("grant.ed25519"), !existing_db)?;
    private_file(&db, b"")?;
    private_file(&home.join("policy.toml"), SAMPLE_POLICY.as_bytes())?;
    private_file(
        &home.join("config.toml"),
        b"# Upstream servers can be configured here.\n",
    )?;
    let config: Config = toml::from_str(&fs::read_to_string(home.join("config.toml"))?)
        .context("invalid config.toml")?;
    let notification_channels = load_notification_channels(&home, config.notify)?;
    let anchor = crate::anchor::Anchor::load(&home, config.anchor)?;
    let git_proxy =
        sekisho::git::proxy::GitProxy::load(&home, config.remote, config.git_body_limit_bytes)?
            .configure_push(
                config.git_max_concurrent_pushes,
                config.git_push_timeout_seconds,
            )?;
    let mcp_gateway = sekisho::mcp::Gateway::load(
        &home,
        config.mcp,
        config.mcp_wait_seconds,
        config.mcp_timeout_seconds,
    )?
    .with_limits(config.mcp_limits)?;
    let policy_path = fs::canonicalize(home.join("policy.toml"))?;
    let store = Arc::new(open_store(&home)?);
    let admin = if store.has_users()? {
        None
    } else {
        Some(enroll_admin(options.admin_password_stdin)?)
    };
    let listener = tokio::net::TcpListener::bind(options.bind)
        .await
        .context("cannot bind server")?;
    let loopback = listener.local_addr()?.ip().is_loopback();
    let public_url = public_base_url(config.public_url.as_deref(), listener.local_addr()?)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let state = AppState::new_with_agents(
        store.clone(),
        store.clone(),
        store.clone(),
        clock.clone(),
        loopback,
    )?
    .with_public_url(public_url.clone())
    .with_trusted_proxies(config.trusted_proxies.clone());
    let slack_integrations = NotificationChannel::slack_integrations(&notification_channels)?;
    let state = state.with_slack_integrations(slack_integrations);
    let notifications = Notifications::start(
        notification_channels,
        store.clone(),
        public_url,
        clock.clone(),
    )?;
    let checks = CheckApi::load_for_startup(
        store.clone(),
        &policy_path,
        Ed25519Signer::from_secret_bytes("grant", &grant).public_key(),
        config.approval_ttl_seconds,
        admin.as_ref(),
        SystemClock.now(),
    )?
    .with_grant_signer(Arc::new(Ed25519Signer::from_secret_bytes("grant", &grant)))?
    .with_protected_dir(&home)?
    .with_notifications(Arc::new(notifications));
    let mut state = state
        .with_check_api(Arc::new(checks))
        .with_mcp_gateway(Arc::new(mcp_gateway))
        .with_git_proxy(Arc::new(git_proxy));
    if loopback {
        let token = admin_token(&home)?;
        let actor = store
            .bootstrap_admin()?
            .context("bootstrap admin is missing")?;
        state = state.with_local_admin(&token, policy_path, Principal::User(actor));
        let path = home.join("admin.url");
        private_file(&path, b"")?;
        check_admin_file(&path)?;
        let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
        write!(file, "http://{}", listener.local_addr()?)?;
        file.sync_all()?;
    } else {
        match fs::remove_file(home.join("admin.url")) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(admin) = admin {
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            admin.totp_secret.context("admin must have TOTP")?,
        )
        .map_err(|_| anyhow::anyhow!("cannot enroll TOTP"))?;
        let secret = totp.get_secret_base32();
        println!(
            "TOTP enrollment URI: otpauth://totp/Sekisho:{}?secret={secret}&issuer=Sekisho&algorithm=SHA1&digits=6&period=30",
            admin.id
        );
        println!("TOTP secret: {secret}");
    }
    if let Some(anchor) = anchor {
        tokio::spawn(anchor.run(store.clone()));
    }
    println!("Listening on http://{}", listener.local_addr()?);
    io::stdout().flush()?;
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server failed")
}

fn public_base_url(configured: Option<&str>, bound: SocketAddr) -> Result<String> {
    let value = configured
        .map(str::to_owned)
        .unwrap_or_else(|| format!("http://{bound}"));
    let mut url = reqwest::Url::parse(&value).context("invalid public_url")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "public_url must be an HTTP URL without credentials, query or fragment"
    );
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn load_notification_channels(
    home: &Path,
    configs: Vec<NotifyConfig>,
) -> Result<Vec<NotificationChannel>> {
    configs
        .into_iter()
        .map(|config| match config {
            NotifyConfig::Webhook {
                url,
                token_file,
                include_params,
            } => {
                let token = token_file
                    .map(|path| read_notification_secret(home, &path, "notification bearer token"))
                    .transpose()?;
                Ok(NotificationChannel::webhook(url, token, include_params)?)
            }
            NotifyConfig::Slack {
                webhook_url_file,
                interactive,
                signing_secret_file,
                slack_users,
                slack_requires_totp,
                include_params,
            } => {
                let url = read_notification_secret(home, &webhook_url_file, "Slack webhook URL")?;
                if interactive {
                    let path = signing_secret_file
                        .context("interactive Slack requires signing_secret_file")?;
                    let secret = read_notification_secret(home, &path, "Slack signing secret")?;
                    Ok(NotificationChannel::interactive_slack(
                        url,
                        secret,
                        slack_users,
                        slack_requires_totp.unwrap_or(true),
                        include_params,
                    )?)
                } else {
                    ensure!(
                        signing_secret_file.is_none()
                            && slack_users.is_empty()
                            && slack_requires_totp.is_none()
                            && !include_params,
                        "Slack interaction settings require interactive = true"
                    );
                    Ok(NotificationChannel::slack(url)?)
                }
            }
        })
        .collect()
}

fn read_notification_secret(home: &Path, configured: &Path, label: &'static str) -> Result<String> {
    let path = home.join(configured);
    check_mode(&path, false)?;
    ensure!(
        fs::metadata(&path)?.len() <= 4096,
        "{label} file is too large"
    );
    let secret = fs::read_to_string(&path).with_context(|| format!("cannot read {label} file"))?;
    let secret = secret.trim();
    ensure!(!secret.is_empty(), "{label} file must not be empty");
    ensure!(
        !secret.chars().any(char::is_control),
        "{label} contains invalid characters"
    );
    Ok(secret.to_owned())
}

fn private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot create {}", path.display()));
        }
    }
    check_mode(path, true)
}

pub(crate) fn check_mode(path: &Path, directory: bool) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        },
        "{} must be a regular {}",
        path.display(),
        if directory { "directory" } else { "file" }
    );
    let mode = metadata.permissions().mode() & 0o7777;
    let allowed = if directory { 0o700 } else { 0o600 };
    ensure!(
        mode & !allowed == 0,
        "{} has mode {mode:04o}; requires permissions no wider than {allowed:04o}",
        path.display()
    );
    Ok(())
}

fn private_file(path: &Path, content: &[u8]) -> Result<()> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(content)?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot create {}", path.display()));
        }
    }
    check_mode(path, false)
}

pub fn key(path: &Path, create: bool) -> Result<[u8; 32]> {
    if create && !path.try_exists()? {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
        private_file(path, &bytes)?;
    }
    check_mode(path, false)?;
    fs::read(path)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain 32 key bytes", path.display()))
}

fn check_admin_file(path: &Path) -> Result<()> {
    check_mode(path, false)?;
    ensure!(
        fs::symlink_metadata(path)?.permissions().mode() & 0o7777 == 0o600,
        "{} requires mode 0600",
        path.display()
    );
    Ok(())
}

pub fn read_admin_file(path: &Path) -> Result<String> {
    check_admin_file(path)?;
    fs::read_to_string(path).context("cannot read local admin file")
}

fn admin_token(home: &Path) -> Result<String> {
    let path = home.join("admin.token");
    if !path.try_exists()? {
        let mut bytes = [0; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
        private_file(&path, URL_SAFE_NO_PAD.encode(bytes).as_bytes())?;
    }
    let token = read_admin_file(&path)?;
    ensure!(
        URL_SAFE_NO_PAD
            .decode(&token)
            .is_ok_and(|bytes| bytes.len() == 32),
        "invalid local admin token file"
    );
    Ok(token)
}

fn line(input: &mut impl BufRead, prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut value = String::new();
    ensure!(input.read_line(&mut value)? != 0, "missing setup input");
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

struct EchoGuard {
    settings: String,
}
impl EchoGuard {
    fn disable() -> Result<Self> {
        ensure!(
            io::stdin().is_terminal(),
            "use --admin-password-stdin for scripted setup"
        );
        let saved = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::inherit())
            .output()?;
        ensure!(saved.status.success(), "cannot read terminal settings");
        let guard = Self {
            settings: String::from_utf8(saved.stdout)?.trim().to_owned(),
        };
        ensure!(guard.set("-echo")?, "cannot disable terminal echo");
        Ok(guard)
    }
    fn set(&self, setting: &str) -> Result<bool> {
        Ok(Command::new("stty")
            .arg(setting)
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .status()?
            .success())
    }
}
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if !self.set(&self.settings).unwrap_or(false) {
            eprintln!("could not restore terminal settings; run stty echo");
        }
    }
}

fn enroll_admin(scripted: bool) -> Result<User> {
    let mut input = io::stdin().lock();
    let id = UserId::try_from_human(line(&mut input, "Admin id: ")?.as_str())?;
    let echo = if scripted {
        None
    } else {
        Some(EchoGuard::disable()?)
    };
    let password = line(&mut input, "Admin password: ")?;
    let confirmation = line(&mut input, "Confirm password: ")?;
    drop(echo);
    eprintln!();
    ensure!(!password.is_empty(), "password must not be empty");
    ensure!(password == confirmation, "passwords do not match");
    let mut salt = [0; 16];
    let mut secret = vec![0; 20];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
    OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
    let salt = SaltString::encode_b64(&salt)
        .map_err(|_| anyhow::anyhow!("cannot encode password salt"))?;
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("cannot hash admin password"))?
        .to_string();
    Ok(User {
        id,
        password_hash,
        totp_secret: Some(secret),
        roles: [Role::Admin].into(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn public_url_defaults_to_the_bound_address_and_validates_configuration() {
        let bind = SocketAddr::from(([127, 0, 0, 1], 7471));
        assert_eq!(
            public_base_url(None, bind).unwrap(),
            "http://127.0.0.1:7471"
        );
        assert_eq!(
            public_base_url(Some("https://sekisho.example/base/"), bind).unwrap(),
            "https://sekisho.example/base"
        );
        for invalid in [
            "ftp://sekisho.example",
            "https://user:secret@sekisho.example",
            "https://sekisho.example?token=secret",
            "https://sekisho.example#fragment",
        ] {
            assert!(public_base_url(Some(invalid), bind).is_err(), "{invalid}");
        }
    }
}
