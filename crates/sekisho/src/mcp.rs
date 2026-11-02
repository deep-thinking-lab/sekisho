//! Configured MCP upstreams and their bounded, credential-holding transports.

use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParam, CallToolResult, PaginatedRequestParam, Tool},
    service::RunningService,
};
use sekisho_core::{AgentId, ToolName};
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
mod transport;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

#[derive(Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(flatten)]
    pub transport: TransportConfig,
}

#[derive(Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase", deny_unknown_fields)]
pub enum TransportConfig {
    Http {
        url: String,
        token_file: Option<PathBuf>,
    },
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        secret_env: Vec<String>,
    },
}

enum Upstream {
    Http {
        url: String,
        token: Option<String>,
    },
    Stdio {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub discovery_ttl_seconds: u64,
    pub request_bytes: usize,
    pub response_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            discovery_ttl_seconds: 300,
            request_bytes: 1024 * 1024,
            response_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Catalog {
    pub tools: Vec<Tool>,
    pub skipped: usize,
}
struct CachedCatalog {
    at: tokio::time::Instant,
    result: Result<Catalog, &'static str>,
}
pub(crate) struct Discovery {
    pub server: String,
    pub result: Result<Catalog, &'static str>,
    pub cached: bool,
}
#[derive(Clone, Default)]
pub(crate) struct FailureWindow {
    at: Option<tokio::time::Instant>,
    count: u64,
}
impl FailureWindow {
    pub(crate) fn record(&mut self) -> Option<u64> {
        self.count = self.count.saturating_add(1);
        if self
            .at
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
        {
            self.at = Some(tokio::time::Instant::now());
            Some(std::mem::take(&mut self.count))
        } else {
            None
        }
    }
}

pub struct Gateway {
    upstreams: BTreeMap<String, Upstream>,
    client: reqwest::Client,
    secrets: Vec<String>,
    pub(crate) wait_seconds: u64,
    timeout: Duration,
    pub(crate) limits: Limits,
    discovery: BTreeMap<String, Mutex<Option<CachedCatalog>>>,
    operations: Arc<Semaphore>,
    agents: Mutex<BTreeMap<String, Arc<Semaphore>>>,
    pub(crate) failures: Mutex<BTreeMap<String, FailureWindow>>,
}

impl Gateway {
    pub fn load(
        home: &Path,
        configs: Vec<UpstreamConfig>,
        wait_seconds: Option<u64>,
        timeout_seconds: Option<u64>,
    ) -> anyhow::Result<Self> {
        let seconds = timeout_seconds.unwrap_or(30);
        anyhow::ensure!(seconds > 0 && seconds <= 600, "invalid MCP timeout");
        let wait_seconds = wait_seconds.unwrap_or(120);
        anyhow::ensure!(wait_seconds <= 300, "invalid MCP approval wait");
        let timeout = Duration::from_secs(seconds);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("cannot initialize MCP HTTP client"))?;
        let mut upstreams = BTreeMap::new();
        let mut secrets = Vec::new();
        for config in configs {
            anyhow::ensure!(
                !config.name.is_empty()
                    && !matches!(config.name.as_str(), "." | "..")
                    && config.name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                    })
                    && ToolName::try_from(format!("mcp:{}/tool", config.name).as_str()).is_ok(),
                "invalid MCP server name"
            );
            let upstream = match config.transport {
                TransportConfig::Http { url, token_file } => {
                    let parsed = reqwest::Url::parse(&url)
                        .map_err(|_| anyhow::anyhow!("invalid MCP upstream URL"))?;
                    anyhow::ensure!(
                        matches!(parsed.scheme(), "http" | "https")
                            && parsed.host_str().is_some()
                            && parsed.username().is_empty()
                            && parsed.password().is_none()
                            && parsed.query().is_none()
                            && parsed.fragment().is_none(),
                        "invalid MCP upstream URL"
                    );
                    let loopback = parsed.host_str().is_some_and(|host| {
                        host.eq_ignore_ascii_case("localhost")
                            || host
                                .trim_matches(['[', ']'])
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                    });
                    anyhow::ensure!(
                        token_file.is_none() || parsed.scheme() == "https" || loopback,
                        "MCP upstream credentials require HTTPS or a loopback host"
                    );
                    let token = token_file
                        .map(|path| load_token(&home.join(path)))
                        .transpose()?;
                    if let Some(token) = &token {
                        secrets.push(token.clone());
                    }
                    Upstream::Http { url, token }
                }
                TransportConfig::Stdio {
                    command,
                    args,
                    env,
                    secret_env,
                } => {
                    anyhow::ensure!(!command.is_empty(), "empty MCP command");
                    for key in secret_env {
                        let value = env
                            .get(&key)
                            .ok_or_else(|| anyhow::anyhow!("MCP secret_env variable is missing"))?;
                        anyhow::ensure!(
                            value.chars().count() >= 8,
                            "MCP secret_env values must contain at least 8 bytes"
                        );
                        secrets.push(value.clone());
                    }
                    Upstream::Stdio { command, args, env }
                }
            };
            anyhow::ensure!(
                upstreams.insert(config.name, upstream).is_none(),
                "duplicate MCP server name"
            );
        }
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        let discovery = upstreams
            .keys()
            .map(|name| (name.clone(), Mutex::new(None)))
            .collect();
        Ok(Self {
            upstreams,
            client,
            secrets,
            wait_seconds,
            timeout,
            limits: Limits::default(),
            discovery,
            operations: Arc::new(Semaphore::new(16)),
            agents: Mutex::new(BTreeMap::new()),
            failures: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn has_server(&self, name: &str) -> bool {
        self.upstreams.contains_key(name)
    }

    pub fn with_limits(mut self, limits: Limits) -> anyhow::Result<Self> {
        anyhow::ensure!(
            limits.discovery_ttl_seconds > 0 && limits.discovery_ttl_seconds <= 86400,
            "invalid MCP discovery TTL"
        );
        anyhow::ensure!(
            limits.request_bytes > 0 && limits.request_bytes <= 64 * 1024 * 1024,
            "invalid MCP request limit"
        );
        anyhow::ensure!(
            limits.response_bytes > 0 && limits.response_bytes <= 64 * 1024 * 1024,
            "invalid MCP response limit"
        );
        self.limits = limits;
        Ok(self)
    }

    pub(crate) async fn acquire(
        &self,
        agent: &AgentId,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), &'static str> {
        let global = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| "MCP global concurrency limit reached")?;
        let mut agents = self.agents.lock().await;
        agents.retain(|_, semaphore| semaphore.available_permits() < 4);
        let per_agent = agents
            .entry(agent.as_str().to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(4)))
            .clone();
        let permit = per_agent
            .try_acquire_owned()
            .map_err(|_| "MCP agent concurrency limit reached")?;
        Ok((global, permit))
    }

    async fn connect(
        &self,
        upstream: &Upstream,
    ) -> Result<RunningService<RoleClient, ()>, &'static str> {
        match upstream {
            Upstream::Http { url, token } => ()
                .serve(transport::Http::new(
                    self.client.clone(),
                    url.clone(),
                    token.clone(),
                    self.limits.response_bytes,
                ))
                .await
                .map_err(|_| "transport"),
            Upstream::Stdio { command, args, env } => {
                let mut process = tokio::process::Command::new(command);
                process
                    .args(args)
                    .env_clear()
                    .envs(env)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true);
                let child = process.spawn().map_err(|_| "transport")?;
                ().serve(transport::StdioTransport::new(
                    child,
                    self.limits.response_bytes,
                )?)
                .await
                .map_err(|_| "transport")
            }
        }
    }

    async fn discover(&self, server: &str, upstream: &Upstream) -> Result<Catalog, &'static str> {
        tokio::time::timeout(self.timeout, async {
            let service = self.connect(upstream).await?;
            let mut tools = Vec::new();
            let mut count = 0;
            let mut skipped = 0;
            let mut cursor = None;
            for _ in 0..100 {
                let page = service
                    .list_tools(Some(PaginatedRequestParam { cursor }))
                    .await
                    .map_err(|_| "transport")?;
                count += page.tools.len();
                if count > 1000 {
                    return Err("tool_limit");
                }
                for mut tool in page.tools {
                    let name = format!("{server}/{}", tool.name);
                    if tool.name.is_empty()
                        || tool.name.contains('/')
                        || ToolName::try_from(format!("mcp:{name}").as_str()).is_err()
                    {
                        skipped += 1;
                        continue;
                    }
                    tool.name = name.into();
                    tools.push(tool);
                }
                self.check_size(&tools)?;
                cursor = page.next_cursor;
                if cursor.is_none() {
                    let mut tools: Vec<Tool> = self.redact(tools)?;
                    tools.retain(|tool| {
                        if ToolName::try_from(format!("mcp:{}", tool.name).as_str()).is_err() {
                            skipped += 1;
                            false
                        } else {
                            true
                        }
                    });
                    return Ok(Catalog { tools, skipped });
                }
            }
            Err("page_limit")
        })
        .await
        .map_err(|_| "timeout")?
    }

    pub(crate) async fn list_tools(&self) -> Vec<Discovery> {
        let mut discoveries = Vec::new();
        for (server, upstream) in &self.upstreams {
            let Some(cache) = self.discovery.get(server) else {
                continue;
            };
            // One refresh per server, including failures, prevents discovery stampedes.
            let mut cache = cache.lock().await;
            let cached = cache.as_ref().is_some_and(|entry| {
                entry.at.elapsed() < Duration::from_secs(self.limits.discovery_ttl_seconds)
            });
            if !cached {
                let result = self.discover(server, upstream).await;
                *cache = Some(CachedCatalog {
                    at: tokio::time::Instant::now(),
                    result,
                });
            }
            if let Some(entry) = cache.as_ref() {
                discoveries.push(Discovery {
                    server: server.clone(),
                    result: entry.result.clone(),
                    cached,
                });
            }
        }
        discoveries
    }

    pub(crate) fn check_size(&self, value: &impl Serialize) -> Result<(), &'static str> {
        let mut writer = transport::SizeLimit(self.limits.response_bytes);
        serde_json::to_writer(&mut writer, value).map_err(|_| "response_limit")
    }

    pub(crate) async fn call(
        &self,
        server: &str,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, &'static str> {
        tokio::time::timeout(self.timeout, async {
            let upstream = self.upstreams.get(server).ok_or("transport")?;
            let service = self.connect(upstream).await?;
            let result = service.call_tool(request).await.map_err(|_| "transport")?;
            self.redact(result)
        })
        .await
        .map_err(|_| "timeout")?
    }

    fn redact<T: Serialize + DeserializeOwned>(&self, value: T) -> Result<T, &'static str> {
        self.check_size(&value)?;
        let mut json = serde_json::to_value(value).map_err(|_| "transport")?;
        redact_value(&mut json, &self.secrets);
        serde_json::from_value(json).map_err(|_| "transport")
    }
}

fn load_token(path: &Path) -> anyhow::Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("cannot read MCP upstream credential"))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o7777 == 0o600,
        "MCP upstream token must be a regular 0600 file"
    );
    let token = std::fs::read_to_string(path)
        .map_err(|_| anyhow::anyhow!("cannot read MCP upstream credential"))?
        .trim()
        .to_owned();
    anyhow::ensure!(
        !token.is_empty() && !token.chars().any(char::is_control),
        "invalid MCP upstream token"
    );
    Ok(token)
}

fn redact_value(value: &mut serde_json::Value, secrets: &[String]) {
    match value {
        serde_json::Value::String(text) => {
            for secret in secrets {
                *text = text.replace(secret, "[REDACTED]");
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_value(value, secrets);
            }
        }
        serde_json::Value::Object(values) => {
            *values = std::mem::take(values)
                .into_iter()
                .map(|(mut key, mut value)| {
                    for secret in secrets {
                        key = key.replace(secret, "[REDACTED]");
                    }
                    redact_value(&mut value, secrets);
                    (key, value)
                })
                .collect();
        }
        _ => (),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(value: serde_json::Value) -> UpstreamConfig {
        serde_json::from_value(value).unwrap()
    }

    fn http(name: &str, url: &str) -> UpstreamConfig {
        config(json!({"name":name,"transport":"http","url":url}))
    }

    #[tokio::test(start_paused = true)]
    async fn upstream_failure_window_reports_suppressed_count() {
        let mut window = FailureWindow::default();
        assert_eq!(window.record(), Some(1));
        assert_eq!(window.record(), None);
        tokio::time::advance(Duration::from_secs(59)).await;
        assert_eq!(window.record(), None);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(window.record(), Some(3));
        assert_eq!(window.record(), None);
    }

    #[test]
    fn mcp_limits_validate_configuration_and_cap_serialization() {
        for options in [
            json!({"discovery_ttl_seconds":0}),
            json!({"request_bytes":0}),
            json!({"response_bytes":0}),
            json!({"discovery_ttl_seconds":86401}),
            json!({"response_bytes":67108865}),
        ] {
            let gateway = Gateway::load(Path::new("."), vec![], None, None).unwrap();
            assert!(
                gateway
                    .with_limits(serde_json::from_value(options).unwrap())
                    .is_err()
            );
        }
        let limits: Limits = serde_json::from_value(json!({"response_bytes":100})).unwrap();
        assert_eq!(limits.discovery_ttl_seconds, 300);
        assert_eq!(limits.request_bytes, 1024 * 1024);
        let gateway = Gateway::load(Path::new("."), vec![], None, None)
            .unwrap()
            .with_limits(limits)
            .unwrap();
        assert!(gateway.redact(json!({"text":"x".repeat(100)})).is_err());
        assert!(gateway.redact(json!({"text":"small"})).is_ok());
    }

    #[test]
    fn token_file_requires_tls_or_loopback() {
        let dir = std::env::temp_dir().join(format!("sekisho-mcp-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "private-token").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        for (url, allowed) in [
            ("http://example.com/mcp", false),
            ("http://127.0.0.1/mcp", true),
            ("http://[::1]/mcp", true),
            ("http://localhost/mcp", true),
            ("https://example.com/mcp", true),
            ("http://localhost.example.com/mcp", false),
        ] {
            let cfg =
                config(json!({"name":"fake", "transport":"http", "url":url, "token_file":path}));
            assert_eq!(
                Gateway::load(&dir, vec![cfg], None, None).is_ok(),
                allowed,
                "{url}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn non_secret_env_values_not_redacted() {
        let cfg = config(
            json!({"name":"fake","transport":"stdio","command":"/nonexistent",
            "env":{"PUBLIC":"public-value","SECRET":"private-value"},"secret_env":["SECRET"]}),
        );
        let gateway = Gateway::load(Path::new("."), vec![cfg], None, None).unwrap();
        let value: serde_json::Value = gateway
            .redact(json!({"text":"public-value private-value"}))
            .unwrap();
        assert_eq!(value["text"], "public-value [REDACTED]");
        for env in [json!({"SECRET":"short"}), json!({})] {
            let cfg = config(
                json!({"name":"fake","transport":"stdio","command":"/nonexistent", "env":env, "secret_env":["SECRET"]}),
            );
            assert!(Gateway::load(Path::new("."), vec![cfg], None, None).is_err());
        }
    }

    #[test]
    fn mcp_config_validates_server_registry_and_urls() {
        for name in ["", ".", "..", "fake/tool", "fake:tool", "Fake", "fake*"] {
            assert!(
                Gateway::load(
                    Path::new("."),
                    vec![http(name, "http://localhost/mcp")],
                    None,
                    None
                )
                .is_err(),
                "accepted server {name}"
            );
        }
        assert!(
            Gateway::load(
                Path::new("."),
                vec![
                    http("fake", "http://localhost/mcp"),
                    http("fake", "http://localhost/mcp")
                ],
                None,
                None
            )
            .is_err()
        );
        for url in [
            "invalid",
            "file:///tmp/socket",
            "http://user:password@localhost/mcp",
            "http://localhost/mcp?token=secret",
            "http://localhost/mcp#secret",
        ] {
            assert!(Gateway::load(Path::new("."), vec![http("fake", url)], None, None).is_err());
        }
        assert!(
            Gateway::load(
                Path::new("."),
                vec![http("fake-1.test", "http://localhost/mcp")],
                None,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn mcp_config_bounds_wait_and_transport_timeout() {
        for timeout in [0, 601, u64::MAX] {
            assert!(Gateway::load(Path::new("."), vec![], None, Some(timeout)).is_err());
        }
        assert!(Gateway::load(Path::new("."), vec![], Some(301), None).is_err());
        assert!(Gateway::load(Path::new("."), vec![], Some(0), Some(1)).is_ok());
    }

    #[test]
    fn mcp_credentials_require_regular_private_files() {
        let dir = std::env::temp_dir().join(format!("sekisho-mcp-secret-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, "private-token").unwrap();
        for mode in [0o644, 0o666, 0o400, 0o1600] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(load_token(&file).is_err(), "accepted mode {mode:o}");
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_token(&file).unwrap(), "private-token");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(load_token(&link).is_err());
        assert!(load_token(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mcp_redaction_covers_json_keys_and_nested_content() {
        let gateway = Gateway::load(
            Path::new("."),
            vec![config(json!({
                "name":"fake", "transport":"stdio", "command":"/nonexistent",
                    "env":{"API_TOKEN":"private-value", "ONLY_CONFIGURED":"yes", "API_PASS":"private-password"}, "secret_env":["API_TOKEN","API_PASS"]
            }))],
            None,
            None,
        )
        .unwrap();
        let value: serde_json::Value = gateway
            .redact(json!({
                "private-value":{"content":[{"text":"Bearer private-value"}]},
                "visible":"ONLY_CONFIGURED=yes", "password":"private-password"
            }))
            .unwrap();
        assert_eq!(
            value["[REDACTED]"]["content"][0]["text"],
            "Bearer [REDACTED]"
        );
        assert_eq!(value["visible"], "ONLY_CONFIGURED=yes");
        assert_eq!(value["password"], "[REDACTED]");
        assert!(!value.to_string().contains("private-value"));
    }
}
