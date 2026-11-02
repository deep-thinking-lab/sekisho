//! Configured remotes and the bounded Read-to-HTTP streaming adapter.
use super::{
    pack::{CommitGraph, HashKind},
    pktline::{Commands, Encoding, ParseOutcome, decode_body, parse_commands},
};
use axum::{
    body::{Body, Bytes, HttpBody},
    http::HeaderMap,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, Write},
    os::{
        fd::OwnedFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    pub name: String,
    pub base_url: String,
    pub token_file: PathBuf,
    #[serde(default)]
    pub api_url: Option<String>,
    #[serde(default = "default_case_insensitive")]
    pub case_insensitive: bool,
}
fn default_case_insensitive() -> bool {
    true
}

pub struct GitProxy {
    pub(crate) remotes: BTreeMap<String, Remote>,
    pub(crate) client: reqwest::Client,
    pub(crate) body_limit: usize,
    pub(crate) push_slots: Arc<tokio::sync::Semaphore>,
    pub(crate) push_timeout: Duration,
}
pub(crate) struct Remote {
    pub(crate) base: reqwest::Url,
    pub(crate) host: String,
    pub(crate) api: Option<reqwest::Url>,
    pub(crate) case_insensitive: bool,
    token: String,
}
impl GitProxy {
    pub fn load(
        home: &Path,
        configs: Vec<RemoteConfig>,
        limit: Option<usize>,
    ) -> anyhow::Result<Self> {
        let body_limit = limit.unwrap_or(1024 * 1024 * 1024);
        anyhow::ensure!(body_limit > 0, "git body limit must be positive");
        let mut remotes = BTreeMap::new();
        for config in configs {
            anyhow::ensure!(component(&config.name), "invalid remote name");
            let mut base = reqwest::Url::parse(&config.base_url)
                .map_err(|_| anyhow::anyhow!("invalid remote URL"))?;
            anyhow::ensure!(
                matches!(base.scheme(), "http" | "https")
                    && base.username().is_empty()
                    && base.password().is_none()
                    && base.query().is_none()
                    && base.fragment().is_none(),
                "invalid remote URL"
            );
            let host = base
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("remote host required"))?
                .to_owned();
            anyhow::ensure!(
                secure_transport(&base),
                "remote base_url must use HTTPS unless the host is loopback, because Sekisho sends the upstream token to it"
            );
            let api = match config.api_url {
                Some(url) => Some(validated_url(&url)?),
                None if host == "github.com" => Some(validated_url("https://api.github.com")?),
                None => None,
            };
            let path = format!("{}/", base.path().trim_end_matches('/'));
            base.set_path(&path);
            let file = home.join(config.token_file);
            let metadata = std::fs::symlink_metadata(&file)?;
            anyhow::ensure!(
                metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600,
                "upstream token must be a regular 0600 file"
            );
            let token = std::fs::read_to_string(file)?.trim().to_owned();
            anyhow::ensure!(
                !token.is_empty() && !token.chars().any(char::is_control),
                "invalid upstream token"
            );
            anyhow::ensure!(
                remotes
                    .insert(
                        config.name,
                        Remote {
                            base,
                            host,
                            token,
                            api,
                            case_insensitive: config.case_insensitive
                        }
                    )
                    .is_none(),
                "duplicate remote name"
            );
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(600))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            remotes,
            client,
            body_limit,
            push_slots: Arc::new(tokio::sync::Semaphore::new(8)),
            push_timeout: Duration::from_secs(600),
        })
    }
    pub fn configure_push(
        mut self,
        max: Option<usize>,
        timeout_seconds: Option<u64>,
    ) -> anyhow::Result<Self> {
        let max = max.unwrap_or(8);
        let seconds = timeout_seconds.unwrap_or(600);
        anyhow::ensure!(
            max > 0 && max <= tokio::sync::Semaphore::MAX_PERMITS,
            "invalid concurrent push limit"
        );
        anyhow::ensure!(seconds > 0, "push timeout must be positive");
        anyhow::ensure!(
            Instant::now()
                .checked_add(Duration::from_secs(seconds))
                .is_some(),
            "push timeout too large"
        );
        self.push_slots = Arc::new(tokio::sync::Semaphore::new(max));
        self.push_timeout = Duration::from_secs(seconds);
        Ok(self)
    }
}
fn validated_url(value: &str) -> anyhow::Result<reqwest::Url> {
    let mut url =
        reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid remote API URL"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid remote API URL"
    );
    anyhow::ensure!(
        secure_transport(&url),
        "remote api_url must use HTTPS unless the host is loopback, because Sekisho sends the upstream token to it"
    );
    url.set_path(&format!("{}/", url.path().trim_end_matches('/')));
    Ok(url)
}

/// HTTPS, or plain HTTP to a loopback host, matching the MCP gateway's rule.
fn secure_transport(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        || url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
}
impl Remote {
    pub(crate) fn authenticate(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.basic_auth("x-access-token", Some(&self.token))
    }
}
pub(crate) fn component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub(crate) fn basic_token(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(value).ok()?).ok()?;
    let (_, token) = decoded.split_once(':')?;
    (!token.is_empty()).then(|| token.to_owned())
}

struct BodyReader {
    body: Body,
    pending: Bytes,
    runtime: tokio::runtime::Handle,
    deadline: Instant,
    cancellation: Arc<AtomicBool>,
    idle_timeout: Duration,
}
impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.pending.is_empty() {
                let count = out.len().min(self.pending.len());
                out[..count].copy_from_slice(&self.pending[..count]);
                self.pending = self.pending.slice(count..);
                return Ok(count);
            }
            let deadline = self.deadline.min(Instant::now() + self.idle_timeout);
            let frame = self.runtime.block_on(async {
                let next = std::future::poll_fn(|cx| Pin::new(&mut self.body).poll_frame(cx));
                tokio::pin!(next);
                loop {
                    if self.cancellation.load(Ordering::Relaxed) {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "git push cancelled"));
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "git request body timed out"));
                    }
                    tokio::select! {
                        frame = &mut next => return Ok(frame),
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) =>
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "git request body timed out")),
                        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                    }
                }
            })?;
            match frame {
                None => return Ok(0),
                Some(Err(_)) => return Err(io::Error::other("git request body failed")),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.pending = data;
                    }
                }
            }
        }
    }
}
pub(crate) struct PushBody {
    pub(crate) commands: Commands,
    prefix: Vec<u8>,
    reader: Box<dyn Read + Send>,
}
impl PushBody {
    pub(crate) fn parse(
        body: Body,
        encoding: Encoding,
        limit: usize,
        runtime: tokio::runtime::Handle,
        deadline: Instant,
        cancellation: Arc<AtomicBool>,
    ) -> anyhow::Result<Self> {
        let source = BodyReader {
            body,
            pending: Bytes::new(),
            runtime,
            deadline,
            cancellation,
            idle_timeout: Duration::from_secs(30),
        };
        let mut reader = decode_body(encoding, source, limit)?;
        let mut prefix = Vec::new();
        // Bound command buffering independently of the (potentially much larger) pack.
        const MAX_PREFIX: usize = 1024 * 1024;
        loop {
            match parse_commands(&prefix, 256)? {
                ParseOutcome::Done(commands) => {
                    return Ok(Self {
                        commands,
                        prefix,
                        reader: Box::new(reader),
                    });
                }
                ParseOutcome::NeedMore => {}
            }
            anyhow::ensure!(prefix.len() < MAX_PREFIX, "git command prefix too large");
            let mut chunk = [0; 8192];
            let count = reader.read(&mut chunk)?;
            anyhow::ensure!(count > 0, "truncated git commands");
            prefix.extend_from_slice(&chunk[..count]);
        }
    }
    /// Read the rest of the body into an unlinked 0600 spool file, scan the pack
    /// for commit ancestry, and forward from the spool afterwards. Body errors
    /// (limit, gzip trailer, disconnect) surface here, before any decision.
    pub(crate) fn scan(
        &mut self,
        kind: HashKind,
        deadline: Instant,
    ) -> anyhow::Result<CommitGraph> {
        let mut name = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut name);
        let path = std::env::temp_dir().join(format!(
            "sekisho-pack-{}",
            name.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        std::fs::remove_file(&path)?;
        let pack = self.prefix.split_off(self.commands.consumed);
        file.write_all(&pack)?;
        io::copy(&mut self.reader, &mut file)?;
        file.seek(io::SeekFrom::Start(0))?;
        let graph = CommitGraph::scan(
            io::BufReader::with_capacity(65536, &mut file),
            kind,
            deadline,
        );
        file.seek(io::SeekFrom::Start(0))?;
        self.reader = Box::new(file);
        Ok(graph)
    }
    pub(crate) fn forward(self) -> reqwest::blocking::Body {
        // reqwest's bounded reader adapter emits an abort error on any Read
        // failure, including errors discovered after the complete pack bytes.
        reqwest::blocking::Body::new(io::Cursor::new(self.prefix).chain(self.reader))
    }
}

pub(crate) async fn response_body(
    mut response: reqwest::blocking::Response,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
    deadline: Instant,
    failed: impl FnOnce() -> io::Result<()> + Send + 'static,
) -> io::Result<Body> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let output = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        tokio::net::TcpStream::connect(listener.local_addr()?),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "git response bridge timed out"))??;
    let expected_peer = output.local_addr()?;
    let input = loop {
        let (input, peer) =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), listener.accept())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "git response bridge timed out")
                })??;
        if peer == expected_peer {
            break input;
        }
    };
    drop(listener);
    let input = input.into_std()?;
    input.set_nonblocking(false)?;
    input.set_read_timeout(Some(
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
            .min(Duration::from_secs(30)),
    ))?;
    let mut output = output.into_std()?;
    output.set_nonblocking(false)?;
    let control = tokio::net::TcpSocket::from_std_stream(output.try_clone()?);
    // Abortive close makes a producer failure an HTTP body error. A pipe would
    // turn it into successful EOF. Only a fully copied response gets a FIN.
    control.set_send_buffer_size(32768)?;
    let file = std::fs::File::from(OwnedFd::from(input));
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let result = (|| {
            let mut chunk = [0; 16384];
            loop {
                if Instant::now() >= deadline {
                    failed()?;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "git response timed out",
                    ));
                }
                let count = match response.read(&mut chunk) {
                    Ok(0) => return Ok(()),
                    Ok(count) => count,
                    Err(error) => {
                        failed()?;
                        return Err(error);
                    }
                };
                let mut pending = &chunk[..count];
                while !pending.is_empty() {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "git response timed out",
                        ));
                    }
                    output.set_write_timeout(Some(remaining))?;
                    let written = output.write(pending)?;
                    if written == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "git response closed",
                        ));
                    }
                    pending = &pending[written..];
                }
            }
        })();
        if result.is_err() {
            control.set_zero_linger()?;
        }
        drop(_slot);
        drop(output);
        drop(control);
        result
    });
    Ok(Body::new(reqwest::Body::from(tokio::fs::File::from_std(
        file,
    ))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn stalled_response_consumer_releases_push_slot_at_deadline() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let slot = slots.clone().try_acquire_owned().unwrap();
        let response = reqwest::blocking::Response::from(axum::http::Response::new(vec![
            b'p';
            4 * 1024
                * 1024
        ]));
        let body = response_body(
            response,
            Some(slot),
            Instant::now() + Duration::from_millis(50),
            || Ok(()),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(slots.available_permits(), 1);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await;
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn remote_config_defaults_to_case_insensitive_without_api_override() {
        let config: RemoteConfig = toml::from_str(
            "name = 'origin'\nbase_url = 'https://github.com'\ntoken_file = 'origin.secret'",
        )
        .unwrap();
        assert!(config.case_insensitive);
        assert!(config.api_url.is_none());
        assert_eq!(
            validated_url("https://enterprise.invalid/api/v3")
                .unwrap()
                .as_str(),
            "https://enterprise.invalid/api/v3/"
        );
        for url in [
            "https://user:secret@enterprise.invalid",
            "file:///tmp/api",
            "https://enterprise.invalid?token=secret",
            "https://enterprise.invalid#fragment",
        ] {
            assert!(validated_url(url).is_err());
        }
    }

    #[tokio::test]
    async fn body_reader_cancellation_interrupts_pending_client() {
        let runtime = tokio::runtime::Handle::current();
        let (input, output) = io::pipe().unwrap();
        let file = std::fs::File::from(OwnedFd::from(input));
        let cancellation = Arc::new(AtomicBool::new(false));
        let mut reader = BodyReader {
            body: Body::new(reqwest::Body::from(tokio::fs::File::from_std(file))),
            pending: Bytes::new(),
            runtime,
            deadline: Instant::now() + Duration::from_secs(30),
            cancellation: cancellation.clone(),
            idle_timeout: Duration::from_secs(30),
        };
        let worker = tokio::task::spawn_blocking(move || reader.read(&mut [0; 1]));
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancellation.store(true, Ordering::Relaxed);
        let error = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        drop(output);
    }

    #[tokio::test]
    async fn body_reader_idle_timeout_interrupts_pending_client() {
        assert_pending_reader_timeout(Duration::from_secs(30), Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn body_reader_deadline_interrupts_pending_client() {
        assert_pending_reader_timeout(Duration::from_millis(20), Duration::from_secs(30)).await;
    }

    async fn assert_pending_reader_timeout(deadline_after: Duration, idle_timeout: Duration) {
        let runtime = tokio::runtime::Handle::current();
        let (input, output) = io::pipe().unwrap();
        let file = std::fs::File::from(OwnedFd::from(input));
        let body = Body::new(reqwest::Body::from(tokio::fs::File::from_std(file)));
        let mut reader = BodyReader {
            body,
            pending: Bytes::new(),
            runtime,
            deadline: Instant::now() + deadline_after,
            cancellation: Arc::new(AtomicBool::new(false)),
            idle_timeout,
        };
        let error = tokio::task::spawn_blocking(move || reader.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(output);
    }

    #[tokio::test]
    async fn reader_error_is_an_http_body_error() {
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_millis(50));
                Err(io::Error::other("invalid pack"))
            }
        }
        assert_reader_aborts(Box::new(Failed)).await;
    }

    #[tokio::test]
    async fn corrupt_gzip_reader_aborts_http_body() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'p'; 32768]).unwrap();
        let mut gzip = encoder.finish().unwrap();
        let trailer = gzip.len() - 8;
        gzip[trailer] ^= 1;
        let reader = decode_body(Encoding::Gzip, io::Cursor::new(gzip), 65536).unwrap();
        assert_reader_aborts(Box::new(reader)).await;
    }

    #[tokio::test]
    async fn truncated_gzip_reader_aborts_http_body() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'p'; 32768]).unwrap();
        let mut gzip = encoder.finish().unwrap();
        gzip.truncate(gzip.len() - 4);
        let reader = decode_body(Encoding::Gzip, io::Cursor::new(gzip), 65536).unwrap();
        assert_reader_aborts(Box::new(reader)).await;
    }

    #[tokio::test]
    async fn over_limit_by_one_reader_aborts_http_body() {
        let reader = decode_body(
            Encoding::Identity,
            io::Cursor::new(vec![b'p'; 32769]),
            32768,
        )
        .unwrap();
        assert_reader_aborts(Box::new(reader)).await;
    }

    async fn assert_reader_aborts(reader: Box<dyn Read + Send>) {
        let push = PushBody {
            commands: Commands {
                updates: vec![],
                capabilities: vec![],
                consumed: 0,
            },
            prefix: b"PACK".to_vec(),
            reader,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket.set_nonblocking(false).unwrap();
                        socket
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let _ = socket.read_to_end(&mut bytes);
                        return bytes;
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return vec![],
                }
            }
        });
        let result = tokio::task::spawn_blocking(move || {
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap()
                .post(format!("http://{address}/push"))
                .body(push.forward())
                .send()
        })
        .await
        .unwrap();
        assert!(
            result.unwrap_err().is_body(),
            "reader must cause HTTP body failure"
        );
        let bytes = server.join().unwrap();
        assert!(
            !bytes.ends_with(b"0\r\n\r\n"),
            "reader failure must not become clean HTTP EOF"
        );
    }
}
