use rmcp::{
    RoleClient,
    model::{ClientJsonRpcMessage, ProtocolVersion, ServerJsonRpcMessage, ServerResult},
    transport::Transport,
};
use std::{io, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout},
    sync::{Mutex, mpsc},
};

fn invalid() -> io::Error {
    io::Error::other("MCP upstream transport failed or response limit exceeded")
}

pub(super) struct SizeLimit(pub usize);
impl io::Write for SizeLimit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or_else(invalid)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct StdioTransport {
    child: Child,
    input: Arc<Mutex<Option<ChildStdin>>>,
    output: BufReader<ChildStdout>,
    limit: usize,
}
impl StdioTransport {
    pub fn new(mut child: Child, limit: usize) -> Result<Self, &'static str> {
        let input = child.stdin.take().ok_or("transport")?;
        let output = child.stdout.take().ok_or("transport")?;
        Ok(Self {
            child,
            input: Arc::new(Mutex::new(Some(input))),
            output: BufReader::new(output),
            limit,
        })
    }
}
impl Transport<RoleClient> for StdioTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        message: ClientJsonRpcMessage,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let input = self.input.clone();
        async move {
            let mut bytes = serde_json::to_vec(&message).map_err(|_| invalid())?;
            bytes.push(b'\n');
            let mut guard = input.lock().await;
            guard.as_mut().ok_or_else(invalid)?.write_all(&bytes).await
        }
    }

    async fn receive(&mut self) -> Option<ServerJsonRpcMessage> {
        let mut line = Vec::new();
        loop {
            let available = self.output.fill_buf().await.ok()?;
            if available.is_empty() {
                return None;
            }
            let end = available.iter().position(|b| *b == b'\n');
            let length = end.map_or(available.len(), |index| index + 1);
            if line.len().saturating_add(length) > self.limit {
                return None;
            }
            line.extend_from_slice(&available[..length]);
            self.output.consume(length);
            if end.is_some() {
                return serde_json::from_slice(&line).ok();
            }
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        self.input.lock().await.take();
        self.child.kill().await
    }
}

pub(super) struct Http {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
    session: Arc<Mutex<Option<String>>>,
    protocol: Arc<Mutex<String>>,
    sender: mpsc::Sender<ServerJsonRpcMessage>,
    receiver: mpsc::Receiver<ServerJsonRpcMessage>,
    limit: usize,
}
impl Http {
    pub fn new(client: reqwest::Client, url: String, token: Option<String>, limit: usize) -> Self {
        let (sender, receiver) = mpsc::channel(16);
        Self {
            client,
            url,
            token,
            session: Arc::new(Mutex::new(None)),
            protocol: Arc::new(Mutex::new(ProtocolVersion::default().to_string())),
            sender,
            receiver,
            limit,
        }
    }
}

impl Transport<RoleClient> for Http {
    type Error = io::Error;

    fn send(
        &mut self,
        message: ClientJsonRpcMessage,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let client = self.client.clone();
        let url = self.url.clone();
        let token = self.token.clone();
        let session = self.session.clone();
        let protocol = self.protocol.clone();
        let sender = self.sender.clone();
        let limit = self.limit;
        async move {
            let mut request = client
                .post(url)
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", protocol.lock().await.clone());
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            if let Some(id) = session.lock().await.as_ref() {
                request = request.header("Mcp-Session-Id", id);
            }
            let mut response = request
                .json(&message)
                .send()
                .await
                .map_err(|_| invalid())?
                .error_for_status()
                .map_err(|_| invalid())?;
            if matches!(response.status().as_u16(), 202 | 204) {
                return Ok(());
            }
            if response
                .content_length()
                .is_some_and(|length| length > limit as u64)
            {
                return Err(invalid());
            }
            if let Some(id) = response.headers().get("Mcp-Session-Id") {
                *session.lock().await = Some(id.to_str().map_err(|_| invalid())?.to_owned());
            }
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            let sse = content_type.starts_with("text/event-stream");
            if !sse && !content_type.starts_with("application/json") {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            let mut total = 0usize;
            while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
                total = total.checked_add(chunk.len()).ok_or_else(invalid)?;
                if total > limit {
                    return Err(invalid());
                }
                bytes.extend_from_slice(&chunk);
                if sse {
                    while let Some((end, separator)) = event_end(&bytes) {
                        let event = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?;
                        let data = event
                            .lines()
                            .filter_map(|line| {
                                line.strip_prefix("data:")
                                    .map(|data| data.strip_prefix(' ').unwrap_or(data))
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !data.is_empty() {
                            let message: ServerJsonRpcMessage =
                                serde_json::from_str(&data).map_err(|_| invalid())?;
                            let done = matches!(
                                message,
                                ServerJsonRpcMessage::Response(_) | ServerJsonRpcMessage::Error(_)
                            );
                            remember_protocol(&message, &protocol).await;
                            sender.send(message).await.map_err(|_| invalid())?;
                            if done {
                                return Ok(());
                            }
                        }
                        bytes.drain(..end + separator);
                    }
                }
            }
            if sse {
                return Err(invalid());
            }
            let message = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            remember_protocol(&message, &protocol).await;
            sender.send(message).await.map_err(|_| invalid())
        }
    }

    async fn receive(&mut self) -> Option<ServerJsonRpcMessage> {
        self.receiver.recv().await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.receiver.close();
        if let Some(id) = self.session.lock().await.take() {
            let mut request = self
                .client
                .delete(&self.url)
                .header("Mcp-Session-Id", id)
                .header("MCP-Protocol-Version", self.protocol.lock().await.clone());
            if let Some(token) = &self.token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.map_err(|_| invalid())?;
            if response.status().as_u16() != 405 {
                response.error_for_status().map_err(|_| invalid())?;
            }
        }
        Ok(())
    }
}

fn event_end(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|end| (end, 2))
        .or_else(|| {
            bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|end| (end, 4))
        })
}

async fn remember_protocol(message: &ServerJsonRpcMessage, protocol: &Mutex<String>) {
    if let ServerJsonRpcMessage::Response(response) = message
        && let ServerResult::InitializeResult(info) = &response.result
    {
        *protocol.lock().await = info.protocol_version.to_string();
    }
}
