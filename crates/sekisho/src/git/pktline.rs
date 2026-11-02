//! Incremental receive-pack command parsing and bounded streaming body decoding.

use flate2::read::MultiGzDecoder;
use std::{
    fmt,
    io::{self, Read},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: ObjectId,
    pub new: ObjectId,
    pub refname: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commands {
    pub updates: Vec<RefUpdate>,
    pub capabilities: Vec<String>,
    /// Bytes through the command flush in the decoded stream, excluding pack data.
    pub consumed: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum Encoding {
    Identity,
    Gzip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    NeedMore,
    Done(Commands),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktError {
    InvalidLength,
    EmptyCommands,
    TooManyCommands,
    InvalidCommand,
    InvalidObjectId,
    InvalidRefname,
    DuplicateRefname,
    InvalidCapabilities,
    Unsupported(&'static str),
    BodyLimit,
}

impl fmt::Display for PktError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid pkt-line length",
            Self::EmptyCommands => "at least one ref update is required",
            Self::TooManyCommands => "command count exceeds limit",
            Self::InvalidCommand => "invalid ref update command",
            Self::InvalidObjectId => "invalid or mismatched object ids",
            Self::InvalidRefname => "invalid git refname",
            Self::DuplicateRefname => "a ref appears more than once",
            Self::InvalidCapabilities => {
                "invalid capabilities or capabilities after the first command"
            }
            Self::Unsupported(feature) => {
                return write!(f, "unsupported receive-pack feature: {feature}");
            }
            Self::BodyLimit => "decoded body exceeds limit",
        })
    }
}
impl std::error::Error for PktError {}

/// Parse only the command section. Incomplete input returns `NeedMore`, including
/// a complete list without its flush. At EOF the caller must reject `NeedMore`.
///
/// # Errors
/// Rejects malformed commands and unsupported shallow, signed-push and push-option input.
pub fn parse_commands(prefix: &[u8], max_commands: usize) -> Result<ParseOutcome, PktError> {
    let mut commands = Commands {
        updates: Vec::new(),
        capabilities: Vec::new(),
        consumed: 0,
    };
    let mut offset = 0;
    loop {
        let remaining = &prefix[offset..];
        let header = &remaining[..remaining.len().min(4)];
        let mut length = 0usize;
        for &byte in header {
            length = length * 16 + usize::from(hex_digit(byte).ok_or(PktError::InvalidLength)?);
        }
        if header.len() < 4 {
            return Ok(ParseOutcome::NeedMore);
        }
        if length == 0 {
            if commands.updates.is_empty() {
                return Err(PktError::EmptyCommands);
            }
            commands.consumed = offset + 4;
            return Ok(ParseOutcome::Done(commands));
        }
        if !(4..=65520).contains(&length) {
            return Err(PktError::InvalidLength);
        }
        if commands.updates.len() >= max_commands {
            return Err(PktError::TooManyCommands);
        }
        if remaining.len() < length {
            return Ok(ParseOutcome::NeedMore);
        }
        let payload = &remaining[4..length];
        if payload.starts_with(b"shallow ") {
            return Err(PktError::Unsupported("shallow"));
        }
        if payload.starts_with(b"push-cert") {
            return Err(PktError::Unsupported("signed push"));
        }
        if payload.starts_with(b"push-option") {
            return Err(PktError::Unsupported("push options"));
        }
        let mut parts = payload.split(|&byte| byte == 0);
        let command = parts.next().ok_or(PktError::InvalidCommand)?;
        if let Some(capabilities) = parts.next() {
            if !commands.updates.is_empty() || parts.next().is_some() {
                return Err(PktError::InvalidCapabilities);
            }
            if !capabilities.is_empty() {
                for capability in capabilities
                    .split(|&byte| byte == b' ')
                    .filter(|part| !part.is_empty())
                {
                    if !capability.iter().all(|b| (33..=126).contains(b)) {
                        return Err(PktError::InvalidCapabilities);
                    }
                    if capability == b"push-options" {
                        return Err(PktError::Unsupported("push options"));
                    }
                    let capability = std::str::from_utf8(capability)
                        .map_err(|_| PktError::InvalidCapabilities)?;
                    commands.capabilities.push(capability.to_owned());
                }
            }
        }
        let command = std::str::from_utf8(command).map_err(|_| PktError::InvalidCommand)?;
        let mut fields = command.split(' ');
        let old = fields.next().ok_or(PktError::InvalidCommand)?;
        let new = fields.next().ok_or(PktError::InvalidCommand)?;
        let refname = fields.next().ok_or(PktError::InvalidCommand)?;
        if fields.next().is_some() {
            return Err(PktError::InvalidCommand);
        }
        if old.len() != new.len() {
            return Err(PktError::InvalidObjectId);
        }
        let old = object_id(old)?;
        let new = object_id(new)?;
        if !valid_refname(refname) {
            return Err(PktError::InvalidRefname);
        }
        // Git never sends one ref twice; duplicates only multiply Sekisho's work.
        if commands
            .updates
            .iter()
            .any(|update| update.refname == refname)
        {
            return Err(PktError::DuplicateRefname);
        }
        commands.updates.push(RefUpdate {
            old,
            new,
            refname: refname.to_owned(),
        });
        offset += length;
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn object_id(hex: &str) -> Result<ObjectId, PktError> {
    fn decode<const N: usize>(hex: &[u8]) -> Result<[u8; N], PktError> {
        let mut bytes = [0; N];
        for (byte, pair) in bytes.iter_mut().zip(hex.chunks_exact(2)) {
            *byte = hex_digit(pair[0]).ok_or(PktError::InvalidObjectId)? * 16
                + hex_digit(pair[1]).ok_or(PktError::InvalidObjectId)?;
        }
        Ok(bytes)
    }
    match hex.len() {
        40 => Ok(ObjectId::Sha1(decode(hex.as_bytes())?)),
        64 => Ok(ObjectId::Sha256(decode(hex.as_bytes())?)),
        _ => Err(PktError::InvalidObjectId),
    }
}

fn valid_refname(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.ends_with('.')
        && !name.contains("..")
        && !name.contains("@{")
        && !name
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
        && name
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

enum Decoded<R: Read> {
    Identity(R),
    Gzip(MultiGzDecoder<R>),
}
impl<R: Read> Read for Decoded<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Identity(reader) => reader.read(output),
            Self::Gzip(reader) => reader.read(output),
        }
    }
}
struct Limited<R> {
    reader: R,
    remaining: usize,
}
impl<R: Read> Read for Limited<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0];
            return match self.reader.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(PktError::BodyLimit)),
            };
        }
        let size = output.len().min(self.remaining);
        let count = self.reader.read(&mut output[..size])?;
        self.remaining -= count;
        Ok(count)
    }
}

/// Stream decoded bytes without collecting the body. `limit` bounds total decoded bytes,
/// including pack data. Continue using this reader for the pack remainder.
///
/// # Errors
/// Construction may read the gzip header. Gzip, source and limit errors are
/// returned by `Read` as `io::Error`. Read to EOF to validate gzip trailers and the full limit.
pub fn decode_body(
    encoding: Encoding,
    body: impl Read,
    limit: usize,
) -> Result<impl Read, PktError> {
    let reader = match encoding {
        Encoding::Identity => Decoded::Identity(body),
        Encoding::Gzip => Decoded::Gzip(MultiGzDecoder::new(body)),
    };
    Ok(Limited {
        reader,
        remaining: limit,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use proptest::prelude::*;
    use std::io::{self, Write};

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut bytes = format!("{:04x}", payload.len() + 4).into_bytes();
        bytes.extend_from_slice(payload);
        bytes
    }
    fn command(old: &str, new: &str, name: &str) -> Vec<u8> {
        packet(format!("{old} {new} {name}").as_bytes())
    }
    fn plain() -> Vec<u8> {
        let mut bytes = packet(
            format!(
                "{} {} refs/heads/main\0report-status side-band-64k object-format=sha1",
                "0".repeat(40),
                "a".repeat(40)
            )
            .as_bytes(),
        );
        bytes.extend(b"0000");
        bytes
    }
    fn done(bytes: &[u8]) -> Commands {
        match parse_commands(bytes, 16).unwrap() {
            ParseOutcome::Done(commands) => commands,
            ParseOutcome::NeedMore => panic!("complete command section returned NeedMore"),
        }
    }
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn gzip_body_parses_like_plain() {
        let body = plain();
        let compressed = gzip(&body);
        for (encoding, bytes) in [(Encoding::Identity, &body), (Encoding::Gzip, &compressed)] {
            let mut reader = decode_body(encoding, bytes.as_slice(), body.len()).unwrap();
            let mut decoded = Vec::new();
            reader.read_to_end(&mut decoded).unwrap();
            assert_eq!(done(&decoded), done(&body));
        }
    }

    #[test]
    fn truncated_input_needs_more() {
        let body = plain();
        for end in 0..body.len() {
            assert_eq!(
                parse_commands(&body[..end], 1).unwrap(),
                ParseOutcome::NeedMore,
                "prefix {end}"
            );
        }
        assert!(matches!(
            parse_commands(&body, 1),
            Ok(ParseOutcome::Done(_))
        ));
    }

    #[test]
    fn invalid_length_rejected() {
        for bytes in [
            b"0001", b"0002", b"0003", b"fff1", b"ffff", b"zzzz", b"-001", b"+004", b" 004",
            b"0g00",
        ] {
            assert!(parse_commands(bytes, 1).is_err(), "{bytes:?}");
        }
        assert!(parse_commands(b"0000", 1).is_err());
        assert!(parse_commands(b"0004", 1).is_err());
    }

    #[test]
    fn bad_refname_rejected() {
        for name in [
            "main",
            "refs/",
            "refs//main",
            "refs/.hidden",
            "refs/heads/.hidden/x",
            "refs/heads/a..b",
            "refs/heads/a@{b",
            "refs/heads/a.lock",
            "refs/a.lock/b",
            "refs/heads/a/",
            "refs/heads/a.",
            "refs/heads/a b",
            "refs/heads/a~b",
            "refs/heads/a^b",
            "refs/heads/a:b",
            "refs/heads/a?b",
            "refs/heads/a*b",
            "refs/heads/a[b",
            "refs/heads/a\\b",
            "refs/heads/a\t",
            "refs/heads/a\n",
            "refs/heads/a\r",
            "refs/heads/a\x7f",
        ] {
            let mut bytes = command(&"a".repeat(40), &"b".repeat(40), name);
            bytes.extend(b"0000");
            assert!(parse_commands(&bytes, 1).is_err(), "accepted {name:?}");
        }
        for name in [
            "refs/heads/main",
            "refs/tags/v1.0",
            "refs/heads/a@b",
            "refs/heads/日本語",
            "refs/heads/a.locked",
        ] {
            let mut bytes = command(&"a".repeat(40), &"b".repeat(40), name);
            bytes.extend(b"0000");
            assert_eq!(done(&bytes).updates[0].refname, name);
        }
    }

    #[test]
    fn delete_and_create_detected() {
        let mut bytes = command(&"a".repeat(40), &"0".repeat(40), "refs/heads/old");
        bytes.extend(command(&"0".repeat(40), &"b".repeat(40), "refs/heads/new"));
        bytes.extend(b"0000");
        let commands = done(&bytes);
        assert_eq!(commands.updates[0].old, ObjectId::Sha1([0xaa; 20]));
        assert_eq!(commands.updates[0].new, ObjectId::Sha1([0; 20]));
        assert_eq!(commands.updates[1].old, ObjectId::Sha1([0; 20]));
        assert_eq!(commands.updates[1].new, ObjectId::Sha1([0xbb; 20]));
    }

    #[test]
    fn sha256_object_ids() {
        let mut bytes = command(&"A".repeat(64), &"b".repeat(64), "refs/heads/main");
        bytes.extend(b"0000");
        let commands = done(&bytes);
        assert_eq!(commands.updates[0].old, ObjectId::Sha256([0xaa; 32]));
        assert_eq!(commands.updates[0].new, ObjectId::Sha256([0xbb; 32]));
    }

    #[test]
    fn malformed_objects_and_commands_rejected() {
        for payload in [
            format!("{} {} refs/heads/main", "g".repeat(40), "a".repeat(40)),
            format!("{} {} refs/heads/main", "a".repeat(39), "b".repeat(39)),
            format!("{} {} refs/heads/main", "a".repeat(40), "b".repeat(64)),
            "shallow abc".into(),
            "push-cert\0report-status\n".into(),
            "push-option hello".into(),
        ] {
            let mut bytes = packet(payload.as_bytes());
            bytes.extend(b"0000");
            assert!(parse_commands(&bytes, 4).is_err(), "{payload:?}");
        }
        let mut bytes = plain();
        bytes.truncate(bytes.len() - 4);
        bytes.extend(packet(
            format!(
                "{} {} refs/heads/other\0report-status",
                "a".repeat(40),
                "b".repeat(40)
            )
            .as_bytes(),
        ));
        bytes.extend(b"0000");
        assert!(parse_commands(&bytes, 4).is_err());
        for caps in [
            "push-options",
            "report-status push-options",
            "report-status\0other",
            "report-status\tother",
        ] {
            let mut bytes = packet(
                format!(
                    "{} {} refs/heads/main\0{caps}",
                    "a".repeat(40),
                    "b".repeat(40)
                )
                .as_bytes(),
            );
            bytes.extend(b"0000");
            assert!(parse_commands(&bytes, 4).is_err(), "{caps:?}");
        }
    }

    #[test]
    fn too_many_commands_rejected() {
        assert!(parse_commands(&plain(), 0).is_err());
        let mut bytes = plain();
        bytes.truncate(bytes.len() - 4);
        bytes.extend(command(
            &"a".repeat(40),
            &"b".repeat(40),
            "refs/heads/other",
        ));
        bytes.extend(b"0000");
        assert!(parse_commands(&bytes, 1).is_err());
        assert_eq!(done(&bytes).updates.len(), 2);
    }

    /// DS-02: a ref named twice is refused instead of multiplying prechecks
    /// and upstream compare calls.
    #[test]
    fn duplicate_refnames_rejected() {
        let mut bytes = plain();
        bytes.truncate(bytes.len() - 4);
        bytes.extend(command(&"a".repeat(40), &"b".repeat(40), "refs/heads/main"));
        bytes.extend(b"0000");
        assert_eq!(parse_commands(&bytes, 256), Err(PktError::DuplicateRefname));
    }

    #[test]
    fn pack_data_not_consumed() {
        let mut body = plain();
        let consumed = body.len();
        let pack = b"PACK\0\0\0\x02\xffgarbage0001";
        body.extend(pack);
        let commands = done(&body);
        assert_eq!(commands.consumed, consumed);
        assert_eq!(&body[commands.consumed..], pack);
        assert_eq!(
            commands.capabilities,
            ["report-status", "side-band-64k", "object-format=sha1"]
        );
        let compressed = gzip(&body);
        let mut reader = decode_body(Encoding::Gzip, compressed.as_slice(), body.len()).unwrap();
        let mut prefix = vec![0; consumed];
        reader.read_exact(&mut prefix).unwrap();
        assert_eq!(done(&prefix), commands);
        let mut remainder = Vec::new();
        reader.read_to_end(&mut remainder).unwrap();
        assert_eq!(remainder, pack);
    }

    #[test]
    fn decoded_limit_is_an_error_not_silent_truncation() {
        let body = plain();
        let compressed = gzip(&body);
        for (encoding, bytes) in [(Encoding::Identity, &body), (Encoding::Gzip, &compressed)] {
            for limit in [0, body.len() - 1] {
                let mut reader = decode_body(encoding, bytes.as_slice(), limit).unwrap();
                assert!(reader.read_to_end(&mut Vec::new()).is_err());
            }
            let mut reader = decode_body(encoding, bytes.as_slice(), body.len()).unwrap();
            let mut decoded = Vec::new();
            reader.read_to_end(&mut decoded).unwrap();
            assert_eq!(decoded, body);
        }
    }

    #[test]
    fn corrupt_and_truncated_gzip_rejected() {
        let compressed = gzip(&plain());
        for bytes in [&b"not gzip"[..], &compressed[..compressed.len() - 1]] {
            let mut reader = decode_body(Encoding::Gzip, bytes, 10000).unwrap();
            assert!(reader.read_to_end(&mut Vec::new()).is_err());
        }
        let mut corrupt = compressed;
        let end = corrupt.len();
        corrupt[end - 8] ^= 1;
        let mut reader = decode_body(Encoding::Gzip, corrupt.as_slice(), 10000).unwrap();
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
    }

    #[test]
    fn maximum_packet_and_capability_spacing() {
        let base = format!("{} {} refs/heads/main\0 ", "a".repeat(40), "b".repeat(40));
        let payload = format!("{base}{}", "a".repeat(65520 - 4 - base.len()));
        let mut bytes = packet(payload.as_bytes());
        assert_eq!(&bytes[..4], b"fff0");
        bytes.extend(b"0000");
        let commands = done(&bytes);
        assert_eq!(commands.consumed, bytes.len());
        assert_eq!(commands.capabilities.len(), 1);
        let mut spaced = packet(
            format!(
                "{} {} refs/heads/main\0 report-status  agent=git ",
                "a".repeat(40),
                "b".repeat(40)
            )
            .as_bytes(),
        );
        spaced.extend(b"0000");
        assert_eq!(done(&spaced).capabilities, ["report-status", "agent=git"]);
    }

    #[test]
    fn concatenated_gzip_members_obey_total_limit() {
        let body = plain();
        let mut compressed = gzip(&body[..40]);
        compressed.extend(gzip(&body[40..]));
        let mut reader = decode_body(Encoding::Gzip, compressed.as_slice(), body.len()).unwrap();
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
        let mut reader =
            decode_body(Encoding::Gzip, compressed.as_slice(), body.len() - 1).unwrap();
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
    }

    #[test]
    fn unsupported_features_have_clear_errors() {
        for (payload, feature) in [
            (b"shallow abc".as_slice(), "shallow"),
            (b"push-cert\0report-status", "signed push"),
            (b"push-option foo", "push options"),
        ] {
            assert_eq!(
                parse_commands(&packet(payload), 1),
                Err(PktError::Unsupported(feature))
            );
        }
        let bytes = packet(
            format!(
                "{} {} refs/heads/main\0push-options",
                "a".repeat(40),
                "b".repeat(40)
            )
            .as_bytes(),
        );
        assert_eq!(
            parse_commands(&bytes, 1),
            Err(PktError::Unsupported("push options"))
        );
    }

    fn git(repo: &std::path::Path, args: &[&str]) -> Vec<u8> {
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=Parser Test",
                "-c",
                "user.email=parser@example.invalid",
                "-c",
                "commit.gpgSign=false",
            ])
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn capture_push(work: &std::path::Path, bare: &std::path::Path, args: &[&str]) -> Vec<u8> {
        use std::{
            io::BufRead,
            net::TcpListener,
            time::{Duration, Instant},
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/repo.git", listener.local_addr().unwrap());
        let advertisement = git(
            bare,
            &["receive-pack", "--stateless-rpc", "--advertise-refs", "."],
        );
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "git never sent a POST");
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                // macOS: accepted sockets inherit the listener's non-blocking flag.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut input = io::BufReader::new(&mut stream);
                let mut request = String::new();
                input.read_line(&mut request).unwrap();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    input.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                    assert!(
                        !line.to_ascii_lowercase().starts_with("transfer-encoding:"),
                        "small test push must use Content-Length"
                    );
                    assert!(!line.is_empty(), "truncated HTTP headers");
                }
                if request.starts_with("GET ") {
                    let mut body = packet(b"# service=git-receive-pack\n");
                    body.extend(b"0000");
                    body.extend(&advertisement);
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-advertisement\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                } else {
                    assert!(request.starts_with("POST /repo.git/git-receive-pack "));
                    assert!(length > 0);
                    let mut body = vec![0; length];
                    input.read_exact(&mut body).unwrap();
                    stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    return body;
                }
            }
        });
        let output = std::process::Command::new("git")
            .args([
                "-c",
                "http.proxy=",
                "-c",
                "http.postBuffer=1048576",
                "push",
                &url,
            ])
            .args(args)
            .current_dir(work)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        let body = server.join().unwrap();
        assert!(
            !output.status.success(),
            "capture server rejects after capturing the real push body"
        );
        body
    }

    #[test]
    fn golden_real_git_push_captures() {
        struct TempRepo(std::path::PathBuf);
        impl Drop for TempRepo {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let dir = TempRepo(std::env::temp_dir().join(format!(
                "sekisho-pktline-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        std::fs::create_dir(&dir.0).unwrap();
        let work = dir.0.join("work");
        let bare = dir.0.join("remote.git");
        git(&dir.0, &["init", "-q", "--initial-branch=main", "work"]);
        git(&dir.0, &["init", "-q", "--bare", "remote.git"]);
        git(&work, &["commit", "-q", "--allow-empty", "-m", "capture"]);
        let head = git(&work, &["rev-parse", "HEAD"]);
        let head = String::from_utf8(head).unwrap();
        let create = capture_push(&work, &bare, &["HEAD:refs/heads/main", "HEAD:refs/tags/v1"]);
        let commands = done(&create);
        assert_eq!(commands.updates.len(), 2);
        for update in &commands.updates {
            assert_eq!(update.old, ObjectId::Sha1([0; 20]));
            assert_eq!(update.new, parse_expected_sha1(head.trim()));
        }
        assert_eq!(commands.updates[0].refname, "refs/heads/main");
        assert_eq!(commands.updates[1].refname, "refs/tags/v1");
        assert!(
            commands
                .capabilities
                .iter()
                .any(|c| c.starts_with("report-status"))
        );
        assert!(create[commands.consumed..].starts_with(b"PACK"));
        git(
            &work,
            &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/heads/main"],
        );
        let delete = capture_push(&work, &bare, &[":refs/heads/main"]);
        let commands = done(&delete);
        assert_eq!(commands.updates.len(), 1);
        assert_eq!(commands.updates[0].old, parse_expected_sha1(head.trim()));
        assert_eq!(commands.updates[0].new, ObjectId::Sha1([0; 20]));
        assert_eq!(commands.updates[0].refname, "refs/heads/main");
        assert_eq!(commands.consumed, delete.len());
    }

    fn parse_expected_sha1(hex: &str) -> ObjectId {
        let mut bytes = [0; 20];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        ObjectId::Sha1(bytes)
    }

    proptest! {
        #[test]
        fn valid_generated_commands_are_parsed(name in "refs/heads/[a-z][a-z0-9-]{0,40}") {
            let mut bytes = command(&"a".repeat(40), &"b".repeat(40), &name);
            bytes.extend(b"0000");
            let commands = done(&bytes);
            prop_assert_eq!(&commands.updates[0].refname, &name);
            prop_assert_eq!(commands.consumed, bytes.len());
        }
        #[test]
        fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048), max in 0usize..16) {
            if let Ok(ParseOutcome::Done(commands)) = parse_commands(&bytes, max) {
                prop_assert!(!commands.updates.is_empty());
                prop_assert!(commands.updates.len() <= max);
                prop_assert!(commands.consumed <= bytes.len());
                prop_assert_eq!(&bytes[commands.consumed-4..commands.consumed], b"0000");
                for update in commands.updates {
                    assert_refname(&update.refname);
                }
            }
        }
        #[test]
        fn arbitrary_refnames_in_framed_commands(name in ".{0,100}") {
            let mut bytes = command(&"a".repeat(40), &"b".repeat(40), &name);
            bytes.extend(b"0000");
            if let Ok(ParseOutcome::Done(commands)) = parse_commands(&bytes, 1) {
                assert_refname(&commands.updates[0].refname);
            }
        }
    }
    fn assert_refname(name: &str) {
        assert!(name.starts_with("refs/"));
        assert!(!name.ends_with('.') && !name.ends_with('/'));
        assert!(!name.contains("..") && !name.contains("@{"));
        for component in name.split('/') {
            assert!(
                !component.is_empty()
                    && !component.starts_with('.')
                    && !component.ends_with(".lock")
            );
        }
        assert!(
            !name
                .bytes()
                .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
        );
    }
}
