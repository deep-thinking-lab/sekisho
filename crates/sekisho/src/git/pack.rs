//! Commit ancestry from a pushed packfile, used to prove that a ref update is a
//! fast-forward before the push reaches the upstream.
//!
//! Every recorded commit id is the hash of the inflated object, so its parent
//! list is genuine whatever the client sent. A partial or failed scan only
//! drops commits, which can turn a proof into "unknown" but never into a false
//! fast-forward.

use flate2::bufread::ZlibDecoder;
use sha2::Digest as _;
use std::{
    collections::{HashMap, HashSet},
    io::{self, BufRead, Read},
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Sha1,
    Sha256,
}
impl HashKind {
    fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
    fn hash(self, kind: &str, data: &[u8]) -> String {
        let header = format!("{kind} {}\0", data.len());
        match self {
            Self::Sha1 => hex(&sha1::Sha1::new()
                .chain_update(header)
                .chain_update(data)
                .finalize()),
            Self::Sha256 => hex(&sha2::Sha256::new()
                .chain_update(header)
                .chain_update(data)
                .finalize()),
        }
    }
}

/// Result of asking whether `old` is an ancestor of `new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ancestry {
    FastForward,
    /// The complete history of `new` is in the pack and does not contain `old`.
    NotFastForward,
    /// The history of `new` leaves the pack at these commits, which the client
    /// claims the upstream already has. `old` is an ancestor of `new` exactly when
    /// it is an ancestor of one of them.
    Upstream(Vec<String>),
}

#[derive(Debug, Default)]
pub struct CommitGraph {
    parents: HashMap<String, Vec<String>>,
}

/// Retained commit and commit-delta bytes. Beyond this the scan stops.
const MAX_RETAINED: usize = 64 * 1024 * 1024;
/// Total inflated bytes across the pack. Bounds CPU on compression bombs.
const MAX_INFLATED: u64 = 8 * 1024 * 1024 * 1024;

impl CommitGraph {
    /// Scan a packfile. Never fails: the graph holds every commit read before
    /// the first error, limit or deadline.
    pub fn scan(reader: impl BufRead, kind: HashKind, deadline: Instant) -> Self {
        let mut scanner = Scanner {
            reader: Counting {
                inner: reader,
                count: 0,
            },
            kind,
            graph: Self::default(),
            data: HashMap::new(),
            by_offset: HashMap::new(),
            retained: 0,
            inflated: 0,
        };
        let _ = scanner.run(deadline);
        scanner.graph
    }

    #[must_use]
    pub fn ancestry(&self, old: &str, new: &str) -> Ancestry {
        self.ancestry_until(old, new, None)
            .unwrap_or_else(|| Ancestry::Upstream(Vec::new()))
    }

    /// `ancestry` that gives up at `deadline`, returning `None`; callers treat
    /// that as unproven, so the update stays forced.
    #[must_use]
    pub fn ancestry_until(
        &self,
        old: &str,
        new: &str,
        deadline: Option<Instant>,
    ) -> Option<Ancestry> {
        let mut seen = HashSet::new();
        let mut stack = vec![new];
        let mut frontier = Vec::new();
        while let Some(id) = stack.pop() {
            if seen.len() % 4096 == 0 && deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                return None;
            }
            if id == old {
                return Some(Ancestry::FastForward);
            }
            if !seen.insert(id) {
                continue;
            }
            match self.parents.get(id) {
                Some(parents) => stack.extend(parents.iter().map(String::as_str)),
                None => frontier.push(id.to_owned()),
            }
        }
        Some(if frontier.is_empty() {
            Ancestry::NotFastForward
        } else {
            Ancestry::Upstream(frontier)
        })
    }
}

struct Counting<R> {
    inner: R,
    count: u64,
}
impl<R: BufRead> Read for Counting<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(out)?;
        self.count += count as u64;
        Ok(count)
    }
}
impl<R: BufRead> BufRead for Counting<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.count += amount as u64;
        self.inner.consume(amount);
    }
}

#[derive(Clone)]
enum Seen {
    Commit(String),
    Other,
}

struct Scanner<R> {
    reader: Counting<R>,
    kind: HashKind,
    graph: CommitGraph,
    /// Inflated commit bodies by id, kept as possible delta bases.
    data: HashMap<String, Vec<u8>>,
    by_offset: HashMap<u64, Seen>,
    retained: usize,
    inflated: u64,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unsupported pack data")
}

impl<R: BufRead> Scanner<R> {
    fn byte(&mut self) -> io::Result<u8> {
        let mut byte = [0];
        self.reader.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    fn run(&mut self, deadline: Instant) -> io::Result<()> {
        let mut header = [0; 12];
        self.reader.read_exact(&mut header)?;
        if &header[..4] != b"PACK" || !matches!(header[4..8], [0, 0, 0, 2 | 3]) {
            return Err(invalid());
        }
        let count = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        for _ in 0..count {
            if Instant::now() >= deadline {
                return Err(invalid());
            }
            self.object()?;
        }
        Ok(())
    }

    fn object(&mut self) -> io::Result<()> {
        let offset = self.reader.count;
        let mut byte = self.byte()?;
        let kind = (byte >> 4) & 7;
        let mut size = u64::from(byte & 15);
        let mut shift = 4;
        while byte & 0x80 != 0 {
            byte = self.byte()?;
            if shift > 57 {
                return Err(invalid());
            }
            size |= u64::from(byte & 0x7f) << shift;
            shift += 7;
        }
        let seen = match kind {
            1 => {
                let data = self.inflate(size, true)?;
                self.commit(data)?
            }
            2..=4 => {
                self.inflate(size, false)?;
                Seen::Other
            }
            6 => {
                let mut byte = self.byte()?;
                let mut distance = u64::from(byte & 0x7f);
                while byte & 0x80 != 0 {
                    byte = self.byte()?;
                    distance = distance
                        .checked_add(1)
                        .and_then(|d| d.checked_mul(128))
                        .ok_or_else(invalid)?
                        | u64::from(byte & 0x7f);
                }
                let base = offset
                    .checked_sub(distance)
                    .and_then(|base| self.by_offset.get(&base))
                    .cloned();
                self.delta(size, base)?
            }
            7 => {
                let mut id = vec![0; self.kind.len()];
                self.reader.read_exact(&mut id)?;
                let id = hex(&id);
                let base = self.data.contains_key(&id).then_some(Seen::Commit(id));
                self.delta(size, base)?
            }
            _ => return Err(invalid()),
        };
        self.by_offset.insert(offset, seen);
        Ok(())
    }

    /// A delta keeps its base's type. Only commit bases are resolved; any other
    /// or unknown base cannot yield a commit we rely on.
    fn delta(&mut self, size: u64, base: Option<Seen>) -> io::Result<Seen> {
        match base {
            Some(Seen::Commit(id)) => {
                let delta = self.inflate(size, true)?;
                let base = self.data.get(&id).ok_or_else(invalid)?;
                let data = apply_delta(base, &delta).ok_or_else(invalid)?;
                self.retain(data.len())?;
                self.commit(data)
            }
            _ => {
                self.inflate(size, false)?;
                Ok(Seen::Other)
            }
        }
    }

    fn commit(&mut self, data: Vec<u8>) -> io::Result<Seen> {
        let id = self.kind.hash("commit", &data);
        let parents = commit_parents(&data, self.kind).ok_or_else(invalid)?;
        self.graph.parents.insert(id.clone(), parents);
        self.data.insert(id.clone(), data);
        Ok(Seen::Commit(id))
    }

    fn retain(&mut self, bytes: usize) -> io::Result<()> {
        self.retained = self.retained.saturating_add(bytes);
        if self.retained > MAX_RETAINED {
            return Err(invalid());
        }
        Ok(())
    }

    /// Inflate exactly one zlib stream of `size` bytes, leaving the reader at the
    /// next object. Returns the bytes only when `keep` is set.
    fn inflate(&mut self, size: u64, keep: bool) -> io::Result<Vec<u8>> {
        self.inflated = self.inflated.saturating_add(size);
        if self.inflated > MAX_INFLATED {
            return Err(invalid());
        }
        let mut output = Vec::new();
        let mut decoder = ZlibDecoder::new(&mut self.reader);
        let copied = if keep {
            self.retained = self
                .retained
                .saturating_add(usize::try_from(size).map_err(|_| invalid())?);
            if self.retained > MAX_RETAINED {
                return Err(invalid());
            }
            (&mut decoder).take(size + 1).read_to_end(&mut output)? as u64
        } else {
            io::copy(&mut (&mut decoder).take(size + 1), &mut io::sink())?
        };
        if copied != size || decoder.read(&mut [0])? != 0 {
            return Err(invalid());
        }
        Ok(output)
    }
}

/// Parent ids exactly as git reads them: a `tree` line, then consecutive
/// `parent` lines. A `parent` line anywhere else is not a parent.
fn commit_parents(data: &[u8], kind: HashKind) -> Option<Vec<String>> {
    let mut lines = data.split(|&b| b == b'\n');
    let tree = lines.next()?.strip_prefix(b"tree ")?;
    valid_hex(tree, kind)?;
    let mut parents = Vec::new();
    for line in lines {
        let Some(parent) = line.strip_prefix(b"parent ") else {
            break;
        };
        parents.push(valid_hex(parent, kind)?);
    }
    Some(parents)
}

fn valid_hex(value: &[u8], kind: HashKind) -> Option<String> {
    (value.len() == kind.len() * 2 && value.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| String::from_utf8_lossy(value).into_owned())
}

fn varint(data: &[u8], position: &mut usize) -> Option<usize> {
    let mut value = 0usize;
    let mut shift = 0;
    loop {
        let byte = *data.get(*position)?;
        *position += 1;
        if shift > 56 {
            return None;
        }
        value |= usize::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let mut position = 0;
    if varint(delta, &mut position)? != base.len() {
        return None;
    }
    let size = varint(delta, &mut position)?;
    if size > MAX_RETAINED {
        return None;
    }
    let mut output = Vec::with_capacity(size);
    while position < delta.len() {
        let op = delta[position];
        position += 1;
        if op & 0x80 != 0 {
            let mut start = 0usize;
            let mut length = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    start |= usize::from(*delta.get(position)?) << (8 * bit);
                    position += 1;
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    length |= usize::from(*delta.get(position)?) << (8 * bit);
                    position += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            output.extend_from_slice(base.get(start..start.checked_add(length)?)?);
        } else if op != 0 {
            let end = position + usize::from(op);
            output.extend_from_slice(delta.get(position..end)?);
            position = end;
        } else {
            return None;
        }
        if output.len() > size {
            return None;
        }
    }
    (output.len() == size).then_some(output)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{io::Write, path::Path, process::Command, time::Duration};

    fn git(dir: &Path, args: &[&str], input: Option<&str>) -> String {
        let mut child = Command::new("git")
            .args([
                "-c",
                "user.name=Pack Test",
                "-c",
                "user.email=pack@example.invalid",
                "-c",
                "commit.gpgSign=false",
            ])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input.unwrap_or("").as_bytes()).unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "git {args:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    struct Repo(std::path::PathBuf);
    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn repo() -> Repo {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sekisho-pack-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        git(&dir, &["init", "-q"], None);
        Repo(dir)
    }
    fn commit(dir: &Path, message: &str) -> String {
        std::fs::write(dir.join("file"), message.repeat(200)).unwrap();
        git(dir, &["add", "file"], None);
        git(dir, &["commit", "-q", "-m", message], None);
        git(dir, &["rev-parse", "HEAD"], None)
    }
    fn pack(dir: &Path, revs: &str, extra: &[&str]) -> CommitGraph {
        let mut args = vec!["pack-objects", "--stdout", "--revs"];
        args.extend_from_slice(extra);
        let output = Command::new("git")
            .args(&args)
            .current_dir(dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = output;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(revs.as_bytes())
            .unwrap();
        let bytes = child.wait_with_output().unwrap().stdout;
        CommitGraph::scan(
            io::Cursor::new(bytes),
            HashKind::Sha1,
            Instant::now() + Duration::from_secs(30),
        )
    }

    #[test]
    fn real_git_packs_prove_fast_forward_and_rewrite() {
        let repo = repo();
        let dir = &repo.0;
        let base = commit(dir, "base");
        let one = commit(dir, "one");
        let two = commit(dir, "two");
        // A thin pack of what a push of `two` over `base` sends.
        let graph = pack(dir, &format!("{two}\n^{base}\n"), &["--thin"]);
        assert_eq!(graph.ancestry(&base, &two), Ancestry::FastForward);
        assert_eq!(graph.ancestry(&one, &two), Ancestry::FastForward);
        // Rewritten history: amend `two` onto `one`'s parent.
        git(dir, &["reset", "-q", "--hard", &base], None);
        let other = commit(dir, "other");
        let graph = pack(dir, &format!("{other}\n^{base}\n"), &["--thin"]);
        assert_eq!(
            graph.ancestry(&two, &other),
            Ancestry::Upstream(vec![base.clone()])
        );
        // With the whole history in the pack the answer is definite.
        let graph = pack(dir, &format!("{other}\n"), &[]);
        assert_eq!(graph.ancestry(&two, &other), Ancestry::NotFastForward);
        assert_eq!(graph.ancestry(&base, &other), Ancestry::FastForward);
        // An empty pack proves nothing about `new`.
        let graph = pack(dir, &format!("{other}\n^{other}\n"), &[]);
        assert_eq!(
            graph.ancestry(&base, &other),
            Ancestry::Upstream(vec![other.clone()])
        );
    }

    #[test]
    fn deltified_commits_are_resolved() {
        let repo = repo();
        let dir = &repo.0;
        let mut ids = vec![commit(dir, "start")];
        let long = "x".repeat(4000);
        for index in 0..20 {
            // Large near-identical messages make git deltify commits.
            std::fs::write(dir.join("file"), format!("{index}")).unwrap();
            git(dir, &["add", "file"], None);
            git(
                dir,
                &["commit", "-q", "-F", "-"],
                Some(&format!("{long}\n{index}")),
            );
            ids.push(git(dir, &["rev-parse", "HEAD"], None));
        }
        let last = ids.last().unwrap().clone();
        for extra in [
            &[][..],
            &["--no-reuse-delta", "--window=50", "--depth=50"][..],
        ] {
            let graph = pack(dir, &format!("{last}\n^{}\n", ids[0]), extra);
            assert_eq!(graph.parents.len(), 20, "{extra:?}");
            assert_eq!(graph.ancestry(&ids[0], &last), Ancestry::FastForward);
        }
    }

    #[test]
    fn parent_line_outside_header_position_is_not_a_parent() {
        let old = "1".repeat(40);
        let data = format!(
            "tree {}\nauthor a <a> 0 +0000\nparent {old}\ncommitter a <a> 0 +0000\n\nm",
            "2".repeat(40)
        );
        assert_eq!(
            commit_parents(data.as_bytes(), HashKind::Sha1),
            Some(vec![])
        );
    }

    #[test]
    fn corrupt_or_truncated_packs_drop_commits_not_fake_them() {
        let repo = repo();
        let dir = &repo.0;
        let base = commit(dir, "base");
        let next = commit(dir, "next");
        let mut child = Command::new("git")
            .args(["pack-objects", "--stdout", "--revs"])
            .current_dir(dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{next}\n^{base}\n").as_bytes())
            .unwrap();
        let bytes = child.wait_with_output().unwrap().stdout;
        let deadline = Instant::now() + Duration::from_secs(30);
        for cut in 0..bytes.len() {
            let graph = CommitGraph::scan(io::Cursor::new(&bytes[..cut]), HashKind::Sha1, deadline);
            assert_ne!(graph.ancestry(&next, &base), Ancestry::FastForward);
        }
        let mut flipped = bytes.clone();
        for index in 12..flipped.len() {
            flipped[index] ^= 0x55;
            let graph = CommitGraph::scan(io::Cursor::new(&flipped), HashKind::Sha1, deadline);
            for (id, parents) in &graph.parents {
                // Anything recorded is still a real commit of this repo.
                if id == &next {
                    assert_eq!(parents, &vec![base.clone()]);
                }
            }
            flipped[index] ^= 0x55;
        }
        let graph = CommitGraph::scan(io::Cursor::new(&bytes), HashKind::Sha1, deadline);
        assert_eq!(graph.ancestry(&base, &next), Ancestry::FastForward);
    }

    /// NEW-4: a walk past its deadline gives up (unproven, so forced) instead
    /// of blocking; within its deadline it answers as before.
    #[test]
    fn ancestry_walk_gives_up_at_its_deadline() {
        let mut graph = CommitGraph::default();
        // A long linear history: c0 <- c1 <- ... <- c49999.
        for index in 1..50_000 {
            graph
                .parents
                .insert(format!("c{index}"), vec![format!("c{}", index - 1)]);
        }
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(graph.ancestry_until("c0", "c49999", Some(past)), None);
        let future = Instant::now() + Duration::from_secs(30);
        assert_eq!(
            graph.ancestry_until("c0", "c49999", Some(future)),
            Some(Ancestry::FastForward)
        );
    }

    #[test]
    fn delta_application_rejects_out_of_range_copies() {
        assert_eq!(
            apply_delta(b"abc", &[3, 3, 0x91, 0, 3]),
            Some(b"abc".to_vec())
        );
        assert_eq!(apply_delta(b"abc", &[3, 4, 0x91, 0, 4]), None);
        assert_eq!(apply_delta(b"abc", &[3, 1, 0]), None);
        assert_eq!(apply_delta(b"abc", &[2, 1, 1, b'x']), None);
        assert_eq!(
            apply_delta(b"abc", &[3, 2, 2, b'x', b'y']),
            Some(b"xy".to_vec())
        );
    }
}
