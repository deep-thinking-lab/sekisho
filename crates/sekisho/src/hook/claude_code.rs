use sekisho_core::{Action, AgentId, CoreError, ToolName};
use serde::Deserialize;
use serde_json::{Number, Value, json};
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("invalid hook JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported hook event: {0}")]
    UnsupportedEvent(String),
    #[error("hook cwd must be absolute: {0}")]
    RelativeCwd(String),
    #[error("the tool's path argument must be a non-empty path without `~`")]
    InvalidFilePath,
    #[error("invalid MCP tool name: {0}")]
    InvalidMcpToolName(String),
    #[error("hook path is not valid UTF-8")]
    NonUtf8Path,
    #[error("failed to resolve real path {path}: {source}")]
    RealPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid action: {0}")]
    InvalidAction(#[from] CoreError),
}

#[derive(Deserialize)]
struct HookInput {
    hook_event_name: String,
    tool_name: String,
    cwd: String,
    tool_input: Value,
}

pub fn action_from_hook(agent: &AgentId, hook_json: &[u8]) -> Result<Action, HookError> {
    let mut input: HookInput = serde_json::from_slice(hook_json)?;
    if input.hook_event_name != "PreToolUse" {
        return Err(HookError::UnsupportedEvent(input.hook_event_name));
    }

    convert_unsafe_integers(&mut input.tool_input);

    let tool_name = input.tool_name.to_ascii_lowercase();
    let (tool, target) = if let Some(mcp_name) = tool_name.strip_prefix("mcp__") {
        let (server, mcp_tool) = mcp_name
            .split_once("__")
            .ok_or_else(|| HookError::InvalidMcpToolName(input.tool_name.clone()))?;
        if server.is_empty() || mcp_tool.is_empty() {
            return Err(HookError::InvalidMcpToolName(input.tool_name));
        }
        let tool = format!("mcp:{server}/{mcp_tool}");
        (ToolName::try_from(tool.as_str())?, server.to_owned())
    } else {
        let target = hook_target(&tool_name, &input.cwd, &input.tool_input)?;
        let tool = format!("hook:claude-code/{tool_name}");
        (ToolName::try_from(tool.as_str())?, target)
    };

    Action::new(agent.clone(), tool, target, input.tool_input).map_err(HookError::from)
}

/// The target a hook rule matches against.
///
/// Each known tool's path argument is fixed: `file_path` for Read, Edit, Write
/// and MultiEdit, `notebook_path` for NotebookEdit, `path` for Grep, Glob and LS
/// (the search root, defaulting to cwd), plus the fixed directory part of a Glob
/// pattern. Any other tool may carry at most one path-like argument, which is
/// its target; with none it targets cwd. A tool input with an unexpected or
/// extra path-like argument, an empty or non-string path, a `~` path or an
/// ambiguous Glob pattern is an error, which the hook turns into a deny.
///
/// Every path is resolved to its real path. Directories end in `/`, so
/// `/project/**` matches a search of `/project` itself. Bash targets
/// `cwd:<real dir>/`, so file allow rules never cover shell commands.
fn hook_target(tool: &str, cwd: &str, input: &Value) -> Result<String, HookError> {
    let keys = path_keys(input);
    let (key, required) = match tool {
        "bash" => (None, false),
        "edit" | "write" | "read" | "multiedit" => (Some("file_path"), true),
        "notebookedit" | "notebookread" => (Some("notebook_path"), true),
        "grep" | "glob" | "ls" => (Some("path"), false),
        _ => match keys.as_slice() {
            [] => (None, false),
            [only] => (Some(only.as_str()), true),
            _ => return Err(HookError::InvalidFilePath),
        },
    };
    // A path-like argument the target does not cover could be what the tool acts on.
    if keys.iter().any(|other| Some(other.as_str()) != key) {
        return Err(HookError::InvalidFilePath);
    }
    let mut path = match key.map(|key| input.get(key)) {
        None | Some(None) if !required => None,
        Some(Some(Value::String(path))) if !path.is_empty() && !path.starts_with('~') => {
            Some(path.clone())
        }
        _ => return Err(HookError::InvalidFilePath),
    };
    if tool == "glob" {
        let pattern = input
            .get("pattern")
            .and_then(Value::as_str)
            .ok_or(HookError::InvalidFilePath)?;
        if let Some(base) = glob_base(pattern)? {
            let root = path.as_deref().unwrap_or(cwd);
            path = Some(Path::new(root).join(base).to_string_lossy().into_owned());
        }
    }
    let resolved = unalias(resolve_path(cwd, Some(path.as_deref().unwrap_or(cwd)))?)?;
    let resolved = if !resolved.ends_with('/') && Path::new(&resolved).is_dir() {
        format!("{resolved}/")
    } else {
        resolved
    };
    Ok(if tool == "bash" {
        format!("cwd:{resolved}")
    } else {
        resolved
    })
}

/// One spelling per file for macOS aliases that `canonicalize` keeps: refuse
/// `/.nofollow`, `/.resolve` and `/.vol` paths, and rewrite the data volume
/// firmlink root `/System/Volumes/Data` to `/`.
fn unalias(path: String) -> Result<String, HookError> {
    let refused = sekisho_core::PATH_ALIAS_PREFIXES.iter().any(|alias| {
        path.get(..alias.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(alias))
            && matches!(path.as_bytes().get(alias.len()), None | Some(b'/'))
    });
    if refused {
        return Err(HookError::InvalidFilePath);
    }
    Ok(sekisho_core::without_data_volume(&path).unwrap_or(path))
}

/// Keys of the tool input that name a file or directory.
fn path_keys(input: &Value) -> Vec<String> {
    let Some(object) = input.as_object() else {
        return Vec::new();
    };
    let mut keys: Vec<String> = object
        .keys()
        .filter(|key| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "path" | "paths" | "file" | "files" | "filename" | "dir" | "directory" | "cwd"
            ) || ["_path", "_paths", "_file", "_files", "_dir", "_directory"]
                .iter()
                .any(|suffix| key.ends_with(suffix))
        })
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// The fixed directory a Glob pattern searches under, relative or absolute.
/// Patterns whose reach cannot be read off a literal prefix are refused:
/// alternation, character classes, `..`, `~`, or an absolute pattern with a
/// `/` after its first wildcard.
fn glob_base(pattern: &str) -> Result<Option<&str>, HookError> {
    let wildcard = pattern.find(['*', '?']).unwrap_or(pattern.len());
    if pattern.contains(['{', '[', '\\'])
        || pattern.starts_with('~')
        || pattern.split('/').any(|part| part == "..")
        || (pattern.starts_with('/') && pattern[wildcard..].contains('/'))
    {
        return Err(HookError::InvalidFilePath);
    }
    Ok(pattern[..wildcard]
        .rfind('/')
        .map(|slash| &pattern[..=slash]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    Allow,
    Deny {
        reason: String,
    },
    #[allow(dead_code)]
    // The mapper supports ask; the waiting command turns a pending ask into deny.
    Ask {
        reason: String,
    },
}

// Field names follow Claude Code's current PreToolUse output schema:
// https://code.claude.com/docs/en/hooks#pretooluse-decision-control
pub fn hook_output(decision: &HookDecision) -> serde_json::Value {
    match decision {
        HookDecision::Allow => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow"
            }
        }),
        HookDecision::Deny { reason } => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }),
        HookDecision::Ask { reason } => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reason
            }
        }),
    }
}

fn resolve_path(cwd: &str, file_path: Option<&str>) -> Result<String, HookError> {
    let cwd = Path::new(cwd);
    if !cwd.is_absolute() {
        return Err(HookError::RelativeCwd(cwd.display().to_string()));
    }
    let path = match file_path {
        Some(file_path) if Path::new(file_path).is_absolute() => PathBuf::from(file_path),
        Some(file_path) => cwd.join(file_path),
        None => cwd.to_owned(),
    };
    let resolved = if file_path.is_some() {
        resolve_real_path(
            &path,
            |candidate| std::fs::canonicalize(candidate),
            |candidate| std::fs::symlink_metadata(candidate),
        )?
    } else {
        normalize_path(&path)
    };
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or(HookError::NonUtf8Path)
}

// Defence in depth: the hook runs before Claude Code acts, so the path can change
// between this check and the tool call. The git and credential proxies remain the
// strong enforcement points.
fn resolve_real_path<C, S>(
    path: &Path,
    mut canonicalize: C,
    mut symlink_metadata: S,
) -> Result<PathBuf, HookError>
where
    C: FnMut(&Path) -> io::Result<PathBuf>,
    S: FnMut(&Path) -> io::Result<std::fs::Metadata>,
{
    for ancestor in path.ancestors() {
        match canonicalize(ancestor) {
            Ok(resolved) => {
                let tail = path
                    .strip_prefix(ancestor)
                    .map_err(|error| HookError::RealPath {
                        path: path.to_path_buf(),
                        source: io::Error::new(io::ErrorKind::InvalidInput, error),
                    })?;
                if has_relative_component(tail) {
                    return Err(HookError::RealPath {
                        path: path.to_path_buf(),
                        source: io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "missing path tail contains relative components",
                        ),
                    });
                }
                return Ok(if tail.as_os_str().is_empty() {
                    resolved
                } else {
                    resolved.join(tail)
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match symlink_metadata(ancestor) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(HookError::RealPath {
                            path: ancestor.to_path_buf(),
                            source: error,
                        });
                    }
                    Ok(_) => {
                        return Err(HookError::RealPath {
                            path: ancestor.to_path_buf(),
                            source: error,
                        });
                    }
                    Err(metadata_error) if metadata_error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(HookError::RealPath {
                            path: ancestor.to_path_buf(),
                            source,
                        });
                    }
                }
            }
            Err(source) => {
                return Err(HookError::RealPath {
                    path: ancestor.to_path_buf(),
                    source,
                });
            }
        }
    }

    Err(HookError::RealPath {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::NotFound, "path has no existing ancestor"),
    })
}

fn has_relative_component(path: &Path) -> bool {
    let raw_components = path
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/' || (cfg!(windows) && *byte == b'\\'));
    path.components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || raw_components
            .into_iter()
            .any(|component| component == b"." || component == b"..")
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !normalized.has_root() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn convert_unsafe_integers(value: &mut Value) {
    if let Value::Number(number) = value {
        if is_unsafe_integer(number) {
            *value = Value::String(number.to_string());
        }
        return;
    }
    match value {
        Value::Array(values) => {
            for value in values {
                convert_unsafe_integers(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                convert_unsafe_integers(value);
            }
        }
        _ => {}
    }
}

fn is_unsafe_integer(number: &Number) -> bool {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    if let Some(value) = number.as_i64() {
        value.unsigned_abs() > MAX_SAFE_INTEGER
    } else {
        number
            .as_u64()
            .is_some_and(|value| value > MAX_SAFE_INTEGER)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sekisho_core::ToolName;
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sekisho-hook-{label}-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn agent() -> AgentId {
        AgentId::try_from("claude").unwrap()
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/claude-code")
            .join(name);
        fs::read(path).unwrap()
    }

    fn expected(tool: &str, target: &str, params: serde_json::Value) -> Action {
        Action::new(
            agent(),
            ToolName::try_from(tool).unwrap(),
            target.to_owned(),
            params,
        )
        .unwrap()
    }

    fn expected_real_path(path: &str) -> String {
        let path = Path::new(path);
        let existing_ancestor = path.ancestors().find(|ancestor| ancestor.exists()).unwrap();
        let tail = path.strip_prefix(existing_ancestor).unwrap();
        let real = fs::canonicalize(existing_ancestor)
            .unwrap()
            .join(tail)
            .to_str()
            .unwrap()
            .to_owned();
        sekisho_core::without_data_volume(&real).unwrap_or(real)
    }

    fn file_hook(tool: &str, cwd: &Path, file_path: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "session_id": "abc123",
            "cwd": cwd.to_string_lossy(),
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {
                "file_path": file_path,
                "content": "test"
            }
        }))
        .unwrap()
    }

    #[test]
    fn bash_fixture_maps_to_action() {
        let params = json!({
            "command": "npm test",
            "description": "Run test suite",
            "timeout": 120000,
            "run_in_background": false
        });
        assert_eq!(
            action_from_hook(&agent(), &fixture("bash.json")).unwrap(),
            expected(
                "hook:claude-code/bash",
                &format!("cwd:{}", expected_real_path("/home/user/my-project")),
                params
            )
        );
    }

    #[test]
    fn edit_fixture_maps_to_action() {
        let params = json!({
            "file_path": "/home/user/my-project/src/auth.rs",
            "old_string": "fn old() {}",
            "new_string": "fn new() {}",
            "replace_all": false
        });
        assert_eq!(
            action_from_hook(&agent(), &fixture("edit.json")).unwrap(),
            expected(
                "hook:claude-code/edit",
                &expected_real_path("/home/user/my-project/src/auth.rs"),
                params
            )
        );
    }

    #[test]
    fn write_fixture_maps_to_action() {
        let params = json!({
            "file_path": "/home/user/my-project/src/checkpoint.rs",
            "content": "pub fn checkpoint() {}\n"
        });
        assert_eq!(
            action_from_hook(&agent(), &fixture("write.json")).unwrap(),
            expected(
                "hook:claude-code/write",
                &expected_real_path("/home/user/my-project/src/checkpoint.rs"),
                params
            )
        );
    }

    #[test]
    fn read_fixture_maps_to_action() {
        let params = json!({
            "file_path": "/home/user/my-project/Cargo.toml",
            "offset": 1,
            "limit": 20
        });
        assert_eq!(
            action_from_hook(&agent(), &fixture("read.json")).unwrap(),
            expected(
                "hook:claude-code/read",
                &expected_real_path("/home/user/my-project/Cargo.toml"),
                params
            )
        );
    }

    #[test]
    fn mcp_fixture_maps_to_action() {
        let params = json!({
            "query": "open issues",
            "limit": 5
        });
        assert_eq!(
            action_from_hook(&agent(), &fixture("mcp.json")).unwrap(),
            expected("mcp:server/tool", "server", params)
        );
    }

    #[test]
    fn unknown_tool_maps_generically() {
        let hook = json!({
            "session_id": "abc123",
            "cwd": "/home/user/my-project",
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.invalid"}
        });
        assert_eq!(
            action_from_hook(&agent(), &serde_json::to_vec(&hook).unwrap()).unwrap(),
            expected(
                "hook:claude-code/webfetch",
                &expected_real_path("/home/user/my-project"),
                json!({"url": "https://example.invalid"})
            )
        );
    }

    fn target_of(tool: &str, cwd: &Path, input: serde_json::Value) -> Result<String, HookError> {
        let hook = json!({
            "cwd": cwd.to_string_lossy(),
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
        });
        action_from_hook(&agent(), &serde_json::to_vec(&hook).unwrap())
            .map(|action| action.target().to_owned())
    }

    /// SEK-03: every tool's own path argument is the target, never the cwd.
    #[test]
    fn path_arguments_of_search_and_notebook_tools_are_targets() {
        let project = TempDir::new("project");
        let secret = TempDir::new("secret");
        fs::write(secret.path().join("token"), "x").unwrap();
        let project_real = fs::canonicalize(project.path()).unwrap();
        let secret_real = fs::canonicalize(secret.path()).unwrap();
        let outside = format!("{}/", secret_real.display());
        let s = secret.path().to_str().unwrap();
        for (tool, input, expected) in [
            ("Grep", json!({"pattern": ".", "path": s}), outside.clone()),
            ("Glob", json!({"pattern": "*", "path": s}), outside.clone()),
            (
                "Glob",
                json!({"pattern": format!("{s}/**")}),
                outside.clone(),
            ),
            ("LS", json!({"path": s}), outside.clone()),
            (
                "NotebookEdit",
                json!({"notebook_path": format!("{s}/token"), "new_source": ""}),
                format!("{}/token", secret_real.display()),
            ),
            (
                "MultiEdit",
                json!({"file_path": format!("{s}/token"), "edits": []}),
                format!("{}/token", secret_real.display()),
            ),
            (
                "Grep",
                json!({"pattern": "."}),
                format!("{}/", project_real.display()),
            ),
            (
                "Glob",
                json!({"pattern": "src/**/*.rs"}),
                format!("{}/src", project_real.display()),
            ),
        ] {
            assert_eq!(
                target_of(tool, project.path(), input.clone()).unwrap(),
                expected,
                "{tool} {input}"
            );
        }
        // Patterns whose reach is not a literal prefix are refused.
        let escape = format!(
            "{}/**",
            Path::new("..")
                .join(secret.path().file_name().unwrap())
                .display()
        );
        for input in [
            json!({"pattern": escape}),
            json!({"pattern": "~/.sekisho/**"}),
            json!({"pattern": "x", "path": "~/.sekisho"}),
            json!({"pattern": format!("{{{s},x}}/*")}),
            json!({"pattern": "[.]sekisho/**"}),
            json!({"pattern": "/home/*/.sekisho/admin.token"}),
            json!({"pattern": "src/../../x"}),
            json!({"pattern": "*", "path": ""}),
        ] {
            assert!(
                target_of("Glob", project.path(), input.clone()).is_err(),
                "{input}"
            );
        }
        assert!(target_of("NotebookEdit", project.path(), json!({})).is_err());
        // One path argument per tool: anything else fails closed.
        let inside = format!("{}/a", project.path().display());
        for (tool, input) in [
            ("Read", json!({"file_path": inside, "path": s})),
            ("Grep", json!({"pattern": ".", "path": "", "file_path": s})),
            ("Grep", json!({"pattern": ".", "path": 7})),
            ("Bash", json!({"command": "ls", "cwd": s})),
            ("SomeTool", json!({"source_path": "a", "target_path": s})),
            ("SomeTool", json!({"target_file": ""})),
        ] {
            assert!(
                target_of(tool, project.path(), input.clone()).is_err(),
                "{tool} {input}"
            );
        }
        assert_eq!(
            target_of(
                "SomeTool",
                project.path(),
                json!({"target_file": format!("{s}/token")})
            )
            .unwrap(),
            format!("{}/token", secret_real.display())
        );
        // Bash never shares a target with file paths, and uses the real cwd.
        let link = project.path().join("link");
        std::os::unix::fs::symlink(secret.path(), &link).unwrap();
        assert_eq!(
            target_of("Bash", &link, json!({"command": "ls"})).unwrap(),
            format!("cwd:{outside}")
        );
    }

    /// NEW-1: macOS alias spellings are refused or rewritten to one form.
    #[test]
    fn macos_aliases_are_refused_or_unaliased() {
        for alias in [
            "/.nofollow/Users/u/x",
            "/.resolve/1/2",
            "/.vol/1/2",
            "/.NoFollow/x",
            "/.vol",
        ] {
            assert!(unalias(alias.to_owned()).is_err(), "{alias}");
        }
        assert_eq!(
            unalias("/System/Volumes/Data/Users/u/x".to_owned()).unwrap(),
            "/Users/u/x"
        );
        assert_eq!(unalias("/System/Volumes/Data".to_owned()).unwrap(), "/");
        assert_eq!(
            unalias("/.nofollowed/x".to_owned()).unwrap(),
            "/.nofollowed/x"
        );
        assert_eq!(
            unalias("/System/Volumes/DataX/y".to_owned()).unwrap(),
            "/System/Volumes/DataX/y"
        );
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(action_from_hook(&agent(), br#"{"tool_name":"Bash""#).is_err());
    }

    #[test]
    fn relative_paths_are_resolved_against_cwd() {
        let hook = json!({
            "session_id": "abc123",
            "cwd": "/home/user/my-project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "src/lib.rs",
                "content": "pub fn answer() -> u8 { 42 }\n"
            }
        });
        assert_eq!(
            action_from_hook(&agent(), &serde_json::to_vec(&hook).unwrap()).unwrap(),
            expected(
                "hook:claude-code/write",
                &expected_real_path("/home/user/my-project/src/lib.rs"),
                json!({
                    "file_path": "src/lib.rs",
                    "content": "pub fn answer() -> u8 { 42 }\n"
                })
            )
        );
    }

    #[test]
    fn path_traversal_is_normalised() {
        let temp = TempDir::new("traversal");
        let repo = temp.path().join("repo");
        fs::create_dir_all(repo.join("a")).unwrap();
        let hook = json!({
            "session_id": "abc123",
            "cwd": repo,
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {
                "file_path": "a/../../etc/passwd",
                "offset": 1,
                "limit": 10
            }
        });
        assert_eq!(
            action_from_hook(&agent(), &serde_json::to_vec(&hook).unwrap()).unwrap(),
            expected(
                "hook:claude-code/read",
                fs::canonicalize(temp.path())
                    .unwrap()
                    .join("etc/passwd")
                    .to_str()
                    .unwrap(),
                json!({
                    "file_path": "a/../../etc/passwd",
                    "offset": 1,
                    "limit": 10
                })
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directory_resolves_to_real_target() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("symlink");
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, repo.join("link")).unwrap();

        let action = action_from_hook(&agent(), &file_hook("Write", &repo, "link/passwd")).unwrap();
        let expected = fs::canonicalize(&outside).unwrap().join("passwd");

        assert_eq!(action.target(), expected.to_str().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn dotdot_through_symlink_resolves_like_the_os() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("dotdot-symlink");
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        let subdirectory = outside.join("sub");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&subdirectory).unwrap();
        symlink(&subdirectory, repo.join("link")).unwrap();

        let action =
            action_from_hook(&agent(), &file_hook("Write", &repo, "link/../escape.txt")).unwrap();
        let expected = fs::canonicalize(&outside).unwrap().join("escape.txt");

        assert_eq!(action.target(), expected.to_str().unwrap());
    }

    #[test]
    fn nonexistent_file_under_real_dir_keeps_tail() {
        let temp = TempDir::new("tail");
        let repo = temp.path().join("repo");
        let existing = repo.join("subdir");
        fs::create_dir_all(&existing).unwrap();

        let action = action_from_hook(
            &agent(),
            &file_hook("Write", &repo, "subdir/missing/new.txt"),
        )
        .unwrap();
        let expected = fs::canonicalize(&existing)
            .unwrap()
            .join("missing")
            .join("new.txt");

        assert_eq!(action.target(), expected.to_str().unwrap());
    }

    #[test]
    fn dotdot_in_missing_tail_is_refused() {
        let temp = TempDir::new("missing-dotdot");
        let repo = temp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();

        let result = action_from_hook(
            &agent(),
            &file_hook("Write", &repo, "missing/../escape.txt"),
        );

        assert!(matches!(result, Err(HookError::RealPath { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loop_is_an_error() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("loop");
        let repo = temp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        symlink("loop", repo.join("loop")).unwrap();

        let result = action_from_hook(&agent(), &file_hook("Read", &repo, "loop/passwd"));

        assert!(matches!(result, Err(HookError::RealPath { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_refused() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("dangling");
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(outside.join("newfile"), repo.join("dangling")).unwrap();

        let result = action_from_hook(&agent(), &file_hook("Write", &repo, "dangling"));

        assert!(matches!(result, Err(HookError::RealPath { .. })));
    }

    #[test]
    fn unsafe_integers_become_strings_recursively() {
        let hook = json!({
            "session_id": "abc123",
            "cwd": "/home/user/my-project",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "true",
                "timeout": 9007199254740992_u64,
                "safe_limit": 9007199254740991_u64,
                "negative_timeout": -9007199254740992_i64,
                "metadata": {"ids": [1, 18446744073709551615_u64]}
            }
        });
        let action = action_from_hook(&agent(), &serde_json::to_vec(&hook).unwrap()).unwrap();
        assert_eq!(
            action.params(),
            &json!({
                "command": "true",
                "timeout": "9007199254740992",
                "safe_limit": 9007199254740991_u64,
                "negative_timeout": "-9007199254740992",
                "metadata": {"ids": [1, "18446744073709551615"]}
            })
        );
    }

    #[test]
    fn decision_output_matches_schema() {
        let outputs = [
            hook_output(&HookDecision::Allow),
            hook_output(&HookDecision::Deny {
                reason: "policy denied".into(),
            }),
            hook_output(&HookDecision::Ask {
                reason: "approval required".into(),
            }),
        ];
        insta::assert_json_snapshot!(outputs, @r###"
        [
          {
            "hookSpecificOutput": {
              "hookEventName": "PreToolUse",
              "permissionDecision": "allow"
            }
          },
          {
            "hookSpecificOutput": {
              "hookEventName": "PreToolUse",
              "permissionDecision": "deny",
              "permissionDecisionReason": "policy denied"
            }
          },
          {
            "hookSpecificOutput": {
              "hookEventName": "PreToolUse",
              "permissionDecision": "ask",
              "permissionDecisionReason": "approval required"
            }
          }
        ]
        "###);
    }
}
