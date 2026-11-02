//! Policy TOML parsing and validation.

use crate::action::{json_pointer_segment, validate_integers};
use crate::{Digest, ToolName};
use globset::{GlobBuilder, GlobMatcher};
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const POLICY_VERSION: u32 = 1;
const MAX_RULE_NAME_CHARS: usize = 128;
const MAX_TOOL_NAME_BYTES: usize = 128;
const MAX_BUDGET_SECONDS: u32 = 30 * 24 * 60 * 60;
const TOP_LEVEL_KEYS: [&str; 2] = ["version", "rule"];
const RULE_KEYS: [&str; 8] = [
    "name",
    "tool",
    "tool_prefix",
    "target",
    "params",
    "decision",
    "budget",
    "approvers",
];
const BUDGET_KEYS: [&str; 2] = ["max", "per"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionKind {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolMatch {
    Exact(ToolName),
    Prefix(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub max: u32,
    pub per_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub index: usize,
    pub name: String,
    pub tool: ToolMatch,
    pub target: Option<GlobMatcher>,
    pub target_pattern: Option<String>,
    pub params: BTreeMap<String, JsonValue>,
    pub decision: DecisionKind,
    pub budget: Option<Budget>,
    pub approvers: u8,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub version: u32,
    pub rules: Vec<Rule>,
    pub sha256: Digest,
}

impl Policy {
    /// Parse and validate a policy file. The digest covers the exact input bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let sha256 = Digest::from(<[u8; 32]>::from(Sha256::digest(bytes)));
        let document: toml::Value = toml::from_slice(bytes)
            .map_err(|error| PolicyError::top(None, format!("invalid TOML: {error}")))?;
        let table = document
            .as_table()
            .ok_or_else(|| PolicyError::top(None, "policy must be a TOML table"))?;

        reject_unknown_keys(table, &TOP_LEVEL_KEYS, None, "", "policy")?;
        let version = parse_version(table)?;
        let rules = parse_rules(table.get("rule"))?;

        Ok(Self {
            version,
            rules,
            sha256,
        })
    }
}

/// macOS path prefixes that reach any file without the canonical path:
/// `/.nofollow/` and `/.resolve/` re-enter the root, `/.vol/<dev>/<ino>` names
/// files by inode. No hook target may use them.
pub const PATH_ALIAS_PREFIXES: [&str; 3] = ["/.nofollow", "/.resolve", "/.vol"];

/// The macOS data volume firmlink root: `/System/Volumes/Data/Users/u` is the
/// same directory as `/Users/u`, and `canonicalize` keeps whichever was given.
pub const DATA_VOLUME_ROOT: &str = "/System/Volumes/Data";

/// A path with the data volume firmlink root rewritten to `/`, so the same
/// file has one spelling for matching. `None` when nothing changed. The
/// comparison ignores case, as the default macOS file system does.
#[must_use]
pub fn without_data_volume(path: &str) -> Option<String> {
    let prefix = path.get(..DATA_VOLUME_ROOT.len())?;
    if !prefix.eq_ignore_ascii_case(DATA_VOLUME_ROOT) {
        return None;
    }
    let rest = &path[DATA_VOLUME_ROOT.len()..];
    if rest.is_empty() {
        Some("/".to_owned())
    } else if rest.starts_with('/') {
        Some(rest.to_owned())
    } else {
        None
    }
}

/// Every directory that contains `dir` under any of its spellings: the plain
/// path and its macOS data volume form (`/System/Volumes/Data<dir>`), so
/// `/System/Volumes/Data`, `/System/Volumes` and `/System` count as ancestors
/// of `/Users/u/.sekisho`. A search rooted at any of them reaches `dir`. The
/// hook's inode check and the built-in rule both use this list.
#[must_use]
pub fn protected_ancestors(dir: &str) -> Vec<String> {
    let dir = dir.trim_end_matches('/');
    let plain = without_data_volume(dir).unwrap_or_else(|| dir.to_owned());
    let spellings = [plain.clone(), format!("{DATA_VOLUME_ROOT}{plain}")];
    let mut ancestors: Vec<String> = Vec::new();
    for spelling in &spellings {
        for ancestor in std::path::Path::new(spelling).ancestors().skip(1) {
            if let Some(ancestor) = ancestor.to_str()
                && !ancestors.iter().any(|seen| seen == ancestor)
            {
                ancestors.push(ancestor.to_owned());
            }
        }
    }
    ancestors
}

/// Name of the built-in rule added by [`Policy::protect_dir`].
pub const PROTECTED_DIR_RULE: &str = "built-in: Sekisho state directory";

impl Policy {
    /// Deny every `hook:` action whose target is `dir` or a path below it, as a
    /// file path or as a hook working directory (`cwd:<dir>`), and every search
    /// of a directory that contains `dir` (a directory target `<ancestor>/`).
    ///
    /// The rule is a deny rule, so `decide` applies it before grants and before
    /// any rule in the policy file, and a policy file cannot override it. It does
    /// not change the policy digest, which covers only the file bytes.
    pub fn protect_dir(&mut self, dir: &str) -> Result<(), PolicyError> {
        let dir = dir.trim_end_matches('/');
        let invalid = || PolicyError::top(None, "protected directory must be an absolute path");
        if !dir.starts_with('/') {
            return Err(invalid());
        }
        let escaped = globset::escape(dir);
        let mut patterns = vec![
            escaped.clone(),
            format!("{escaped}/**"),
            format!("cwd:{escaped}"),
            format!("cwd:{escaped}/**"),
        ];
        patterns.extend(
            protected_ancestors(dir)
                .iter()
                .map(|ancestor| format!("{}/", globset::escape(ancestor.trim_end_matches('/')))),
        );
        // Alias prefixes that bypass canonical paths are never a valid target.
        for alias in PATH_ALIAS_PREFIXES {
            for form in ["", "cwd:"] {
                patterns.push(format!("{form}{alias}"));
                patterns.push(format!("{form}{alias}/**"));
            }
        }
        for pattern in patterns {
            let glob = GlobBuilder::new(&pattern)
                .literal_separator(true)
                .case_insensitive(true)
                .build()
                .map_err(|_| invalid())?;
            self.rules.insert(
                0,
                Rule {
                    index: 0,
                    name: PROTECTED_DIR_RULE.to_owned(),
                    tool: ToolMatch::Prefix("hook:".to_owned()),
                    target: Some(glob.compile_matcher()),
                    target_pattern: Some(pattern),
                    params: BTreeMap::new(),
                    decision: DecisionKind::Deny,
                    budget: None,
                    approvers: 1,
                },
            );
        }
        Ok(())
    }
}

fn parse_version(table: &toml::Table) -> Result<u32, PolicyError> {
    let value = table
        .get("version")
        .ok_or_else(|| PolicyError::top(Some("version"), "version is required"))?;
    let version = value
        .as_integer()
        .ok_or_else(|| PolicyError::top(Some("version"), "version must be an integer"))?;
    if version != i64::from(POLICY_VERSION) {
        return Err(PolicyError::top(
            Some("version"),
            format!("unsupported policy version {version}: expected {POLICY_VERSION}"),
        ));
    }
    Ok(POLICY_VERSION)
}

fn parse_rules(value: Option<&toml::Value>) -> Result<Vec<Rule>, PolicyError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| PolicyError::top(Some("rule"), "rule must be an array of tables"))?;
    let mut names = BTreeSet::new();
    let mut rules = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        rules.push(parse_rule(entry, index, &mut names)?);
    }
    Ok(rules)
}

fn parse_rule(
    value: &toml::Value,
    index: usize,
    names: &mut BTreeSet<String>,
) -> Result<Rule, PolicyError> {
    let table = value
        .as_table()
        .ok_or_else(|| PolicyError::rule(index, None, "rule", "rule must be a table"))?;

    let name = match table.get("name") {
        None => return Err(PolicyError::rule(index, None, "name", "name is required")),
        Some(toml::Value::String(name)) => name.clone(),
        Some(_) => {
            return Err(PolicyError::rule(
                index,
                None,
                "name",
                "name must be a string",
            ));
        }
    };
    let length = name.chars().count();
    if !(1..=MAX_RULE_NAME_CHARS).contains(&length) {
        return Err(PolicyError::rule(
            index,
            Some(&name),
            "name",
            format!("name must be between 1 and {MAX_RULE_NAME_CHARS} characters"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(PolicyError::rule(
            index,
            Some(&name),
            "name",
            "name must not contain control characters",
        ));
    }
    if name.trim() != name {
        return Err(PolicyError::rule(
            index,
            Some(&name),
            "name",
            "name must not have leading or trailing whitespace",
        ));
    }
    if !names.insert(name.clone()) {
        return Err(PolicyError::rule(
            index,
            Some(&name),
            "name",
            format!("duplicate rule name {name:?}"),
        ));
    }
    reject_unknown_keys(table, &RULE_KEYS, Some((index, name.as_str())), "", "rule")?;

    let tool = parse_tool(table, index, &name)?;
    let (target, target_pattern) = parse_target(table, index, &name)?;
    let params = parse_params(table, index, &name)?;
    let decision = parse_decision(table, index, &name)?;
    let budget = parse_budget(table, index, &name, decision)?;
    let approvers = parse_approvers(table, index, &name, decision)?;

    Ok(Rule {
        index,
        name,
        tool,
        target,
        target_pattern,
        params,
        decision,
        budget,
        approvers,
    })
}

fn parse_tool(table: &toml::Table, index: usize, name: &str) -> Result<ToolMatch, PolicyError> {
    match (table.get("tool"), table.get("tool_prefix")) {
        (Some(_), Some(_)) => Err(PolicyError::rule(
            index,
            Some(name),
            "tool",
            "`tool` and `tool_prefix` cannot be used together",
        )),
        (None, None) => Err(PolicyError::rule(
            index,
            Some(name),
            "tool",
            "exactly one of `tool` or `tool_prefix` is required",
        )),
        (Some(value), None) => {
            let value = value.as_str().ok_or_else(|| {
                PolicyError::rule(index, Some(name), "tool", "tool must be a string")
            })?;
            let tool = ToolName::try_from(value)
                .map_err(|error| PolicyError::rule(index, Some(name), "tool", error.to_string()))?;
            Ok(ToolMatch::Exact(tool))
        }
        (None, Some(value)) => {
            let value = value.as_str().ok_or_else(|| {
                PolicyError::rule(
                    index,
                    Some(name),
                    "tool_prefix",
                    "tool_prefix must be a string",
                )
            })?;
            validate_tool_prefix(value)
                .map_err(|message| PolicyError::rule(index, Some(name), "tool_prefix", message))?;
            Ok(ToolMatch::Prefix(value.to_owned()))
        }
    }
}

/// A prefix must end at a segment boundary (`/`, `_`, `.` or `:`), so
/// `mcp:github/` cannot also match `mcp:github-admin/...`.
fn validate_tool_prefix(value: &str) -> Result<(), String> {
    let base = value
        .strip_suffix(['/', '_', '.', ':'])
        .filter(|base| !base.ends_with(['/', '_', '.', ':']));
    if (1..=MAX_TOOL_NAME_BYTES).contains(&value.len())
        && base.is_some_and(|base| ToolName::try_from(base).is_ok())
    {
        Ok(())
    } else {
        Err(format!(
            "tool prefix {value:?} must follow the tool-name character rules and end in \"/\", \"_\", \".\" or \":\""
        ))
    }
}

fn parse_target(
    table: &toml::Table,
    index: usize,
    name: &str,
) -> Result<(Option<GlobMatcher>, Option<String>), PolicyError> {
    let Some(value) = table.get("target") else {
        return Ok((None, None));
    };
    let pattern = value
        .as_str()
        .ok_or_else(|| PolicyError::rule(index, Some(name), "target", "target must be a string"))?;
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|error| {
            PolicyError::rule(
                index,
                Some(name),
                "target",
                format!("invalid target glob {pattern:?}: {error}"),
            )
        })?;
    Ok((Some(glob.compile_matcher()), Some(pattern.to_owned())))
}

fn parse_params(
    table: &toml::Table,
    index: usize,
    name: &str,
) -> Result<BTreeMap<String, JsonValue>, PolicyError> {
    let Some(value) = table.get("params") else {
        return Ok(BTreeMap::new());
    };
    let table = value
        .as_table()
        .ok_or_else(|| PolicyError::rule(index, Some(name), "params", "params must be a table"))?;
    let mut params = BTreeMap::new();
    for (key, value) in table {
        let path = format!("/{}", json_pointer_segment(key));
        let json = json_value(value, &path)
            .map_err(|message| PolicyError::rule(index, Some(name), "params", message))?;
        if let Err(error) = validate_integers(&json, &path) {
            return Err(PolicyError::rule(
                index,
                Some(name),
                "params",
                error.to_string(),
            ));
        }
        params.insert(key.clone(), json);
    }
    Ok(params)
}

fn json_value(value: &toml::Value, path: &str) -> Result<JsonValue, String> {
    Ok(match value {
        toml::Value::String(value) => JsonValue::String(value.clone()),
        toml::Value::Integer(value) => JsonValue::Number((*value).into()),
        toml::Value::Float(value) => JsonValue::Number(
            serde_json::Number::from_f64(*value)
                .ok_or_else(|| format!("params float at {path} is not finite"))?,
        ),
        toml::Value::Boolean(value) => JsonValue::Bool(*value),
        toml::Value::Datetime(_) => {
            return Err(format!(
                "params value at {path} is not representable in JSON"
            ));
        }
        toml::Value::Array(values) => JsonValue::Array(
            values
                .iter()
                .enumerate()
                .map(|(index, value)| json_value(value, &format!("{path}/{index}")))
                .collect::<Result<_, _>>()?,
        ),
        toml::Value::Table(table) => JsonValue::Object(
            table
                .iter()
                .map(|(key, value)| {
                    let child = format!("{path}/{}", json_pointer_segment(key));
                    json_value(value, &child).map(|value| (key.clone(), value))
                })
                .collect::<Result<_, _>>()?,
        ),
    })
}

fn parse_decision(
    table: &toml::Table,
    index: usize,
    name: &str,
) -> Result<DecisionKind, PolicyError> {
    let value = table
        .get("decision")
        .ok_or_else(|| PolicyError::rule(index, Some(name), "decision", "decision is required"))?;
    let decision = value.as_str().ok_or_else(|| {
        PolicyError::rule(index, Some(name), "decision", "decision must be a string")
    })?;
    match decision {
        "allow" => Ok(DecisionKind::Allow),
        "ask" => Ok(DecisionKind::Ask),
        "deny" => Ok(DecisionKind::Deny),
        _ => Err(PolicyError::rule(
            index,
            Some(name),
            "decision",
            format!("invalid decision {decision:?}: expected \"allow\", \"ask\" or \"deny\""),
        )),
    }
}

fn parse_budget(
    table: &toml::Table,
    index: usize,
    name: &str,
    decision: DecisionKind,
) -> Result<Option<Budget>, PolicyError> {
    let Some(value) = table.get("budget") else {
        return Ok(None);
    };
    if decision != DecisionKind::Allow {
        return Err(PolicyError::rule(
            index,
            Some(name),
            "budget",
            "budget is only allowed on allow rules",
        ));
    }
    let table = value
        .as_table()
        .ok_or_else(|| PolicyError::rule(index, Some(name), "budget", "budget must be a table"))?;
    reject_unknown_keys(table, &BUDGET_KEYS, Some((index, name)), "budget", "budget")?;

    let max = parse_budget_max(table, index, name)?;
    let per_seconds = parse_budget_period(table, index, name)?;
    Ok(Some(Budget { max, per_seconds }))
}

fn parse_budget_max(table: &toml::Table, index: usize, name: &str) -> Result<u32, PolicyError> {
    let value = table
        .get("max")
        .ok_or_else(|| PolicyError::rule(index, Some(name), "budget.max", "max is required"))?;
    let value = value.as_integer().ok_or_else(|| {
        PolicyError::rule(index, Some(name), "budget.max", "max must be an integer")
    })?;
    u32::try_from(value)
        .ok()
        .filter(|max| *max >= 1)
        .ok_or_else(|| {
            PolicyError::rule(
                index,
                Some(name),
                "budget.max",
                format!("max must be between 1 and {}", u32::MAX),
            )
        })
}

fn parse_budget_period(table: &toml::Table, index: usize, name: &str) -> Result<u32, PolicyError> {
    let value = table
        .get("per")
        .ok_or_else(|| PolicyError::rule(index, Some(name), "budget.per", "per is required"))?;
    let value = value.as_str().ok_or_else(|| {
        PolicyError::rule(index, Some(name), "budget.per", "per must be a string")
    })?;
    parse_duration(value)
        .map_err(|message| PolicyError::rule(index, Some(name), "budget.per", message))
}

fn parse_duration(value: &str) -> Result<u32, String> {
    let Some((index, unit)) = value.char_indices().next_back() else {
        return Err(invalid_duration(value));
    };
    let multiplier: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return Err(invalid_duration(value)),
    };
    let number = &value[..index];
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_duration(value));
    }
    let number = number
        .parse::<u64>()
        .map_err(|_| duration_out_of_range(value))?;
    let seconds = number
        .checked_mul(multiplier)
        .filter(|seconds| (1..=u64::from(MAX_BUDGET_SECONDS)).contains(seconds))
        .ok_or_else(|| duration_out_of_range(value))?;
    u32::try_from(seconds).map_err(|_| duration_out_of_range(value))
}

fn invalid_duration(value: &str) -> String {
    format!("invalid budget duration {value:?}: expected <n>s, <n>m, <n>h or <n>d")
}

fn duration_out_of_range(value: &str) -> String {
    format!("budget duration {value:?} must be between 1s and 30d")
}

fn parse_approvers(
    table: &toml::Table,
    index: usize,
    name: &str,
    decision: DecisionKind,
) -> Result<u8, PolicyError> {
    let Some(value) = table.get("approvers") else {
        return Ok(1);
    };
    if decision != DecisionKind::Ask {
        return Err(PolicyError::rule(
            index,
            Some(name),
            "approvers",
            "approvers is only allowed on ask rules",
        ));
    }
    if value.as_integer() != Some(1) {
        return Err(PolicyError::rule(
            index,
            Some(name),
            "approvers",
            "approvers must be 1 in v0.1",
        ));
    }
    Ok(1)
}

fn reject_unknown_keys(
    table: &toml::Table,
    allowed: &[&str],
    rule: Option<(usize, &str)>,
    field_prefix: &str,
    scope: &str,
) -> Result<(), PolicyError> {
    for key in table.keys() {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        let field = if field_prefix.is_empty() {
            key.clone()
        } else {
            format!("{field_prefix}.{key}")
        };
        let message = format!("unknown {scope} key");
        return Err(match rule {
            Some((index, name)) => PolicyError::rule(index, Some(name), &field, message),
            None => PolicyError::top(Some(&field), message),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub rule_index: Option<usize>,
    pub rule_name: Option<String>,
    pub field: Option<String>,
    pub message: String,
}

impl PolicyError {
    fn top(field: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            rule_index: None,
            rule_name: None,
            field: field.map(str::to_owned),
            message: message.into(),
        }
    }

    fn rule(index: usize, name: Option<&str>, field: &str, message: impl Into<String>) -> Self {
        Self {
            rule_index: Some(index),
            rule_name: name.map(str::to_owned),
            field: Some(field.to_owned()),
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(index) = self.rule_index {
            write!(f, "rule {index}")?;
            if let Some(name) = &self.rule_name {
                write!(f, " ({name:?})")?;
            }
            if let Some(field) = &self.field {
                write!(f, ", field `{field}`")?;
            }
        } else if let Some(field) = &self.field {
            write!(f, "field `{field}`")?;
        }
        if self.rule_index.is_some() || self.field.is_some() {
            f.write_str(": ")?;
        }
        f.write_str(&self.message)
    }
}

impl std::error::Error for PolicyError {}
