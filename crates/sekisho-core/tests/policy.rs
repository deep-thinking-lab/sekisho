#![allow(clippy::expect_used, clippy::unwrap_used)]

use sekisho_core::{Budget, DecisionKind, Digest, Policy, PolicyError, ToolMatch, ToolName};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/policy");

const EXPECTED_INVALID_FIXTURES: [&str; 11] = [
    "approvers_two",
    "bad_decision",
    "bad_duration",
    "budget_on_ask",
    "duplicate_names",
    "invalid_glob",
    "neither_tool_nor_prefix",
    "tool_and_tool_prefix",
    "unknown_rule_key",
    "unsafe_integer_in_params",
    "version_two",
];

fn fixture_bytes(path: &str) -> Vec<u8> {
    fs::read(Path::new(FIXTURES).join(path)).expect("fixture should exist")
}

fn parse_fixture(path: &str) -> Policy {
    Policy::parse(&fixture_bytes(path)).expect("fixture should parse")
}

fn policy_error(input: &str) -> PolicyError {
    match Policy::parse(input.as_bytes()) {
        Ok(policy) => panic!(
            "expected a policy error, parsed {} rules",
            policy.rules.len()
        ),
        Err(error) => error,
    }
}

fn assert_rule_error(error: &PolicyError, index: usize, name: Option<&str>, field: &str) {
    assert_eq!(error.rule_index, Some(index), "{error}");
    assert_eq!(error.rule_name.as_deref(), name, "{error}");
    assert_eq!(error.field.as_deref(), Some(field), "{error}");
}

fn rule_toml(body: &str) -> String {
    format!("version = 1\n\n[[rule]]\nname = \"test rule\"\n{body}")
}

#[test]
fn parses_design_example() {
    let bytes = fixture_bytes("valid/design_example.toml");
    let policy = Policy::parse(&bytes).expect("design example parses");

    assert_eq!(policy.version, 1);
    assert_eq!(
        policy.sha256,
        Digest::from(<[u8; 32]>::from(Sha256::digest(&bytes)))
    );
    assert_eq!(policy.rules.len(), 3);

    let push = &policy.rules[0];
    assert_eq!(push.index, 0);
    assert_eq!(push.name, "agents may push to their own branches");
    assert_eq!(
        push.tool,
        ToolMatch::Exact(ToolName::try_from("git.push").expect("valid tool"))
    );
    assert_eq!(
        push.target_pattern.as_deref(),
        Some("github.com/acme/*:refs/heads/agent/**")
    );
    let push_target = push.target.as_ref().expect("target matcher");
    assert!(push_target.is_match("github.com/acme/api:refs/heads/agent/feature/x"));
    assert_eq!(
        push.params,
        BTreeMap::from([("force".to_string(), json!(false))])
    );
    assert_eq!(push.decision, DecisionKind::Allow);
    assert_eq!(
        push.budget,
        Some(Budget {
            max: 50,
            per_seconds: 3600,
        })
    );
    assert_eq!(push.approvers, 1);

    let main = &policy.rules[1];
    assert_eq!(main.index, 1);
    assert_eq!(main.name, "pushes to main need a human");
    assert_eq!(
        main.tool,
        ToolMatch::Exact(ToolName::try_from("git.push").expect("valid tool"))
    );
    assert_eq!(
        main.target_pattern.as_deref(),
        Some("github.com/acme/*:refs/heads/main")
    );
    let main_target = main.target.as_ref().expect("target matcher");
    assert!(main_target.is_match("github.com/acme/api:refs/heads/main"));
    assert!(!main_target.is_match("github.com/acme/api:refs/heads/agent/feature/x"));
    assert!(main.params.is_empty());
    assert_eq!(main.decision, DecisionKind::Ask);
    assert_eq!(main.budget, None);
    assert_eq!(main.approvers, 1);

    let read = &policy.rules[2];
    assert_eq!(read.index, 2);
    assert_eq!(read.name, "read-only MCP tools");
    assert_eq!(read.tool, ToolMatch::Prefix("mcp:github/get_".to_string()));
    assert!(read.target.is_none());
    assert!(read.target_pattern.is_none());
    assert!(read.params.is_empty());
    assert_eq!(read.decision, DecisionKind::Allow);
    assert_eq!(read.budget, None);
    assert_eq!(read.approvers, 1);
}

#[test]
fn invalid_fixtures_snapshot() {
    let dir = Path::new(FIXTURES).join("invalid");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("invalid fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect();
    paths.sort();

    let names: Vec<String> = paths
        .iter()
        .map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .expect("fixture name")
                .to_string()
        })
        .collect();
    assert_eq!(
        names,
        EXPECTED_INVALID_FIXTURES
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>()
    );

    for path in paths {
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("fixture name");
        let bytes = fs::read(&path).expect("fixture bytes");
        let error = Policy::parse(&bytes).expect_err("invalid fixture must be rejected");
        insta::assert_snapshot!(name, error.to_string());
    }
}

#[test]
fn sha256_is_of_exact_bytes() {
    let first = b"version = 1\n";
    let second = b"version = 1\n\n";
    let first_policy = Policy::parse(first).expect("first policy parses");
    let second_policy = Policy::parse(second).expect("second policy parses");

    assert_ne!(first_policy.sha256, second_policy.sha256);
    assert_eq!(
        first_policy.sha256,
        Digest::from(<[u8; 32]>::from(Sha256::digest(first)))
    );
    assert_eq!(
        second_policy.sha256,
        Digest::from(<[u8; 32]>::from(Sha256::digest(second)))
    );
}

#[test]
fn empty_rule_list_is_valid() {
    for input in ["version = 1\n", "version = 1\nrule = []\n"] {
        let policy = Policy::parse(input.as_bytes()).expect("empty policy parses");
        assert_eq!(policy.version, 1);
        assert!(policy.rules.is_empty());
    }
}

#[test]
fn parses_deny_and_prefix_fixture() {
    let policy = parse_fixture("valid/deny_and_prefix.toml");
    assert_eq!(policy.rules.len(), 2);

    let deny = &policy.rules[0];
    assert_eq!(deny.decision, DecisionKind::Deny);
    assert_eq!(
        deny.params,
        BTreeMap::from([("force".to_string(), json!(true))])
    );
    assert_eq!(deny.budget, None);
    assert_eq!(deny.approvers, 1);

    let prefix = &policy.rules[1];
    assert_eq!(prefix.tool, ToolMatch::Prefix("mcp:github/".to_string()));
    assert!(prefix.target.is_none());
    assert_eq!(
        prefix.budget,
        Some(Budget {
            max: 100,
            per_seconds: 2_592_000,
        })
    );
}

#[test]
fn error_display_names_rule_and_field() {
    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\ndecision = \"ask\"\nbudget = { max = 1, per = \"1s\" }\n",
    ));
    assert_eq!(
        error.to_string(),
        "rule 0 (\"test rule\"), field `budget`: budget is only allowed on allow rules"
    );
}

#[test]
fn rejects_unknown_top_level_keys() {
    let error = policy_error("version = 1\nmode = \"strict\"\n");
    assert_eq!(error.rule_index, None);
    assert_eq!(error.field.as_deref(), Some("mode"));
    assert_eq!(error.message, "unknown policy key");
}

#[test]
fn rejects_budget_outside_allow_rules() {
    for decision in ["ask", "deny"] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"{decision}\"\n\
             budget = {{ max = 1, per = \"1s\" }}\n"
        ));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "budget");
        assert_eq!(error.message, "budget is only allowed on allow rules");
    }
}

#[test]
fn rejects_approvers_outside_ask_rules() {
    for decision in ["allow", "deny"] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"{decision}\"\napprovers = 1\n"
        ));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "approvers");
        assert_eq!(error.message, "approvers is only allowed on ask rules");
    }
}

#[test]
fn rejects_approvers_other_than_one() {
    for approvers in ["0", "2", "true"] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"ask\"\napprovers = {approvers}\n"
        ));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "approvers");
        assert_eq!(error.message, "approvers must be 1 in v0.1");
    }
}

#[test]
fn rejects_budget_max_outside_u32() {
    for max in ["0", "-1", "4294967296"] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"allow\"\n\
             budget = {{ max = {max}, per = \"1s\" }}\n"
        ));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "budget.max");
        assert_eq!(error.message, "max must be between 1 and 4294967295");
    }
}

#[test]
fn parses_all_budget_units_and_boundaries() {
    for (per, seconds) in [
        ("1s", 1),
        ("30s", 30),
        ("15m", 900),
        ("1h", 3600),
        ("1d", 86_400),
        ("30d", 2_592_000),
    ] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"allow\"\n\
             budget = {{ max = 1, per = \"{per}\" }}\n"
        ));
        let policy = Policy::parse(input.as_bytes()).expect("budget should parse");
        assert_eq!(
            policy.rules[0].budget,
            Some(Budget {
                max: 1,
                per_seconds: seconds,
            })
        );
    }

    let input = rule_toml(&format!(
        "tool = \"git.push\"\ndecision = \"allow\"\n\
         budget = {{ max = {}, per = \"1s\" }}\n",
        u32::MAX
    ));
    let policy = Policy::parse(input.as_bytes()).expect("maximum budget parses");
    assert_eq!(
        policy.rules[0].budget,
        Some(Budget {
            max: u32::MAX,
            per_seconds: 1,
        })
    );
}

#[test]
fn star_does_not_cross_separator() {
    let child = Policy::parse(
        rule_toml("tool = \"git.push\"\ntarget = \"repo:release/*\"\ndecision = \"allow\"\n")
            .as_bytes(),
    )
    .expect("policy parses");
    let matcher = child.rules[0].target.as_ref().expect("target matcher");
    assert!(matcher.is_match("repo:release/v1"));
    assert!(!matcher.is_match("repo:release/a/b"));

    let recursive = Policy::parse(
        rule_toml("tool = \"git.push\"\ntarget = \"repo:release/**\"\ndecision = \"allow\"\n")
            .as_bytes(),
    )
    .expect("policy parses");
    let matcher = recursive.rules[0].target.as_ref().expect("target matcher");
    assert!(matcher.is_match("repo:release/v1"));
    assert!(matcher.is_match("repo:release/a/b"));
}

#[test]
fn rejects_budget_durations_outside_range() {
    for per in ["0s", "31d", "2592001s", "999999999999999999999d"] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"allow\"\n\
             budget = {{ max = 1, per = \"{per}\" }}\n"
        ));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "budget.per");
        assert_eq!(
            error.message,
            format!("budget duration \"{per}\" must be between 1s and 30d")
        );
    }
}

#[test]
fn rejects_invalid_budget_duration_syntax() {
    for per in ["", "s", "1w", "1.5h", "1H", "-1h", "1 h"] {
        let input = rule_toml(&format!(
            "tool = \"git.push\"\ndecision = \"allow\"\n\
             budget = {{ max = 1, per = \"{per}\" }}\n"
        ));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "budget.per");
        assert_eq!(
            error.message,
            format!("invalid budget duration \"{per}\": expected <n>s, <n>m, <n>h or <n>d")
        );
    }
}

#[test]
fn rejects_invalid_rule_names() {
    let error =
        policy_error("version = 1\n\n[[rule]]\ntool = \"git.push\"\ndecision = \"allow\"\n");
    assert_eq!(error.rule_index, Some(0));
    assert_eq!(error.rule_name, None);
    assert_eq!(error.field.as_deref(), Some("name"));
    assert_eq!(error.message, "name is required");

    for name in [String::new(), "a".repeat(129)] {
        let input = format!(
            "version = 1\n\n[[rule]]\nname = {name:?}\n\
             tool = \"git.push\"\ndecision = \"allow\"\n"
        );
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some(name.as_str()), "name");
        assert_eq!(error.message, "name must be between 1 and 128 characters");
    }

    let name = "a".repeat(128);
    let input = format!(
        "version = 1\n\n[[rule]]\nname = {name:?}\n\
         tool = \"git.push\"\ndecision = \"allow\"\n"
    );
    assert!(Policy::parse(input.as_bytes()).is_ok());
}

#[test]
fn rejects_control_characters_in_rule_names() {
    for (toml_name, name) in [
        ("\"line\\nbreak\"", "line\nbreak"),
        ("\"tab\\tname\"", "tab\tname"),
        ("\"bell\\u0007name\"", "bell\u{7}name"),
    ] {
        let input = format!(
            "version = 1\n\n[[rule]]\nname = {toml_name}\n\
             tool = \"git.push\"\ndecision = \"allow\"\n"
        );
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some(name), "name");
        assert_eq!(error.message, "name must not contain control characters");
    }

    let bidi_name = "right\u{202e}left";
    let input = "version = 1\n\n[[rule]]\nname = \"right\\u202Eleft\"\n\
                 tool = \"git.push\"\ndecision = \"allow\"\n";
    let policy = Policy::parse(input.as_bytes()).expect("U+202E is not a control character");
    assert_eq!(policy.rules[0].name, bidi_name);

    for name in ["   ", " leading", "trailing "] {
        let input = format!(
            "version = 1\n\n[[rule]]\nname = {name:?}\n\
             tool = \"git.push\"\ndecision = \"allow\"\n"
        );
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some(name), "name");
        assert_eq!(
            error.message,
            "name must not have leading or trailing whitespace"
        );
    }
}

#[test]
fn rejects_invalid_tool_names_and_prefixes() {
    let error = policy_error(&rule_toml("tool = \"git.*\"\ndecision = \"allow\"\n"));
    assert_rule_error(&error, 0, Some("test rule"), "tool");
    assert_eq!(error.message, "invalid tool name: git.*");

    let error = policy_error(&rule_toml(
        "tool_prefix = \"mcp:*/get_\"\ndecision = \"allow\"\n",
    ));
    assert_rule_error(&error, 0, Some("test rule"), "tool_prefix");
    assert_eq!(
        error.message,
        "tool prefix \"mcp:*/get_\" must follow the tool-name character rules and end in \"/\", \"_\", \".\" or \":\""
    );

    let long = "a".repeat(129);
    for prefix in [
        "",
        "/git",
        "git..push",
        // SEK-07: no segment boundary, so `mcp:github` would match `mcp:github-admin/x`.
        "a",
        "mcp:github",
        "mcp:github/get",
        "git.push",
        "a b",
        "Git",
        "git//",
        long.as_str(),
    ] {
        let input = rule_toml(&format!("tool_prefix = {prefix:?}\ndecision = \"allow\"\n"));
        let error = policy_error(&input);
        assert_rule_error(&error, 0, Some("test rule"), "tool_prefix");
    }

    for prefix in ["mcp:github/get_", "mcp:github/", "git.", "git:", "hook:"] {
        let input = rule_toml(&format!("tool_prefix = {prefix:?}\ndecision = \"allow\"\n"));
        let policy = Policy::parse(input.as_bytes()).expect("valid prefix");
        assert_eq!(policy.rules[0].tool, ToolMatch::Prefix(prefix.to_string()));
    }

    let error = policy_error(&rule_toml("tool = 1\ndecision = \"allow\"\n"));
    assert_eq!(error.message, "tool must be a string");
    let error = policy_error(&rule_toml("tool_prefix = 1\ndecision = \"allow\"\n"));
    assert_eq!(error.message, "tool_prefix must be a string");
}

#[test]
fn rejects_non_table_params_and_non_json_values() {
    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\nparams = \"force=false\"\ndecision = \"allow\"\n",
    ));
    assert_rule_error(&error, 0, Some("test rule"), "params");
    assert_eq!(error.message, "params must be a table");

    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\nparams = { at = 1979-05-27T07:32:00Z }\ndecision = \"allow\"\n",
    ));
    assert_eq!(
        error.message,
        "params value at /at is not representable in JSON"
    );

    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\nparams = { x = nan }\ndecision = \"allow\"\n",
    ));
    assert_eq!(error.message, "params float at /x is not finite");

    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\nparams = { nested = { amount = 9007199254740992 } }\ndecision = \"allow\"\n",
    ));
    assert_eq!(error.message, "unsafe integer at /nested/amount");

    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\nparams = { \"a/b~c\" = 9007199254740992 }\ndecision = \"allow\"\n",
    ));
    assert_eq!(error.message, "unsafe integer at /a~1b~0c");
}

#[test]
fn accepts_safe_integer_params() {
    let input = rule_toml(
        "tool = \"git.push\"\n\
         params = { n = 9007199254740991, negative = -9007199254740991, \
         nested = { values = [1, 2] } }\n\
         decision = \"allow\"\n",
    );
    let policy = Policy::parse(input.as_bytes()).expect("safe integers parse");
    let params = &policy.rules[0].params;
    assert_eq!(params.get("n"), Some(&json!(9_007_199_254_740_991_i64)));
    assert_eq!(
        params.get("negative"),
        Some(&json!(-9_007_199_254_740_991_i64))
    );
    assert_eq!(params.get("nested"), Some(&json!({"values": [1, 2]})));
}

#[test]
fn rejects_rule_entries_that_are_not_tables() {
    let error = policy_error("version = 1\nrule = [1]\n");
    assert_eq!(error.rule_index, Some(0));
    assert_eq!(error.rule_name, None);
    assert_eq!(error.field.as_deref(), Some("rule"));
    assert_eq!(error.message, "rule must be a table");

    let error = policy_error("version = 1\nrule = \"x\"\n");
    assert_eq!(error.rule_index, None);
    assert_eq!(error.field.as_deref(), Some("rule"));
    assert_eq!(error.message, "rule must be an array of tables");
}

#[test]
fn rejects_missing_decision() {
    let error = policy_error(&rule_toml("tool = \"git.push\"\n"));
    assert_rule_error(&error, 0, Some("test rule"), "decision");
    assert_eq!(error.message, "decision is required");
}

#[test]
fn rejects_unknown_budget_keys() {
    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\ndecision = \"allow\"\n\
         budget = { max = 1, per = \"1s\", window = \"day\" }\n",
    ));
    assert_rule_error(&error, 0, Some("test rule"), "budget.window");
    assert_eq!(error.message, "unknown budget key");
}

#[test]
fn rejects_bad_version_field() {
    for (input, message) in [
        ("rule = []\n", "version is required"),
        ("version = \"1\"\n", "version must be an integer"),
        ("version = 2\n", "unsupported policy version 2: expected 1"),
        (
            "version = -1\n",
            "unsupported policy version -1: expected 1",
        ),
    ] {
        let error = policy_error(input);
        assert_eq!(error.rule_index, None);
        assert_eq!(error.field.as_deref(), Some("version"));
        assert_eq!(error.message, message);
    }
}

#[test]
fn rejects_invalid_glob() {
    let error = policy_error(&rule_toml(
        "tool = \"git.push\"\ntarget = \"github.com/acme/[abc\"\ndecision = \"allow\"\n",
    ));
    assert_rule_error(&error, 0, Some("test rule"), "target");
    assert!(
        error
            .message
            .starts_with("invalid target glob \"github.com/acme/[abc\": "),
        "{error}"
    );
}

#[test]
fn rejects_non_utf8_bytes() {
    let error = Policy::parse(&[0xff, 0xfe]).expect_err("invalid UTF-8 is rejected");
    assert_eq!(error.rule_index, None);
    assert_eq!(error.field, None);
    assert!(error.message.starts_with("invalid TOML: "), "{error}");
}
