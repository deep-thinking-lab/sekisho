#![allow(clippy::expect_used, clippy::unwrap_used)]

use proptest::prelude::*;
use sekisho_core::{
    Action, AgentId, BudgetView, DecisionKind, Ed25519Signer, Grant, GrantId, GrantView, Policy,
    Signer, Timestamp, ToolName, UnsignedGrant, UserId, decide,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const GRANT_ID_1: &str = "grt_00000000000000000000000000";
const GRANT_ID_2: &str = "grt_11111111111111111111111111";
const GRANT_ID_3: &str = "grt_22222222222222222222222222";

fn action(tool: &str, target: &str, params: Value) -> Action {
    action_for("claude", tool, target, params)
}

fn action_for(agent: &str, tool: &str, target: &str, params: Value) -> Action {
    Action::new(
        AgentId::try_from(agent).unwrap(),
        ToolName::try_from(tool).unwrap(),
        target.into(),
        params,
    )
    .unwrap()
}

fn policy(input: &str) -> Policy {
    Policy::parse(input.as_bytes()).unwrap()
}

fn no_budget() -> BudgetView<'static> {
    BudgetView { used: &|_| 0 }
}

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes("grant", &[7; 32])
}

fn matching_grant(id: &str, signer: &Ed25519Signer) -> Grant {
    UnsignedGrant {
        id: GrantId::try_from(id).unwrap(),
        agent_id: AgentId::try_from("claude").unwrap(),
        tool: ToolName::try_from("git.push").unwrap(),
        target_glob: "repo:refs/heads/*".into(),
        params: BTreeMap::new(),
        not_before: 100.into(),
        expires_at: 200.into(),
        max_uses: Some(3),
        issued_by: UserId::try_from("admin").unwrap(),
    }
    .sign(signer)
    .unwrap()
}

fn unsigned_grant(id: &str) -> UnsignedGrant {
    UnsignedGrant {
        id: GrantId::try_from(id).unwrap(),
        agent_id: AgentId::try_from("claude").unwrap(),
        tool: ToolName::try_from("git.push").unwrap(),
        target_glob: "repo:refs/heads/*".into(),
        params: BTreeMap::new(),
        not_before: 100.into(),
        expires_at: 200.into(),
        max_uses: Some(3),
        issued_by: UserId::try_from("admin").unwrap(),
    }
}

fn decision(policy: &Policy, grants: &[GrantView], budgets: &BudgetView) -> sekisho_core::Decision {
    decide(
        &action("git.push", "repo:refs/heads/main", json!({"force": false})),
        policy,
        grants,
        &signer().public_key(),
        budgets,
        Timestamp::from(150),
    )
}

proptest! {
    #[test]
    fn no_rule_and_no_grant_always_denies(
        tool in prop::sample::select(&["git.push", "git.fetch", "mcp:github/get_issue"]),
        target in "[a-z0-9./:_-]{1,64}",
        force in any::<bool>(),
    ) {
        let policy = policy("version = 1\n");
        let result = decide(
            &action(tool, &target, json!({"force": force})),
            &policy,
            &[],
            &signer().public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        prop_assert_eq!(result.kind, DecisionKind::Deny);
        prop_assert!(result.rule.is_none());
        prop_assert!(result.grant.is_none());
        prop_assert_eq!(result.reason, "no rule");
    }

    #[test]
    fn any_matching_deny_rule_beats_a_matching_grant(rule_case in 0usize..3) {
        let (rule, action_params) = match rule_case {
            0 => (
                "tool = \"git.push\"\n".to_string(),
                json!({"force": false}),
            ),
            1 => (
                "tool_prefix = \"git.\"\n".to_string(),
                json!({"force": false}),
            ),
            _ => (
                "tool = \"git.push\"\ntarget = \"repo:refs/heads/**\"\nparams = { force = true }\n"
                    .to_string(),
                json!({"force": true}),
            ),
        };
        let policy = policy(&format!(
            "version = 1\n\n[[rule]]\nname = \"deny\"\n{rule}decision = \"deny\"\n"
        ));
        let grant = matching_grant(GRANT_ID_1, &signer());
        let grants = [GrantView {
            grant: &grant,
            uses: 0,
            revoked: false,
        }];
        let result = decide(
            &action("git.push", "repo:refs/heads/main", action_params),
            &policy,
            &grants,
            &signer().public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        prop_assert_eq!(result.kind, DecisionKind::Deny);
        prop_assert_eq!(result.rule.as_deref(), Some("deny"));
        prop_assert!(result.grant.is_none());
    }

    #[test]
    fn decision_does_not_depend_on_grant_order(rotation in 0usize..3) {
        let first = matching_grant(GRANT_ID_1, &signer());
        let second = matching_grant(GRANT_ID_2, &signer());
        let third = matching_grant(GRANT_ID_3, &signer());
        let all_grants = [first, second, third];
        let mut one_order = all_grants
            .iter()
            .map(|grant| GrantView {
                grant,
                uses: 0,
                revoked: false,
            })
            .collect::<Vec<_>>();
        let grant_count = one_order.len();
        one_order.rotate_left(rotation % grant_count);
        let mut other_order = one_order.clone();
        other_order.reverse();

        let empty = policy("version = 1\n");
        let first_decision = decision(&empty, &one_order, &no_budget());
        let second_decision = decision(&empty, &other_order, &no_budget());
        prop_assert_eq!(&first_decision, &second_decision);
        prop_assert_eq!(first_decision.kind, DecisionKind::Allow);
        prop_assert_eq!(
            first_decision.grant.as_ref().map(GrantId::as_str),
            Some(GRANT_ID_1)
        );
    }

    #[test]
    fn exhausted_budget_denies(
        max in 1u32..100,
        extra in 0u32..100,
    ) {
        let policy = policy(&format!(
            "version = 1\n\n[[rule]]\nname = \"limited\"\n\
             tool = \"git.push\"\ndecision = \"allow\"\n\
             budget = {{ max = {max}, per = \"1h\" }}\n"
        ));
        let used = max.saturating_add(extra);
        let budgets = BudgetView { used: &|_| used };
        let result = decision(&policy, &[], &budgets);
        prop_assert_eq!(result.kind, DecisionKind::Deny);
        prop_assert_eq!(result.rule.as_deref(), Some("limited"));
        prop_assert_eq!(result.reason, "budget exhausted");
    }

    #[test]
    fn expired_revoked_or_tampered_grants_never_allow(grant_case in 0usize..6) {
        let trusted = signer();
        let valid = matching_grant(GRANT_ID_1, &trusted);
        let mut expired_input = unsigned_grant(GRANT_ID_2);
        expired_input.expires_at = 150.into();
        let expired = expired_input.sign(&trusted).unwrap();
        let tampered = |field: &str, value: Value| {
            let mut encoded = serde_json::to_value(&valid).unwrap();
            encoded[field] = value;
            serde_json::from_value::<Grant>(encoded).unwrap()
        };
        let broadened = tampered("target_glob", json!("**"));
        let extended = tampered("expires_at", json!(250));
        let unlimited = tampered("max_uses", Value::Null);
        let wrong_key = Ed25519Signer::from_secret_bytes("grant", &[9; 32]);
        let foreign = matching_grant(GRANT_ID_1, &wrong_key);
        let (grant, revoked, matches_by_scope) = match grant_case {
            0 => (&expired, false, false),
            1 => (&valid, true, false),
            2 => (&broadened, false, true),
            3 => (&extended, false, true),
            4 => (&unlimited, false, true),
            _ => (&foreign, false, true),
        };
        let action = action("git.push", "repo:refs/heads/main", json!({}));
        if matches_by_scope {
            prop_assert!(grant.matches(&action));
        }
        let grants = [GrantView {
            grant,
            uses: 0,
            revoked,
        }];
        let result = decide(
            &action,
            &policy("version = 1\n"),
            &grants,
            &trusted.public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        prop_assert_eq!(result.kind, DecisionKind::Deny);
        prop_assert_eq!(result.reason, "no rule");
    }
}

#[test]
fn invalid_grants_do_not_supply_a_rule() {
    let trusted = signer();
    let wrong_key = Ed25519Signer::from_secret_bytes("grant", &[9; 32]);
    let cases = [
        (
            "not yet valid",
            {
                let mut grant = unsigned_grant(GRANT_ID_1);
                grant.not_before = 151.into();
                grant.sign(&trusted).unwrap()
            },
            action("git.push", "repo:refs/heads/main", json!({})),
            0,
            150,
            &trusted,
        ),
        (
            "expires at now",
            {
                let mut grant = unsigned_grant(GRANT_ID_1);
                grant.expires_at = 150.into();
                grant.sign(&trusted).unwrap()
            },
            action("git.push", "repo:refs/heads/main", json!({})),
            0,
            150,
            &trusted,
        ),
        (
            "uses exhausted",
            unsigned_grant(GRANT_ID_1).sign(&trusted).unwrap(),
            action("git.push", "repo:refs/heads/main", json!({})),
            3,
            150,
            &trusted,
        ),
        (
            "wrong agent",
            unsigned_grant(GRANT_ID_1).sign(&trusted).unwrap(),
            action_for("other-agent", "git.push", "repo:refs/heads/main", json!({})),
            0,
            150,
            &trusted,
        ),
        (
            "wrong tool",
            unsigned_grant(GRANT_ID_1).sign(&trusted).unwrap(),
            action("git.push.x", "repo:refs/heads/main", json!({})),
            0,
            150,
            &trusted,
        ),
        (
            "target outside glob",
            unsigned_grant(GRANT_ID_1).sign(&trusted).unwrap(),
            action("git.push", "repo:refs/heads/a/b", json!({})),
            0,
            150,
            &trusted,
        ),
        (
            "params mismatch",
            {
                let mut grant = unsigned_grant(GRANT_ID_1);
                grant.params = BTreeMap::from([("force".into(), json!(false))]);
                grant.sign(&trusted).unwrap()
            },
            action("git.push", "repo:refs/heads/main", json!({"force": true})),
            0,
            150,
            &trusted,
        ),
        (
            "wrong signing key",
            unsigned_grant(GRANT_ID_1).sign(&wrong_key).unwrap(),
            action("git.push", "repo:refs/heads/main", json!({})),
            0,
            150,
            &trusted,
        ),
    ];

    let empty = policy("version = 1\n");
    for (name, grant, action, uses, now, trusted_key) in cases {
        let grants = [GrantView {
            grant: &grant,
            uses,
            revoked: false,
        }];
        let result = decide(
            &action,
            &empty,
            &grants,
            &trusted_key.public_key(),
            &no_budget(),
            Timestamp::from(now),
        );
        assert_eq!(result.kind, DecisionKind::Deny, "{name}");
        assert_eq!(result.reason, "no rule", "{name}");
        assert!(result.rule.is_none(), "{name}");
        assert!(result.grant.is_none(), "{name}");
    }
}

#[test]
fn budget_boundaries_are_exact() {
    let policy = policy(
        "version = 1\n\n[[rule]]\nname = \"limited\"\n\
         tool = \"git.push\"\ndecision = \"allow\"\n\
         budget = { max = 3, per = \"1h\" }\n",
    );
    for (used, kind, reason) in [
        (2, DecisionKind::Allow, "allow rule"),
        (3, DecisionKind::Deny, "budget exhausted"),
    ] {
        let budgets = BudgetView { used: &|_| used };
        let result = decision(&policy, &[], &budgets);
        assert_eq!(result.kind, kind, "used {used}");
        assert_eq!(result.rule.as_deref(), Some("limited"), "used {used}");
        assert_eq!(result.reason, reason, "used {used}");
    }

    let mut zero_budget = policy;
    zero_budget.rules[0].budget.as_mut().unwrap().max = 0;
    let result = decision(&zero_budget, &[], &no_budget());
    assert_eq!(result.kind, DecisionKind::Deny);
    assert_eq!(result.rule.as_deref(), Some("limited"));
    assert_eq!(result.reason, "budget exhausted");
}

#[test]
fn decision_uses_path_aware_globs() {
    let rule_policy = policy(
        "version = 1\n\n[[rule]]\nname = \"release child\"\n\
         tool = \"git.push\"\ntarget = \"repo:release/*\"\n\
         decision = \"allow\"\n",
    );
    for (target, expected) in [
        ("repo:release/v1", DecisionKind::Allow),
        ("repo:release/a/b", DecisionKind::Deny),
    ] {
        let result = decide(
            &action("git.push", target, json!({})),
            &rule_policy,
            &[],
            &signer().public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        assert_eq!(result.kind, expected, "{target}");
    }

    let trusted = signer();
    let mut grant = unsigned_grant(GRANT_ID_1);
    grant.target_glob = "repo:release/*".into();
    let grant = grant.sign(&trusted).unwrap();
    let grants = [GrantView {
        grant: &grant,
        uses: 0,
        revoked: false,
    }];
    let empty = policy("version = 1\n");
    for (target, expected) in [
        ("repo:release/v1", DecisionKind::Allow),
        ("repo:release/a/b", DecisionKind::Deny),
    ] {
        let result = decide(
            &action("git.push", target, json!({})),
            &empty,
            &grants,
            &trusted.public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        assert_eq!(result.kind, expected, "{target}");
    }
}

#[test]
fn valid_matching_grant_allows() {
    let trusted = signer();
    let valid = matching_grant(GRANT_ID_1, &trusted);
    let valid_view = [GrantView {
        grant: &valid,
        uses: 0,
        revoked: false,
    }];
    let result = decide(
        &action("git.push", "repo:refs/heads/main", json!({})),
        &policy("version = 1\n"),
        &valid_view,
        &trusted.public_key(),
        &no_budget(),
        Timestamp::from(150),
    );
    assert_eq!(result.kind, DecisionKind::Allow);
    assert_eq!(result.grant.as_ref().map(GrantId::as_str), Some(GRANT_ID_1));
}

#[test]
fn exact_tool_and_tool_prefix_are_distinct() {
    let policy = policy(
        "version = 1\n\n[[rule]]\nname = \"push\"\n\
         tool = \"git.push\"\ndecision = \"allow\"\n\n\
         [[rule]]\nname = \"github reads\"\n\
         tool_prefix = \"mcp:github/get_\"\ndecision = \"allow\"\n",
    );
    let exact = decide(
        &action("git.push", "repo:refs/heads/main", json!({})),
        &policy,
        &[],
        &signer().public_key(),
        &no_budget(),
        Timestamp::from(150),
    );
    assert_eq!(exact.kind, DecisionKind::Allow);
    assert_eq!(exact.rule.as_deref(), Some("push"));

    let prefix = decide(
        &action("mcp:github/get_issue", "github", json!({})),
        &policy,
        &[],
        &signer().public_key(),
        &no_budget(),
        Timestamp::from(150),
    );
    assert_eq!(prefix.kind, DecisionKind::Allow);
    assert_eq!(prefix.rule.as_deref(), Some("github reads"));

    let longer_exact = decide(
        &action("git.push.extra", "repo:refs/heads/main", json!({})),
        &policy,
        &[],
        &signer().public_key(),
        &no_budget(),
        Timestamp::from(150),
    );
    assert_eq!(longer_exact.kind, DecisionKind::Deny);
    assert_eq!(longer_exact.reason, "no rule");
}

#[test]
fn target_globs_and_absent_targets_match_the_full_target() {
    let policy = policy(
        "version = 1\n\n[[rule]]\nname = \"agent branches\"\n\
         tool = \"git.push\"\n\
         target = \"github.com/acme/*:refs/heads/agent/**\"\n\
         decision = \"allow\"\n\n\
         [[rule]]\nname = \"any target\"\n\
         tool = \"git.fetch\"\ndecision = \"allow\"\n",
    );
    for (tool, target, expected) in [
        (
            "git.push",
            "github.com/acme/api:refs/heads/agent/fix",
            Some("agent branches"),
        ),
        ("git.push", "github.com/acme/api:refs/heads/main", None),
        ("git.fetch", "anything", Some("any target")),
    ] {
        let result = decide(
            &action(tool, target, json!({})),
            &policy,
            &[],
            &signer().public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        assert_eq!(result.rule.as_deref(), expected, "{tool} {target}");
        assert_eq!(
            result.kind,
            if expected.is_some() {
                DecisionKind::Allow
            } else {
                DecisionKind::Deny
            }
        );
    }
}

#[test]
fn every_constrained_param_must_match_exactly() {
    let policy = policy(
        "version = 1\n\n[[rule]]\nname = \"non-force push\"\n\
         tool = \"git.push\"\nparams = { force = false, ref = \"main\" }\n\
         decision = \"allow\"\n",
    );
    for params in [
        json!({"force": false, "ref": "main"}),
        json!({"force": false, "ref": "main", "extra": true}),
    ] {
        let result = decide(
            &action("git.push", "repo:main", params),
            &policy,
            &[],
            &signer().public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        assert_eq!(result.kind, DecisionKind::Allow);
    }
    for params in [
        json!({"force": false}),
        json!({"ref": "main"}),
        json!({"force": true, "ref": "main"}),
        json!({"force": false, "ref": null}),
    ] {
        let result = decide(
            &action("git.push", "repo:main", params),
            &policy,
            &[],
            &signer().public_key(),
            &no_budget(),
            Timestamp::from(150),
        );
        assert_eq!(result.kind, DecisionKind::Deny);
        assert_eq!(result.reason, "no rule");
    }
}

#[test]
fn first_matching_rule_wins_after_deny_scan() {
    let policy = policy(
        "version = 1\n\n[[rule]]\nname = \"first allow\"\n\
         tool = \"git.push\"\ndecision = \"allow\"\n\n\
         [[rule]]\nname = \"later ask\"\n\
         tool = \"git.push\"\ndecision = \"ask\"\n",
    );
    let result = decision(&policy, &[], &no_budget());
    assert_eq!(result.kind, DecisionKind::Allow);
    assert_eq!(result.rule.as_deref(), Some("first allow"));
}

/// SEK-02: the built-in state directory rule beats allow rules and grants.
#[test]
fn protected_dir_denies_hook_actions_whatever_the_policy_or_grants() {
    let mut policy = policy(
        "version = 1\n[[rule]]\nname = 'everything'\ntool_prefix = 'hook:claude-code/'\ndecision = 'allow'\n",
    );
    let digest = policy.sha256;
    policy.protect_dir("/home/u/.sekisho/").unwrap();
    assert_eq!(policy.sha256, digest);
    let signer = signer();
    let grant = UnsignedGrant {
        id: GrantId::try_from(GRANT_ID_1).unwrap(),
        agent_id: AgentId::try_from("claude").unwrap(),
        tool: ToolName::try_from("hook:claude-code/read").unwrap(),
        target_glob: "**".into(),
        params: BTreeMap::new(),
        not_before: 100.into(),
        expires_at: 200.into(),
        max_uses: None,
        issued_by: UserId::try_from("admin").unwrap(),
    }
    .sign(&signer)
    .unwrap();
    let grants = [GrantView {
        grant: &grant,
        uses: 0,
        revoked: false,
    }];
    let check = |target: &str| {
        decide(
            &action("hook:claude-code/read", target, json!({})),
            &policy,
            &grants,
            &signer.public_key(),
            &no_budget(),
            150.into(),
        )
    };
    for target in [
        "/home/u/.sekisho",
        "/home/u/.sekisho/admin.token",
        "/home/u/.sekisho/upstreams/github.secret",
        "/home/u/.sekisho/",
        "cwd:/home/u/.sekisho/",
        "cwd:/home/u/.sekisho/keys/",
    ] {
        let decision = check(target);
        assert_eq!(decision.kind, DecisionKind::Deny, "{target}");
        assert_eq!(
            decision.rule.as_deref(),
            Some(sekisho_core::PROTECTED_DIR_RULE)
        );
    }
    for target in ["/home/u/.sekisho-other/x", "/home/u/project/file"] {
        assert_eq!(check(target).kind, DecisionKind::Allow, "{target}");
    }
    let git = decide(
        &action("git.push", "/home/u/.sekisho/x", json!({})),
        &policy,
        &[],
        &signer.public_key(),
        &no_budget(),
        150.into(),
    );
    assert_eq!(git.rule, None, "only hook actions are covered");
    // Searching any directory that contains the home is denied too.
    for target in ["/home/u/", "/home/", "/", "cwd:/home/u/"] {
        assert_eq!(check(target).kind, DecisionKind::Deny, "{target}");
    }
    assert_eq!(check("/home/u/project/").kind, DecisionKind::Allow);
    assert!(policy.protect_dir("relative/home").is_err());
}

/// SEK-03 migration: deny rules written for paths keep covering Bash
/// (`cwd:<dir>/`) and directory searches (`<dir>/`); allow rules do not widen.
#[test]
fn deny_rules_match_legacy_target_forms_but_allow_rules_do_not() {
    let policy = policy(concat!(
        "version = 1\n",
        "[[rule]]\nname = 'no secrets'\ntool_prefix = 'hook:claude-code/'\ntarget = '/secret/**'\ndecision = 'deny'\n",
        "[[rule]]\nname = 'no exact'\ntool_prefix = 'hook:claude-code/'\ntarget = '/exact'\ndecision = 'deny'\n",
        "[[rule]]\nname = 'project'\ntool_prefix = 'hook:claude-code/'\ntarget = '/project/**'\ndecision = 'allow'\n",
    ));
    let signer = signer();
    let kind = |tool: &str, target: &str| {
        decide(
            &action(tool, target, json!({})),
            &policy,
            &[],
            &signer.public_key(),
            &no_budget(),
            150.into(),
        )
        .kind
    };
    assert_eq!(
        kind("hook:claude-code/bash", "cwd:/secret/x/"),
        DecisionKind::Deny
    );
    assert_eq!(kind("hook:claude-code/grep", "/exact/"), DecisionKind::Deny);
    assert_eq!(
        kind("hook:claude-code/bash", "cwd:/exact/"),
        DecisionKind::Deny
    );
    assert_eq!(
        kind("hook:claude-code/read", "/project/a"),
        DecisionKind::Allow
    );
    assert_eq!(
        kind("hook:claude-code/bash", "cwd:/project/"),
        DecisionKind::Deny
    );
}

/// SEK-07: a prefix rule for one MCP server does not cover a server whose name
/// merely starts the same way.
#[test]
fn tool_prefix_stops_at_a_segment_boundary() {
    let policy = policy(
        "version = 1\n[[rule]]\nname = 'github'\ntool_prefix = 'mcp:github/'\ndecision = 'allow'\n",
    );
    let signer = signer();
    let kind = |tool: &str| {
        decide(
            &action(tool, "github", json!({})),
            &policy,
            &[],
            &signer.public_key(),
            &no_budget(),
            150.into(),
        )
        .kind
    };
    assert_eq!(kind("mcp:github/create_issue"), DecisionKind::Allow);
    assert_eq!(kind("mcp:github-admin/delete_repo"), DecisionKind::Deny);
    assert!(
        Policy::parse(
            b"version = 1\n[[rule]]\nname = 'x'\ntool_prefix = 'mcp:github'\ndecision = 'allow'\n"
        )
        .is_err()
    );
}

/// NEW-1: macOS aliases of a protected or denied path are denied too.
#[test]
fn macos_path_aliases_do_not_escape_deny_rules() {
    let mut policy = policy(concat!(
        "version = 1\n",
        "[[rule]]\nname = 'ssh'\ntool_prefix = 'hook:claude-code/'\ntarget = '/Users/u/.ssh/**'\ndecision = 'deny'\n",
        "[[rule]]\nname = 'all'\ntool_prefix = 'hook:claude-code/'\ndecision = 'allow'\n",
    ));
    policy.protect_dir("/Users/u/.sekisho").unwrap();
    let signer = signer();
    let kind = |target: &str| {
        decide(
            &action("hook:claude-code/read", target, json!({})),
            &policy,
            &[],
            &signer.public_key(),
            &no_budget(),
            150.into(),
        )
        .kind
    };
    for target in [
        "/System/Volumes/Data/Users/u/.sekisho/admin.token",
        "/system/volumes/data/Users/u/.sekisho/admin.token",
        "/System/Volumes/Data/Users/u/",
        "/System/Volumes/Data/Users/u/.ssh/id_ed25519",
        "/.nofollow/Users/u/.sekisho/admin.token",
        "/.resolve/1/2",
        "/.vol/16777220/383091",
        "/.NOFOLLOW/etc/passwd",
    ] {
        assert_eq!(kind(target), DecisionKind::Deny, "{target}");
    }
    // Directories that contain the home through the firmlink.
    for target in [
        "/System/Volumes/Data/",
        "/System/Volumes/",
        "/System/",
        "/System/Volumes/Data/Users/",
        "/system/volumes/",
        "cwd:/System/Volumes/",
    ] {
        assert_eq!(kind(target), DecisionKind::Deny, "{target}");
    }
    assert_eq!(kind("/Users/u/project/file"), DecisionKind::Allow);
    assert_eq!(
        kind("/System/Volumes/Data/Users/u/project/file"),
        DecisionKind::Allow
    );
    assert_eq!(
        sekisho_core::protected_ancestors("/System/Volumes/Data/Users/u/.sekisho"),
        sekisho_core::protected_ancestors("/Users/u/.sekisho")
    );
    let ancestors = sekisho_core::protected_ancestors("/Users/u/.sekisho");
    for expected in [
        "/Users/u",
        "/Users",
        "/",
        "/System/Volumes/Data/Users/u",
        "/System/Volumes/Data",
        "/System/Volumes",
        "/System",
    ] {
        assert!(
            ancestors.iter().any(|a| a == expected),
            "{expected}: {ancestors:?}"
        );
    }
}
