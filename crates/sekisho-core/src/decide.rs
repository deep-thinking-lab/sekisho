use crate::{Action, DecisionKind, Grant, GrantId, Policy, PublicKey, Rule, Timestamp, ToolMatch};

/// Server-supplied budget usage for the current window, keyed by rule name.
pub struct BudgetView<'a> {
    pub used: &'a dyn Fn(&str) -> u32,
}

/// A grant plus the server-owned state that determines whether it may allow an action.
#[derive(Clone, Copy)]
pub struct GrantView<'a> {
    pub grant: &'a Grant,
    pub uses: u32,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub kind: DecisionKind,
    pub rule: Option<String>,
    pub grant: Option<GrantId>,
    pub reason: String,
}

/// Decide one action using deny precedence, then grants, then ordered policy rules.
pub fn decide(
    action: &Action,
    policy: &Policy,
    grants: &[GrantView<'_>],
    grant_key: &PublicKey,
    budgets: &BudgetView<'_>,
    now: Timestamp,
) -> Decision {
    if let Some(rule) = policy
        .rules
        .iter()
        .find(|rule| rule.decision == DecisionKind::Deny && deny_matches(rule, action))
    {
        return deny(Some(rule.name.clone()), "deny rule");
    }

    let matching_grant = grants
        .iter()
        .filter(|view| {
            view.grant.matches(action)
                && view
                    .grant
                    .is_valid_at(grant_key, now, view.uses, view.revoked)
                    .is_ok()
        })
        .min_by(|left, right| left.grant.id().as_str().cmp(right.grant.id().as_str()))
        .map(|view| view.grant);
    if let Some(grant) = matching_grant {
        return Decision {
            kind: DecisionKind::Allow,
            rule: None,
            grant: Some(grant.id().clone()),
            reason: "grant".into(),
        };
    }

    let Some(rule) = policy.rules.iter().find(|rule| rule_matches(rule, action)) else {
        return deny(None, "no rule");
    };

    let rule_name = Some(rule.name.clone());
    match rule.decision {
        DecisionKind::Allow => {
            if rule
                .budget
                .as_ref()
                .is_some_and(|budget| (budgets.used)(&rule.name) >= budget.max)
            {
                deny(rule_name, "budget exhausted")
            } else {
                allow(rule_name, "allow rule")
            }
        }
        DecisionKind::Ask => Decision {
            kind: DecisionKind::Ask,
            rule: rule_name,
            grant: None,
            reason: "approval required".into(),
        },
        DecisionKind::Deny => deny(rule_name, "deny rule"),
    }
}

/// Deny rules also match the forms a target had before hook targets gained a
/// `cwd:` prefix for Bash and a trailing `/` for directories, so a deny rule
/// written for a path keeps covering those actions. Allow and ask rules match
/// only the exact target.
/// They also match with the macOS data volume root rewritten to `/`, so
/// `/System/Volumes/Data/Users/u/x` meets a rule written for `/Users/u/x`.
fn deny_matches(rule: &Rule, action: &Action) -> bool {
    let target = action.target();
    let bare = target.strip_prefix("cwd:").unwrap_or(target);
    let unaliased = crate::without_data_volume(bare);
    let unaliased = unaliased.as_deref().unwrap_or(bare);
    [
        target,
        bare,
        bare.trim_end_matches('/'),
        unaliased,
        unaliased.trim_end_matches('/'),
    ]
    .into_iter()
    .filter(|candidate| !candidate.is_empty())
    .any(|candidate| matches_target(rule, action, candidate))
}

fn rule_matches(rule: &Rule, action: &Action) -> bool {
    matches_target(rule, action, action.target())
}

fn matches_target(rule: &Rule, action: &Action, target: &str) -> bool {
    let tool_matches = match &rule.tool {
        ToolMatch::Exact(tool) => tool == action.tool(),
        ToolMatch::Prefix(prefix) => action.tool().as_str().starts_with(prefix),
    };
    tool_matches
        && rule
            .target
            .as_ref()
            .is_none_or(|glob| glob.is_match(target))
        && rule
            .params
            .iter()
            .all(|(key, value)| action.params().get(key) == Some(value))
}

fn allow(rule: Option<String>, reason: &str) -> Decision {
    Decision {
        kind: DecisionKind::Allow,
        rule,
        grant: None,
        reason: reason.into(),
    }
}

fn deny(rule: Option<String>, reason: &str) -> Decision {
    Decision {
        kind: DecisionKind::Deny,
        rule,
        grant: None,
        reason: reason.into(),
    }
}
