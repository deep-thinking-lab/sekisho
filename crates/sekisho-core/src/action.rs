use crate::{AgentId, CoreError, Digest, ToolName};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// An agent's proposed tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Action {
    agent_id: AgentId,
    tool: ToolName,
    target: String,
    params: Value,
}

impl Action {
    /// Construct an action with a valid target, object params, and JCS-safe integers.
    pub fn new(
        agent_id: AgentId,
        tool: ToolName,
        target: String,
        params: Value,
    ) -> Result<Self, CoreError> {
        if !(1..=1024).contains(&target.len()) || target.chars().any(char::is_control) {
            return Err(CoreError::InvalidTarget(target));
        }
        if !params.is_object() {
            return Err(CoreError::ParamsNotObject);
        }
        validate_numbers(&params, "", true)?;
        Ok(Self {
            agent_id,
            tool,
            target,
            params,
        })
    }

    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub fn tool(&self) -> &ToolName {
        &self.tool
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn params(&self) -> &Value {
        &self.params
    }

    /// Hash the versioned RFC 8785 canonical representation.
    ///
    /// Returns a canonicalization error if the serializer rejects the value.
    pub fn digest(&self) -> Result<Digest, CoreError> {
        let value = json!({
            "v": 1,
            "agent_id": self.agent_id.as_str(),
            "tool": self.tool.as_str(),
            "target": self.target,
            "params": self.params,
        });
        let bytes = serde_jcs::to_vec(&value)
            .map_err(|error| CoreError::Canonicalization(error.to_string()))?;
        Ok(Digest::from(<[u8; 32]>::from(Sha256::digest(bytes))))
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct RawAction {
            agent_id: AgentId,
            tool: ToolName,
            target: String,
            params: Value,
        }

        let raw = RawAction::deserialize(deserializer)?;
        Self::new(raw.agent_id, raw.tool, raw.target, raw.params).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn validate_integers(value: &Value, path: &str) -> Result<(), CoreError> {
    validate_numbers(value, path, false)
}

/// `exact` also refuses numbers whose JCS form an integer could share; action
/// params need it because their digest binds approvals.
fn validate_numbers(value: &Value, path: &str, exact: bool) -> Result<(), CoreError> {
    const MAX_SAFE_INTEGER: i64 = 9007199254740991;
    match value {
        Value::Number(number)
            if number
                .as_i64()
                .is_some_and(|n| !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n))
                || number.as_u64().is_some_and(|n| n > MAX_SAFE_INTEGER as u64) =>
        {
            return Err(CoreError::UnsafeInteger(path.to_owned()));
        }
        // JCS writes 1.0 as 1 and -0.0 as 0, so these would share a digest with
        // an integer (or zero) and an approval for one would authorize the other.
        Value::Number(number)
            if exact
                && number.as_f64().is_some_and(|n| {
                    number.is_f64()
                        && (n.to_bits() == (-0.0f64).to_bits()
                            || (n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER as f64))
                }) =>
        {
            return Err(CoreError::AmbiguousNumber(path.to_owned()));
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_numbers(value, &format!("{path}/{index}"), exact)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                let escaped = json_pointer_segment(key);
                validate_numbers(value, &format!("{path}/{escaped}"), exact)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn json_pointer_segment(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn action(params: serde_json::Value) -> Action {
        Action::new(
            crate::AgentId::try_from("claude").unwrap(),
            crate::ToolName::try_from("git.push").unwrap(),
            "github.com/acme/api:refs/heads/main".into(),
            params,
        )
        .unwrap()
    }

    #[test]
    fn rejects_integers_beyond_safe_range() {
        for (params, path) in [
            (json!({"n": 9007199254740992_i64}), "/n"),
            (json!({"n": -9007199254740992_i64}), "/n"),
            (json!({"a": [1, {"b": u64::MAX}]}), "/a/1/b"),
            (json!({"amounts": [i64::MIN]}), "/amounts/0"),
            (json!({"a/b~c": {"": 9007199254740992_u64}}), "/a~1b~0c/"),
        ] {
            let result = Action::new(
                AgentId::try_from("claude").unwrap(),
                ToolName::try_from("git.push").unwrap(),
                "target".into(),
                params,
            );
            assert_eq!(result, Err(CoreError::UnsafeInteger(path.into())));
        }
        for params in [
            json!({"n": 9007199254740991_i64}),
            json!({"n": -9007199254740991_i64}),
            json!({"x": 1.5}),
            json!({"x": 1e30}),
            json!({"nested": [{"values": [0, null, false, "large integer"]}]}),
        ] {
            assert_eq!(action(params.clone()).params(), &params);
        }
    }

    #[test]
    fn deserialize_validates() {
        let valid = json!({
            "agent_id": "claude", "tool": "git.push", "target": "target", "params": {}
        });
        for (field, invalid) in [
            ("params", json!([])),
            ("params", json!({"a": [9007199254740992_u64]})),
            ("target", json!("")),
            ("target", json!("a\nb")),
            ("target", json!("a".repeat(1025))),
            ("agent_id", json!("Claude")),
            ("tool", json!("git.*")),
        ] {
            let mut input = valid.clone();
            input[field] = invalid;
            assert!(serde_json::from_value::<Action>(input).is_err(), "{field}");
        }
        let original = action(json!({"a": [9007199254740991_i64, 1.5]}));
        let encoded = serde_json::to_value(&original).unwrap();
        let decoded: Action = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.agent_id().as_str(), "claude");
        assert_eq!(decoded.tool().as_str(), "git.push");
        assert_eq!(decoded.target(), "github.com/acme/api:refs/heads/main");
        assert_eq!(decoded.params(), original.params());
        assert_eq!(decoded, original);
        assert_eq!(decoded.digest().unwrap(), original.digest().unwrap());
    }

    #[test]
    fn params_must_be_object() {
        for params in [
            json!([]),
            json!("string"),
            json!(null),
            json!(1),
            json!(false),
        ] {
            assert!(matches!(
                Action::new(
                    crate::AgentId::try_from("claude").unwrap(),
                    crate::ToolName::try_from("git.push").unwrap(),
                    "target".into(),
                    params
                ),
                Err(crate::CoreError::ParamsNotObject)
            ));
        }
        assert_eq!(action(json!({})).params(), &json!({}));
    }

    #[test]
    fn target_is_validated() {
        for target in [
            "".into(),
            "a".repeat(1025),
            "a\nb".into(),
            "a\u{7f}b".into(),
            "a\u{85}b".into(),
            "é".repeat(513),
        ] {
            assert!(matches!(
                Action::new(
                    crate::AgentId::try_from("claude").unwrap(),
                    crate::ToolName::try_from("git.push").unwrap(),
                    target,
                    json!({})
                ),
                Err(crate::CoreError::InvalidTarget(_))
            ));
        }
        for target in ["a".into(), "é".repeat(512)] {
            assert!(
                Action::new(
                    crate::AgentId::try_from("claude").unwrap(),
                    crate::ToolName::try_from("git.push").unwrap(),
                    target,
                    json!({})
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn digest_is_key_order_independent() {
        let mut first = serde_json::Map::new();
        first.insert("b".into(), json!({"z": 1, "a": 2}));
        first.insert("a".into(), json!(false));
        let mut second = serde_json::Map::new();
        second.insert("a".into(), json!(false));
        second.insert("b".into(), json!({"a": 2, "z": 1}));
        assert_eq!(
            action(first.into()).digest().unwrap(),
            action(second.into()).digest().unwrap()
        );
    }

    #[test]
    fn digest_golden_vector() {
        let literal = br#"{"agent_id":"claude","params":{"force":false,"new":"b","old":"a"},"target":"github.com/acme/api:refs/heads/main","tool":"git.push","v":1}"#;
        let expected = hex::encode(Sha256::digest(literal));
        assert_eq!(
            expected,
            "7940a04b1fcafdd1fecad451e2c867c23db904486498a304dcce5c00fe9c9bc6"
        );
        assert_eq!(
            action(json!({"force": false, "new": "b", "old": "a"}))
                .digest()
                .unwrap()
                .to_string(),
            expected
        );
    }

    #[test]
    fn digest_uses_jcs_numbers_and_utf16_key_order() {
        let literal = "{\"agent_id\":\"claude\",\"params\":{\"numbers\":[0,1,1e+30,0.000001,1e-7],\"𐀀\":\"quote\\\"\\n\",\"\u{e000}\":null},\"target\":\"github.com/acme/api:refs/heads/main\",\"tool\":\"git.push\",\"v\":1}";
        let params =
            json!({"numbers": [0, 1, 1e30, 1e-6, 1e-7], "𐀀": "quote\"\n", "\u{e000}": null});
        assert_eq!(
            action(params).digest().unwrap().to_string(),
            hex::encode(Sha256::digest(literal.as_bytes()))
        );
    }

    /// DS-01: floats that JCS would write as an integer are refused, so an
    /// approval for `1` can never be used by `1.0`.
    #[test]
    fn integral_floats_and_negative_zero_are_refused() {
        for params in [
            json!({"n": 1.0}),
            json!({"n": -0.0}),
            json!({"deep": [{"n": 1e0}]}),
            serde_json::from_str::<Value>(r#"{"n": 1.0}"#).unwrap(),
        ] {
            assert!(
                matches!(
                    Action::new(
                        AgentId::try_from("claude").unwrap(),
                        ToolName::try_from("git.push").unwrap(),
                        "t".into(),
                        params.clone()
                    ),
                    Err(CoreError::AmbiguousNumber(_))
                ),
                "{params}"
            );
        }
        for params in [
            json!({"n": 1}),
            json!({"n": 0}),
            json!({"n": 0.5}),
            json!({"n": 1e30}),
        ] {
            assert!(
                Action::new(
                    AgentId::try_from("claude").unwrap(),
                    ToolName::try_from("git.push").unwrap(),
                    "t".into(),
                    params.clone()
                )
                .is_ok(),
                "{params}"
            );
        }
    }

    proptest! {
        #[test]
        fn distinct_safe_actions_have_distinct_digests(
            value in -9007199254740991_i64..=9007199254740991_i64,
            other in -9007199254740991_i64..=9007199254740991_i64,
        ) {
            prop_assume!(value != other);
            let first = action(json!({"nested": [{"n": value}]}));
            let second = action(json!({"nested": [{"n": other}]}));
            prop_assert_ne!(first.params(), second.params());
            prop_assert_ne!(first.digest().unwrap(), second.digest().unwrap());
        }

        #[test]
        fn digest_changes_with_every_field(value in any::<i32>(), other in any::<i32>(), key in "[a-z]{1,16}") {
            prop_assume!(value != other);
            let original = action(json!({key.clone(): value}));
            let digest = original.digest().unwrap();
            let changed = Action::new(
                AgentId::try_from("other-agent").unwrap(),
                original.tool().clone(),
                original.target().into(),
                original.params().clone(),
            ).unwrap();
            prop_assert_ne!(digest, changed.digest().unwrap());
            let changed = Action::new(
                original.agent_id().clone(),
                ToolName::try_from("git.fetch").unwrap(),
                original.target().into(),
                original.params().clone(),
            ).unwrap();
            prop_assert_ne!(digest, changed.digest().unwrap());
            let changed = Action::new(
                original.agent_id().clone(),
                original.tool().clone(),
                format!("{}x", original.target()),
                original.params().clone(),
            ).unwrap();
            prop_assert_ne!(digest, changed.digest().unwrap());
            let changed = action(json!({key: other}));
            prop_assert_ne!(digest, changed.digest().unwrap());
        }
    }
}
