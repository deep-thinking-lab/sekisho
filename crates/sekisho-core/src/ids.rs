use crate::CoreError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

macro_rules! identifier {
    ($name:ident, $error:ident, $validate:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CoreError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                if ($validate)(value) {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(CoreError::$error(value.to_owned()))
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value.as_str()).map_err(serde::de::Error::custom)
            }
        }
    };
}

identifier!(ToolName, InvalidToolName, |s: &str| {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/-".contains(&b))
        && !s.contains("..")
        && !s.starts_with(['/', ':'])
        && !s.ends_with(['/', ':'])
});

identifier!(AgentId, InvalidAgentId, |s: &str| {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
});

identifier!(UserId, InvalidUserId, |s: &str| {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
});

impl UserId {
    pub fn try_from_human(value: &str) -> Result<Self, CoreError> {
        validate_human_user_id(value)?;
        Self::try_from(value)
    }

    pub fn ensure_human(&self) -> Result<(), CoreError> {
        validate_human_user_id(self.as_str())
    }
}

fn validate_human_user_id(value: &str) -> Result<(), CoreError> {
    let normalized = value.to_ascii_lowercase();
    if normalized == "system" || normalized.starts_with("sekisho-") {
        Err(CoreError::ReservedUserId(value.to_owned()))
    } else {
        Ok(())
    }
}

/// Caller-supplied Unix seconds in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl From<i64> for Timestamp {
    fn from(seconds: i64) -> Self {
        Self(seconds)
    }
}

impl Timestamp {
    pub fn as_secs(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tool_name_rejects_invalid() {
        for value in [
            "Git.push",
            "git.*",
            "git..push",
            "",
            &"a".repeat(129),
            "/git",
            "git:",
            "git push",
            ":git",
            "git/",
            "gít",
        ] {
            assert!(
                matches!(
                    ToolName::try_from(value),
                    Err(crate::CoreError::InvalidToolName(_))
                ),
                "{value:?}"
            );
            assert!(serde_json::from_value::<ToolName>(serde_json::json!(value)).is_err());
        }
    }

    #[test]
    fn ids_accept_valid() {
        for value in [
            "git.push",
            "mcp:github/create_issue",
            "hook:claude-code/bash",
            &"a".repeat(128),
        ] {
            let tool = ToolName::try_from(value).unwrap();
            assert_eq!(tool.as_str(), value);
            assert_eq!(tool.to_string(), value);
            assert_eq!(serde_json::to_value(&tool).unwrap(), value);
            assert_eq!(
                serde_json::from_value::<ToolName>(serde_json::json!(value)).unwrap(),
                tool
            );
        }
        for value in ["claude", "agent-1", &"a".repeat(64)] {
            let id = AgentId::try_from(value).unwrap();
            assert_eq!(id.as_str(), value);
            assert_eq!(id.to_string(), value);
            assert_eq!(serde_json::to_value(&id).unwrap(), value);
            assert_eq!(
                serde_json::from_value::<AgentId>(serde_json::json!(value)).unwrap(),
                id
            );
        }
        for value in ["jane.doe_1", "admin-1", &"a".repeat(64)] {
            let id = UserId::try_from(value).unwrap();
            assert_eq!(id.as_str(), value);
            assert_eq!(id.to_string(), value);
            assert_eq!(serde_json::to_value(&id).unwrap(), value);
            assert_eq!(
                serde_json::from_value::<UserId>(serde_json::json!(value)).unwrap(),
                id
            );
        }
    }

    #[test]
    fn ids_reject_invalid_on_construction_and_deserialization() {
        for value in ["", "Upper", "a b", "a/b", "a:b", "é", &"a".repeat(65)] {
            assert!(matches!(
                AgentId::try_from(value),
                Err(crate::CoreError::InvalidAgentId(_))
            ));
            assert!(matches!(
                UserId::try_from(value),
                Err(crate::CoreError::InvalidUserId(_))
            ));
            assert!(serde_json::from_value::<AgentId>(serde_json::json!(value)).is_err());
            assert!(serde_json::from_value::<UserId>(serde_json::json!(value)).is_err());
        }
        for value in ["a.b", "a_b"] {
            assert!(AgentId::try_from(value).is_err());
        }
    }

    #[test]
    fn human_user_ids_reserve_system_namespace() {
        for value in [
            "system",
            "System",
            "SYSTEM",
            "sekisho-",
            "sekisho-admin",
            "SEKISHO-admin",
        ] {
            assert!(
                matches!(
                    UserId::try_from_human(value),
                    Err(crate::CoreError::ReservedUserId(_))
                ),
                "{value:?}"
            );
        }
        for value in ["admin", "system-admin", "sekisho", "not-sekisho-admin"] {
            assert_eq!(UserId::try_from_human(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn timestamp_preserves_caller_supplied_seconds() {
        for seconds in [i64::MIN, -1, 0, i64::MAX] {
            let at = Timestamp::from(seconds);
            assert_eq!(at.as_secs(), seconds);
            assert_eq!(serde_json::to_value(at).unwrap(), seconds);
            assert_eq!(
                serde_json::from_value::<Timestamp>(serde_json::json!(seconds)).unwrap(),
                at
            );
        }
    }
}
