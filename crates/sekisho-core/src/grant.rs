use crate::{
    Action, AgentId, CoreError, PublicKey, Signature, Signer, Timestamp, ToolName, UserId,
};
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct GrantId(String);

impl GrantId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for GrantId {
    type Error = CoreError;
    fn try_from(value: &str) -> Result<Self, CoreError> {
        if value.strip_prefix("grt_").is_some_and(|s| {
            s.len() == 26
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        }) {
            Ok(Self(value.to_owned()))
        } else {
            Err(CoreError::InvalidGrantId(value.to_owned()))
        }
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GrantId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedGrant {
    pub id: GrantId,
    pub agent_id: AgentId,
    pub tool: ToolName,
    pub target_glob: String,
    pub params: BTreeMap<String, Value>,
    pub not_before: Timestamp,
    pub expires_at: Timestamp,
    pub max_uses: Option<u32>,
    pub issued_by: UserId,
}

impl UnsignedGrant {
    fn validate(&self) -> Result<GlobMatcher, CoreError> {
        if self.expires_at <= self.not_before {
            return Err(CoreError::InvalidGrantWindow);
        }
        // Timestamps are signed JCS numbers too and must not alias after rounding.
        for (name, at) in [
            ("not_before", self.not_before),
            ("expires_at", self.expires_at),
        ] {
            crate::action::validate_integers(&json!(at), &format!("/{name}"))?;
        }
        for (key, value) in &self.params {
            let path = format!("/{}", key.replace('~', "~0").replace('/', "~1"));
            crate::action::validate_integers(value, &path)?;
        }
        GlobBuilder::new(&self.target_glob)
            .literal_separator(true)
            .build()
            .map(|glob| glob.compile_matcher())
            .map_err(|error| CoreError::InvalidGrantGlob(error.to_string()))
    }

    fn message(&self) -> Result<Vec<u8>, CoreError> {
        let message = json!({
            "v": 1, "kind": "grant", "id": self.id, "agent_id": self.agent_id,
            "tool": self.tool, "target_glob": self.target_glob, "params": self.params,
            "not_before": self.not_before, "expires_at": self.expires_at,
            "max_uses": self.max_uses, "issued_by": self.issued_by,
        });
        serde_jcs::to_vec(&message).map_err(|error| CoreError::Canonicalization(error.to_string()))
    }

    pub fn sign(self, signer: &dyn Signer) -> Result<Grant, CoreError> {
        let target = self.validate()?;
        let signature = signer.sign(&self.message()?)?;
        Ok(Grant {
            fields: self,
            signature,
            target,
        })
    }
}

/// Structurally validated signed grant. Authenticity still requires the trusted public key.
#[derive(Debug, Clone, Serialize)]
pub struct Grant {
    #[serde(flatten)]
    fields: UnsignedGrant,
    signature: Signature,
    #[serde(skip)]
    target: GlobMatcher,
}

impl<'de> Deserialize<'de> for Grant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct RawGrant {
            #[serde(flatten)]
            fields: UnsignedGrant,
            signature: Signature,
        }
        let raw = RawGrant::deserialize(deserializer)?;
        let target = raw.fields.validate().map_err(serde::de::Error::custom)?;
        Ok(Self {
            fields: raw.fields,
            signature: raw.signature,
            target,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantInvalid {
    #[error("bad grant signature")]
    BadSignature,
    #[error("grant is not yet valid")]
    NotYetValid,
    #[error("grant has expired")]
    Expired,
    #[error("grant uses exhausted")]
    Exhausted,
    #[error("grant has been revoked")]
    Revoked,
}

impl Grant {
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), CoreError> {
        crate::verify(public_key, &self.fields.message()?, &self.signature)
    }

    /// Revocation and use counts must come from trusted server state.
    pub fn is_valid_at(
        &self,
        public_key: &PublicKey,
        now: Timestamp,
        uses_so_far: u32,
        revoked: bool,
    ) -> Result<(), GrantInvalid> {
        self.verify(public_key)
            .map_err(|_| GrantInvalid::BadSignature)?;
        if revoked {
            return Err(GrantInvalid::Revoked);
        }
        if now < self.not_before() {
            return Err(GrantInvalid::NotYetValid);
        }
        if now >= self.expires_at() {
            return Err(GrantInvalid::Expired);
        }
        if self.max_uses().is_some_and(|max| uses_so_far >= max) {
            return Err(GrantInvalid::Exhausted);
        }
        Ok(())
    }

    /// Scope matching alone does not establish authenticity or validity.
    pub fn matches(&self, action: &Action) -> bool {
        self.agent_id() == action.agent_id()
            && self.tool() == action.tool()
            && self.target.is_match(action.target())
            && self
                .params()
                .iter()
                .all(|(key, value)| action.params().get(key) == Some(value))
    }

    pub fn id(&self) -> &GrantId {
        &self.fields.id
    }
    pub fn agent_id(&self) -> &AgentId {
        &self.fields.agent_id
    }
    pub fn tool(&self) -> &ToolName {
        &self.fields.tool
    }
    pub fn target_glob(&self) -> &str {
        &self.fields.target_glob
    }
    pub fn params(&self) -> &BTreeMap<String, Value> {
        &self.fields.params
    }
    pub fn not_before(&self) -> Timestamp {
        self.fields.not_before
    }
    pub fn expires_at(&self) -> Timestamp {
        self.fields.expires_at
    }
    pub fn max_uses(&self) -> Option<u32> {
        self.fields.max_uses
    }
    pub fn issued_by(&self) -> &UserId {
        &self.fields.issued_by
    }
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::Ed25519Signer;
    use proptest::prelude::*;
    use serde_json::json;

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_secret_bytes("grant", &[7; 32])
    }
    fn unsigned() -> UnsignedGrant {
        UnsignedGrant {
            id: GrantId::try_from("grt_0123456789abcdefghijklmnop").unwrap(),
            agent_id: AgentId::try_from("claude").unwrap(),
            tool: ToolName::try_from("git.push").unwrap(),
            target_glob: "repo:release/*".into(),
            params: BTreeMap::from([("force".into(), json!(false))]),
            not_before: 100.into(),
            expires_at: 200.into(),
            max_uses: Some(3),
            issued_by: UserId::try_from("admin").unwrap(),
        }
    }

    proptest! {
        #[test]
        fn tampering_any_field_breaks_signature(suffix in "[a-z]{1,12}", n in 1u32..1000) {
            let original = unsigned().sign(&signer()).unwrap();
            for field in 0..9 {
                let mut input = unsigned();
                match field {
                    0 => input.id = GrantId::try_from(format!("grt_{}z", "0".repeat(25)).as_str()).unwrap(),
                    1 => input.agent_id = AgentId::try_from(format!("other-{suffix}").as_str()).unwrap(),
                    2 => input.tool = ToolName::try_from(format!("git.other-{suffix}").as_str()).unwrap(),
                    3 => input.target_glob = format!("other-{suffix}/*"),
                    4 => { input.params.insert("n".into(), json!(n)); },
                    5 => input.not_before = (100 - i64::from(n)).into(),
                    6 => input.expires_at = (200 + i64::from(n)).into(),
                    7 => input.max_uses = Some(3 + n),
                    8 => input.issued_by = UserId::try_from(format!("other-{suffix}").as_str()).unwrap(),
                    _ => unreachable!(),
                }
                let mut changed = input.sign(&signer()).unwrap();
                changed.signature = original.signature;
                prop_assert!(changed.verify(&signer().public_key()).is_err(), "field {}", field);
            }
        }
    }

    #[test]
    fn grant_timestamps_cannot_alias_under_jcs() {
        for (start, end) in [
            (100, 9007199254740992i64),
            (-9007199254740992, 200),
            (9007199254740992, 9007199254740993),
            (i64::MIN, i64::MAX),
        ] {
            let mut input = unsigned();
            input.not_before = start.into();
            input.expires_at = end.into();
            assert!(input.sign(&signer()).is_err(), "{start}..{end}");
        }
        let mut input = unsigned();
        input.not_before = (-9007199254740991i64).into();
        input.expires_at = 9007199254740991i64.into();
        input
            .sign(&signer())
            .unwrap()
            .verify(&signer().public_key())
            .unwrap();
    }

    #[test]
    fn signing_failure_refuses_grant() {
        struct FailingSigner;
        impl Signer for FailingSigner {
            fn key_id(&self) -> &str {
                "failed"
            }
            fn public_key(&self) -> PublicKey {
                signer().public_key()
            }
            fn sign(&self, _: &[u8]) -> Result<Signature, CoreError> {
                Err(CoreError::Signing)
            }
        }
        assert!(matches!(
            unsigned().sign(&FailingSigner),
            Err(CoreError::Signing)
        ));
    }

    #[test]
    fn deserialization_enforces_grant_invariants() {
        let original = unsigned().sign(&signer()).unwrap();
        let encoded = serde_json::to_value(&original).unwrap();
        for (field, value) in [
            ("id", json!("grt_bad")),
            ("agent_id", json!("Claude")),
            ("tool", json!("git.*")),
            ("target_glob", json!("[")),
            ("expires_at", json!(100)),
            ("expires_at", json!(99)),
            ("params", json!({"n": [9007199254740992u64]})),
            ("signature", json!("00")),
        ] {
            let mut changed = encoded.clone();
            changed[field] = value;
            assert!(serde_json::from_value::<Grant>(changed).is_err(), "{field}");
        }
        for field in [
            "id",
            "agent_id",
            "tool",
            "target_glob",
            "params",
            "not_before",
            "expires_at",
            "issued_by",
            "signature",
        ] {
            let mut changed = encoded.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Grant>(changed).is_err(), "{field}");
        }
        let mut changed = encoded;
        changed["signature"] = json!("00".repeat(64));
        let changed: Grant = serde_json::from_value(changed).unwrap();
        assert_eq!(
            changed.is_valid_at(&signer().public_key(), 150.into(), 0, false),
            Err(GrantInvalid::BadSignature)
        );
    }

    #[test]
    fn domain_separation() {
        let mut grant = unsigned().sign(&signer()).unwrap();
        let mut message = serde_json::to_value(unsigned()).unwrap();
        message["v"] = json!(1);
        grant.signature = signer()
            .sign(&serde_jcs::to_vec(&message).unwrap())
            .unwrap();
        assert!(grant.verify(&signer().public_key()).is_err());
        message["kind"] = json!("grant");
        grant.signature = signer()
            .sign(&serde_jcs::to_vec(&message).unwrap())
            .unwrap();
        grant.verify(&signer().public_key()).unwrap();
    }

    #[test]
    fn validity_window_and_uses() {
        let grant = unsigned().sign(&signer()).unwrap();
        for (now, uses, revoked, expected) in [
            (99, 0, false, Err(GrantInvalid::NotYetValid)),
            (100, 0, false, Ok(())),
            (199, 2, false, Ok(())),
            (200, 0, false, Err(GrantInvalid::Expired)),
            (201, 0, false, Err(GrantInvalid::Expired)),
            (150, 3, false, Err(GrantInvalid::Exhausted)),
            (150, u32::MAX, false, Err(GrantInvalid::Exhausted)),
            (150, 0, true, Err(GrantInvalid::Revoked)),
        ] {
            assert_eq!(
                grant.is_valid_at(&signer().public_key(), now.into(), uses, revoked),
                expected
            );
        }
        let wrong = Ed25519Signer::from_secret_bytes("wrong", &[9; 32]);
        assert_eq!(
            grant.is_valid_at(&wrong.public_key(), 150.into(), 0, false),
            Err(GrantInvalid::BadSignature)
        );
        let mut unlimited = unsigned();
        unlimited.max_uses = None;
        assert_eq!(
            unlimited.sign(&signer()).unwrap().is_valid_at(
                &signer().public_key(),
                150.into(),
                u32::MAX,
                false
            ),
            Ok(())
        );
        let mut zero = unsigned();
        zero.max_uses = Some(0);
        assert_eq!(
            zero.sign(&signer())
                .unwrap()
                .is_valid_at(&signer().public_key(), 150.into(), 0, false),
            Err(GrantInvalid::Exhausted)
        );
    }

    #[test]
    fn matches_respects_tool_target_and_params() {
        let grant = unsigned().sign(&signer()).unwrap();
        for (agent, tool, target, params, matches) in [
            (
                "claude",
                "git.push",
                "repo:release/v1",
                json!({"force": false, "extra": 1}),
                true,
            ),
            (
                "other",
                "git.push",
                "repo:release/v1",
                json!({"force": false}),
                false,
            ),
            (
                "claude",
                "git.push.more",
                "repo:release/v1",
                json!({"force": false}),
                false,
            ),
            (
                "claude",
                "git.push",
                "xrepo:release/v1",
                json!({"force": false}),
                false,
            ),
            (
                "claude",
                "git.push",
                "repo:main",
                json!({"force": false}),
                false,
            ),
            (
                "claude",
                "git.push",
                "repo:release/v1",
                json!({"force": true}),
                false,
            ),
            ("claude", "git.push", "repo:release/v1", json!({}), false),
            (
                "claude",
                "git.push",
                "repo:release/v1",
                json!({"force": null}),
                false,
            ),
        ] {
            let action = Action::new(
                AgentId::try_from(agent).unwrap(),
                ToolName::try_from(tool).unwrap(),
                target.into(),
                params,
            )
            .unwrap();
            assert_eq!(grant.matches(&action), matches);
        }
        let mut input = unsigned();
        input.params = BTreeMap::from([("nested".into(), json!({"x": [1, false]}))]);
        let grant = input.sign(&signer()).unwrap();
        for (params, expected) in [
            (json!({"nested":{"x":[1,false]}}), true),
            (json!({"nested":{"x":[1,false],"extra":0}}), false),
        ] {
            assert_eq!(
                grant.matches(
                    &Action::new(
                        unsigned().agent_id,
                        unsigned().tool,
                        "repo:release/v1".into(),
                        params
                    )
                    .unwrap()
                ),
                expected
            );
        }
    }

    #[test]
    fn star_does_not_cross_separator() {
        let action = |target: &str| {
            Action::new(
                AgentId::try_from("claude").unwrap(),
                ToolName::try_from("git.push").unwrap(),
                target.into(),
                json!({"force": false}),
            )
            .unwrap()
        };
        let child_grant = unsigned().sign(&signer()).unwrap();
        assert!(child_grant.matches(&action("repo:release/v1")));
        assert!(!child_grant.matches(&action("repo:release/a/b")));

        let mut recursive = unsigned();
        recursive.target_glob = "repo:release/**".into();
        let recursive = recursive.sign(&signer()).unwrap();
        assert!(recursive.matches(&action("repo:release/v1")));
        assert!(recursive.matches(&action("repo:release/a/b")));
    }

    #[test]
    fn rejects_invalid_grant_input() {
        for id in [
            "",
            "grt_0123456789abcdefghijklmno",
            "grt_0123456789abcdefghijklmnopq",
            "apr_0123456789abcdefghijklmnop",
            "grt_0123456789abcdefghijklmnoZ",
        ] {
            assert!(GrantId::try_from(id).is_err());
        }
        for (field, value) in [
            ("target_glob", json!("[")),
            ("expires_at", json!(100)),
            ("expires_at", json!(99)),
            ("params", json!({"nested":[{"n":9007199254740992u64}]})),
        ] {
            let mut input = serde_json::to_value(unsigned()).unwrap();
            input[field] = value;
            assert!(
                serde_json::from_value::<UnsignedGrant>(input)
                    .unwrap()
                    .sign(&signer())
                    .is_err()
            );
        }
    }

    #[test]
    fn grant_round_trip_and_accessors() {
        let input = unsigned();
        let grant = input.clone().sign(&signer()).unwrap();
        assert_eq!(grant.id(), &input.id);
        assert_eq!(grant.agent_id(), &input.agent_id);
        assert_eq!(grant.tool(), &input.tool);
        assert_eq!(grant.target_glob(), input.target_glob);
        assert_eq!(grant.params(), &input.params);
        assert_eq!(grant.not_before(), input.not_before);
        assert_eq!(grant.expires_at(), input.expires_at);
        assert_eq!(grant.max_uses(), input.max_uses);
        assert_eq!(grant.issued_by(), &input.issued_by);
        let restored: Grant =
            serde_json::from_value(serde_json::to_value(&grant).unwrap()).unwrap();
        restored.verify(&signer().public_key()).unwrap();
        assert_eq!(restored.signature(), grant.signature());
    }
}
