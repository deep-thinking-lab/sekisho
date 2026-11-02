use crate::CoreError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

/// A SHA-256 digest, represented externally as 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for Digest {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CoreError::InvalidDigest(value.to_owned()));
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes)
            .map_err(|_| CoreError::InvalidDigest(value.to_owned()))?;
        Ok(Self(bytes))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn digest_hex_round_trip() {
        let hex = "7940a04b1fcafdd1fecad451e2c867c23db904486498a304dcce5c00fe9c9bc6";
        let digest: Digest = hex.parse().unwrap();
        assert_eq!(digest.to_string(), hex);
        assert_eq!(digest.to_string().parse::<Digest>().unwrap(), digest);
        assert_eq!(serde_json::to_value(digest).unwrap(), hex);
        assert_eq!(
            serde_json::from_value::<Digest>(serde_json::json!(hex)).unwrap(),
            digest
        );
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            hex.to_uppercase(),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            assert!(matches!(
                invalid.parse::<Digest>(),
                Err(crate::CoreError::InvalidDigest(_))
            ));
            assert!(serde_json::from_value::<Digest>(serde_json::json!(invalid)).is_err());
        }
    }
}
