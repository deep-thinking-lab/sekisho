use crate::CoreError;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

macro_rules! hex_type {
    ($name:ident, $len:expr, $error:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
        impl FromStr for $name {
            type Err = CoreError;
            fn from_str(value: &str) -> Result<Self, CoreError> {
                if value.len() != $len * 2
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(CoreError::$error);
                }
                let mut bytes = [0; $len];
                hex::decode_to_slice(value, &mut bytes).map_err(|_| CoreError::$error)?;
                Ok(Self(bytes))
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_type!(Signature, 64, InvalidSignature);
hex_type!(PublicKey, 32, InvalidPublicKey);

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Implementations must return an error if signing fails, without exposing key material.
pub trait Signer {
    fn key_id(&self) -> &str;
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8]) -> Result<Signature, CoreError>;
}

pub struct Ed25519Signer {
    key_id: String,
    key: SigningKey,
}

impl Ed25519Signer {
    /// Core accepts key bytes from the caller and never reads or generates keys.
    pub fn from_secret_bytes(key_id: &str, secret: &[u8; 32]) -> Self {
        Self {
            key_id: key_id.to_owned(),
            key: SigningKey::from_bytes(secret),
        }
    }
}

impl Signer for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> PublicKey {
        PublicKey(self.key.verifying_key().to_bytes())
    }
    fn sign(&self, message: &[u8]) -> Result<Signature, CoreError> {
        Ok(Signature(self.key.sign(message).to_bytes()))
    }
}

pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CoreError> {
    let key =
        VerifyingKey::from_bytes(&public_key.0).map_err(|_| CoreError::SignatureVerification)?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature.0))
        .map_err(|_| CoreError::SignatureVerification)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trip() {
        let signer = Ed25519Signer::from_secret_bytes("grant-1", &[7; 32]);
        let signer: &dyn Signer = &signer;
        assert_eq!(signer.key_id(), "grant-1");
        let signature = signer.sign(b"message").unwrap();
        verify(&signer.public_key(), b"message", &signature).unwrap();
        assert!(verify(&signer.public_key(), b"changed", &signature).is_err());
        let other = Ed25519Signer::from_secret_bytes("other", &[8; 32]);
        assert!(verify(&other.public_key(), b"message", &signature).is_err());
        let encoded = serde_json::to_string(&signature).unwrap();
        assert_eq!(
            serde_json::from_str::<Signature>(&encoded).unwrap(),
            signature
        );
        assert_eq!(
            signature.to_string().parse::<Signature>().unwrap(),
            signature
        );
        let key = signer.public_key();
        assert_eq!(key.to_string().parse::<PublicKey>().unwrap(), key);
        assert_eq!(
            serde_json::from_str::<PublicKey>(&serde_json::to_string(&key).unwrap()).unwrap(),
            key
        );
        assert_eq!(signature.to_string().len(), 128);
        assert_eq!(key.to_string().len(), 64);
        for invalid in [
            "a".repeat(127),
            "a".repeat(129),
            "A".repeat(128),
            "g".repeat(128),
        ] {
            assert!(invalid.parse::<Signature>().is_err());
        }
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert!(invalid.parse::<PublicKey>().is_err());
        }
    }

    #[test]
    fn verify_strict_rejects_malleable_signature() {
        // RFC 8032 test vector 1, with the group order L added to S.
        let key: PublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            .parse()
            .unwrap();
        let canonical: Signature = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        .parse()
        .unwrap();
        verify(&key, b"", &canonical).unwrap();
        let mut bytes = canonical.0;
        let order = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
        let mut carry = 0u16;
        for (byte, add) in bytes[32..].iter_mut().zip(order) {
            let sum = u16::from(*byte) + u16::from(add) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert!(verify(&key, b"", &Signature::from(bytes)).is_err());
        // The identity key and R with S=0 satisfy the weak verification equation.
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut weak = [0; 64];
        weak[0] = 1;
        assert!(verify(&PublicKey::from(identity), b"", &Signature::from(weak)).is_err());
    }
}
