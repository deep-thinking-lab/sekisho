use super::NotificationConfigError;
use argon2::password_hash::Output;
use axum::http::HeaderMap;
use reqwest::Url;
use sekisho_core::{Timestamp, UserId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// One Slack app's signing key, identities and authentication requirement stay together.
pub struct SlackIntegration {
    secret: String,
    pub(crate) users: BTreeMap<String, UserId>,
    pub(crate) requires_totp: bool,
    /// Params are shown in Slack, and a button may approve, only with this
    /// opt-in and `requires_totp = false`.
    pub(crate) include_params: bool,
    response_origin: Url,
}

impl SlackIntegration {
    pub(super) fn new(
        secret: String,
        users: BTreeMap<String, String>,
        requires_totp: bool,
        include_params: bool,
        response_origin: Url,
    ) -> Result<Self, NotificationConfigError> {
        if secret.is_empty() || users.is_empty() {
            return Err(NotificationConfigError::InvalidSlack);
        }
        let users = users
            .into_iter()
            .map(|(slack, user)| {
                let user = UserId::try_from(user.as_str())
                    .map_err(|_| NotificationConfigError::InvalidSlack)?;
                user.ensure_human()
                    .map_err(|_| NotificationConfigError::InvalidSlack)?;
                if slack.is_empty() {
                    return Err(NotificationConfigError::InvalidSlack);
                }
                Ok((slack, user))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            secret,
            users,
            requires_totp,
            include_params,
            response_origin,
        })
    }

    /// Whether a button click may approve: the approver decides in Slack and
    /// sees the params there.
    pub(crate) fn one_click(&self) -> bool {
        !self.requires_totp && self.include_params
    }

    pub(super) fn same_secret(&self, other: &Self) -> bool {
        self.secret == other.secret
    }

    pub(super) fn same_settings(&self, other: &Self) -> bool {
        self.users == other.users
            && self.requires_totp == other.requires_totp
            && self.include_params == other.include_params
            && self.response_origin.origin() == other.response_origin.origin()
    }

    pub(crate) fn verifies(&self, headers: &HeaderMap, body: &[u8], now: Timestamp) -> bool {
        let header = |name: &str| {
            let mut values = headers.get_all(name).iter();
            let value = values.next()?.to_str().ok()?;
            if values.next().is_some() {
                return None;
            }
            Some(value)
        };
        let Some(timestamp) = header("x-slack-request-timestamp") else {
            return false;
        };
        let Ok(at) = timestamp.parse::<i64>() else {
            return false;
        };
        if !timestamp.bytes().all(|b| b.is_ascii_digit()) || now.as_secs().abs_diff(at) > 300 {
            return false;
        }
        let Some(signature) = header("x-slack-signature").and_then(|v| v.strip_prefix("v0="))
        else {
            return false;
        };
        if signature.len() != 64 || !signature.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        let mut supplied = [0; 32];
        for (byte, pair) in supplied
            .iter_mut()
            .zip(signature.as_bytes().chunks_exact(2))
        {
            let Ok(pair) = std::str::from_utf8(pair) else {
                return false;
            };
            let Ok(value) = u8::from_str_radix(pair, 16) else {
                return false;
            };
            *byte = value;
        }
        let expected = hmac_sha256(self.secret.as_bytes(), timestamp, body);
        // Output equality uses subtle's constant-time comparison, as in session authentication.
        match (Output::new(&expected), Output::new(&supplied)) {
            (Ok(expected), Ok(supplied)) => expected == supplied,
            _ => false,
        }
    }

    pub(crate) fn response_url(&self, raw: &str) -> Option<Url> {
        let url = Url::parse(raw).ok()?;
        // A signed callback may only send replies to the configured Slack webhook's origin.
        (url.origin() == self.response_origin.origin()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none())
        .then_some(url)
    }
}

fn hmac_sha256(secret: &[u8], timestamp: &str, body: &[u8]) -> [u8; 32] {
    // RFC 2104, using the approved sha2 dependency and SHA-256's 64-byte block size.
    let mut key = [0; 64];
    if secret.len() > key.len() {
        key[..32].copy_from_slice(&Sha256::digest(secret));
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut inner_pad = key;
    let mut outer_pad = key;
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(b"v0:");
    inner.update(timestamp.as_bytes());
    inner.update(b":");
    inner.update(body);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}
