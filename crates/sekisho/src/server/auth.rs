use super::{AppState, AuthStoreError, Role, SessionToken, csrf};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Extension, Form,
    extract::{ConnectInfo, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use sekisho_core::{Timestamp, UserId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};
#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub password_hash: String,
    pub totp_secret: Option<Vec<u8>>,
    pub roles: BTreeSet<Role>,
}
pub trait UserDirectory: Send + Sync {
    fn find(&self, id: &UserId) -> Result<Option<User>, AuthStoreError>;
}
#[derive(Default)]
pub struct InMemoryUsers {
    users: Mutex<HashMap<UserId, User>>,
    failing: AtomicBool,
}
impl InMemoryUsers {
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }
    pub fn insert(&self, user: User) -> Result<(), AuthStoreError> {
        user.id.ensure_human().map_err(|_| AuthStoreError)?;
        self.users
            .lock()
            .map_err(|_| AuthStoreError)?
            .insert(user.id.clone(), user);
        Ok(())
    }
}
impl UserDirectory for InMemoryUsers {
    fn find(&self, id: &UserId) -> Result<Option<User>, AuthStoreError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(AuthStoreError);
        }
        Ok(self
            .users
            .lock()
            .map_err(|_| AuthStoreError)?
            .get(id)
            .cloned())
    }
}
#[derive(Deserialize)]
pub(super) struct CsrfForm {
    pub csrf_token: String,
}
#[derive(Deserialize)]
pub(super) struct LoginForm {
    user_id: String,
    password: String,
    #[serde(default)]
    totp: String,
    #[serde(default)]
    csrf_token: String,
}
struct Attempt {
    start: Timestamp,
    count: u32,
}

/// Window for every login limit.
const WINDOW_SECONDS: i64 = 900;
/// Failures per user before the soft throttle: after it, only a correct
/// password with a correct TOTP code signs that user in.
const LOGIN_LIMIT: u32 = 5;
/// Failed logins per client address (IPv6 per /64) before its failures are delayed.
const SOURCE_LIMIT: u32 = 20;
/// Wrong TOTP codes after a correct password per user before it locks.
const SECOND_FACTOR_LIMIT: u32 = 10;
/// Failed logins across all users per window before failures are slowed down.
const GLOBAL_FAILURE_LIMIT: u32 = 1000;
/// Bound on tracked keys per map.
const MAX_ENTRIES: usize = 10_000;

fn live(entry: &Attempt, now: Timestamp) -> bool {
    let age = now.as_secs().saturating_sub(entry.start.as_secs());
    (0..WINDOW_SECONDS).contains(&age)
}

/// Count one event for `key`; `false` (and no count) at `limit`.
fn bump<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Attempt>,
    key: K,
    now: Timestamp,
    limit: u32,
) -> bool {
    if !map.contains_key(&key) && map.len() >= MAX_ENTRIES {
        return false;
    }
    let entry = map.entry(key).or_insert(Attempt {
        start: now,
        count: 0,
    });
    if !live(entry, now) {
        entry.start = now;
        entry.count = 0;
    }
    if entry.count >= limit {
        return false;
    }
    entry.count += 1;
    true
}

/// Undo one count. An entry back at zero is removed, so a refunded attempt
/// never anchors the start of a later window.
fn refund<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Attempt>, key: &K) {
    if let Some(entry) = map.get_mut(key) {
        entry.count = entry.count.saturating_sub(1);
        if entry.count == 0 {
            map.remove(key);
        }
    }
}

fn at_limit<K: std::hash::Hash + Eq>(
    map: &HashMap<K, Attempt>,
    key: &K,
    now: Timestamp,
    limit: u32,
) -> bool {
    map.get(key)
        .is_some_and(|entry| live(entry, now) && entry.count >= limit)
}

/// Throttling key for a client address: IPv4 as is, IPv6 by its /64.
fn source_key(address: std::net::IpAddr) -> std::net::IpAddr {
    match address {
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !((1u128 << 64) - 1);
            std::net::IpAddr::V6(bits.into())
        }
        v4 => v4,
    }
}

#[derive(Default)]
pub(super) struct Attempts {
    /// Failures per user (any kind): drives the soft throttle, never a lock.
    entries: HashMap<Option<UserId>, Attempt>,
    /// Failed logins per client address key.
    sources: HashMap<std::net::IpAddr, Attempt>,
    /// Correct password with a wrong TOTP code, per user.
    second_factor: HashMap<UserId, Attempt>,
    /// Failed logins across all users.
    global: Option<Attempt>,
    last_pruned: Option<Timestamp>,
}
impl Attempts {
    fn prune(&mut self, now: Timestamp) {
        if self
            .last_pruned
            .is_none_or(|at| now.as_secs().saturating_sub(at.as_secs()) >= 60)
        {
            self.entries.retain(|_, entry| live(entry, now));
            self.sources.retain(|_, entry| live(entry, now));
            self.second_factor.retain(|_, entry| live(entry, now));
            self.last_pruned = Some(now);
        }
    }
    /// Count an attempt for `key`; `false` once it has had five in the window.
    /// Used by the local admin limiter.
    pub(super) fn reserve(&mut self, key: Option<UserId>, now: Timestamp) -> bool {
        self.prune(now);
        bump(&mut self.entries, key, now, LOGIN_LIMIT)
    }
    pub(super) fn accept(&mut self, id: &UserId) {
        self.entries.remove(&Some(id.clone()));
    }
    fn source_blocked(&self, source: &std::net::IpAddr, now: Timestamp) -> bool {
        at_limit(&self.sources, &source_key(*source), now, SOURCE_LIMIT)
    }
    /// Count a failed login for `source`. A full map evicts its oldest entry
    /// rather than ignoring new addresses.
    fn source_failed(&mut self, source: std::net::IpAddr, now: Timestamp) {
        let key = source_key(source);
        if !self.sources.contains_key(&key)
            && self.sources.len() >= MAX_ENTRIES
            && let Some(oldest) = self
                .sources
                .iter()
                .min_by_key(|(_, entry)| entry.start.as_secs())
                .map(|(key, _)| *key)
        {
            self.sources.remove(&oldest);
        }
        let _ = bump(&mut self.sources, key, now, SOURCE_LIMIT);
    }
    /// Count a failed login; `true` when failures across all users are over the
    /// global ceiling and this failure should be slowed down.
    fn global_failure(&mut self, now: Timestamp) -> bool {
        let entry = self.global.get_or_insert(Attempt {
            start: now,
            count: 0,
        });
        if !live(entry, now) {
            entry.start = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        entry.count > GLOBAL_FAILURE_LIMIT
    }
}

/// A slot reserved under the lock before verifying. Dropping it refunds the
/// slot, which covers success, errors, timeouts and cancelled requests;
/// `commit` keeps it.
struct Reservation<K: std::hash::Hash + Eq + Clone> {
    attempts: Arc<Mutex<Attempts>>,
    map: fn(&mut Attempts) -> &mut HashMap<K, Attempt>,
    key: K,
    committed: bool,
}
impl<K: std::hash::Hash + Eq + Clone> Reservation<K> {
    fn reserve(
        attempts: &Arc<Mutex<Attempts>>,
        map: fn(&mut Attempts) -> &mut HashMap<K, Attempt>,
        key: K,
        now: Timestamp,
        limit: u32,
    ) -> Option<Self> {
        let mut guard = attempts.lock().unwrap_or_else(PoisonError::into_inner);
        guard.prune(now);
        bump(map(&mut guard), key.clone(), now, limit).then(|| Self {
            attempts: attempts.clone(),
            map,
            key,
            committed: false,
        })
    }
    fn commit(mut self) {
        self.committed = true;
    }
}
impl<K: std::hash::Hash + Eq + Clone> Drop for Reservation<K> {
    fn drop(&mut self) {
        if !self.committed {
            let mut guard = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
            refund((self.map)(&mut guard), &self.key);
        }
    }
}

fn user_failures(attempts: &mut Attempts) -> &mut HashMap<Option<UserId>, Attempt> {
    &mut attempts.entries
}
fn second_factor_failures(attempts: &mut Attempts) -> &mut HashMap<UserId, Attempt> {
    &mut attempts.second_factor
}

/// The client address used for source throttling, or `None` to skip it. A
/// request from a configured trusted proxy is attributed to the rightmost
/// `X-Forwarded-For` entry that is not itself a trusted proxy. With no trusted
/// proxies, a request carrying `X-Forwarded-For` probably came through an
/// unconfigured proxy, so its peer is not a client address either.
pub(super) fn client_address(
    peer: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[std::net::IpAddr],
) -> Option<std::net::IpAddr> {
    let peer = peer?;
    if trusted_proxies.is_empty() && headers.contains_key("x-forwarded-for") {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "login requests carry X-Forwarded-For but trusted_proxies is empty; \
                 per-address login throttling is off until the proxy is listed"
            );
        });
        return None;
    }
    if !trusted_proxies.contains(&peer) {
        return Some(peer);
    }
    let forwarded: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .collect();
    for part in forwarded.into_iter().rev() {
        match part.trim().parse::<std::net::IpAddr>() {
            Ok(address) if trusted_proxies.contains(&address) => {}
            Ok(address) => return Some(address),
            Err(_) => break,
        }
    }
    // Only the proxy's own address is known: not a client, so no source limit.
    None
}
pub(super) fn dummy_hash() -> Result<String, AuthStoreError> {
    let salt = SaltString::encode_b64(b"sekisho-dummy-salt").map_err(|_| AuthStoreError)?;
    Ok(Argon2::default()
        .hash_password(b"not-a-user-password", &salt)
        .map_err(|_| AuthStoreError)?
        .to_string())
}
pub(super) fn add_cookie(response: &mut Response, value: String) -> Result<(), StatusCode> {
    response.headers_mut().append(
        SET_COOKIE,
        value.parse().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    );
    Ok(())
}
pub(super) async fn login(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, StatusCode> {
    if !csrf::cookie(&headers, "sekisho_prelogin")
        .is_some_and(|cookie| csrf::matches(cookie, &form.csrf_token))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let html = super::ui::wants_html(&headers);
    let csrf_token = form.csrf_token.clone();
    let log_id = UserId::try_from(form.user_id.as_str())
        .map_or_else(|_| "invalid".to_owned(), |id| id.to_string());
    let now = state.clock.now();
    let user = match UserId::try_from(form.user_id.as_str()) {
        Ok(id) => state
            .users
            .find(&id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        Err(_) => None,
    };
    // Login limits (SEK-06):
    // - After five failures a user is soft throttled: every attempt is still
    //   fully verified (Argon2 and TOTP) and succeeds only with the correct
    //   password and a correct code. The failure is counted by a reservation
    //   taken under the lock before verifying, so concurrent requests see it.
    // - Ten wrong codes after a correct password lock the user for the window.
    // - Every failed login is counted per client address; past the limit the
    //   address's failures are delayed. It never refuses a correct password
    //   with a correct code.
    // - Every failed login gets the same 401 and body, whatever the throttle,
    //   lock or source state.
    // - Past a global ceiling, failures are slowed down.
    let key = user.as_ref().map(|u| u.id.clone());
    let source = client_address(
        peer.map(|Extension(ConnectInfo(address))| address.ip()),
        &headers,
        &state.trusted_proxies,
    );
    let second_factor_id = user
        .as_ref()
        .filter(|u| {
            u.totp_secret.is_some()
                && (u.roles.contains(&Role::Approver) || u.roles.contains(&Role::Admin))
        })
        .map(|u| u.id.clone());
    // The Argon2 slot comes first, so waiting for it never touches a counter.
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.password_slots.clone().acquire_owned(),
    )
    .await
    .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let failure = Reservation::reserve(
        &state.attempts,
        user_failures,
        key.clone(),
        now,
        LOGIN_LIMIT,
    );
    let throttled = failure.is_none();
    let second_factor = second_factor_id.as_ref().map(|id| {
        Reservation::reserve(
            &state.attempts,
            second_factor_failures,
            id.clone(),
            now,
            SECOND_FACTOR_LIMIT,
        )
    });
    let locked = matches!(second_factor, Some(None));
    let second_factor = second_factor.flatten();
    let dummy = state.dummy_hash.clone();
    let secret = user.as_ref().and_then(|u| u.totp_secret.clone());
    let raw = user
        .as_ref()
        .map_or_else(|| dummy.as_str().to_owned(), |u| u.password_hash.clone());
    let (password_ok, step) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let parsed = PasswordHash::new(&raw)
            .ok()
            .filter(|h| h.algorithm.as_str() == "argon2id");
        let valid_algorithm = parsed.is_some();
        let hash = parsed.or_else(|| PasswordHash::new(&dummy).ok());
        let password_ok = hash.is_some_and(|hash| {
            Argon2::default()
                .verify_password(form.password.as_bytes(), &hash)
                .is_ok()
        }) && valid_algorithm;
        // Always run the TOTP check, against a fixed secret when not enrolled.
        let enrolled = secret.is_some();
        let secret = secret.unwrap_or_else(|| b"12345678901234567890".to_vec());
        let step = totp_step(&secret, &form.totp, now).filter(|_| enrolled);
        (password_ok, step)
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let required = user
        .as_ref()
        .is_some_and(|u| u.roles.contains(&Role::Approver) || u.roles.contains(&Role::Admin));
    let code_ok = step.is_some();
    let both = password_ok && required && code_ok;
    // The TOTP lock only matters once the password has verified.
    let locked = locked && password_ok;
    let success = !locked && password_ok && (!required || code_ok) && (!throttled || both);
    match second_factor {
        Some(reservation) if password_ok && required && !code_ok => reservation.commit(),
        other => drop(other),
    }
    let user = user.filter(|_| success);
    let step = if required { step } else { None };
    if user.is_some() {
        drop(failure);
    } else {
        if let Some(failure) = failure {
            failure.commit();
        }
        let (blocked, slow) = {
            let mut attempts = state
                .attempts
                .lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            // Every failure counts against its source, whatever was wrong, so the
            // delay schedule does not depend on whether the password was right.
            let blocked = source.is_some_and(|source| attempts.source_blocked(&source, now));
            if let Some(source) = source {
                attempts.source_failed(source, now);
            }
            (blocked, attempts.global_failure(now))
        };
        // A blocked address is slowed down, never told apart: every failed login
        // gets the same answer below, whatever the throttle or lock state, so
        // neither the status nor the body says whether the password was right.
        if slow || blocked {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    let Some(user) = user else {
        tracing::info!(user_id = %log_id, outcome = "login_failure");
        if html {
            return super::ui::login_error(&csrf_token);
        }
        return Ok((StatusCode::UNAUTHORIZED, "invalid credentials").into_response());
    };
    let Some(token) = state
        .sessions
        .create(&user.id, now, 43200, step)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    else {
        tracing::info!(user_id = %user.id, outcome = "login_failure");
        return Ok((StatusCode::UNAUTHORIZED, "invalid credentials").into_response());
    };
    state
        .attempts
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .accept(&user.id);
    let session = state
        .sessions
        .get(&token, now)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    tracing::info!(user_id = %user.id, outcome = "login_success");
    let mut response = if html {
        let mut response = StatusCode::SEE_OTHER.into_response();
        response
            .headers_mut()
            .insert(LOCATION, HeaderValue::from_static("/"));
        response
    } else {
        axum::Json(serde_json::json!({"csrf_token":session.csrf_token})).into_response()
    };
    add_cookie(
        &mut response,
        csrf::set_cookie("sekisho_prelogin", "", "/login", 0, state.loopback),
    )?;
    add_cookie(
        &mut response,
        csrf::set_cookie(
            "sekisho_session",
            token.expose(),
            "/",
            43200,
            state.loopback,
        ),
    )?;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
pub(super) async fn logout(
    State(state): State<AppState>,
    Extension(token): Extension<SessionToken>,
    Extension(session): Extension<super::Session>,
) -> Result<Response, StatusCode> {
    state
        .sessions
        .revoke(&token, state.clock.now())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    tracing::info!(user_id = %session.user, outcome = "logout");
    let mut response = StatusCode::OK.into_response();
    add_cookie(
        &mut response,
        csrf::set_cookie("sekisho_session", "", "/", 0, state.loopback),
    )?;
    Ok(response)
}

/// The TOTP step `code` matches for `secret` within one step of `now`.
pub(super) fn totp_step(secret: &[u8], code: &str, now: Timestamp) -> Option<u64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, secret.to_vec()).ok()?;
    let seconds = u64::try_from(now.as_secs()).ok()?;
    let mut matched = None;
    for at in [
        seconds.saturating_sub(30),
        seconds,
        seconds.saturating_add(30),
    ] {
        // Output's equality is constant time; padding fixes the input length.
        let expected = format!("{}0000", totp.generate(at));
        let provided = format!("{code}0000");
        if let (Ok(a), Ok(b)) = (
            argon2::password_hash::Output::new(expected.as_bytes()),
            argon2::password_hash::Output::new(provided.as_bytes()),
        ) && a == b
        {
            matched = Some(at / 30);
        }
    }
    matched
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn reservations_are_capped_atomically_and_refunded_on_drop() {
        let attempts = Arc::new(Mutex::new(Attempts::default()));
        let id = UserId::try_from("approver").unwrap();
        let now = Timestamp::from(1000);
        let reserve = || {
            Reservation::reserve(
                &attempts,
                second_factor_failures,
                id.clone(),
                now,
                SECOND_FACTOR_LIMIT,
            )
        };
        let held: Vec<_> = (0..20).filter_map(|_| reserve()).collect();
        assert_eq!(held.len(), 10, "concurrent reservations stop at the cap");
        // Dropped without commit (success, error, timeout, cancelled request): refunded.
        drop(held);
        for _ in 0..10 {
            reserve().unwrap().commit();
        }
        assert!(reserve().is_none());
        // Per-user failures use the same guard: five, then throttled.
        let user = Some(id.clone());
        let failures: Vec<_> = (0..8)
            .filter_map(|_| {
                Reservation::reserve(&attempts, user_failures, user.clone(), now, LOGIN_LIMIT)
            })
            .collect();
        assert_eq!(failures.len(), 5);
    }
    #[test]
    fn sources_group_ipv6_by_64_and_evict_oldest_when_full() {
        let a: std::net::IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: std::net::IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(source_key(a), source_key(b));
        assert_ne!(source_key(a), source_key(c));
        let mut attempts = Attempts::default();
        for i in 0..MAX_ENTRIES {
            let address = std::net::IpAddr::V4(std::net::Ipv4Addr::from(i as u32 + 1));
            attempts.source_failed(address, Timestamp::from(1000 + i as i64 % 100));
        }
        let fresh: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        for _ in 0..SOURCE_LIMIT {
            attempts.source_failed(fresh, Timestamp::from(1200));
        }
        assert!(
            attempts.source_blocked(&fresh, Timestamp::from(1200)),
            "a full map still tracks new addresses"
        );
        assert_eq!(attempts.sources.len(), MAX_ENTRIES);
    }
    #[test]
    fn global_failure_ceiling_only_flags_failures_past_it() {
        let mut attempts = Attempts::default();
        let now = Timestamp::from(1000);
        for _ in 0..GLOBAL_FAILURE_LIMIT {
            assert!(!attempts.global_failure(now));
        }
        assert!(attempts.global_failure(now));
        assert!(!attempts.global_failure(Timestamp::from(1900)));
    }
    #[test]
    fn client_address_trusts_only_configured_proxies() {
        let proxy: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "6.6.6.6, 203.0.113.9".parse().unwrap());
        assert_eq!(
            client_address(Some(proxy), &headers, &[proxy]),
            Some("203.0.113.9".parse().unwrap())
        );
        // No trusted proxies but a forwarded header: the peer is not a client.
        assert_eq!(client_address(Some(proxy), &headers, &[]), None);
        // A trusted proxy that names no client: skip, do not share one bucket.
        assert_eq!(
            client_address(Some(proxy), &HeaderMap::new(), &[proxy]),
            None
        );
        let direct: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            client_address(Some(direct), &headers, &[proxy]),
            Some(direct)
        );
    }
    #[test]
    fn login_attempt_map_is_bounded() {
        let mut attempts = Attempts::default();
        for i in 0..10_000 {
            assert!(attempts.reserve(
                Some(UserId::try_from(format!("user-{i}").as_str()).unwrap()),
                1000.into()
            ));
        }
        assert!(!attempts.reserve(Some(UserId::try_from("overflow").unwrap()), 1000.into()));
        assert_eq!(attempts.entries.len(), 10_000);
        for _ in 1..5 {
            assert!(attempts.reserve(Some(UserId::try_from("user-0").unwrap()), 1000.into()));
        }
        assert!(!attempts.reserve(Some(UserId::try_from("user-0").unwrap()), 1000.into()));
        assert!(attempts.reserve(Some(UserId::try_from("overflow").unwrap()), 1900.into()));
    }
    #[test]
    fn expired_attempts_are_pruned_lazily() {
        let mut attempts = Attempts::default();
        assert!(attempts.reserve(Some(UserId::try_from("old").unwrap()), 1000.into()));
        assert!(attempts.reserve(Some(UserId::try_from("recent").unwrap()), 1899.into()));
        assert!(attempts.reserve(Some(UserId::try_from("another").unwrap()), 1900.into()));
        assert_eq!(attempts.entries.len(), 3);
        assert!(attempts.reserve(Some(UserId::try_from("another").unwrap()), 1959.into()));
        assert_eq!(attempts.entries.len(), 2);
        for _ in 0..4 {
            assert!(attempts.reserve(Some(UserId::try_from("another").unwrap()), 2800.into()));
        }
    }
}
