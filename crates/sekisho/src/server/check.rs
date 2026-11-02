use super::{AppState, Clock};
use crate::notifications::Notifications;
use crate::store::{AuditRecord, Store, StoreError};
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use rand_core::{OsRng, RngCore};
use sekisho_core::{
    Action, AgentId, Approval, ApprovalId, ApprovalState, AuditKind, BudgetView, Decision,
    DecisionKind, Digest, GrantView, Policy, Principal, PublicKey, Signer, Timestamp, ToolName,
    decide,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("could not read policy")]
    Io(#[from] std::io::Error),
    #[error("invalid policy")]
    Policy(#[from] sekisho_core::PolicyError),
    #[error("check storage unavailable")]
    Store(#[from] StoreError),
    #[error("check state unavailable")]
    Unavailable,
    #[error("approval TTL must be between 60 and 86400 seconds")]
    InvalidTtl,
    #[error("grant signer does not match the configured grant public key")]
    GrantSignerMismatch,
}

struct LoadedPolicy {
    path: PathBuf,
    text: String,
    policy: Policy,
    loaded_at: Timestamp,
}

pub(super) struct PolicyView {
    pub path: PathBuf,
    pub text: String,
    pub sha256: Digest,
    pub loaded_at: Timestamp,
}

/// Server-owned policy, signing trust, and approval configuration.
/// Load this before serving, and attach it with `AppState::with_check_api`.
pub struct CheckApi {
    pub(super) store: Arc<Store>,
    policy: RwLock<LoadedPolicy>,
    grant_key: PublicKey,
    grant_signer: Option<Arc<dyn Signer + Send + Sync>>,
    ttl_seconds: u32,
    waiters: Mutex<HashMap<ApprovalId, Weak<watch::Sender<()>>>>,
    waiting: Mutex<HashMap<AgentId, usize>>,
    notifications: Option<Arc<Notifications>>,
    protected: Vec<String>,
}
impl CheckApi {
    pub fn load(
        store: Arc<Store>,
        path: &Path,
        grant_key: PublicKey,
        ttl_seconds: Option<u32>,
        actor: &Principal,
        now: Timestamp,
    ) -> Result<Self, CheckError> {
        Self::load_with_audit(store, path, grant_key, ttl_seconds, now, |store, policy| {
            audit_policy(store, policy, actor, now)
        })
    }

    /// Audit bootstrap credentials and the initial policy together before serving.
    pub fn load_for_startup(
        store: Arc<Store>,
        path: &Path,
        grant_key: PublicKey,
        ttl_seconds: Option<u32>,
        admin: Option<&super::User>,
        now: Timestamp,
    ) -> Result<Self, CheckError> {
        Self::load_with_audit(store, path, grant_key, ttl_seconds, now, |store, policy| {
            store.startup(admin, policy.sha256, now)
        })
    }

    fn load_with_audit(
        store: Arc<Store>,
        path: &Path,
        grant_key: PublicKey,
        ttl_seconds: Option<u32>,
        loaded_at: Timestamp,
        audit: impl FnOnce(&Store, &Policy) -> Result<(), StoreError>,
    ) -> Result<Self, CheckError> {
        let ttl_seconds = ttl_seconds.unwrap_or(900);
        if !(60..=86400).contains(&ttl_seconds) {
            return Err(CheckError::InvalidTtl);
        }
        let text = read_policy_file(path)?;
        let policy = Policy::parse(text.as_bytes())?;
        audit(&store, &policy)?;
        Ok(Self {
            store,
            policy: RwLock::new(LoadedPolicy {
                path: path.to_owned(),
                text,
                policy,
                loaded_at,
            }),
            grant_key,
            grant_signer: None,
            ttl_seconds,
            waiters: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            notifications: None,
            protected: Vec::new(),
        })
    }

    /// Deny every `hook:` action targeting `dir` (as given and canonicalized), on
    /// this policy and on every reload. Policy files and grants cannot override it.
    pub fn with_protected_dir(mut self, dir: &Path) -> Result<Self, CheckError> {
        let mut paths = Vec::new();
        if dir.is_absolute() {
            paths.push(dir.to_owned());
        }
        if let Ok(real) = std::fs::canonicalize(dir) {
            paths.push(real);
        }
        let mut loaded = self.policy.write().map_err(|_| CheckError::Unavailable)?;
        for path in paths {
            let path = path.to_str().ok_or(CheckError::Unavailable)?.to_owned();
            if !self.protected.contains(&path) {
                loaded.policy.protect_dir(&path)?;
                self.protected.push(path);
            }
        }
        drop(loaded);
        Ok(self)
    }

    pub fn with_grant_signer(
        mut self,
        signer: Arc<dyn Signer + Send + Sync>,
    ) -> Result<Self, CheckError> {
        if signer.public_key() != self.grant_key {
            return Err(CheckError::GrantSignerMismatch);
        }
        self.grant_signer = Some(signer);
        Ok(self)
    }

    pub fn with_notifications(mut self, notifications: Arc<Notifications>) -> Self {
        self.notifications = Some(notifications);
        self
    }

    pub(super) fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    pub(super) fn grant_signer(&self) -> Option<Arc<dyn Signer + Send + Sync>> {
        self.grant_signer.clone()
    }

    pub(super) fn policy_view(&self) -> Result<PolicyView, CheckError> {
        let loaded = self.policy.read().map_err(|_| CheckError::Unavailable)?;
        Ok(PolicyView {
            path: loaded.path.clone(),
            text: loaded.text.clone(),
            sha256: loaded.policy.sha256,
            loaded_at: loaded.loaded_at,
        })
    }

    /// Publish only after the load's audit transaction commits. Invalid loads keep the old policy.
    pub fn reload_policy(
        &self,
        path: &Path,
        actor: &Principal,
        now: Timestamp,
    ) -> Result<(), CheckError> {
        self.reload_policy_with_totp(path, actor, now, None)
    }

    pub(super) fn reload_policy_with_totp(
        &self,
        path: &Path,
        actor: &Principal,
        now: Timestamp,
        totp: Option<(&sekisho_core::UserId, u64)>,
    ) -> Result<(), CheckError> {
        let text = read_policy_file(path)?;
        let mut next = Policy::parse(text.as_bytes())?;
        for dir in &self.protected {
            next.protect_dir(dir)?;
        }
        let mut policy = self.policy.write().map_err(|_| CheckError::Unavailable)?;
        self.store
            .record_policy_load(next.sha256, actor, now, totp)?;
        *policy = LoadedPolicy {
            path: path.to_owned(),
            text,
            policy: next,
            loaded_at: now,
        };
        Ok(())
    }

    pub(super) fn precheck(
        &self,
        action: &Action,
        clock: &dyn Clock,
    ) -> Result<Decision, CheckError> {
        let loaded = self.policy.read().map_err(|_| CheckError::Unavailable)?;
        let policy = &loaded.policy;
        Ok(self.store.transact_with_time(
            || clock.now(),
            |tx, now| {
                let stored = tx.grant_views_for(action.agent_id(), now)?;
                let grants = grant_views(&stored);
                let usage = budget_usage(tx, action.agent_id(), policy, now)?;
                let used = |rule: &str| usage.get(rule).copied().unwrap_or(0);
                let decision = decide(
                    action,
                    policy,
                    &grants,
                    &self.grant_key,
                    &BudgetView { used: &used },
                    now,
                );
                Ok((decision, vec![]))
            },
        )?)
    }

    pub(super) fn check(
        &self,
        action: Action,
        clock: &dyn Clock,
    ) -> Result<CheckResponse, CheckError> {
        self.check_all(action.agent_id().clone(), vec![action], clock)?
            .pop()
            .ok_or(CheckError::Unavailable)
    }

    pub(super) fn check_all(
        &self,
        agent: AgentId,
        actions: Vec<Action>,
        clock: &dyn Clock,
    ) -> Result<Vec<CheckResponse>, CheckError> {
        if actions.iter().any(|action| action.agent_id() != &agent) {
            return Err(CheckError::Unavailable);
        }
        let loaded = self.policy.read().map_err(|_| CheckError::Unavailable)?;
        let policy = &loaded.policy;
        let (responses, created) = self.store.transact_with_time(|| clock.now(), |tx, now| {
            let mut stored = tx.grant_views_for(&agent, now)?;
            let mut consumed_uses: BTreeMap<_, _> = stored.iter().map(|view| (view.grant.id().as_str().to_owned(), view.uses)).collect();
            let mut usage = budget_usage(tx, &agent, policy, now)?;
            let mut reserved_approvals = std::collections::HashSet::new();
            let mut pending = tx.pending_count(&agent)?;
            let mut planned = Vec::with_capacity(actions.len());
            let mut all_allowed = true;
            for action in actions {
                let grants = grant_views(&stored);
                let used = |rule: &str| usage.get(rule).copied().unwrap_or(0);
                let decision = decide(&action, policy, &grants, &self.grant_key, &BudgetView { used: &used }, now);
                let digest = action.digest()?;
                let approved = if decision.kind == DecisionKind::Ask {
                    tx.approved_for_digest(&digest)?
                        .filter(|id| reserved_approvals.insert(id.as_str().to_owned()))
                } else { None };
                // An agent may hold a bounded number of pending approvals, so a flood
                // cannot fill the inbox or the notification queue. Past the cap a new
                // request is refused and creates nothing.
                let decision = if decision.kind == DecisionKind::Ask && approved.is_none() {
                    if pending >= MAX_PENDING_PER_AGENT {
                        Decision { kind: DecisionKind::Deny, grant: None, reason: "too many pending approvals".into(), ..decision }
                    } else {
                        pending += 1;
                        decision
                    }
                } else { decision };
                if decision.kind == DecisionKind::Allow {
                    if let Some(id) = &decision.grant {
                        let view = stored.iter_mut().find(|view| view.grant.id() == id).ok_or(StoreError::InvalidGrant)?;
                        view.uses = view.uses.checked_add(1).ok_or(StoreError::InvalidGrant)?;
                    } else if let Some(rule) = decision.rule.as_deref()
                        && let Some(used) = usage.get_mut(rule)
                    {
                        *used = used.checked_add(1).ok_or(StoreError::InvalidBudgetCounter)?;
                    }
                } else if approved.is_none() {
                    all_allowed = false;
                }
                planned.push((action, digest, decision, approved));
            }
            let actor = Principal::Agent(agent.clone());
            let mut records = Vec::new();
            let mut created = Vec::new();
            let mut responses = Vec::with_capacity(planned.len());
            for (action, digest, decision, approved) in planned {
                let kind = match decision.kind {
                    DecisionKind::Allow => "allow", DecisionKind::Ask => "ask", DecisionKind::Deny => "deny",
                };
                records.push(AuditRecord {
                    kind: AuditKind::ActionRequested, actor: actor.clone(),
                    subject: json!({"action_digest":digest, "tool":action.tool(), "target":action.target()}),
                });
                records.push(AuditRecord {
                    kind: AuditKind::Decided, actor: actor.clone(),
                    subject: json!({"action_digest":digest, "decision":kind, "rule":decision.rule,
                        "grant":decision.grant.as_ref().map(|id|id.as_str()), "reason":decision.reason}),
                });
                let mut response = CheckResponse {
                    decision: kind, reason: Some(decision.reason), approval_id: None, expires_at: None,
                    rule: decision.rule.clone(),
                };
                match decision.kind {
                    DecisionKind::Allow if all_allowed => {
                        if let Some(id) = &decision.grant {
                            let count = consumed_uses.get_mut(id.as_str()).ok_or(StoreError::InvalidGrant)?;
                            *count = count.checked_add(1).ok_or(StoreError::InvalidGrant)?;
                            tx.record_grant_use(id)?;
                            records.push(AuditRecord {
                                kind: AuditKind::Consumed, actor: actor.clone(),
                                subject: json!({"grant_id":id.as_str(), "uses":*count, "action_digest":digest}),
                            });
                        } else if let Some(rule) = policy.rules.iter().find(|rule| Some(&rule.name) == decision.rule.as_ref())
                            && let Some(budget) = rule.budget
                        {
                            tx.record_budget_use(&agent, &rule.name, budget, now)?;
                        }
                    }
                    DecisionKind::Ask => {
                        if let Some(id) = approved {
                            let approval = if all_allowed {
                                let (consumed, record) = tx.consume_approval(&id, &digest)?;
                                records.push(record);
                                consumed
                            } else {
                                tx.get_approval(&id)?.ok_or(StoreError::InvalidApproval)?
                            };
                            response = CheckResponse::from_consumed(&approval);
                        } else {
                            let approval = Approval::request(random_id()?, action,
                                decision.rule.ok_or(StoreError::InvalidApproval)?, now, self.ttl_seconds)?;
                            tx.insert_approval(&approval)?;
                            created.push(approval.clone());
                            records.push(approval_record(&approval, actor.clone()));
                            response.approval_id = Some(approval.id().as_str().to_owned());
                            response.expires_at = Some(approval.expires_at());
                        }
                    }
                    _ => {}
                }
                responses.push(response);
            }
            Ok(((responses, created), records))
        })?;
        drop(loaded);
        if let Some(notifications) = &self.notifications {
            notifications.enqueue_created(&created);
        }
        Ok(responses)
    }

    fn subscribe(
        &self,
        id: &ApprovalId,
    ) -> Result<(Arc<watch::Sender<()>>, watch::Receiver<()>), CheckError> {
        let mut waiters = self.waiters.lock().map_err(|_| CheckError::Unavailable)?;
        waiters.retain(|_, sender| sender.strong_count() > 0);
        let sender = waiters.get(id).and_then(Weak::upgrade).unwrap_or_else(|| {
            let sender = Arc::new(watch::channel(()).0);
            waiters.insert(id.clone(), Arc::downgrade(&sender));
            sender
        });
        let receiver = sender.subscribe();
        Ok((sender, receiver))
    }

    pub(super) fn notify(&self, id: &ApprovalId) {
        // Persistence is authoritative. A notification is only a hint to reread it.
        if let Ok(waiters) = self.waiters.lock()
            && let Some(sender) = waiters.get(id).and_then(Weak::upgrade)
        {
            sender.send_replace(());
        }
    }

    fn refresh(&self, id: &ApprovalId, clock: &dyn Clock) -> Result<Approval, StoreError> {
        self.store.transact_with_time(
            || clock.now(),
            |tx, now| {
                let approval = tx.get_approval(id)?.ok_or(StoreError::InvalidApproval)?;
                if matches!(
                    approval.state(),
                    ApprovalState::Pending | ApprovalState::Approved
                ) && now >= approval.expires_at()
                {
                    let expired = approval.expire(now)?;
                    tx.update_approval(&expired)?;
                    let record = approval_record(
                        &expired,
                        Principal::Agent(expired.action().agent_id().clone()),
                    );
                    Ok((expired, vec![record]))
                } else {
                    Ok((approval, vec![]))
                }
            },
        )
    }

    async fn wait(
        self: Arc<Self>,
        id: ApprovalId,
        digest: Digest,
        seconds: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<CheckResponse, StatusCode> {
        let (_sender, mut receiver) = self
            .subscribe(&id)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds.min(600));
        loop {
            let api = self.clone();
            let approval_id = id.clone();
            let transaction_clock = clock.clone();
            let response = tokio::task::spawn_blocking(move || {
                let approval = api.refresh(&approval_id, transaction_clock.as_ref())?;
                if approval.state() != ApprovalState::Approved {
                    return Ok(CheckResponse::from_approval(&approval));
                }
                let action = approval.action().clone();
                if action.digest().map_err(|_| CheckError::Unavailable)? != digest {
                    return Err(CheckError::Unavailable);
                }
                // The world may have changed while the agent waited: decide
                // again, as a new request would. `check` consumes the approval
                // only if the current policy still asks for it.
                if !api.store.list_agents()?.contains(action.agent_id()) {
                    return Ok(CheckResponse {
                        decision: "deny",
                        reason: Some("agent removed".into()),
                        approval_id: None,
                        expires_at: None,
                        rule: None,
                    });
                }
                api.check(action, transaction_clock.as_ref())
            })
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if response.decision != "ask" || tokio::time::Instant::now() >= deadline {
                return Ok(response);
            }
            let remaining = response
                .expires_at
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                .as_secs()
                .saturating_sub(clock.now().as_secs())
                .max(0) as u64;
            let wake = deadline.min(tokio::time::Instant::now() + Duration::from_secs(remaining));
            tokio::select! {
                result = receiver.changed() => { result.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?; }
                _ = tokio::time::sleep_until(wake) => {}
            }
        }
    }

    fn wait_slot(self: &Arc<Self>, agent: &AgentId) -> Option<WaitSlot> {
        let mut waiting = self.waiting.lock().ok()?;
        let count = waiting.entry(agent.clone()).or_insert(0);
        if *count >= MAX_WAITERS_PER_AGENT {
            return None;
        }
        *count += 1;
        Some(WaitSlot {
            api: self.clone(),
            agent: agent.clone(),
        })
    }

    pub(super) async fn authorize_action(
        self: Arc<Self>,
        action: Action,
        seconds: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<CheckResponse, StatusCode> {
        let digest = action
            .digest()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let agent = action.agent_id().clone();
        let api = self.clone();
        let transaction_clock = clock.clone();
        let response =
            tokio::task::spawn_blocking(move || api.check(action, transaction_clock.as_ref()))
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if seconds > 0
            && response.decision == "ask"
            && let Some(id) = &response.approval_id
        {
            let id =
                ApprovalId::try_from(id.as_str()).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let Some(_slot) = self.wait_slot(&agent) else {
                return Ok(response);
            };
            return self.wait(id, digest, seconds, clock).await;
        }
        Ok(response)
    }
}

/// Read the policy file only if nobody but Sekisho's own user could have
/// written it: a regular file (not a symlink) owned by this process's user,
/// without group or world write permission, in a directory owned by this user
/// that is not group or world writable. The file is opened once and every check
/// runs on that descriptor; a swap between the `lstat` and the `open` changes
/// the inode and is refused.
fn read_policy_file(path: &Path) -> Result<String, CheckError> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let refused = |message: &str| CheckError::Io(std::io::Error::other(message.to_owned()));
    let uid = process_uid()?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = std::fs::metadata(parent)?;
    if directory.uid() != uid || directory.permissions().mode() & 0o022 != 0 {
        return Err(refused(
            "policy directory must be owned by Sekisho's user and not group or world writable",
        ));
    }
    let linked = std::fs::symlink_metadata(path)?;
    if !linked.is_file() {
        return Err(refused("policy file must be a regular file, not a symlink"));
    }
    // std opens with O_CLOEXEC.
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.dev() != linked.dev() || metadata.ino() != linked.ino() || !metadata.is_file() {
        return Err(refused("policy file changed while it was being opened"));
    }
    if metadata.uid() != uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(refused(
            "policy file must be owned by Sekisho's user and not group or world writable",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

/// This process's effective uid: the owner of a file it creates. std has no
/// direct API and the approved dependencies do not include libc.
fn process_uid() -> Result<u32, CheckError> {
    use std::os::unix::fs::MetadataExt;
    static UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    if let Some(uid) = UID.get() {
        return Ok(*uid);
    }
    let mut name = [0u8; 16];
    OsRng.fill_bytes(&mut name);
    let probe = std::env::temp_dir().join(format!(
        "sekisho-uid-{}",
        name.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    let uid = file.metadata();
    std::fs::remove_file(&probe)?;
    let uid = uid?.uid();
    Ok(*UID.get_or_init(|| uid))
}

/// Live pending approvals one agent may hold.
const MAX_PENDING_PER_AGENT: u32 = 20;
/// Requests one agent may have waiting for approval at once; more return
/// `ask` immediately instead of waiting.
const MAX_WAITERS_PER_AGENT: usize = 16;

/// One of an agent's waiting slots, released on drop.
struct WaitSlot {
    api: Arc<CheckApi>,
    agent: AgentId,
}
impl Drop for WaitSlot {
    fn drop(&mut self) {
        if let Ok(mut waiting) = self.api.waiting.lock()
            && let Some(count) = waiting.get_mut(&self.agent)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                waiting.remove(&self.agent);
            }
        }
    }
}

fn budget_usage<'a>(
    tx: &crate::store::Tx<'_>,
    agent: &AgentId,
    policy: &'a Policy,
    now: Timestamp,
) -> Result<BTreeMap<&'a str, u32>, StoreError> {
    let mut usage = BTreeMap::new();
    for rule in &policy.rules {
        if let Some(budget) = rule.budget {
            usage.insert(
                rule.name.as_str(),
                tx.budget_used(agent, &rule.name, budget, now)?,
            );
        }
    }
    Ok(usage)
}

fn grant_views(stored: &[crate::store::GrantView]) -> Vec<GrantView<'_>> {
    stored
        .iter()
        .map(|view| GrantView {
            grant: &view.grant,
            uses: view.uses,
            revoked: view.revoked,
        })
        .collect()
}

fn audit_policy(
    store: &Store,
    policy: &Policy,
    actor: &Principal,
    now: Timestamp,
) -> Result<(), StoreError> {
    store.transact(now, |_| {
        Ok((
            (),
            vec![AuditRecord {
                kind: AuditKind::PolicyLoaded,
                actor: actor.clone(),
                subject: json!({"policy_sha256":policy.sha256}),
            }],
        ))
    })
}

fn random_id() -> Result<ApprovalId, StoreError> {
    let mut bytes = [0; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StoreError::TokenGeneration)?;
    let mut number = u128::from_be_bytes(bytes);
    let alphabet = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut suffix = String::with_capacity(26);
    for _ in 0..26 {
        suffix.push(char::from(alphabet[(number & 31) as usize]));
        number >>= 5;
    }
    Ok(ApprovalId::try_from(format!("apr_{suffix}").as_str())?)
}

pub(super) fn approval_record(approval: &Approval, actor: Principal) -> AuditRecord {
    let kind = match approval.state() {
        ApprovalState::Pending => AuditKind::ApprovalRequested,
        ApprovalState::Approved => AuditKind::Approved,
        ApprovalState::Denied => AuditKind::Denied,
        ApprovalState::Expired => AuditKind::Expired,
        ApprovalState::Consumed => AuditKind::Consumed,
    };
    AuditRecord {
        kind,
        actor,
        subject: json!({"approval_id":approval.id().as_str(), "action_digest":approval.action_digest(), "state":format!("{:?}", approval.state())}),
    }
}

#[derive(Deserialize)]
pub(super) struct CheckRequest {
    tool: ToolName,
    target: String,
    params: Value,
}
#[derive(Default, Deserialize)]
pub(super) struct WaitQuery {
    #[serde(default)]
    wait: u64,
}
#[derive(Serialize)]
pub(super) struct CheckResponse {
    pub(super) decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    #[serde(skip)]
    pub(super) rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<Timestamp>,
}
impl CheckResponse {
    fn from_consumed(approval: &Approval) -> Self {
        Self {
            decision: "allow",
            rule: None,
            reason: Some("approved".into()),
            approval_id: Some(approval.id().as_str().to_owned()),
            expires_at: Some(approval.expires_at()),
        }
    }
    fn from_approval(approval: &Approval) -> Self {
        let (decision, reason) = match approval.state() {
            ApprovalState::Pending => ("ask", "approval required"),
            ApprovalState::Approved => ("ask", "approval requires consumption"),
            ApprovalState::Denied => ("deny", "approval denied"),
            ApprovalState::Expired => ("expired", "approval expired"),
            ApprovalState::Consumed => ("deny", "approval already consumed"),
        };
        Self {
            decision,
            rule: None,
            reason: Some(reason.into()),
            approval_id: Some(approval.id().as_str().to_owned()),
            expires_at: Some(approval.expires_at()),
        }
    }
}
pub(super) async fn check(
    State(state): State<AppState>,
    Extension(agent): Extension<AgentId>,
    Query(query): Query<WaitQuery>,
    Json(body): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, StatusCode> {
    let checks = state.checks.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let action = Action::new(agent, body.tool, body.target, body.params)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    checks
        .authorize_action(action, query.wait, state.clock)
        .await
        .map(Json)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::server::{InMemorySessions, InMemoryUsers, Session, approvals};
    use axum::extract::Path;
    use sekisho_core::{CoreError, Ed25519Signer, Signature, Signer, UserId};

    /// SEK-02 follow-up: only a policy file nobody else could have written loads.
    #[test]
    fn policy_file_must_be_private_to_sekisho() {
        use std::os::unix::fs::PermissionsExt;
        let mut name = [0u8; 8];
        OsRng.fill_bytes(&mut name);
        let dir = std::env::temp_dir().join(format!("sekisho-policy-{}", u64::from_le_bytes(name)));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "version = 1\n").unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_policy_file(&policy).unwrap(), "version = 1\n");

        let real = dir.join("real.toml");
        std::fs::rename(&policy, &real).unwrap();
        std::os::unix::fs::symlink(&real, &policy).unwrap();
        assert!(read_policy_file(&policy).is_err(), "symlink");
        std::fs::remove_file(&policy).unwrap();
        std::fs::rename(&real, &policy).unwrap();

        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(read_policy_file(&policy).is_err(), "group-writable file");
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            read_policy_file(&policy).is_err(),
            "world-writable directory"
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_policy_file(&policy).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
    use std::sync::atomic::{AtomicBool, Ordering};

    struct BlockingSigner {
        inner: Ed25519Signer,
        block: AtomicBool,
        entered: tokio::sync::Notify,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Signer for BlockingSigner {
        fn key_id(&self) -> &str {
            self.inner.key_id()
        }
        fn public_key(&self) -> PublicKey {
            self.inner.public_key()
        }
        fn sign(&self, message: &[u8]) -> Result<Signature, CoreError> {
            if self.block.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.lock().unwrap().recv().unwrap();
            }
            self.inner.sign(message)
        }
    }
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            100.into()
        }
    }

    fn batch_fixture(policy: &str) -> (CheckApi, Arc<Ed25519Signer>, std::path::PathBuf) {
        use std::hash::BuildHasher;
        let suffix = std::hash::RandomState::new().hash_one(policy);
        let dir =
            std::env::temp_dir().join(format!("sekisho-batch-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, policy).unwrap();
        let signer = Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]));
        let store = Arc::new(Store::open(&dir.join("store.db"), signer.clone()).unwrap());
        let actor = Principal::User(UserId::try_from("admin").unwrap());
        let api =
            CheckApi::load(store, &path, signer.public_key(), None, &actor, 100.into()).unwrap();
        (api, signer, dir)
    }

    fn batch_action(target: &str) -> Action {
        Action::new(
            AgentId::try_from("claude").unwrap(),
            ToolName::try_from("git.push").unwrap(),
            target.into(),
            json!({}),
        )
        .unwrap()
    }

    #[test]
    fn reloaded_policy_governs_precheck_batch_and_single_action() {
        let allow = "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ndecision = 'allow'\n";
        let (api, signer, dir) = batch_fixture(allow);
        let api = api.with_grant_signer(signer).unwrap();
        assert!(api.grant_signer().is_some());
        let actor = Principal::User(UserId::try_from("admin").unwrap());
        let path = dir.join("policy.toml");
        for (text, expected, kind) in [
            (allow, "allow", DecisionKind::Allow),
            ("version = 1", "deny", DecisionKind::Deny),
            (allow, "allow", DecisionKind::Allow),
        ] {
            std::fs::write(&path, text).unwrap();
            api.reload_policy(&path, &actor, 100.into()).unwrap();
            assert_eq!(
                api.policy_view().unwrap().sha256,
                Policy::parse(text.as_bytes()).unwrap().sha256
            );
            let action = batch_action("repo:a");
            assert_eq!(api.precheck(&action, &FixedClock).unwrap().kind, kind);
            let responses = api
                .check_all(
                    action.agent_id().clone(),
                    vec![action.clone(), batch_action("repo:b")],
                    &FixedClock,
                )
                .unwrap();
            assert_eq!(responses.len(), 2);
            assert!(
                responses
                    .iter()
                    .all(|response| response.decision == expected)
            );
            assert_eq!(api.check(action, &FixedClock).unwrap().decision, expected);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mixed_push_does_not_burn_approvals() {
        let (api, _, dir) = batch_fixture(
            "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ndecision = 'ask'\n",
        );
        let first = batch_action("repo:a");
        let response = api.check(first.clone(), &FixedClock).unwrap();
        let id = ApprovalId::try_from(response.approval_id.as_deref().unwrap()).unwrap();
        let approved = api
            .store
            .approval(&id)
            .unwrap()
            .unwrap()
            .approve(
                &Principal::User(UserId::try_from("admin").unwrap()),
                100.into(),
            )
            .unwrap();
        api.store
            .transact(100.into(), |tx| {
                tx.update_approval(&approved)?;
                Ok((
                    (),
                    vec![approval_record(
                        &approved,
                        Principal::User(UserId::try_from("admin").unwrap()),
                    )],
                ))
            })
            .unwrap();
        let responses = api
            .check_all(
                first.agent_id().clone(),
                vec![first.clone(), batch_action("repo:b")],
                &FixedClock,
            )
            .unwrap();
        assert!(responses.iter().any(|response| response.decision == "ask"));
        assert_eq!(
            api.store.approval(&id).unwrap().unwrap().state(),
            ApprovalState::Approved
        );
        assert_eq!(api.check(first, &FixedClock).unwrap().decision, "allow");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mixed_push_does_not_burn_budget() {
        let (api, _, dir) = batch_fixture(
            "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ntarget = 'repo:a'\ndecision = 'allow'\nbudget = { max = 1, per = '1h' }\n",
        );
        let first = batch_action("repo:a");
        let responses = api
            .check_all(
                first.agent_id().clone(),
                vec![first.clone(), batch_action("repo:b")],
                &FixedClock,
            )
            .unwrap();
        assert!(responses.iter().any(|response| response.decision == "deny"));
        let audit = api.store.audit_snapshot().unwrap();
        assert_eq!(
            audit
                .iter()
                .filter(|entry| entry.kind() == AuditKind::ActionRequested)
                .count(),
            2
        );
        assert_eq!(
            audit
                .iter()
                .filter(|entry| entry.kind() == AuditKind::Decided)
                .count(),
            2
        );
        assert_eq!(api.check(first, &FixedClock).unwrap().decision, "allow");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn batch_budget_counts_every_ref_and_rolls_back_exhaustion() {
        let (api, _, dir) = batch_fixture(
            "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ndecision = 'allow'\nbudget = { max = 1, per = '1h' }\n",
        );
        let first = batch_action("repo:a");
        let responses = api
            .check_all(
                first.agent_id().clone(),
                vec![first.clone(), batch_action("repo:b")],
                &FixedClock,
            )
            .unwrap();
        assert!(responses.iter().any(|response| response.decision == "deny"));
        assert_eq!(
            api.check(first.clone(), &FixedClock).unwrap().decision,
            "allow"
        );
        assert_eq!(api.check(first, &FixedClock).unwrap().decision, "deny");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mixed_push_does_not_burn_grant() {
        use sekisho_core::{GrantId, UnsignedGrant};
        let (api, signer, dir) = batch_fixture("version = 1");
        let first = batch_action("repo:a");
        let grant = UnsignedGrant {
            id: GrantId::try_from("grt_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            agent_id: first.agent_id().clone(),
            tool: first.tool().clone(),
            target_glob: "repo:a".into(),
            params: BTreeMap::new(),
            not_before: 100.into(),
            expires_at: 160.into(),
            max_uses: Some(1),
            issued_by: UserId::try_from("admin").unwrap(),
        }
        .sign(signer.as_ref())
        .unwrap();
        api.store.issue_grant(&grant, 100.into()).unwrap();
        let responses = api
            .check_all(
                first.agent_id().clone(),
                vec![first.clone(), batch_action("repo:b")],
                &FixedClock,
            )
            .unwrap();
        assert!(responses.iter().any(|response| response.decision == "deny"));
        assert_eq!(api.store.list_grants().unwrap()[0].uses, 0);
        assert_eq!(api.check(first, &FixedClock).unwrap().decision, "allow");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn successful_batch_consumes_every_grant_use() {
        use sekisho_core::{GrantId, UnsignedGrant};
        let (api, signer, dir) = batch_fixture("version = 1");
        let first = batch_action("repo:a");
        let grant = UnsignedGrant {
            id: GrantId::try_from("grt_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            agent_id: first.agent_id().clone(),
            tool: first.tool().clone(),
            target_glob: "repo:*".into(),
            params: BTreeMap::new(),
            not_before: 100.into(),
            expires_at: 160.into(),
            max_uses: Some(2),
            issued_by: UserId::try_from("admin").unwrap(),
        }
        .sign(signer.as_ref())
        .unwrap();
        api.store.issue_grant(&grant, 100.into()).unwrap();
        let responses = api
            .check_all(
                first.agent_id().clone(),
                vec![first.clone(), batch_action("repo:b")],
                &FixedClock,
            )
            .unwrap();
        assert!(
            responses
                .iter()
                .all(|response| response.decision == "allow")
        );
        assert_eq!(api.store.list_grants().unwrap()[0].uses, 2);
        assert_eq!(api.check(first, &FixedClock).unwrap().decision, "deny");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn batch_cannot_reuse_single_approval_for_duplicate_action() {
        let (api, _, dir) = batch_fixture(
            "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ndecision = 'ask'\n",
        );
        let first = batch_action("repo:a");
        let response = api.check(first.clone(), &FixedClock).unwrap();
        let id = ApprovalId::try_from(response.approval_id.as_deref().unwrap()).unwrap();
        let actor = Principal::User(UserId::try_from("admin").unwrap());
        let approved = api
            .store
            .approval(&id)
            .unwrap()
            .unwrap()
            .approve(&actor, 100.into())
            .unwrap();
        api.store
            .transact(100.into(), |tx| {
                tx.update_approval(&approved)?;
                Ok(((), vec![approval_record(&approved, actor)]))
            })
            .unwrap();
        let responses = api
            .check_all(
                first.agent_id().clone(),
                vec![first.clone(), first],
                &FixedClock,
            )
            .unwrap();
        assert!(responses.iter().any(|response| response.decision == "ask"));
        assert_eq!(
            api.store.approval(&id).unwrap().unwrap().state(),
            ApprovalState::Approved
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn precheck_has_no_audit_approval_or_budget_side_effects() {
        let (api, _, dir) = batch_fixture(
            "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ntarget = 'repo:a'\ndecision = 'allow'\nbudget = { max = 1, per = '1h' }\n[[rule]]\nname = 'ask'\ntool = 'git.push'\ndecision = 'ask'\n",
        );
        let audits = api.store.audit_snapshot().unwrap().len();
        for _ in 0..2 {
            assert_eq!(
                api.precheck(&batch_action("repo:a"), &FixedClock)
                    .unwrap()
                    .kind,
                DecisionKind::Allow
            );
            assert_eq!(
                api.precheck(&batch_action("repo:b"), &FixedClock)
                    .unwrap()
                    .kind,
                DecisionKind::Ask
            );
        }
        assert_eq!(api.store.audit_snapshot().unwrap().len(), audits);
        assert!(api.store.pending_approvals(100.into()).unwrap().is_empty());
        assert_eq!(
            api.check(batch_action("repo:a"), &FixedClock)
                .unwrap()
                .decision,
            "allow"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cancelled_approval_handler_still_notifies_after_commit() {
        use std::hash::BuildHasher;
        let suffix = std::hash::RandomState::new().hash_one("cancel-check");
        let dir =
            std::env::temp_dir().join(format!("sekisho-cancel-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(
            &path,
            "version = 1\n[[rule]]\nname = 'push'\ntool = 'git.push'\ndecision = 'ask'\n",
        )
        .unwrap();
        let (release, receive) = std::sync::mpsc::channel();
        let signer = Arc::new(BlockingSigner {
            inner: Ed25519Signer::from_secret_bytes("audit", &[7; 32]),
            block: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: Mutex::new(receive),
        });
        let store = Arc::new(Store::open(&dir.join("store.db"), signer.clone()).unwrap());
        let actor = Principal::User(UserId::try_from("admin").unwrap());
        let api = Arc::new(
            CheckApi::load(store, &path, signer.public_key(), None, &actor, 100.into()).unwrap(),
        );
        let action = Action::new(
            AgentId::try_from("claude").unwrap(),
            ToolName::try_from("git.push").unwrap(),
            "repo".into(),
            json!({}),
        )
        .unwrap();
        let response = api.check(action, &FixedClock).unwrap();
        let id = ApprovalId::try_from(response.approval_id.as_deref().unwrap()).unwrap();
        let (_sender, mut receiver) = api.subscribe(&id).unwrap();
        let state = AppState::new(
            Arc::new(InMemoryUsers::default()),
            Arc::new(InMemorySessions::default()),
            Arc::new(FixedClock),
            true,
        )
        .unwrap()
        .with_check_api(api.clone());
        let session = Session {
            user: UserId::try_from("admin").unwrap(),
            csrf_token: String::new(),
            expires_at: 1000.into(),
        };
        signer.block.store(true, Ordering::SeqCst);
        let handler = tokio::spawn(approvals::approve(
            State(state),
            Extension(session),
            Path(id.as_str().to_owned()),
            axum::http::HeaderMap::new(),
        ));
        signer.entered.notified().await;
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        let notified = tokio::time::timeout(Duration::from_secs(1), receiver.changed()).await;
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            notified.is_ok(),
            "committed approval did not wake its waiter after cancellation"
        );
        assert_eq!(
            api.refresh(&id, &FixedClock).unwrap().state(),
            ApprovalState::Approved
        );
    }
    #[test]
    fn queued_grant_check_uses_transaction_time() {
        use sekisho_core::{GrantId, UnsignedGrant};
        use std::{
            hash::BuildHasher,
            sync::{atomic::AtomicI64, mpsc},
        };
        struct MovingClock(AtomicI64, mpsc::Sender<()>);
        impl Clock for MovingClock {
            fn now(&self) -> Timestamp {
                let now = self.0.load(Ordering::SeqCst);
                self.1.send(()).unwrap();
                now.into()
            }
        }
        let suffix = std::hash::RandomState::new().hash_one("queued-check");
        let dir =
            std::env::temp_dir().join(format!("sekisho-queued-{}-{suffix}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, "version = 1").unwrap();
        let signer = Arc::new(Ed25519Signer::from_secret_bytes("audit", &[7; 32]));
        let store = Arc::new(Store::open(&dir.join("store.db"), signer.clone()).unwrap());
        let actor = Principal::User(UserId::try_from("admin").unwrap());
        let api = Arc::new(
            CheckApi::load(
                store.clone(),
                &path,
                signer.public_key(),
                None,
                &actor,
                100.into(),
            )
            .unwrap(),
        );
        let grant = UnsignedGrant {
            id: GrantId::try_from("grt_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            agent_id: AgentId::try_from("claude").unwrap(),
            tool: ToolName::try_from("git.push").unwrap(),
            target_glob: "repo".into(),
            params: BTreeMap::new(),
            not_before: 100.into(),
            expires_at: 160.into(),
            max_uses: Some(1),
            issued_by: UserId::try_from("admin").unwrap(),
        }
        .sign(signer.as_ref())
        .unwrap();
        store.transact(100.into(), |tx| { tx.insert_grant(&grant)?; Ok(((), vec![AuditRecord { kind: AuditKind::GrantIssued, actor, subject: json!({"grant_id":grant.id().as_str(),"agent_id":grant.agent_id().as_str(),"issued_by":grant.issued_by().as_str(),"expires_at":grant.expires_at()}) }])) }).unwrap();
        let (held, locked) = mpsc::channel();
        let (release, receive) = mpsc::channel();
        let holding = store.clone();
        let holder = std::thread::spawn(move || {
            holding
                .transact(100.into(), |_| {
                    held.send(()).unwrap();
                    receive.recv().unwrap();
                    Ok(((), vec![]))
                })
                .unwrap()
        });
        locked.recv().unwrap();
        let (sampled, samples) = mpsc::channel();
        let clock = Arc::new(MovingClock(AtomicI64::new(100), sampled));
        let worker_clock = clock.clone();
        let worker = std::thread::spawn(move || {
            api.check(
                Action::new(
                    AgentId::try_from("claude").unwrap(),
                    ToolName::try_from("git.push").unwrap(),
                    "repo".into(),
                    json!({}),
                )
                .unwrap(),
                worker_clock.as_ref(),
            )
            .unwrap()
        });
        // Old code samples before waiting. Correct code cannot sample until the lock is released.
        let _ = samples.recv_timeout(Duration::from_millis(50));
        clock.0.store(200, Ordering::SeqCst);
        release.send(()).unwrap();
        holder.join().unwrap();
        let response = worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert_eq!(
            response.decision, "deny",
            "grant expired while the check was waiting for the transaction"
        );
    }
}
