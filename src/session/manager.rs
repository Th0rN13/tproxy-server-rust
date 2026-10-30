use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::config;
use crate::frame;
use crate::token::{self, TokenClass};

use super::{PendingClass, Session, SessionError, SessionOptions, pending_control_reserve};

#[derive(Debug, PartialEq)]
pub struct CreateResult {
    pub token: String,
    pub welcome: Vec<u8>,
    pub session: Arc<Session>,
}

#[derive(Clone)]
struct Bootstrap {
    expires: Instant,
    profile: Arc<config::Profile>,
    issuance_ip: String,
    body_digest: [u8; 32],
    session_token: String,
    session: Option<Arc<Session>>,
    used: bool,
}

#[derive(Clone, Copy)]
struct RateState {
    tokens: f64,
    last: Option<Instant>,
}

impl RateState {
    fn new() -> Self {
        Self {
            tokens: 0.0,
            last: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Metrics {
    pub sessions_created: u64,
    pub sessions_closed: u64,
    pub streams_opened: u64,
    pub streams_rejected: u64,
    pub backend_dial_failures: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub limit_hits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capacity {
    pub sessions: usize,
    pub streams: usize,
    pub backend_dials_in_flight: usize,
    pub pending_bytes: i64,
    pub pending_items: i64,
}

struct ManagerState {
    bootstraps: HashMap<[u8; 32], Bootstrap>,
    bootstraps_per_ip: HashMap<String, usize>,
    sessions: HashMap<[u8; 32], Arc<Session>>,
    closed_tokens: HashMap<[u8; 32], Instant>,
    sessions_per_ip: HashMap<String, usize>,
    sessions_per_profile: HashMap<String, usize>,
    streams_per_profile: HashMap<String, usize>,
    dials_per_profile: HashMap<String, usize>,
    bootstrap_rate: RateState,
    session_rate: RateState,
    stream_rate: RateState,
    profile_session_rates: HashMap<String, RateState>,
    profile_stream_rates: HashMap<String, RateState>,
    streams_live: usize,
    backend_dials_in_flight: usize,
    pending_global_cost: i64,
    pending_global_items: i64,
    closed: bool,
}

pub struct Manager {
    config: config::Config,
    profiles: Vec<Arc<config::Profile>>,
    token_key: [u8; 32],
    capability_prefixes: HashSet<u64>,
    state: Mutex<ManagerState>,
    cleanup_cancel: CancellationToken,
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    sessions_created: AtomicU64,
    sessions_closed: AtomicU64,
    streams_opened: AtomicU64,
    streams_rejected: AtomicU64,
    backend_dial_failures: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    limit_hits: AtomicU64,
}

impl Manager {
    pub fn new(mut value: config::Config, token_key: [u8; 32]) -> Arc<Manager> {
        let profiles: Vec<Arc<config::Profile>> = value
            .profiles
            .drain(..)
            .map(|mut profile| {
                profile.limits = profile.limits.with_defaults(&value.limits);
                Arc::new(profile)
            })
            .collect();
        let mut capability_prefixes = HashSet::with_capacity(profiles.len());
        for profile in &profiles {
            capability_prefixes.insert(capability_prefix(&profile.capability));
        }
        let manager = Arc::new(Manager {
            config: value,
            profiles,
            token_key,
            capability_prefixes,
            state: Mutex::new(ManagerState {
                bootstraps: HashMap::new(),
                bootstraps_per_ip: HashMap::new(),
                sessions: HashMap::new(),
                closed_tokens: HashMap::new(),
                sessions_per_ip: HashMap::new(),
                sessions_per_profile: HashMap::new(),
                streams_per_profile: HashMap::new(),
                dials_per_profile: HashMap::new(),
                bootstrap_rate: RateState::new(),
                session_rate: RateState::new(),
                stream_rate: RateState::new(),
                profile_session_rates: HashMap::new(),
                profile_stream_rates: HashMap::new(),
                streams_live: 0,
                backend_dials_in_flight: 0,
                pending_global_cost: 0,
                pending_global_items: 0,
                closed: false,
            }),
            cleanup_cancel: CancellationToken::new(),
            cleanup_handle: Mutex::new(None),
            sessions_created: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            streams_rejected: AtomicU64::new(0),
            backend_dial_failures: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            limit_hits: AtomicU64::new(0),
        });
        let cleanup_manager = manager.clone();
        let cleanup_cancel = manager.cleanup_cancel.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = cleanup_cancel.cancelled() => return,
                    _ = ticker.tick() => cleanup_manager.cleanup_tick(),
                }
            }
        });
        *manager.cleanup_handle.lock().unwrap() = Some(handle);
        manager
    }

    pub fn config(&self) -> &config::Config {
        &self.config
    }

    pub fn match_capability(&self, value: &[u8]) -> Option<Arc<config::Profile>> {
        if value.len() != 32 {
            return None;
        }
        if !self.capability_prefixes.contains(&capability_prefix(value)) {
            return None;
        }
        let mut matched = None;
        for profile in &self.profiles {
            if token::constant_time_eq(value, &profile.capability) {
                matched = Some(profile.clone());
            }
        }
        matched
    }

    pub fn classify_token(&self, token_text: &str) -> TokenClass {
        token::classify_token(&self.token_key, token_text)
    }

    pub fn issue_bootstrap(
        &self,
        profile: &config::Profile,
        client_ip: &str,
    ) -> Result<String, SessionError> {
        let Some(profile) = self.match_capability(&profile.capability) else {
            return Err(SessionError::Authentication);
        };
        let (bootstrap_token, hash) = token::new_token(&self.token_key, TokenClass::Bootstrap);
        let now = Instant::now();
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return Err(SessionError::Closed);
        }
        self.remove_expired_bootstraps_locked(&mut st, now);
        let limits = &self.config.limits;
        if (limits.max_bootstraps_per_ip != 0
            && st.bootstraps_per_ip.get(client_ip).copied().unwrap_or(0)
                >= limits.max_bootstraps_per_ip)
            || !allow_rate_locked(
                &mut st.bootstrap_rate,
                now,
                limits.new_bootstraps_per_minute,
                limits.new_bootstraps_burst,
            )
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(SessionError::Limit);
        }
        if st.bootstraps.len() >= limits.max_bootstraps_global
            && !self.evict_oldest_unused_bootstrap_locked(&mut st)
        {
            self.limit_hits.fetch_add(1, Ordering::Relaxed);
            return Err(SessionError::Limit);
        }
        *st.bootstraps_per_ip
            .entry(client_ip.to_string())
            .or_insert(0) += 1;
        st.bootstraps.insert(
            hash,
            Bootstrap {
                expires: now + self.config.timeouts.bootstrap_lifetime.value(),
                profile,
                issuance_ip: client_ip.to_string(),
                body_digest: [0; 32],
                session_token: String::new(),
                session: None,
                used: false,
            },
        );
        Ok(bootstrap_token)
    }

    pub fn create(
        self: &Arc<Self>,
        bootstrap_token: &str,
        client_ip: &str,
        body: &[u8],
    ) -> Result<CreateResult, SessionError> {
        if frame::parse_hello(body).is_err() {
            return Err(SessionError::Protocol);
        }
        let Some(token_hash) = token::token_hash(bootstrap_token) else {
            return Err(SessionError::Authentication);
        };
        let body_digest = sha256_digest(body);
        let now = Instant::now();

        let entry_snapshot = {
            let st = self.state.lock().unwrap();
            let Some(entry) = st.bootstraps.get(&token_hash) else {
                return Err(SessionError::Authentication);
            };
            if now > entry.expires {
                return Err(SessionError::Authentication);
            }
            entry.clone()
        };
        if entry_snapshot.used {
            let Some(session) = &entry_snapshot.session else {
                return Err(SessionError::Authentication);
            };
            if !token::constant_time_eq(&entry_snapshot.body_digest, &body_digest) {
                return Err(SessionError::Authentication);
            }
            return Ok(CreateResult {
                token: entry_snapshot.session_token.clone(),
                welcome: frame::encode(frame::FrameType::WELCOME, 0, &[]),
                session: session.clone(),
            });
        }
        let profile = entry_snapshot.profile.clone();
        let profile_limits = profile.limits;

        let created = {
            let mut st = self.state.lock().unwrap();
            let limits = &self.config.limits;
            if st.closed
                || st.sessions.len() >= limits.max_sessions_global
                || st
                    .sessions_per_profile
                    .get(&profile.name)
                    .copied()
                    .unwrap_or(0)
                    >= profile_limits.max_sessions
                || (limits.max_sessions_per_ip != 0
                    && st.sessions_per_ip.get(client_ip).copied().unwrap_or(0)
                        >= limits.max_sessions_per_ip)
            {
                self.limit_hits.fetch_add(1, Ordering::Relaxed);
                return Err(SessionError::Limit);
            }
            let ManagerState {
                session_rate,
                profile_session_rates,
                ..
            } = &mut *st;
            if !allow_profile_rate_locked(
                session_rate,
                profile_session_rates,
                &profile.name,
                now,
                RateParams {
                    per_minute: limits.new_sessions_per_minute,
                    burst: limits.new_sessions_burst,
                },
                RateParams {
                    per_minute: profile_limits.new_sessions_per_minute,
                    burst: profile_limits.new_sessions_burst,
                },
            ) {
                self.limit_hits.fetch_add(1, Ordering::Relaxed);
                return Err(SessionError::Limit);
            }
            let (session_token, session_hash) =
                token::new_token(&self.token_key, TokenClass::Session);
            let mut limits = self.config.limits.clone();
            limits.max_streams_per_session = profile_limits.max_streams_per_session;
            limits.max_pending_per_session = profile_limits.max_pending_per_session;
            let created = Session::new(
                profile.clone(),
                limits,
                self.config.timeouts,
                self.session_options(&profile, client_ip),
            );
            st.sessions.insert(session_hash, created.clone());
            *st.sessions_per_ip.entry(client_ip.to_string()).or_insert(0) += 1;
            *st.sessions_per_profile
                .entry(profile.name.clone())
                .or_insert(0) += 1;
            self.release_unused_bootstrap_locked(&mut st, &entry_snapshot);
            let entry = st.bootstraps.get_mut(&token_hash).unwrap();
            entry.used = true;
            entry.body_digest = body_digest;
            entry.session_token = session_token.clone();
            entry.session = Some(created.clone());
            self.sessions_created.fetch_add(1, Ordering::Relaxed);
            CreateResult {
                token: session_token,
                welcome: frame::encode(frame::FrameType::WELCOME, 0, &[]),
                session: created,
            }
        };
        Ok(created)
    }

    fn session_options(
        self: &Arc<Self>,
        profile: &Arc<config::Profile>,
        client_ip: &str,
    ) -> SessionOptions {
        let budget_manager = self.clone();
        let finished_manager = self.clone();
        let acquire_manager = self.clone();
        let dial_manager = self.clone();
        let stream_manager = self.clone();
        let rejected_manager = self.clone();
        let up_manager = self.clone();
        let down_manager = self.clone();
        let acquire_profile = profile.clone();
        let dial_profile = profile.clone();
        let stream_profile = profile.clone();
        SessionOptions {
            client_ip: client_ip.to_string(),
            budget: Some(Arc::new(move |cost, items, class| {
                budget_manager.change_pending_budget(cost, items, class)
            })),
            on_finished: Some(Arc::new(move |session| {
                finished_manager.session_finished(&session);
            })),
            acquire_stream: Some(Arc::new(move || {
                acquire_manager.acquire_stream(&acquire_profile)
            })),
            on_backend_dial_finished: Some(Arc::new(move |failed| {
                dial_manager.backend_dial_finished(&dial_profile, failed);
            })),
            on_stream_finished: Some(Arc::new(move || {
                stream_manager.stream_finished(&stream_profile);
            })),
            on_stream_rejected: Some(Arc::new(move || {
                rejected_manager
                    .streams_rejected
                    .fetch_add(1, Ordering::Relaxed);
                rejected_manager.limit_hits.fetch_add(1, Ordering::Relaxed);
            })),
            on_up: Some(Arc::new(move |count| {
                up_manager
                    .bytes_up
                    .fetch_add(count as u64, Ordering::Relaxed);
            })),
            on_down: Some(Arc::new(move |count| {
                down_manager
                    .bytes_down
                    .fetch_add(count as u64, Ordering::Relaxed);
            })),
        }
    }

    pub fn has_bootstrap(&self, bootstrap_token: &str) -> bool {
        let Some(hash) = token::token_hash(bootstrap_token) else {
            return false;
        };
        let now = Instant::now();
        let st = self.state.lock().unwrap();
        st.bootstraps
            .get(&hash)
            .is_some_and(|entry| now <= entry.expires)
    }

    pub fn get(&self, session_token: &str) -> Result<Arc<Session>, SessionError> {
        let Some(hash) = token::token_hash(session_token) else {
            return Err(SessionError::Authentication);
        };
        let st = self.state.lock().unwrap();
        st.sessions
            .get(&hash)
            .cloned()
            .ok_or(SessionError::Authentication)
    }

    pub fn close_token(&self, session_token: &str) -> Result<(), SessionError> {
        let Some(hash) = token::token_hash(session_token) else {
            return Err(SessionError::Authentication);
        };
        let session = {
            let st = self.state.lock().unwrap();
            match st.sessions.get(&hash).cloned() {
                Some(session) => session,
                None => {
                    return if st.closed_tokens.contains_key(&hash) {
                        Ok(())
                    } else {
                        Err(SessionError::Authentication)
                    };
                }
            }
        };
        session.close();
        Ok(())
    }

    pub fn metrics(&self) -> Metrics {
        Metrics {
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_closed: self.sessions_closed.load(Ordering::Relaxed),
            streams_opened: self.streams_opened.load(Ordering::Relaxed),
            streams_rejected: self.streams_rejected.load(Ordering::Relaxed),
            backend_dial_failures: self.backend_dial_failures.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            limit_hits: self.limit_hits.load(Ordering::Relaxed),
        }
    }

    pub fn capacity(&self) -> Capacity {
        let st = self.state.lock().unwrap();
        Capacity {
            sessions: st.sessions.len(),
            streams: st.streams_live,
            backend_dials_in_flight: st.backend_dials_in_flight,
            pending_bytes: st.pending_global_cost,
            pending_items: st.pending_global_items,
        }
    }

    pub async fn shutdown(self: &Arc<Self>) {
        let already_closed = {
            let mut st = self.state.lock().unwrap();
            let already = st.closed;
            if !already {
                st.closed = true;
                self.cleanup_cancel.cancel();
            }
            already
        };
        if already_closed {
            let handle = self.cleanup_handle.lock().unwrap().take();
            if let Some(handle) = handle {
                let _ = handle.await;
            }
            return;
        }
        let sessions = {
            let st = self.state.lock().unwrap();
            st.sessions.values().cloned().collect::<Vec<_>>()
        };
        for session in &sessions {
            session.close();
        }
        for session in &sessions {
            session.wait().await;
        }
        let handle = self.cleanup_handle.lock().unwrap().take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    fn session_finished(&self, value: &Arc<Session>) {
        let mut st = self.state.lock().unwrap();
        let mut found = None;
        for (hash, session) in st.sessions.iter() {
            if Arc::ptr_eq(session, value) {
                found = Some(*hash);
                break;
            }
        }
        if let Some(hash) = found {
            st.sessions.remove(&hash);
            if st.closed_tokens.len() >= self.config.limits.max_sessions_global * 16 {
                let oldest = st
                    .closed_tokens
                    .iter()
                    .min_by_key(|(_, expires)| *expires)
                    .map(|(hash, _)| *hash);
                if let Some(oldest) = oldest {
                    st.closed_tokens.remove(&oldest);
                }
            }
            st.closed_tokens.insert(
                hash,
                Instant::now() + self.config.timeouts.bootstrap_lifetime.value(),
            );
            decrement_counter(&mut st.sessions_per_ip, value.client_ip());
            decrement_counter(&mut st.sessions_per_profile, &value.profile().name);
        }
        let used_hashes = st
            .bootstraps
            .iter()
            .filter(|(_, entry)| {
                entry
                    .session
                    .as_ref()
                    .is_some_and(|session| Arc::ptr_eq(session, value))
            })
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        for hash in used_hashes {
            let entry = st.bootstraps.get(&hash).unwrap().clone();
            self.remove_bootstrap_locked(&mut st, hash, &entry);
        }
        drop(st);
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn acquire_stream(&self, profile: &config::Profile) -> bool {
        let now = Instant::now();
        let mut st = self.state.lock().unwrap();
        let limits = &profile.limits;
        if st.closed
            || st.streams_live >= self.config.limits.max_streams_global
            || st.backend_dials_in_flight >= self.config.limits.max_backend_dials_in_flight
            || st
                .streams_per_profile
                .get(&profile.name)
                .copied()
                .unwrap_or(0)
                >= limits.max_streams
            || st
                .dials_per_profile
                .get(&profile.name)
                .copied()
                .unwrap_or(0)
                >= limits.max_backend_dials_in_flight
        {
            return false;
        }
        let ManagerState {
            stream_rate,
            profile_stream_rates,
            ..
        } = &mut *st;
        if !allow_profile_rate_locked(
            stream_rate,
            profile_stream_rates,
            &profile.name,
            now,
            RateParams {
                per_minute: self.config.limits.new_streams_per_minute,
                burst: self.config.limits.new_streams_burst,
            },
            RateParams {
                per_minute: limits.new_streams_per_minute,
                burst: limits.new_streams_burst,
            },
        ) {
            return false;
        }
        st.streams_live += 1;
        st.backend_dials_in_flight += 1;
        *st.streams_per_profile
            .entry(profile.name.clone())
            .or_insert(0) += 1;
        *st.dials_per_profile
            .entry(profile.name.clone())
            .or_insert(0) += 1;
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn backend_dial_finished(&self, profile: &config::Profile, failed: bool) {
        let mut st = self.state.lock().unwrap();
        if st.backend_dials_in_flight == 0
            || st
                .dials_per_profile
                .get(&profile.name)
                .copied()
                .unwrap_or(0)
                == 0
        {
            panic!("invalid backend dial accounting");
        }
        st.backend_dials_in_flight -= 1;
        decrement_counter(&mut st.dials_per_profile, &profile.name);
        drop(st);
        if failed {
            self.backend_dial_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn stream_finished(&self, profile: &config::Profile) {
        let mut st = self.state.lock().unwrap();
        if st.streams_live == 0
            || st
                .streams_per_profile
                .get(&profile.name)
                .copied()
                .unwrap_or(0)
                == 0
        {
            panic!("invalid stream accounting");
        }
        st.streams_live -= 1;
        decrement_counter(&mut st.streams_per_profile, &profile.name);
    }

    pub fn change_pending_budget(
        &self,
        cost_delta: i64,
        item_delta: i64,
        class: PendingClass,
    ) -> bool {
        let mut st = self.state.lock().unwrap();
        if cost_delta > 0 || item_delta > 0 {
            let mut cost_limit = self.config.limits.max_pending_global as i64;
            let mut item_limit = self.config.limits.max_pending_items_global as i64;
            if class != PendingClass::Control {
                let (reserve_cost, reserve_items) = pending_control_reserve(&self.config.limits);
                let sessions = self.config.limits.max_sessions_global as i64;
                if reserve_cost > cost_limit / sessions {
                    cost_limit = 0;
                } else {
                    cost_limit -= reserve_cost * sessions;
                }
                if reserve_items > item_limit / sessions {
                    item_limit = 0;
                } else {
                    item_limit -= reserve_items * sessions;
                }
            }
            if cost_delta > cost_limit || st.pending_global_cost > cost_limit - cost_delta {
                self.limit_hits.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if item_delta > item_limit || st.pending_global_items > item_limit - item_delta {
                self.limit_hits.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        st.pending_global_cost += cost_delta;
        st.pending_global_items += item_delta;
        if st.pending_global_cost < 0 || st.pending_global_items < 0 {
            panic!("negative global pending budget");
        }
        true
    }

    fn release_unused_bootstrap_locked(&self, st: &mut ManagerState, entry: &Bootstrap) {
        if entry.used {
            return;
        }
        decrement_counter(&mut st.bootstraps_per_ip, &entry.issuance_ip);
    }

    fn remove_bootstrap_locked(&self, st: &mut ManagerState, hash: [u8; 32], entry: &Bootstrap) {
        self.release_unused_bootstrap_locked(st, entry);
        st.bootstraps.remove(&hash);
    }

    fn evict_oldest_unused_bootstrap_locked(&self, st: &mut ManagerState) -> bool {
        let oldest = st
            .bootstraps
            .iter()
            .filter(|(_, entry)| !entry.used)
            .min_by_key(|(_, entry)| entry.expires)
            .map(|(hash, _)| *hash);
        let Some(hash) = oldest else {
            return false;
        };
        let entry = st.bootstraps.get(&hash).unwrap().clone();
        self.remove_bootstrap_locked(st, hash, &entry);
        true
    }

    fn cleanup_tick(self: &Arc<Self>) {
        let now = Instant::now();
        let sessions = {
            let mut st = self.state.lock().unwrap();
            self.remove_expired_bootstraps_locked(&mut st, now);
            st.sessions.values().cloned().collect::<Vec<_>>()
        };
        let grace = self.config.timeouts.reconnect_grace.value();
        for session in sessions {
            if now.duration_since(session.last_activity()) > grace {
                session.close();
            }
        }
    }

    pub(crate) fn remove_expired_bootstraps(&self, now: Instant) {
        let mut st = self.state.lock().unwrap();
        self.remove_expired_bootstraps_locked(&mut st, now);
    }

    fn remove_expired_bootstraps_locked(&self, st: &mut ManagerState, now: Instant) {
        let expired = st
            .bootstraps
            .iter()
            .filter(|(_, entry)| now > entry.expires)
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        for hash in expired {
            let entry = st.bootstraps.get(&hash).unwrap().clone();
            self.remove_bootstrap_locked(st, hash, &entry);
        }
        let expired_tokens = st
            .closed_tokens
            .iter()
            .filter(|(_, expires)| now > **expires)
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        for hash in expired_tokens {
            st.closed_tokens.remove(&hash);
        }
    }
}

fn capability_prefix(capability: &[u8]) -> u64 {
    u64::from_le_bytes(capability[..8].try_into().unwrap())
}

fn decrement_counter(map: &mut HashMap<String, usize>, key: &str) {
    if let Some(count) = map.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            map.remove(key);
        }
    }
}

fn allow_rate_locked(
    state: &mut RateState,
    now: Instant,
    per_minute: usize,
    burst_limit: usize,
) -> bool {
    let (updated, allowed) = take_rate(*state, now, per_minute, burst_limit);
    *state = updated;
    allowed
}

#[derive(Clone, Copy)]
struct RateParams {
    per_minute: usize,
    burst: usize,
}

fn allow_profile_rate_locked(
    global: &mut RateState,
    profiles: &mut HashMap<String, RateState>,
    profile: &str,
    now: Instant,
    global_params: RateParams,
    profile_params: RateParams,
) -> bool {
    let (updated_global, global_allowed) =
        take_rate(*global, now, global_params.per_minute, global_params.burst);
    let profile_state = profiles
        .entry(profile.to_string())
        .or_insert_with(RateState::new);
    let (updated_profile, profile_allowed) = take_rate(
        *profile_state,
        now,
        profile_params.per_minute,
        profile_params.burst,
    );
    if !global_allowed || !profile_allowed {
        return false;
    }
    *global = updated_global;
    profiles.insert(profile.to_string(), updated_profile);
    true
}

fn take_rate(
    mut state: RateState,
    now: Instant,
    per_minute: usize,
    burst_limit: usize,
) -> (RateState, bool) {
    let burst = burst_limit as f64;
    match state.last {
        None => {
            state.tokens = burst;
            state.last = Some(now);
        }
        Some(last) => {
            let per_second = per_minute as f64 / 60.0;
            state.tokens += now.duration_since(last).as_secs_f64() * per_second;
            if state.tokens > burst {
                state.tokens = burst;
            }
            state.last = Some(now);
        }
    }
    if state.tokens < 1.0 {
        return (state, false);
    }
    state.tokens -= 1.0;
    (state, true)
}

fn sha256_digest(body: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(body).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn hex_bytes(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn hello() -> Vec<u8> {
        frame::encode(frame::FrameType::HELLO, 0, &[1])
    }

    fn test_config(backend: &str) -> config::Config {
        let mut value = config::Config::default();
        value.timeouts.backend_dial = config::Duration::from_millis(20);
        let secret = hex_bytes("000102030405060708090a0b0c0d0e0f");
        value.profiles.push(config::Profile {
            name: "default".to_string(),
            backend: backend.to_string(),
            carrier_mode: config::CarrierMode::Https,
            capability: config::derive_capability("proxy.example.com", "", &secret),
            limits: config::ProfileLimits::default(),
        });
        value
    }

    fn test_manager(backend: &str) -> (config::Config, Arc<Manager>) {
        let value = test_config(backend);
        let manager = Manager::new(value.clone(), [1u8; 32]);
        (value, manager)
    }

    async fn wait_for(condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !condition() {
            assert!(
                std::time::Instant::now() < deadline,
                "condition was not reached"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn previous_release_class(key: &[u8; 32], token: &str) -> TokenClass {
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(token) else {
            return TokenClass::External;
        };
        if decoded.len() != 32 {
            return TokenClass::External;
        }
        for kind in [TokenClass::Bootstrap, TokenClass::Session] {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
            mac.update(b"tproxy-server-token-v1\x00");
            mac.update(&[kind as u8]);
            mac.update(&decoded[..16]);
            if decoded[16..] == mac.finalize().into_bytes()[..16] {
                return kind;
            }
        }
        TokenClass::External
    }

    #[tokio::test]
    async fn token_provenance_survives_expiry_and_restart() {
        let (value, manager) = test_manager("127.0.0.1:1");
        let bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "127.0.0.1")
            .unwrap();
        let created = manager.create(&bootstrap, "127.0.0.1", &hello()).unwrap();
        created.session.close();
        wait_for(|| manager.capacity().sessions == 0).await;
        manager.remove_expired_bootstraps(Instant::now() + Duration::from_secs(3600));
        assert!(!manager.has_bootstrap(&bootstrap));
        assert!(manager.get(&created.token).is_err());
        let (_, restarted) = test_manager("127.0.0.1:1");
        let other = Manager::new(test_config("127.0.0.1:1"), [3u8; 32]);
        for (token_text, want) in [
            (&bootstrap, TokenClass::Bootstrap),
            (&created.token, TokenClass::Session),
        ] {
            assert_eq!(token_text.len(), 43);
            assert_eq!(manager.classify_token(token_text), want);
            assert_eq!(restarted.classify_token(token_text), want);
            assert_eq!(other.classify_token(token_text), TokenClass::External);
            let mut decoded = URL_SAFE_NO_PAD.decode(token_text).unwrap();
            for index in 0..decoded.len() {
                decoded[index] ^= 1;
                assert_eq!(
                    manager.classify_token(&URL_SAFE_NO_PAD.encode(&decoded)),
                    TokenClass::External
                );
                decoded[index] ^= 1;
            }
        }
        assert!(restarted.create(&bootstrap, "127.0.0.1", &hello()).is_err());
        manager.shutdown().await;
        restarted.shutdown().await;
        other.shutdown().await;
    }

    #[tokio::test]
    async fn previous_release_recognizes_tagged_tokens() {
        let (value, manager) = test_manager("127.0.0.1:1");
        let bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.9")
            .unwrap();
        let created = manager
            .create(&bootstrap, "198.51.100.9", &hello())
            .unwrap();
        assert_eq!(
            previous_release_class(&[1u8; 32], &bootstrap),
            TokenClass::Bootstrap
        );
        assert_eq!(
            previous_release_class(&[1u8; 32], &created.token),
            TokenClass::Session
        );
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn bootstrap_limits_expiry_and_consumption() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_bootstraps_per_ip = 2;
        value.limits.max_bootstraps_global = 3;
        value.limits.new_bootstraps_burst = 10;
        value.limits.new_bootstraps_per_minute = 600;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let profile = &value.profiles[0];
        let first = manager.issue_bootstrap(profile, "198.51.100.11").unwrap();
        manager.issue_bootstrap(profile, "198.51.100.11").unwrap();
        assert_eq!(
            manager.issue_bootstrap(profile, "198.51.100.11"),
            Err(SessionError::Limit)
        );
        manager.create(&first, "198.51.100.11", &hello()).unwrap();
        manager
            .issue_bootstrap(profile, "198.51.100.11")
            .expect("using a bootstrap did not release its per-IP slot");

        let mut expiring_config = test_config("127.0.0.1:1");
        expiring_config.limits.max_bootstraps_per_ip = 1;
        expiring_config.timeouts.bootstrap_lifetime = config::Duration::from_millis(1);
        let expiring = Manager::new(expiring_config.clone(), [1u8; 32]);
        let expired = expiring
            .issue_bootstrap(&expiring_config.profiles[0], "198.51.100.12")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(3)).await;
        expiring
            .issue_bootstrap(&expiring_config.profiles[0], "198.51.100.12")
            .expect("expired bootstrap retained its slot");
        assert_eq!(
            expiring.create(&expired, "198.51.100.12", &hello()),
            Err(SessionError::Authentication)
        );
        manager.shutdown().await;
        expiring.shutdown().await;
    }

    #[tokio::test]
    async fn bootstrap_survives_changing_client_address() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_bootstraps_per_ip = 1;
        value.limits.max_sessions_per_ip = 1;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let profile = &value.profiles[0];
        let bootstrap = manager.issue_bootstrap(profile, "198.51.100.31").unwrap();
        let created = manager
            .create(&bootstrap, "198.51.100.32", &hello())
            .expect("rotating egress rejected the bootstrap");
        let retried = manager
            .create(&bootstrap, "198.51.100.33", &hello())
            .expect("rotating egress rejected an identical retry");
        assert_eq!(retried.token, created.token);
        assert!(Arc::ptr_eq(&retried.session, &created.session));
        manager
            .issue_bootstrap(profile, "198.51.100.31")
            .expect("consumption did not release the issuing address slot");
        let second = manager.issue_bootstrap(profile, "198.51.100.34").unwrap();
        assert_eq!(
            manager.create(&second, "198.51.100.32", &hello()),
            Err(SessionError::Limit)
        );
        manager
            .create(&second, "198.51.100.35", &hello())
            .expect("an address change could not recover from a per-IP limit");
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn bootstrap_rate_is_global() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_bootstraps_per_ip = 10;
        value.limits.max_bootstraps_global = 10;
        value.limits.new_bootstraps_burst = 2;
        value.limits.new_bootstraps_per_minute = 1;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let profile = &value.profiles[0];
        manager.issue_bootstrap(profile, "198.51.100.13").unwrap();
        manager.issue_bootstrap(profile, "198.51.100.13").unwrap();
        assert_eq!(
            manager.issue_bootstrap(profile, "198.51.100.14"),
            Err(SessionError::Limit)
        );
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn global_bootstrap_pool_evicts_oldest_unused_entry() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_bootstraps_global = 2;
        value.limits.new_bootstraps_burst = 10;
        value.limits.new_bootstraps_per_minute = 600;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let profile = &value.profiles[0];
        let oldest = manager.issue_bootstrap(profile, "198.51.100.13").unwrap();
        manager.issue_bootstrap(profile, "198.51.100.13").unwrap();
        manager
            .issue_bootstrap(profile, "198.51.100.14")
            .expect("global bootstrap pool did not evict an unused entry");
        assert_eq!(
            manager.create(&oldest, "198.51.100.13", &hello()),
            Err(SessionError::Authentication)
        );
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn disabled_per_ip_session_limit_allows_shared_address() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_sessions_per_ip = 0;
        value.limits.max_sessions_global = 8;
        value.limits.new_sessions_burst = 8;
        value.limits.new_sessions_per_minute = 600;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        for index in 0..5 {
            let bootstrap = manager
                .issue_bootstrap(&value.profiles[0], "198.51.100.20")
                .unwrap();
            manager
                .create(&bootstrap, "198.51.100.20", &hello())
                .unwrap_or_else(|_| panic!("shared source address was limited at session {index}"));
        }
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn profile_session_limit_does_not_consume_global_capacity() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_sessions_global = 4;
        value.limits.new_sessions_burst = 10;
        value.limits.new_sessions_per_minute = 600;
        value.profiles[0].limits.max_sessions = 1;
        value.profiles.push(config::Profile {
            name: "second".to_string(),
            backend: "127.0.0.1:1".to_string(),
            carrier_mode: config::CarrierMode::Https,
            capability: config::derive_capability(
                "proxy.example.com",
                "",
                &hex_bytes("101112131415161718191a1b1c1d1e1f"),
            ),
            limits: config::ProfileLimits::default(),
        });
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let first_bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.22")
            .unwrap();
        manager
            .create(&first_bootstrap, "198.51.100.22", &hello())
            .unwrap();
        let limited_bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.23")
            .unwrap();
        assert_eq!(
            manager.create(&limited_bootstrap, "198.51.100.23", &hello()),
            Err(SessionError::Limit)
        );
        let second_bootstrap = manager
            .issue_bootstrap(&value.profiles[1], "198.51.100.24")
            .unwrap();
        manager
            .create(&second_bootstrap, "198.51.100.24", &hello())
            .expect("one profile's limit blocked another profile");
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn session_creation_rate_is_global() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.new_sessions_burst = 1;
        value.limits.new_sessions_per_minute = 1;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        for (index, client_ip) in ["198.51.100.25", "198.51.100.26"].iter().enumerate() {
            let bootstrap = manager
                .issue_bootstrap(&value.profiles[0], client_ip)
                .unwrap();
            let created = manager.create(&bootstrap, client_ip, &hello());
            if index == 0 {
                assert!(created.is_ok());
            } else {
                assert_eq!(created, Err(SessionError::Limit));
            }
        }
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn stream_limit_rejects_only_the_new_stream() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_streams_global = 1;
        value.limits.max_backend_dials_in_flight = 1;
        value.limits.new_streams_burst = 10;
        value.limits.new_streams_per_minute = 600;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.21")
            .unwrap();
        let created = manager
            .create(&bootstrap, "198.51.100.21", &hello())
            .unwrap();
        let mut body = frame::encode(frame::FrameType::OPEN, 30, &[]);
        body.extend_from_slice(&frame::encode(frame::FrameType::OPEN, 31, &[]));
        created.session.process_up(1, &body).unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = created.session.poll(&cancel, 0).await.unwrap();
        let frames = frame::parse_all(&outcome.body, frame::MAX_PAYLOAD).unwrap();
        assert!(
            frames
                .iter()
                .any(|value| value.frame_type == frame::FrameType::CLOSE && value.stream_id == 31),
            "rejected stream did not receive CLOSE: {frames:?}"
        );
        assert!(manager.get(&created.token).is_ok());
        let metrics = manager.metrics();
        assert_eq!(metrics.streams_opened, 1);
        assert_eq!(metrics.streams_rejected, 1);
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn backend_dial_limit_reopens_after_dial_completes() {
        let mut value = test_config("127.0.0.1:1");
        value.limits.max_streams_global = 2;
        value.limits.max_backend_dials_in_flight = 1;
        value.limits.new_streams_burst = 10;
        value.limits.new_streams_per_minute = 600;
        let manager = Manager::new(value.clone(), [1u8; 32]);
        let profile = manager
            .match_capability(&value.profiles[0].capability)
            .unwrap();
        assert!(manager.acquire_stream(&profile));
        assert!(!manager.acquire_stream(&profile));
        manager.backend_dial_finished(&profile, false);
        assert!(manager.acquire_stream(&profile));
        manager.backend_dial_finished(&profile, false);
        manager.stream_finished(&profile);
        manager.stream_finished(&profile);
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn session_close_stops_backend_goroutines() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((connection, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(500)).await;
                drop(connection);
            }
        });
        let (value, manager) = test_manager(&addr);
        let bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.10")
            .unwrap();
        let created = manager
            .create(&bootstrap, "198.51.100.10", &hello())
            .unwrap();
        created
            .session
            .process_up(1, &frame::encode(frame::FrameType::OPEN, 14, &[]))
            .unwrap();
        wait_for(|| manager.capacity().backend_dials_in_flight == 0).await;
        let started = std::time::Instant::now();
        manager.shutdown().await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "manager shutdown stranded a backend goroutine"
        );
        assert_eq!(manager.capacity().pending_bytes, 0);
        assert_eq!(manager.capacity().pending_items, 0);
    }

    #[tokio::test]
    async fn backend_eof_closes_only_its_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((connection, _)) = listener.accept().await {
                drop(connection);
            }
        });
        let (value, manager) = test_manager(&addr);
        let bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.15")
            .unwrap();
        let created = manager
            .create(&bootstrap, "198.51.100.15", &hello())
            .unwrap();
        created
            .session
            .process_up(1, &frame::encode(frame::FrameType::OPEN, 17, &[]))
            .unwrap();
        wait_for(|| {
            let st = created.session.inner.lock().unwrap();
            !st.streams.contains_key(&17)
        })
        .await;
        let cancel = tokio_util::sync::CancellationToken::new();
        let outcome = created.session.poll(&cancel, 0).await.unwrap();
        let frames = frame::parse_all(&outcome.body, frame::MAX_PAYLOAD).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, frame::FrameType::CLOSE);
        assert_eq!(frames[0].stream_id, 17);
        assert!(manager.get(&created.token).is_ok());
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn protocol_failure_removes_session_from_manager() {
        let (value, manager) = test_manager("127.0.0.1:1");
        let bootstrap = manager
            .issue_bootstrap(&value.profiles[0], "198.51.100.9")
            .unwrap();
        let created = manager
            .create(&bootstrap, "198.51.100.9", &hello())
            .unwrap();
        let first = frame::encode(frame::FrameType::OPEN, 1, &[]);
        assert_eq!(created.session.process_up(1, &first), Ok(1));
        let changed = frame::encode(frame::FrameType::CLOSE, 1, &[]);
        assert_eq!(
            created.session.process_up(1, &changed),
            Err(SessionError::Protocol)
        );
        wait_for(|| manager.get(&created.token).is_err()).await;
        manager.shutdown().await;
    }
}
