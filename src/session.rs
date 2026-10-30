use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::frame;

pub mod manager;

const QUEUE_ITEM_COST: i64 = 256;
const CONTROL_RESERVE_EXTRA_ITEMS: usize = 16;
const CONTROL_RESERVE_ITEMS_PER_STREAM: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingClass {
    Uplink,
    Downlink,
    Control,
}

pub type BudgetFn = dyn Fn(i64, i64, PendingClass) -> bool + Send + Sync;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("authentication failed")]
    Authentication,
    #[error("temporary backpressure")]
    Backpressure,
    #[error("resource limit reached")]
    Limit,
    #[error("protocol error")]
    Protocol,
    #[error("concurrent request")]
    Concurrent,
    #[error("session closed")]
    Closed,
    #[error("request cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollOutcome {
    pub body: Vec<u8>,
    pub next_cursor: u64,
    pub lane_closed: bool,
}

fn empty_poll(cursor: u64) -> PollOutcome {
    PollOutcome {
        body: Vec::new(),
        next_cursor: cursor,
        lane_closed: false,
    }
}

fn lane_closed_poll(cursor: u64) -> PollOutcome {
    PollOutcome {
        body: Vec::new(),
        next_cursor: cursor,
        lane_closed: true,
    }
}

#[derive(Default)]
pub struct SessionOptions {
    pub client_ip: String,
    pub budget: Option<Arc<BudgetFn>>,
    pub on_finished: Option<Arc<dyn Fn(Arc<Session>) + Send + Sync>>,
    pub acquire_stream: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub on_backend_dial_finished: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    pub on_stream_finished: Option<Arc<dyn Fn() + Send + Sync>>,
    pub on_stream_rejected: Option<Arc<dyn Fn() + Send + Sync>>,
    pub on_up: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    pub on_down: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

struct QueuedFrame {
    encoded: Vec<u8>,
    type_code: frame::FrameType,
    stream_id: u32,
    cost: i64,
}

struct DownBatch {
    body: Vec<u8>,
    cost: i64,
    items: usize,
}

pub struct StreamState {
    backend: Arc<BackendStream>,
    receive_window: u32,
    send_credit: u64,
    pending_write_bytes: i64,
    pending_write_cost: i64,
    pending_write_items: i64,
    credit_notify: Arc<Notify>,
    writes: VecDeque<Vec<u8>>,
    write_notify: Arc<Notify>,
}

static LANE_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_lane_generation() -> u64 {
    LANE_GENERATION.fetch_add(1, Ordering::Relaxed)
}

struct CarrierLane {
    generation: u64,
    last_up_sequence: u64,
    last_up_digest: [u8; 32],
    up_active: bool,
    websocket_active: bool,
    pending_frames: VecDeque<QueuedFrame>,
    pending_windows: HashMap<u32, usize>,
    unacked: Vec<u8>,
    unacked_cost: i64,
    unacked_items: i64,
    unacked_base: u64,
    down_cursor: u64,
    down_active: bool,
    superseded: Option<CancellationToken>,
    notify: Arc<Notify>,
}

fn new_carrier_lane() -> CarrierLane {
    CarrierLane {
        generation: next_lane_generation(),
        last_up_sequence: 0,
        last_up_digest: [0; 32],
        up_active: false,
        websocket_active: false,
        pending_frames: VecDeque::new(),
        pending_windows: HashMap::new(),
        unacked: Vec::new(),
        unacked_cost: 0,
        unacked_items: 0,
        unacked_base: 0,
        down_cursor: 0,
        down_active: false,
        superseded: None,
        notify: Arc::new(Notify::new()),
    }
}

struct SessionState {
    streams: HashMap<u32, StreamState>,
    closed_streams: HashMap<u32, ()>,
    closed_order: VecDeque<u32>,
    pending_frames: VecDeque<QueuedFrame>,
    pending_windows: HashMap<u32, usize>,
    pending_cost: i64,
    pending_items: i64,
    unacked: Vec<u8>,
    unacked_cost: i64,
    unacked_items: i64,
    unacked_base: u64,
    down_cursor: u64,
    last_up_sequence: u64,
    last_up_digest: [u8; 32],
    up_active: bool,
    down_active: bool,
    superseded: Option<CancellationToken>,
    websocket_active: bool,
    closed: bool,
    finished_fired: bool,
    last_activity: Instant,
    carrier_lanes: HashMap<u32, CarrierLane>,
}

pub struct Session {
    profile: Arc<config::Profile>,
    client_ip: String,
    limits: config::Limits,
    timeouts: config::Timeouts,
    budget: Option<Arc<BudgetFn>>,
    carrier: config::CarrierMode,
    inner: Mutex<SessionState>,
    cancel: CancellationToken,
    notify: Notify,
    budget_notify: Notify,
    backend_counter: Arc<TaskCounter>,
    on_finished: Option<Arc<dyn Fn(Arc<Session>) + Send + Sync>>,
    acquire_stream: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    on_backend_dial_finished: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    on_stream_finished: Option<Arc<dyn Fn() + Send + Sync>>,
    on_stream_rejected: Option<Arc<dyn Fn() + Send + Sync>>,
    on_up: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    on_down: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Session {
    pub fn new(
        profile: Arc<config::Profile>,
        limits: config::Limits,
        timeouts: config::Timeouts,
        options: SessionOptions,
    ) -> Arc<Session> {
        let carrier = profile.carrier_mode;
        let mut carrier_lanes = HashMap::new();
        if carrier == config::CarrierMode::HttpsLanes {
            carrier_lanes.insert(0, new_carrier_lane());
        }
        Arc::new(Session {
            profile,
            client_ip: options.client_ip,
            limits,
            timeouts,
            budget: options.budget,
            carrier,
            inner: Mutex::new(SessionState {
                streams: HashMap::new(),
                closed_streams: HashMap::new(),
                closed_order: VecDeque::new(),
                pending_frames: VecDeque::new(),
                pending_windows: HashMap::new(),
                pending_cost: 0,
                pending_items: 0,
                unacked: Vec::new(),
                unacked_cost: 0,
                unacked_items: 0,
                unacked_base: 0,
                down_cursor: 0,
                last_up_sequence: 0,
                last_up_digest: [0; 32],
                up_active: false,
                down_active: false,
                superseded: None,
                websocket_active: false,
                closed: false,
                finished_fired: false,
                last_activity: Instant::now(),
                carrier_lanes,
            }),
            cancel: CancellationToken::new(),
            notify: Notify::new(),
            budget_notify: Notify::new(),
            backend_counter: Arc::new(TaskCounter::default()),
            on_finished: options.on_finished,
            acquire_stream: options.acquire_stream,
            on_backend_dial_finished: options.on_backend_dial_finished,
            on_stream_finished: options.on_stream_finished,
            on_stream_rejected: options.on_stream_rejected,
            on_up: options.on_up,
            on_down: options.on_down,
        })
    }

    pub fn carrier_mode(&self) -> config::CarrierMode {
        self.carrier
    }

    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }

    pub fn profile(&self) -> &Arc<config::Profile> {
        &self.profile
    }

    pub fn acquire_websocket(self: &Arc<Self>) -> bool {
        let mut st = self.inner.lock().unwrap();
        if st.closed || self.carrier != config::CarrierMode::WebSocket || st.websocket_active {
            return false;
        }
        st.websocket_active = true;
        true
    }

    pub fn acquire_websocket_lane(self: &Arc<Self>, lane_id: u32) -> bool {
        let mut st = self.inner.lock().unwrap();
        if st.closed
            || self.carrier != config::CarrierMode::WebSocketLanes
            || lane_id == 0
            || lane_id > frame::MAX_STREAM_ID
        {
            return false;
        }
        if st.closed_streams.contains_key(&lane_id) {
            return false;
        }
        if !st.carrier_lanes.contains_key(&lane_id) {
            if st.carrier_lanes.len() >= self.limits.max_streams_per_session {
                return false;
            }
            st.carrier_lanes.insert(lane_id, new_carrier_lane());
        }
        let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
        if lane.websocket_active {
            return false;
        }
        lane.websocket_active = true;
        st.last_activity = Instant::now();
        true
    }

    pub fn release_websocket_lane(self: &Arc<Self>, lane_id: u32) {
        let mut backend = None;
        {
            let mut st = self.inner.lock().unwrap();
            if self.carrier != config::CarrierMode::WebSocketLanes {
                return;
            }
            let Some(lane) = st.carrier_lanes.get_mut(&lane_id) else {
                return;
            };
            lane.websocket_active = false;
            if let Some(state) = st.streams.get(&lane_id) {
                backend = Some(state.backend.clone());
            }
            let (cost, items) = match st.streams.get(&lane_id) {
                Some(state) => (state.pending_write_cost, state.pending_write_items),
                None => (0, 0),
            };
            release_stream_writes(&mut st, lane_id);
            release_pending_locked(self, &mut st, cost, items);
            st.streams.remove(&lane_id);
            remember_closed_locked(self, &mut st, lane_id);
            st.carrier_lanes.remove(&lane_id);
            st.last_activity = Instant::now();
        }
        if let Some(backend) = backend {
            backend.close();
        }
    }

    pub fn process_up(self: &Arc<Self>, sequence: u64, body: &[u8]) -> Result<u64, SessionError> {
        if self.uses_carrier_lanes() {
            return Err(SessionError::Protocol);
        }
        let digest = sha256_digest(body);
        {
            let mut st = self.inner.lock().unwrap();
            if st.closed {
                return Err(SessionError::Closed);
            }
            st.last_activity = Instant::now();
            if sequence == st.last_up_sequence && sequence != 0 {
                let matches = digest == st.last_up_digest;
                drop(st);
                if !matches {
                    self.protocol_failure();
                    return Err(SessionError::Protocol);
                }
                return Ok(sequence);
            }
            if sequence != st.last_up_sequence + 1 || sequence == 0 {
                drop(st);
                self.protocol_failure();
                return Err(SessionError::Protocol);
            }
            if st.up_active {
                return Err(SessionError::Concurrent);
            }
            st.up_active = true;
        }

        let frames = match parse_and_shape(body, self.limits.max_frame_payload) {
            Ok(frames) => frames,
            Err(()) => {
                self.protocol_failure();
                return Err(SessionError::Protocol);
            }
        };

        let outcome = {
            let mut st = self.inner.lock().unwrap();
            st.up_active = false;
            if st.closed {
                return Err(SessionError::Closed);
            }
            if !self.validate_batch_locked(&st, &frames) {
                drop(st);
                self.protocol_failure();
                return Err(SessionError::Protocol);
            }
            let (reserved_cost, reserved_items) =
                self.backend_write_reservation_locked(&st, &frames);
            if (reserved_cost != 0 || reserved_items != 0)
                && !self.reserve_pending_locked(
                    &mut st,
                    reserved_cost,
                    reserved_items,
                    PendingClass::Uplink,
                )
            {
                return Err(SessionError::Backpressure);
            }
            let (opened, closed, unused_cost, unused_items, applied) =
                self.apply_batch_locked(&mut st, &frames, reserved_cost, reserved_items);
            if unused_cost != 0 || unused_items != 0 {
                release_pending_locked(self, &mut st, unused_cost, unused_items);
            }
            if applied {
                st.last_up_sequence = sequence;
                st.last_up_digest = digest;
            }
            for backend in &closed {
                backend.close();
            }
            for _ in 0..opened.len() {
                self.backend_counter.acquire();
            }
            (opened, applied)
        };
        for backend in outcome.0 {
            self.spawn_backend(backend);
        }
        if !outcome.1 {
            self.close();
            return Err(SessionError::Closed);
        }
        if let Some(on_up) = &self.on_up {
            on_up(body.len());
        }
        Ok(sequence)
    }

    pub fn process_up_lane(
        self: &Arc<Self>,
        lane_id: u32,
        sequence: u64,
        body: &[u8],
    ) -> Result<u64, SessionError> {
        if !self.uses_carrier_lanes() || lane_id > frame::MAX_STREAM_ID {
            return Err(SessionError::Protocol);
        }
        let digest = sha256_digest(body);
        let frames = match parse_and_shape_lane(body, self.limits.max_frame_payload, lane_id) {
            Ok(frames) => frames,
            Err(()) => {
                self.lane_protocol_failure(lane_id);
                return Err(SessionError::Protocol);
            }
        };

        enum LaneReplay {
            Body(Vec<u8>, u64),
            Fail,
            Release(i64, i64),
            Proceed,
        }

        let applied = {
            let mut st = self.inner.lock().unwrap();
            if st.closed {
                return Err(SessionError::Closed);
            }
            if !st.carrier_lanes.contains_key(&lane_id) {
                if lane_id != 0
                    && !frames.is_empty()
                    && frames[0].frame_type != frame::FrameType::OPEN
                    && only_late_frames(&frames)
                {
                    st.last_activity = Instant::now();
                    return Ok(sequence);
                }
                if lane_id == 0
                    || frames.is_empty()
                    || frames[0].frame_type != frame::FrameType::OPEN
                {
                    drop(st);
                    self.lane_protocol_failure(lane_id);
                    return Err(SessionError::Protocol);
                }
                st.carrier_lanes.insert(lane_id, new_carrier_lane());
            }
            st.last_activity = Instant::now();
            let decision = {
                let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
                if sequence == lane.last_up_sequence && sequence != 0 {
                    if digest != lane.last_up_digest {
                        LaneReplay::Fail
                    } else {
                        drop(st);
                        return Ok(sequence);
                    }
                } else if sequence != lane.last_up_sequence + 1 || sequence == 0 {
                    LaneReplay::Fail
                } else if lane.up_active {
                    drop(st);
                    return Err(SessionError::Concurrent);
                } else {
                    lane.up_active = true;
                    LaneReplay::Proceed
                }
            };
            match decision {
                LaneReplay::Fail => {
                    drop(st);
                    self.lane_protocol_failure(lane_id);
                    return Err(SessionError::Protocol);
                }
                LaneReplay::Body(..) => unreachable!(),
                LaneReplay::Release(..) => unreachable!(),
                LaneReplay::Proceed => {}
            }
            if !self.validate_batch_locked(&st, &frames) {
                if let Some(lane) = st.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
                drop(st);
                self.lane_protocol_failure(lane_id);
                return Err(SessionError::Protocol);
            }
            let (reserved_cost, reserved_items) =
                self.backend_write_reservation_locked(&st, &frames);
            if (reserved_cost != 0 || reserved_items != 0)
                && !self.reserve_pending_locked(
                    &mut st,
                    reserved_cost,
                    reserved_items,
                    PendingClass::Uplink,
                )
            {
                if let Some(lane) = st.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                }
                return Err(SessionError::Backpressure);
            }
            let (opened, closed, unused_cost, unused_items, applied) =
                self.apply_batch_locked(&mut st, &frames, reserved_cost, reserved_items);
            if unused_cost != 0 || unused_items != 0 {
                release_pending_locked(self, &mut st, unused_cost, unused_items);
            }
            if applied {
                if let Some(lane) = st.carrier_lanes.get_mut(&lane_id) {
                    lane.up_active = false;
                    lane.last_up_sequence = sequence;
                    lane.last_up_digest = digest;
                }
            } else if let Some(lane) = st.carrier_lanes.get_mut(&lane_id) {
                lane.up_active = false;
            }
            for backend in &closed {
                backend.close();
            }
            for _ in 0..opened.len() {
                self.backend_counter.acquire();
            }
            (opened, applied)
        };
        for backend in applied.0 {
            self.spawn_backend(backend);
        }
        if !applied.1 {
            self.close();
            return Err(SessionError::Closed);
        }
        if let Some(on_up) = &self.on_up {
            on_up(body.len());
        }
        Ok(sequence)
    }

    pub async fn poll(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        cursor: u64,
    ) -> Result<PollOutcome, SessionError> {
        if self.uses_carrier_lanes() {
            return Err(SessionError::Protocol);
        }
        let deadline = tokio::time::Instant::now() + self.timeouts.long_poll.value();
        let mine = CancellationToken::new();
        {
            let mut st = self.inner.lock().unwrap();
            if st.closed {
                return Err(SessionError::Closed);
            }
            st.last_activity = Instant::now();
            if !st.unacked.is_empty() {
                if cursor == st.unacked_base {
                    let body = st.unacked.clone();
                    let next = st.down_cursor;
                    return Ok(PollOutcome {
                        body,
                        next_cursor: next,
                        lane_closed: false,
                    });
                }
                if cursor != st.down_cursor {
                    drop(st);
                    self.protocol_failure();
                    return Err(SessionError::Protocol);
                }
                let cost = st.unacked_cost;
                let items = st.unacked_items;
                release_pending_locked(self, &mut st, cost, items);
                st.unacked = Vec::new();
                st.unacked_cost = 0;
                st.unacked_items = 0;
            } else if cursor != st.down_cursor {
                drop(st);
                self.protocol_failure();
                return Err(SessionError::Protocol);
            }
            if st.down_active
                && let Some(previous) = st.superseded.take()
            {
                previous.cancel();
            }
            st.superseded = Some(mine.clone());
            st.down_active = true;
        }
        loop {
            if mine.is_cancelled() {
                return Ok(empty_poll(cursor));
            }
            let notify_fut = self.notify.notified();
            tokio::pin!(notify_fut);
            {
                let mut st = self.inner.lock().unwrap();
                if !st.pending_frames.is_empty() {
                    let batch = self.take_down_batch_locked(&mut st);
                    st.down_cursor += 1;
                    st.unacked_base = cursor;
                    st.unacked = batch.body.clone();
                    st.unacked_cost = batch.cost;
                    st.unacked_items = batch.items as i64;
                    st.down_active = false;
                    st.superseded = None;
                    let next = st.down_cursor;
                    let body = batch.body;
                    drop(st);
                    if let Some(on_down) = &self.on_down {
                        on_down(body.len());
                    }
                    return Ok(PollOutcome {
                        body,
                        next_cursor: next,
                        lane_closed: false,
                    });
                }
                if st.closed {
                    st.down_active = false;
                    st.superseded = None;
                    drop(st);
                    return Err(SessionError::Closed);
                }
                notify_fut.as_mut().enable();
            }
            tokio::select! {
                _ = mine.cancelled() => {
                    self.notify.notify_one();
                    return Ok(empty_poll(cursor));
                }
                _ = self.cancel.cancelled() => {
                    let mut st = self.inner.lock().unwrap();
                    if st.superseded.as_ref() == Some(&mine) {
                        st.down_active = false;
                        st.superseded = None;
                    }
                    return Err(SessionError::Closed);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let mut st = self.inner.lock().unwrap();
                    if st.superseded.as_ref() != Some(&mine) {
                        drop(st);
                        self.notify.notify_one();
                        return Ok(empty_poll(cursor));
                    }
                    if !st.pending_frames.is_empty() {
                        drop(st);
                        continue;
                    }
                    st.down_active = false;
                    st.superseded = None;
                    st.last_activity = Instant::now();
                    return Ok(empty_poll(cursor));
                }
                _ = cancel.cancelled() => {
                    let mut st = self.inner.lock().unwrap();
                    if st.superseded.as_ref() == Some(&mine) {
                        st.down_active = false;
                        st.superseded = None;
                    }
                    return Err(SessionError::Cancelled);
                }
                _ = notify_fut => {
                    let st = self.inner.lock().unwrap();
                    if st.superseded.as_ref() != Some(&mine) {
                        self.notify.notify_one();
                    }
                    continue;
                }
            }
        }
    }

    pub async fn poll_lane(
        self: &Arc<Self>,
        cancel: &CancellationToken,
        lane_id: u32,
        cursor: u64,
    ) -> Result<PollOutcome, SessionError> {
        if !self.uses_carrier_lanes() || lane_id > frame::MAX_STREAM_ID {
            return Err(SessionError::Protocol);
        }
        let deadline = tokio::time::Instant::now() + self.timeouts.long_poll.value();
        let mine = CancellationToken::new();
        let (generation, lane_notify) = {
            let mut st = self.inner.lock().unwrap();
            if st.closed {
                return Err(SessionError::Closed);
            }
            st.last_activity = Instant::now();
            let Some(lane) = st.carrier_lanes.get_mut(&lane_id) else {
                drop(st);
                return Err(SessionError::Protocol);
            };
            enum LaneReplay {
                Body(Vec<u8>, u64),
                Fail,
                Release(i64, i64),
                Proceed,
            }
            let decision = {
                if !lane.unacked.is_empty() {
                    if cursor == lane.unacked_base {
                        LaneReplay::Body(lane.unacked.clone(), lane.down_cursor)
                    } else if cursor != lane.down_cursor {
                        LaneReplay::Fail
                    } else {
                        LaneReplay::Release(lane.unacked_cost, lane.unacked_items)
                    }
                } else if cursor != lane.down_cursor {
                    LaneReplay::Fail
                } else {
                    LaneReplay::Proceed
                }
            };
            match decision {
                LaneReplay::Body(body, next) => {
                    return Ok(PollOutcome {
                        body,
                        next_cursor: next,
                        lane_closed: false,
                    });
                }
                LaneReplay::Fail => {
                    drop(st);
                    self.lane_protocol_failure(lane_id);
                    return Err(SessionError::Protocol);
                }
                LaneReplay::Release(cost, items) => {
                    release_pending_locked(self, &mut st, cost, items);
                    let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
                    lane.unacked = Vec::new();
                    lane.unacked_cost = 0;
                    lane.unacked_items = 0;
                }
                LaneReplay::Proceed => {}
            }
            let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
            if lane.down_active
                && let Some(previous) = lane.superseded.take()
            {
                previous.cancel();
            }
            lane.superseded = Some(mine.clone());
            lane.down_active = true;
            (lane.generation, lane.notify.clone())
        };
        loop {
            if mine.is_cancelled() {
                return Ok(empty_poll(cursor));
            }
            let notify_fut = lane_notify.notified();
            tokio::pin!(notify_fut);
            {
                let mut st = self.inner.lock().unwrap();
                let lane_alive = st
                    .carrier_lanes
                    .get(&lane_id)
                    .is_some_and(|lane| lane.generation == generation);
                if !lane_alive {
                    drop(st);
                    return Ok(lane_closed_poll(cursor));
                }
                let has_pending = st
                    .carrier_lanes
                    .get(&lane_id)
                    .is_some_and(|lane| !lane.pending_frames.is_empty());
                if has_pending {
                    let batch = self.take_lane_down_batch_locked(&mut st, lane_id);
                    let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
                    lane.down_cursor += 1;
                    lane.unacked_base = cursor;
                    lane.unacked = batch.body.clone();
                    lane.unacked_cost = batch.cost;
                    lane.unacked_items = batch.items as i64;
                    lane.down_active = false;
                    lane.superseded = None;
                    let next = lane.down_cursor;
                    let body = batch.body;
                    drop(st);
                    if let Some(on_down) = &self.on_down {
                        on_down(body.len());
                    }
                    return Ok(PollOutcome {
                        body,
                        next_cursor: next,
                        lane_closed: false,
                    });
                }
                if st.closed {
                    if let Some(lane) = st.carrier_lanes.get_mut(&lane_id) {
                        lane.down_active = false;
                        lane.superseded = None;
                    }
                    drop(st);
                    return Err(SessionError::Closed);
                }
                if lane_id != 0
                    && !st.streams.contains_key(&lane_id)
                    && st.closed_streams.contains_key(&lane_id)
                {
                    if let Some(lane) = st.carrier_lanes.get_mut(&lane_id) {
                        lane.down_active = false;
                        lane.superseded = None;
                    }
                    drop(st);
                    return Ok(lane_closed_poll(cursor));
                }
                notify_fut.as_mut().enable();
            }
            tokio::select! {
                _ = mine.cancelled() => {
                    lane_notify.notify_one();
                    return Ok(empty_poll(cursor));
                }
                _ = self.cancel.cancelled() => {
                    let mut st = self.inner.lock().unwrap();
                    if let Some(lane) = st.carrier_lanes.get_mut(&lane_id)
                        && lane.generation == generation
                        && lane.superseded.as_ref() == Some(&mine)
                    {
                        lane.down_active = false;
                        lane.superseded = None;
                    }
                    return Err(SessionError::Closed);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let mut st = self.inner.lock().unwrap();
                    let replaced = !st
                        .carrier_lanes
                        .get(&lane_id)
                        .is_some_and(|lane| {
                            lane.generation == generation && lane.superseded.as_ref() == Some(&mine)
                        });
                    if replaced {
                        drop(st);
                        lane_notify.notify_one();
                        return Ok(empty_poll(cursor));
                    }
                    let has_pending = st
                        .carrier_lanes
                        .get(&lane_id)
                        .is_some_and(|lane| !lane.pending_frames.is_empty());
                    if has_pending {
                        drop(st);
                        continue;
                    }
                    let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
                    lane.down_active = false;
                    lane.superseded = None;
                    st.last_activity = Instant::now();
                    return Ok(empty_poll(cursor));
                }
                _ = cancel.cancelled() => {
                    let mut st = self.inner.lock().unwrap();
                    if let Some(lane) = st.carrier_lanes.get_mut(&lane_id)
                        && lane.generation == generation
                        && lane.superseded.as_ref() == Some(&mine)
                    {
                        lane.down_active = false;
                        lane.superseded = None;
                    }
                    return Err(SessionError::Cancelled);
                }
                _ = notify_fut => {
                    let st = self.inner.lock().unwrap();
                    if !st
                        .carrier_lanes
                        .get(&lane_id)
                        .is_some_and(|lane| {
                            lane.generation == generation && lane.superseded.as_ref() == Some(&mine)
                        })
                    {
                        lane_notify.notify_one();
                    }
                    continue;
                }
            }
        }
    }

    pub fn last_activity(&self) -> Instant {
        self.inner.lock().unwrap().last_activity
    }

    pub fn close(self: &Arc<Self>) {
        let fire = {
            let mut st = self.inner.lock().unwrap();
            self.close_locked(&mut st)
        };
        if fire && let Some(on_finished) = &self.on_finished {
            on_finished(self.clone());
        }
    }

    pub async fn wait(&self) {
        self.backend_counter.wait().await;
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }

    fn protocol_failure(self: &Arc<Self>) {
        self.close();
    }

    fn lane_protocol_failure(self: &Arc<Self>, lane_id: u32) {
        if self.carrier == config::CarrierMode::WebSocketLanes {
            self.release_websocket_lane(lane_id);
        } else {
            self.protocol_failure();
        }
    }

    fn uses_carrier_lanes(&self) -> bool {
        self.carrier == config::CarrierMode::HttpsLanes
            || self.carrier == config::CarrierMode::WebSocketLanes
    }

    fn close_locked(self: &Arc<Self>, st: &mut SessionState) -> bool {
        if st.closed {
            return false;
        }
        st.closed = true;
        self.cancel.cancel();
        for lane in st.carrier_lanes.values_mut() {
            lane.pending_frames.clear();
            lane.pending_windows.clear();
            lane.unacked = Vec::new();
            lane.unacked_cost = 0;
            lane.unacked_items = 0;
            lane.notify.notify_one();
        }
        for state in st.streams.values() {
            state.backend.close();
        }
        st.streams.clear();
        if st.pending_cost != 0 || st.pending_items != 0 {
            if let Some(budget) = &self.budget {
                budget(-st.pending_cost, -st.pending_items, PendingClass::Uplink);
            }
            st.pending_cost = 0;
            st.pending_items = 0;
        }
        st.pending_frames.clear();
        st.pending_windows.clear();
        st.unacked = Vec::new();
        st.unacked_cost = 0;
        st.unacked_items = 0;
        self.notify.notify_one();
        let fire = self.on_finished.is_some() && !st.finished_fired;
        st.finished_fired = fire || st.finished_fired;
        fire
    }

    fn validate_batch_locked(&self, st: &SessionState, frames: &[frame::Frame<'_>]) -> bool {
        let mut live: HashMap<u32, (u32, u64)> = HashMap::with_capacity(st.streams.len());
        for (id, state) in &st.streams {
            live.insert(*id, (state.receive_window, state.send_credit));
        }
        let mut closed_in_batch: HashSet<u32> = HashSet::new();
        for value in frames {
            if value.stream_id == 0 {
                if value.frame_type != frame::FrameType::PONG {
                    return false;
                }
                continue;
            }
            let was_closed = st.closed_streams.contains_key(&value.stream_id)
                || closed_in_batch.contains(&value.stream_id);
            match value.frame_type {
                frame::FrameType::OPEN => {
                    if live.contains_key(&value.stream_id) || was_closed {
                        return false;
                    }
                    live.insert(
                        value.stream_id,
                        (
                            frame::INITIAL_STREAM_WINDOW,
                            u64::from(frame::INITIAL_STREAM_WINDOW),
                        ),
                    );
                }
                frame::FrameType::DATA => {
                    if was_closed {
                        continue;
                    }
                    let Some(entry) = live.get_mut(&value.stream_id) else {
                        return false;
                    };
                    if value.payload.len() as u32 > entry.0 {
                        return false;
                    }
                    entry.0 -= value.payload.len() as u32;
                }
                frame::FrameType::WINDOW => {
                    if was_closed {
                        continue;
                    }
                    let amount = frame::window_amount(value.payload).unwrap_or(0);
                    let Some(entry) = live.get_mut(&value.stream_id) else {
                        return false;
                    };
                    entry.1 = (entry.1 + u64::from(amount)).min(u64::from(u32::MAX));
                }
                frame::FrameType::CLOSE => {
                    if was_closed {
                        continue;
                    }
                    if live.remove(&value.stream_id).is_none() {
                        return false;
                    }
                    closed_in_batch.insert(value.stream_id);
                }
                _ => return false,
            }
        }
        true
    }

    fn backend_write_reservation_locked(
        &self,
        st: &SessionState,
        frames: &[frame::Frame<'_>],
    ) -> (i64, i64) {
        let mut live: HashMap<u32, bool> = HashMap::with_capacity(st.streams.len());
        for id in st.streams.keys() {
            live.insert(*id, true);
        }
        let mut cost = 0i64;
        let mut items = 0i64;
        for value in frames {
            if value.stream_id == 0 {
                continue;
            }
            match value.frame_type {
                frame::FrameType::OPEN => {
                    live.insert(value.stream_id, true);
                }
                frame::FrameType::DATA => {
                    if live.get(&value.stream_id).copied().unwrap_or(false) {
                        cost += value.payload.len() as i64 + QUEUE_ITEM_COST;
                        items += 1;
                    }
                }
                frame::FrameType::CLOSE => {
                    live.remove(&value.stream_id);
                }
                _ => {}
            }
        }
        (cost, items)
    }

    fn apply_batch_locked(
        self: &Arc<Self>,
        st: &mut SessionState,
        frames: &[frame::Frame<'_>],
        reserved_cost: i64,
        reserved_items: i64,
    ) -> (
        Vec<Arc<BackendStream>>,
        Vec<Arc<BackendStream>>,
        i64,
        i64,
        bool,
    ) {
        let mut opened = Vec::new();
        let mut closed = Vec::new();
        let mut unused_cost = reserved_cost;
        let mut unused_items = reserved_items;
        for value in frames {
            if value.stream_id == 0 {
                continue;
            }
            let was_closed = st.closed_streams.contains_key(&value.stream_id);
            match value.frame_type {
                frame::FrameType::OPEN => {
                    if st.streams.len() >= self.limits.max_streams_per_session
                        || self
                            .acquire_stream
                            .as_ref()
                            .is_some_and(|acquire| !acquire())
                    {
                        remember_closed_locked(self, st, value.stream_id);
                        if let Some(on_rejected) = &self.on_stream_rejected {
                            on_rejected();
                        }
                        if !self.queue_frame_locked(
                            st,
                            frame::FrameType::CLOSE,
                            value.stream_id,
                            &[],
                        ) {
                            return (opened, closed, unused_cost, unused_items, false);
                        }
                        continue;
                    }
                    let backend = Arc::new(BackendStream::new(
                        self.clone(),
                        value.stream_id,
                        self.profile.backend.clone(),
                    ));
                    st.streams.insert(
                        value.stream_id,
                        StreamState {
                            backend: backend.clone(),
                            receive_window: frame::INITIAL_STREAM_WINDOW,
                            send_credit: u64::from(frame::INITIAL_STREAM_WINDOW),
                            pending_write_bytes: 0,
                            pending_write_cost: 0,
                            pending_write_items: 0,
                            credit_notify: Arc::new(Notify::new()),
                            writes: VecDeque::new(),
                            write_notify: Arc::new(Notify::new()),
                        },
                    );
                    opened.push(backend);
                }
                frame::FrameType::DATA => {
                    if was_closed {
                        continue;
                    }
                    let (cost, items) = {
                        let state = st
                            .streams
                            .get_mut(&value.stream_id)
                            .expect("validated stream");
                        let (cost, items) = append_backend_write(state, value.payload);
                        state.receive_window -= value.payload.len() as u32;
                        state.write_notify.notify_one();
                        (cost, items)
                    };
                    unused_cost -= cost;
                    unused_items -= items;
                }
                frame::FrameType::WINDOW => {
                    if was_closed {
                        continue;
                    }
                    if let Some(state) = st.streams.get_mut(&value.stream_id) {
                        let amount = frame::window_amount(value.payload).unwrap_or(0);
                        state.send_credit =
                            (state.send_credit + u64::from(amount)).min(u64::from(u32::MAX));
                        state.credit_notify.notify_one();
                    }
                }
                frame::FrameType::CLOSE => {
                    if was_closed {
                        continue;
                    }
                    let (backend, cost, items) = {
                        let state = st
                            .streams
                            .get_mut(&value.stream_id)
                            .expect("validated stream");
                        (
                            state.backend.clone(),
                            state.pending_write_cost,
                            state.pending_write_items,
                        )
                    };
                    release_stream_writes(st, value.stream_id);
                    release_pending_locked(self, st, cost, items);
                    st.streams.remove(&value.stream_id);
                    remember_closed_locked(self, st, value.stream_id);
                    closed.push(backend);
                }
                _ => {}
            }
        }
        (opened, closed, unused_cost, unused_items, true)
    }

    fn queue_frame_locked(
        &self,
        st: &mut SessionState,
        frame_type: frame::FrameType,
        id: u32,
        payload: &[u8],
    ) -> bool {
        if self.uses_carrier_lanes() {
            return self.queue_lane_frame_locked(st, frame_type, id, payload);
        }
        if frame_type == frame::FrameType::WINDOW
            && let Some(&index) = st.pending_windows.get(&id)
        {
            let coalesced = st.pending_frames.get_mut(index).and_then(|queued| {
                let previous = frame::window_amount(&queued.encoded[frame::HEADER_SIZE..]).ok()?;
                let amount = frame::window_amount(payload).ok()?;
                let total = u64::from(previous) + u64::from(amount);
                (total <= u64::from(u32::MAX)).then(|| {
                    queued.encoded[frame::HEADER_SIZE..frame::HEADER_SIZE + 4]
                        .copy_from_slice(&(total as u32).to_be_bytes());
                })
            });
            if coalesced.is_some() {
                self.notify.notify_one();
                return true;
            }
        }
        let coalesce = st.pending_frames.back().is_some_and(|last| {
            last.type_code == frame::FrameType::DATA
                && frame_type == frame::FrameType::DATA
                && last.stream_id == id
                && last.encoded.len() - frame::HEADER_SIZE + payload.len()
                    <= self.limits.max_frame_payload
        });
        if coalesce {
            if !self.reserve_pending_locked(st, payload.len() as i64, 0, PendingClass::Downlink) {
                return false;
            }
            let last = st.pending_frames.back_mut().unwrap();
            last.encoded.extend_from_slice(payload);
            last.cost += payload.len() as i64;
            let length = (last.encoded.len() - frame::HEADER_SIZE) as u32;
            last.encoded[4..8].copy_from_slice(&length.to_be_bytes());
            self.notify.notify_one();
            return true;
        }
        let encoded = frame::encode(frame_type, id, payload);
        let cost = encoded.len() as i64 + QUEUE_ITEM_COST;
        let class = if frame_type == frame::FrameType::DATA {
            PendingClass::Downlink
        } else {
            PendingClass::Control
        };
        if !self.reserve_pending_locked(st, cost, 1, class) {
            return false;
        }
        st.pending_frames.push_back(QueuedFrame {
            encoded,
            type_code: frame_type,
            stream_id: id,
            cost,
        });
        if frame_type == frame::FrameType::WINDOW {
            st.pending_windows.insert(id, st.pending_frames.len() - 1);
        }
        self.notify.notify_one();
        true
    }

    fn queue_lane_frame_locked(
        &self,
        st: &mut SessionState,
        frame_type: frame::FrameType,
        id: u32,
        payload: &[u8],
    ) -> bool {
        let Some(lane) = st.carrier_lanes.get_mut(&id) else {
            return false;
        };
        if frame_type == frame::FrameType::WINDOW
            && let Some(&index) = lane.pending_windows.get(&id)
        {
            let coalesced = lane.pending_frames.get_mut(index).and_then(|queued| {
                let previous = frame::window_amount(&queued.encoded[frame::HEADER_SIZE..]).ok()?;
                let amount = frame::window_amount(payload).ok()?;
                let total = u64::from(previous) + u64::from(amount);
                (total <= u64::from(u32::MAX)).then(|| {
                    queued.encoded[frame::HEADER_SIZE..frame::HEADER_SIZE + 4]
                        .copy_from_slice(&(total as u32).to_be_bytes());
                })
            });
            if coalesced.is_some() {
                lane.notify.notify_one();
                return true;
            }
        }
        let coalesce = lane.pending_frames.back().is_some_and(|last| {
            last.type_code == frame::FrameType::DATA
                && frame_type == frame::FrameType::DATA
                && last.stream_id == id
                && last.encoded.len() - frame::HEADER_SIZE + payload.len()
                    <= self.limits.max_frame_payload
        });
        if coalesce {
            if !self.reserve_pending_locked(st, payload.len() as i64, 0, PendingClass::Downlink) {
                return false;
            }
            let lane = st.carrier_lanes.get_mut(&id).unwrap();
            let last = lane.pending_frames.back_mut().unwrap();
            last.encoded.extend_from_slice(payload);
            last.cost += payload.len() as i64;
            let length = (last.encoded.len() - frame::HEADER_SIZE) as u32;
            last.encoded[4..8].copy_from_slice(&length.to_be_bytes());
            lane.notify.notify_one();
            return true;
        }
        let encoded = frame::encode(frame_type, id, payload);
        let cost = encoded.len() as i64 + QUEUE_ITEM_COST;
        let class = if frame_type == frame::FrameType::DATA {
            PendingClass::Downlink
        } else {
            PendingClass::Control
        };
        if !self.reserve_pending_locked(st, cost, 1, class) {
            return false;
        }
        let lane = st.carrier_lanes.get_mut(&id).unwrap();
        lane.pending_frames.push_back(QueuedFrame {
            encoded,
            type_code: frame_type,
            stream_id: id,
            cost,
        });
        if frame_type == frame::FrameType::WINDOW {
            lane.pending_windows
                .insert(id, lane.pending_frames.len() - 1);
        }
        lane.notify.notify_one();
        true
    }

    pub async fn next_write(&self, id: u32, cancel: &CancellationToken) -> Option<Vec<u8>> {
        loop {
            let (result, write_notify) = {
                let mut st = self.inner.lock().unwrap();
                if st.closed {
                    return None;
                }
                let state = st.streams.get_mut(&id)?;
                if let Some(data) = state.writes.pop_front() {
                    (Some(data), None)
                } else {
                    (None, Some(state.write_notify.clone()))
                }
            };
            if let Some(data) = result {
                return Some(data);
            }
            let write_notify = write_notify.unwrap();
            let notify_fut = write_notify.notified();
            tokio::pin!(notify_fut);
            notify_fut.as_mut().enable();
            tokio::select! {
                _ = &mut notify_fut => {}
                _ = self.cancel.cancelled() => return None,
                _ = cancel.cancelled() => return None,
            }
        }
    }

    pub fn backend_drained(&self, id: u32, amount: usize) -> bool {
        let amount = amount as i64;
        let mut st = self.inner.lock().unwrap();
        if st.closed {
            return false;
        }
        let ok = {
            let Some(state) = st.streams.get(&id) else {
                return false;
            };
            !(amount <= 0
                || amount > state.pending_write_bytes
                || amount > state.pending_write_cost
                || u64::from(state.receive_window) + amount as u64
                    > u64::from(frame::INITIAL_STREAM_WINDOW))
        };
        if !ok {
            return false;
        }
        {
            let state = st.streams.get_mut(&id).unwrap();
            state.pending_write_bytes -= amount;
            state.pending_write_cost -= amount;
            state.receive_window += amount as u32;
        }
        release_pending_locked(self, &mut st, amount, 0);
        self.queue_frame_locked(
            &mut st,
            frame::FrameType::WINDOW,
            id,
            &frame::window_payload(amount as u32),
        )
    }

    pub fn backend_write_finished(&self, id: u32) -> bool {
        let mut st = self.inner.lock().unwrap();
        if st.closed {
            return false;
        }
        let ok = {
            let Some(state) = st.streams.get_mut(&id) else {
                return false;
            };
            if state.pending_write_items == 0 || state.pending_write_cost < QUEUE_ITEM_COST {
                false
            } else {
                state.pending_write_items -= 1;
                state.pending_write_cost -= QUEUE_ITEM_COST;
                true
            }
        };
        if ok {
            release_pending_locked(self, &mut st, QUEUE_ITEM_COST, 1);
        }
        ok
    }

    pub async fn next_read_allowance(&self, id: u32, cancel: &CancellationToken) -> Option<usize> {
        loop {
            let credit_notify = {
                let mut st = self.inner.lock().unwrap();
                let SessionState {
                    streams,
                    pending_cost,
                    pending_items,
                    closed,
                    ..
                } = &mut *st;
                if *closed {
                    return None;
                }
                let state = streams.get_mut(&id)?;
                let mut result = 0usize;
                if state.send_credit != 0 {
                    result = (state.send_credit as usize).min(frame::DATA_CHUNK);
                    result = self.data_frame_allowance(*pending_cost, *pending_items, result);
                }
                if result != 0 {
                    return Some(result);
                }
                state.credit_notify.clone()
            };
            let credit_fut = credit_notify.notified();
            let budget_fut = self.budget_notify.notified();
            tokio::pin!(credit_fut, budget_fut);
            {
                let mut st = self.inner.lock().unwrap();
                let SessionState {
                    streams,
                    pending_cost,
                    pending_items,
                    closed,
                    ..
                } = &mut *st;
                if *closed {
                    return None;
                }
                let state = streams.get_mut(&id)?;
                let mut result = 0usize;
                if state.send_credit != 0 {
                    result = (state.send_credit as usize).min(frame::DATA_CHUNK);
                    result = self.data_frame_allowance(*pending_cost, *pending_items, result);
                }
                if result != 0 {
                    return Some(result);
                }
                credit_fut.as_mut().enable();
                budget_fut.as_mut().enable();
            }
            tokio::select! {
                _ = &mut credit_fut => {}
                _ = &mut budget_fut => {}
                _ = self.cancel.cancelled() => return None,
                _ = cancel.cancelled() => return None,
            }
        }
    }

    pub fn backend_data(&self, id: u32, data: &[u8]) -> bool {
        let mut st = self.inner.lock().unwrap();
        if st.closed {
            return false;
        }
        let allowed = {
            let Some(state) = st.streams.get_mut(&id) else {
                return false;
            };
            if data.is_empty() || data.len() as u64 > state.send_credit {
                false
            } else {
                state.send_credit -= data.len() as u64;
                true
            }
        };
        if !allowed {
            return false;
        }
        self.queue_frame_locked(&mut st, frame::FrameType::DATA, id, data)
    }

    pub fn backend_closed(self: &Arc<Self>, id: u32, backend: &Arc<BackendStream>) {
        let fire = {
            let mut st = self.inner.lock().unwrap();
            let same = st
                .streams
                .get(&id)
                .is_some_and(|state| Arc::ptr_eq(&state.backend, backend));
            if st.closed || !same {
                return;
            }
            let (cost, items) = {
                let state = st.streams.get_mut(&id).unwrap();
                (state.pending_write_cost, state.pending_write_items)
            };
            release_stream_writes(&mut st, id);
            release_pending_locked(self, &mut st, cost, items);
            st.streams.remove(&id);
            remember_closed_locked(self, &mut st, id);
            if self.queue_frame_locked(&mut st, frame::FrameType::CLOSE, id, &[]) {
                return;
            }
            self.close_locked(&mut st)
        };
        if fire && let Some(on_finished) = &self.on_finished {
            on_finished(self.clone());
        }
        backend.close();
    }

    fn data_frame_allowance(&self, pending_cost: i64, pending_items: i64, limit: usize) -> usize {
        let (cost_limit, item_limit) = downlink_pending_limits(&self.limits);
        if pending_items >= item_limit {
            return 0;
        }
        let available = cost_limit - pending_cost - QUEUE_ITEM_COST - frame::HEADER_SIZE as i64;
        if available <= 0 {
            return 0;
        }
        limit.min(available as usize)
    }

    fn reserve_pending_locked(
        &self,
        st: &mut SessionState,
        cost: i64,
        items: i64,
        class: PendingClass,
    ) -> bool {
        let (mut cost_limit, mut item_limit) = (
            self.limits.max_pending_per_session as i64,
            self.limits.max_pending_items_per_session as i64,
        );
        if class == PendingClass::Uplink {
            (cost_limit, item_limit) = uplink_pending_limits(&self.limits);
        } else if class == PendingClass::Downlink {
            (cost_limit, item_limit) = downlink_pending_limits(&self.limits);
        }
        if cost <= 0
            || items < 0
            || cost > cost_limit
            || items > item_limit
            || st.pending_cost > cost_limit - cost
            || st.pending_items > item_limit - items
        {
            return false;
        }
        if let Some(budget) = &self.budget
            && !budget(cost, items, class)
        {
            return false;
        }
        st.pending_cost += cost;
        st.pending_items += items;
        true
    }

    fn take_down_batch_locked(&self, st: &mut SessionState) -> DownBatch {
        let mut frames = std::mem::take(&mut st.pending_frames);
        let mut windows = std::mem::take(&mut st.pending_windows);
        let batch = take_batch(&mut frames, &mut windows, self.limits.carrier_batch_bytes);
        st.pending_frames = frames;
        st.pending_windows = windows;
        batch
    }

    fn take_lane_down_batch_locked(&self, st: &mut SessionState, lane_id: u32) -> DownBatch {
        let (mut frames, mut windows) = {
            let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
            (
                std::mem::take(&mut lane.pending_frames),
                std::mem::take(&mut lane.pending_windows),
            )
        };
        let batch = take_batch(&mut frames, &mut windows, self.limits.carrier_batch_bytes);
        let lane = st.carrier_lanes.get_mut(&lane_id).unwrap();
        lane.pending_frames = frames;
        lane.pending_windows = windows;
        batch
    }

    fn spawn_backend(self: &Arc<Self>, backend: Arc<BackendStream>) {
        let counter = self.backend_counter.clone();
        let on_stream_finished = self.on_stream_finished.clone();
        tokio::spawn(async move {
            let _guard = StreamTaskGuard {
                counter,
                on_stream_finished,
            };
            backend.run().await;
        });
    }
}

struct StreamTaskGuard {
    counter: Arc<TaskCounter>,
    on_stream_finished: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Drop for StreamTaskGuard {
    fn drop(&mut self) {
        self.counter.release();
        if let Some(on_stream_finished) = &self.on_stream_finished {
            on_stream_finished();
        }
    }
}

#[derive(Default)]
struct TaskCounter {
    count: Mutex<usize>,
    notify: Notify,
}

impl TaskCounter {
    fn acquire(&self) {
        *self.count.lock().unwrap() += 1;
    }

    fn release(&self) {
        let count = {
            let mut count = self.count.lock().unwrap();
            *count -= 1;
            *count
        };
        if count == 0 {
            self.notify.notify_waiters();
        }
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            {
                let count = self.count.lock().unwrap();
                if *count == 0 {
                    return;
                }
                notified.as_mut().enable();
            }
            notified.await;
        }
    }
}

pub struct BackendStream {
    session: Arc<Session>,
    id: u32,
    address: String,
    cancel: CancellationToken,
}

impl BackendStream {
    fn new(session: Arc<Session>, id: u32, address: String) -> Self {
        Self {
            session,
            id,
            address,
            cancel: CancellationToken::new(),
        }
    }

    pub fn close(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub async fn run(self: Arc<Self>) {
        let dial_timeout = self.session.timeouts.backend_dial.value();
        let connected = tokio::select! {
            _ = self.cancel.cancelled() => None,
            result = tokio::time::timeout(dial_timeout, TcpStream::connect(&self.address)) => {
                result.ok().and_then(|value| value.ok())
            }
        };
        let failed = connected.is_none() && !self.cancel.is_cancelled();
        if let Some(on_dial) = &self.session.on_backend_dial_finished {
            on_dial(failed);
        }
        let Some(connection) = connected else {
            self.session.backend_closed(self.id, &self);
            return;
        };
        let (mut read_half, mut write_half) = connection.into_split();
        let write_stream = self.clone();
        let write_task = tokio::spawn(async move {
            Self::write_loop(&write_stream, &mut write_half).await;
            write_stream.close();
        });
        Self::read_loop(&self, &mut read_half).await;
        self.close();
        let _ = write_task.await;
        self.session.backend_closed(self.id, &self);
    }

    async fn write_loop(stream: &Arc<Self>, connection: &mut OwnedWriteHalf) {
        loop {
            let Some(data) = stream.session.next_write(stream.id, &stream.cancel).await else {
                return;
            };
            let mut data: &[u8] = &data;
            while !data.is_empty() {
                let written = tokio::select! {
                    _ = stream.cancel.cancelled() => return,
                    result = connection.write(data) => match result {
                        Ok(written) => written,
                        Err(_) => return,
                    },
                };
                if written > 0 {
                    if !stream.session.backend_drained(stream.id, written) {
                        return;
                    }
                    data = &data[written..];
                }
                if written == 0 {
                    return;
                }
            }
            if !stream.session.backend_write_finished(stream.id) {
                return;
            }
        }
    }

    async fn read_loop(stream: &Arc<Self>, connection: &mut OwnedReadHalf) {
        let mut buffer = vec![0u8; frame::DATA_CHUNK];
        loop {
            let Some(allowance) = stream
                .session
                .next_read_allowance(stream.id, &stream.cancel)
                .await
            else {
                return;
            };
            let read = tokio::select! {
                _ = stream.cancel.cancelled() => return,
                result = connection.read(&mut buffer[..allowance]) => match result {
                    Ok(read) => read,
                    Err(_) => return,
                },
            };
            if read > 0 && !stream.session.backend_data(stream.id, &buffer[..read]) {
                return;
            }
            if read == 0 {
                return;
            }
        }
    }
}

fn remember_closed_locked(session: &Session, st: &mut SessionState, id: u32) {
    if st.closed_streams.contains_key(&id) {
        return;
    }
    st.closed_streams.insert(id, ());
    if st.closed_order.len() < session.limits.max_closed_stream_ids {
        st.closed_order.push_back(id);
    } else {
        let old = st.closed_order.pop_front().unwrap();
        st.closed_streams.remove(&old);
        if let Some(lane) = st.carrier_lanes.remove(&old) {
            release_lane_locked(session, st, &lane);
        }
        st.closed_order.push_back(id);
    }
    if let Some(lane) = st.carrier_lanes.get(&id) {
        lane.notify.notify_one();
    }
}

fn release_lane_locked(session: &Session, st: &mut SessionState, lane: &CarrierLane) {
    let mut cost = lane.unacked_cost;
    let mut items = lane.unacked_items;
    for frame_item in &lane.pending_frames {
        cost += frame_item.cost;
        items += 1;
    }
    if cost != 0 || items != 0 {
        release_pending_locked(session, st, cost, items);
    }
    lane.notify.notify_one();
}

fn release_stream_writes(st: &mut SessionState, id: u32) {
    let Some(state) = st.streams.get_mut(&id) else {
        return;
    };
    state.pending_write_bytes = 0;
    state.pending_write_cost = 0;
    state.pending_write_items = 0;
    state.writes.clear();
}

fn release_pending_locked(session: &Session, st: &mut SessionState, cost: i64, items: i64) {
    if cost == 0 && items == 0 {
        return;
    }
    if cost < 0 || items < 0 || cost > st.pending_cost || items > st.pending_items {
        panic!("invalid session pending budget release");
    }
    st.pending_cost -= cost;
    st.pending_items -= items;
    if let Some(budget) = &session.budget {
        budget(-cost, -items, PendingClass::Uplink);
    }
    session.budget_notify.notify_waiters();
}

fn append_backend_write(state: &mut StreamState, payload: &[u8]) -> (i64, i64) {
    let coalesce = state
        .writes
        .back()
        .is_some_and(|last| last.len() + payload.len() <= frame::DATA_CHUNK);
    let (cost, items) = if coalesce {
        (payload.len() as i64, 0)
    } else {
        (payload.len() as i64 + QUEUE_ITEM_COST, 1)
    };
    if coalesce {
        state.writes.back_mut().unwrap().extend_from_slice(payload);
    } else {
        state.writes.push_back(payload.to_vec());
    }
    state.pending_write_bytes += payload.len() as i64;
    state.pending_write_cost += cost;
    state.pending_write_items += items;
    (cost, items)
}

fn take_batch(
    pending_frames: &mut VecDeque<QueuedFrame>,
    pending_windows: &mut HashMap<u32, usize>,
    carrier_batch_bytes: usize,
) -> DownBatch {
    let mut size = 0usize;
    let mut cost = 0i64;
    let mut count = 0usize;
    for item in pending_frames.iter() {
        if count == frame::MAX_BATCH_FRAMES {
            break;
        }
        let next = item.encoded.len();
        if count != 0 && size + next > carrier_batch_bytes {
            break;
        }
        size += next;
        cost += item.cost;
        count += 1;
    }
    let mut result = Vec::with_capacity(size);
    for index in 0..count {
        let item = pending_frames.pop_front().unwrap();
        if item.type_code == frame::FrameType::WINDOW
            && pending_windows.get(&item.stream_id).copied() == Some(index)
        {
            pending_windows.remove(&item.stream_id);
        }
        result.extend_from_slice(&item.encoded);
    }
    for value in pending_windows.values_mut() {
        *value -= count;
    }
    DownBatch {
        body: result,
        cost,
        items: count,
    }
}

fn parse_and_shape(body: &[u8], max_payload: usize) -> Result<Vec<frame::Frame<'_>>, ()> {
    let frames = frame::parse_all(body, max_payload).map_err(|_| ())?;
    for value in &frames {
        if frame::validate_client_shape(*value).is_err() {
            return Err(());
        }
    }
    Ok(frames)
}

fn parse_and_shape_lane(
    body: &[u8],
    max_payload: usize,
    lane_id: u32,
) -> Result<Vec<frame::Frame<'_>>, ()> {
    let frames = frame::parse_all(body, max_payload).map_err(|_| ())?;
    for value in &frames {
        if frame::validate_client_shape(*value).is_err() || value.stream_id != lane_id {
            return Err(());
        }
    }
    Ok(frames)
}

fn only_late_frames(frames: &[frame::Frame<'_>]) -> bool {
    if frames.is_empty() {
        return false;
    }
    frames.iter().all(|value| {
        value.frame_type == frame::FrameType::DATA
            || value.frame_type == frame::FrameType::WINDOW
            || value.frame_type == frame::FrameType::CLOSE
    })
}

fn sha256_digest(body: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(body).into()
}

pub fn pending_control_reserve(limits: &config::Limits) -> (i64, i64) {
    let mut items = CONTROL_RESERVE_EXTRA_ITEMS;
    if limits.max_streams_per_session > (usize::MAX - items) / CONTROL_RESERVE_ITEMS_PER_STREAM {
        return (
            limits.max_pending_per_session as i64,
            limits.max_pending_items_per_session as i64,
        );
    }
    items += limits.max_streams_per_session * CONTROL_RESERVE_ITEMS_PER_STREAM;
    let cost_per_item = QUEUE_ITEM_COST + frame::HEADER_SIZE as i64 + 4;
    if items as u128 > (i64::MAX as u128) / cost_per_item as u128 {
        return (
            limits.max_pending_per_session as i64,
            limits.max_pending_items_per_session as i64,
        );
    }
    (items as i64 * cost_per_item, items as i64)
}

fn pending_uplink_reserve(limits: &config::Limits) -> (i64, i64) {
    let mut items = limits.max_body_bytes / frame::HEADER_SIZE;
    if items > frame::MAX_BATCH_FRAMES {
        items = frame::MAX_BATCH_FRAMES;
    }
    if items > (usize::MAX - limits.max_body_bytes) / QUEUE_ITEM_COST as usize {
        return (
            limits.max_pending_per_session as i64,
            limits.max_pending_items_per_session as i64,
        );
    }
    (
        limits.max_body_bytes as i64 + items as i64 * QUEUE_ITEM_COST,
        items as i64,
    )
}

fn subtract_pending_reserve(
    cost: i64,
    items: i64,
    reserve_cost: i64,
    reserve_items: i64,
) -> (i64, i64) {
    (
        if reserve_cost >= cost {
            0
        } else {
            cost - reserve_cost
        },
        if reserve_items >= items {
            0
        } else {
            items - reserve_items
        },
    )
}

fn uplink_pending_limits(limits: &config::Limits) -> (i64, i64) {
    let (reserve_cost, reserve_items) = pending_control_reserve(limits);
    subtract_pending_reserve(
        limits.max_pending_per_session as i64,
        limits.max_pending_items_per_session as i64,
        reserve_cost,
        reserve_items,
    )
}

fn downlink_pending_limits(limits: &config::Limits) -> (i64, i64) {
    let (cost, items) = uplink_pending_limits(limits);
    let (reserve_cost, reserve_items) = pending_uplink_reserve(limits);
    subtract_pending_reserve(cost, items, reserve_cost, reserve_items)
}

pub fn validate_budget(limits: &config::Limits) -> Result<(), crate::config::ConfigError> {
    let (reserve_cost, reserve_items) = pending_control_reserve(limits);
    let sessions = limits.max_sessions_global as i64;
    if reserve_cost > limits.max_pending_global as i64 / sessions {
        return Err(crate::config::ConfigError(
            "per-session control reserve times max_sessions_global exhausts max_pending_global"
                .to_string(),
        ));
    }
    if reserve_items > limits.max_pending_items_global as i64 / sessions {
        return Err(crate::config::ConfigError(
            "per-session control reserve times max_sessions_global exhausts max_pending_items_global"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_profile(carrier: config::CarrierMode) -> Arc<config::Profile> {
        Arc::new(config::Profile {
            name: "default".to_string(),
            backend: "127.0.0.1:1".to_string(),
            carrier_mode: carrier,
            capability: [0; 32],
            limits: config::ProfileLimits::default(),
        })
    }

    fn test_timeouts() -> config::Timeouts {
        config::Timeouts {
            backend_dial: config::Duration::from_millis(20),
            ..config::Timeouts::default()
        }
    }

    fn test_session(limits: config::Limits, carrier: config::CarrierMode) -> Arc<Session> {
        Session::new(
            test_profile(carrier),
            limits.clone(),
            test_timeouts(),
            SessionOptions {
                budget: Some(manager_budget(&limits)),
                ..Default::default()
            },
        )
    }

    fn plain_session(limits: config::Limits, carrier: config::CarrierMode) -> Arc<Session> {
        Session::new(
            test_profile(carrier),
            limits,
            test_timeouts(),
            SessionOptions {
                budget: Some(Arc::new(|_, _, _| true)),
                ..Default::default()
            },
        )
    }

    fn manager_budget(limits: &config::Limits) -> Arc<BudgetFn> {
        let (reserve_cost, reserve_items) = pending_control_reserve(limits);
        let sessions = limits.max_sessions_global as i64;
        let max_cost = limits.max_pending_global as i64;
        let max_items = limits.max_pending_items_global as i64;
        let state = Arc::new(std::sync::Mutex::new((0i64, 0i64)));
        Arc::new(move |cost, items, class| {
            let mut state = state.lock().unwrap();
            let (mut cost_limit, mut item_limit) = (max_cost, max_items);
            if class != PendingClass::Control {
                cost_limit = if reserve_cost > max_cost / sessions {
                    0
                } else {
                    max_cost - reserve_cost * sessions
                };
                item_limit = if reserve_items > max_items / sessions {
                    0
                } else {
                    max_items - reserve_items * sessions
                };
            }
            if cost > cost_limit || state.0 > cost_limit - cost {
                return false;
            }
            if items > item_limit || state.1 > item_limit - items {
                return false;
            }
            state.0 += cost;
            state.1 += items;
            true
        })
    }

    fn reserved_limits() -> config::Limits {
        config::Limits {
            max_streams_per_session: 1,
            max_body_bytes: 1024,
            max_pending_per_session: 64 * 1024,
            max_pending_items_per_session: 256,
            ..config::Limits::default()
        }
    }

    fn fill_downlink_queue(session: &Arc<Session>) {
        let mut st = session.inner.lock().unwrap();
        let (cost_limit, item_limit) = downlink_pending_limits(&session.limits);
        assert!(session.reserve_pending_locked(
            &mut st,
            cost_limit,
            item_limit,
            PendingClass::Downlink
        ));
    }

    fn insert_fake_stream(session: &Arc<Session>, id: u32, send_credit: u64) -> Arc<BackendStream> {
        let backend = Arc::new(BackendStream::new(
            session.clone(),
            id,
            "127.0.0.1:1".to_string(),
        ));
        let mut st = session.inner.lock().unwrap();
        st.streams.insert(
            id,
            StreamState {
                backend: backend.clone(),
                receive_window: 0,
                send_credit,
                pending_write_bytes: 0,
                pending_write_cost: 0,
                pending_write_items: 0,
                credit_notify: Arc::new(Notify::new()),
                writes: VecDeque::new(),
                write_notify: Arc::new(Notify::new()),
            },
        );
        backend
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

    #[tokio::test]
    async fn sequence_retry_and_mismatch() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        let first = frame::encode(frame::FrameType::OPEN, 1, &[]);
        assert_eq!(session.process_up(1, &first), Ok(1));
        assert_eq!(session.process_up(1, &first), Ok(1));
        let changed = frame::encode(frame::FrameType::CLOSE, 1, &[]);
        assert_eq!(session.process_up(1, &changed), Err(SessionError::Protocol));
        assert!(session.is_closed());
        session.wait().await;
    }

    #[tokio::test]
    async fn lane_sequences_are_independent() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::HttpsLanes);
        let first = frame::encode(frame::FrameType::OPEN, 51, &[]);
        let second = frame::encode(frame::FrameType::OPEN, 52, &[]);
        assert_eq!(session.process_up_lane(51, 1, &first), Ok(1));
        assert_eq!(session.process_up_lane(52, 1, &second), Ok(1));
        assert_eq!(session.process_up_lane(51, 1, &first), Ok(1));
        session.close();
        session.wait().await;
    }

    #[tokio::test]
    async fn lane_rejects_cross_stream_frames() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::HttpsLanes);
        let mut body = frame::encode(frame::FrameType::OPEN, 61, &[]);
        body.extend_from_slice(&frame::encode(frame::FrameType::OPEN, 62, &[]));
        assert_eq!(
            session.process_up_lane(61, 1, &body),
            Err(SessionError::Protocol)
        );
        session.wait().await;
    }

    #[tokio::test]
    async fn closed_lane_replays_downlink_and_final_uplink() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::HttpsLanes);
        let lane_id = 71u32;
        let opened = frame::encode(frame::FrameType::OPEN, lane_id, &[]);
        session.process_up_lane(lane_id, 1, &opened).unwrap();
        wait_for(|| {
            let st = session.inner.lock().unwrap();
            !st.streams.contains_key(&lane_id)
        })
        .await;
        let cancel = CancellationToken::new();
        let outcome = session.poll_lane(&cancel, lane_id, 0).await.unwrap();
        assert!(!outcome.lane_closed);
        assert_eq!(outcome.next_cursor, 1);
        let frames = frame::parse_all(&outcome.body, frame::MAX_PAYLOAD).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, frame::FrameType::CLOSE);
        let replay = session.poll_lane(&cancel, lane_id, 0).await.unwrap();
        assert!(!replay.lane_closed);
        assert_eq!(replay.next_cursor, outcome.next_cursor);
        assert_eq!(replay.body, outcome.body);
        let final_poll = session.poll_lane(&cancel, lane_id, 1).await.unwrap();
        assert!(final_poll.lane_closed);
        assert!(final_poll.body.is_empty());
        assert_eq!(final_poll.next_cursor, 1);
        assert_eq!(session.process_up_lane(lane_id, 1, &opened), Ok(1));
        session.close();
        session.wait().await;
    }

    #[tokio::test]
    async fn rejects_stream_reuse_and_window_overrun() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        let mut batch = frame::encode(frame::FrameType::OPEN, 7, &[]);
        batch.extend_from_slice(&frame::encode(frame::FrameType::CLOSE, 7, &[]));
        assert_eq!(session.process_up(1, &batch), Ok(1));
        assert_eq!(
            session.process_up(2, &frame::encode(frame::FrameType::OPEN, 7, &[])),
            Err(SessionError::Protocol)
        );
        assert!(session.is_closed());

        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        let too_large = vec![1u8; frame::INITIAL_STREAM_WINDOW as usize + 1];
        let mut overrun = frame::encode(frame::FrameType::OPEN, 8, &[]);
        overrun.extend_from_slice(&frame::encode(frame::FrameType::DATA, 8, &too_large));
        assert_eq!(session.process_up(1, &overrun), Err(SessionError::Protocol));
        session.wait().await;
    }

    #[tokio::test]
    async fn pending_byte_limit_includes_backend_writes() {
        let limits = config::Limits {
            max_pending_per_session: 4,
            ..config::Limits::default()
        };
        let session = plain_session(limits, config::CarrierMode::Https);
        let mut batch = frame::encode(frame::FrameType::OPEN, 9, &[]);
        batch.extend_from_slice(&frame::encode(frame::FrameType::DATA, 9, b"12345"));
        assert_eq!(
            session.process_up(1, &batch),
            Err(SessionError::Backpressure)
        );
        assert_eq!(session.inner.lock().unwrap().last_up_sequence, 0);
        assert!(!session.is_closed());
        session.wait().await;
    }

    #[tokio::test]
    async fn process_pending_byte_limit_includes_backend_writes() {
        let limits = config::Limits {
            max_pending_global: 4,
            ..config::Limits::default()
        };
        let session = test_session(limits, config::CarrierMode::Https);
        let mut batch = frame::encode(frame::FrameType::OPEN, 10, &[]);
        batch.extend_from_slice(&frame::encode(frame::FrameType::DATA, 10, b"12345"));
        assert_eq!(
            session.process_up(1, &batch),
            Err(SessionError::Backpressure)
        );
        session.wait().await;
    }

    #[tokio::test]
    async fn process_pending_item_limit_includes_backend_writes() {
        let limits = config::Limits {
            max_pending_items_global: 1,
            ..config::Limits::default()
        };
        let session = test_session(limits, config::CarrierMode::Https);
        let mut batch = frame::encode(frame::FrameType::OPEN, 15, &[]);
        batch.extend_from_slice(&frame::encode(frame::FrameType::DATA, 15, &[1]));
        batch.extend_from_slice(&frame::encode(frame::FrameType::OPEN, 16, &[]));
        batch.extend_from_slice(&frame::encode(frame::FrameType::DATA, 16, &[2]));
        assert_eq!(
            session.process_up(1, &batch),
            Err(SessionError::Backpressure)
        );
        session.wait().await;
    }

    #[tokio::test]
    async fn pending_item_limit_includes_tiny_writes() {
        let limits = config::Limits {
            max_pending_items_per_session: 1,
            ..config::Limits::default()
        };
        let session = plain_session(limits, config::CarrierMode::Https);
        let mut batch = frame::encode(frame::FrameType::OPEN, 11, &[]);
        batch.extend_from_slice(&frame::encode(frame::FrameType::DATA, 11, &[1]));
        batch.extend_from_slice(&frame::encode(frame::FrameType::OPEN, 12, &[]));
        batch.extend_from_slice(&frame::encode(frame::FrameType::DATA, 12, &[2]));
        assert_eq!(
            session.process_up(1, &batch),
            Err(SessionError::Backpressure)
        );
        session.wait().await;
    }

    #[tokio::test]
    async fn control_frames_use_reserved_queue_headroom() {
        let mut limits = reserved_limits();
        limits.max_pending_global = limits.max_pending_per_session;
        limits.max_pending_items_global = limits.max_pending_items_per_session;
        limits.max_sessions_global = 1;
        let session = test_session(limits, config::CarrierMode::Https);
        {
            let mut st = session.inner.lock().unwrap();
            let (cost_limit, item_limit) = downlink_pending_limits(&session.limits);
            assert!(session.reserve_pending_locked(
                &mut st,
                cost_limit,
                item_limit,
                PendingClass::Downlink
            ));
            assert!(!session.queue_frame_locked(&mut st, frame::FrameType::DATA, 1, &[1]));
            assert!(session.queue_frame_locked(
                &mut st,
                frame::FrameType::WINDOW,
                1,
                &frame::window_payload(1)
            ));
            assert!(session.queue_frame_locked(&mut st, frame::FrameType::CLOSE, 1, &[]));
            assert!(!st.closed);
        }
        session.close();
    }

    #[tokio::test]
    async fn downlink_budget_preserves_one_uplink_batch() {
        let session = plain_session(reserved_limits(), config::CarrierMode::Https);
        fill_downlink_queue(&session);
        let mut body = frame::encode(frame::FrameType::OPEN, 21, &[]);
        body.extend_from_slice(&frame::encode(frame::FrameType::DATA, 21, &vec![1u8; 512]));
        assert_eq!(session.process_up(1, &body), Ok(1));
        session.close();
        session.wait().await;
    }

    #[tokio::test]
    async fn window_frames_coalesce_across_other_control_frames() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        {
            let mut st = session.inner.lock().unwrap();
            let queued = session.queue_frame_locked(
                &mut st,
                frame::FrameType::WINDOW,
                1,
                &frame::window_payload(2),
            );
            let queued =
                queued && session.queue_frame_locked(&mut st, frame::FrameType::CLOSE, 2, &[]);
            let queued = queued
                && session.queue_frame_locked(
                    &mut st,
                    frame::FrameType::WINDOW,
                    1,
                    &frame::window_payload(3),
                );
            assert!(queued);
            assert_eq!(st.pending_frames.len(), 2);
        }
        let cancel = CancellationToken::new();
        let outcome = session.poll(&cancel, 0).await.unwrap();
        let frames = frame::parse_all(&outcome.body, frame::MAX_PAYLOAD).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frame::window_amount(frames[0].payload).unwrap(), 5);
        session.close();
    }

    #[tokio::test]
    async fn downlink_budget_pauses_backend_reads() {
        let session = plain_session(reserved_limits(), config::CarrierMode::Https);
        insert_fake_stream(&session, 19, u64::from(frame::INITIAL_STREAM_WINDOW));
        fill_downlink_queue(&session);
        let cancel = CancellationToken::new();
        let waiter = {
            let session = session.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move { session.next_read_allowance(19, &cancel).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "backend read ran against a full queue"
        );
        {
            let mut st = session.inner.lock().unwrap();
            release_pending_locked(&session, &mut st, 1024, 1);
        }
        let allowance = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(allowance > 0);
        assert!(allowance <= 1024 - frame::HEADER_SIZE - QUEUE_ITEM_COST as usize);
        session.close();
    }

    #[tokio::test]
    async fn downlink_data_limit_does_not_close_session() {
        let session = plain_session(reserved_limits(), config::CarrierMode::Https);
        insert_fake_stream(&session, 20, u64::from(frame::INITIAL_STREAM_WINDOW));
        fill_downlink_queue(&session);
        assert!(!session.backend_data(20, &[1]));
        assert!(!session.is_closed());
        session.close();
    }

    #[tokio::test]
    async fn stream_cancellation_wakes_zero_credit_waiter() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        let backend = insert_fake_stream(&session, 18, 0);
        let stream_cancel = backend.cancel.clone();
        let waiter = {
            let session = session.clone();
            tokio::spawn(async move { session.next_read_allowance(18, &stream_cancel).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        backend.close();
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, None);
        session.close();
        session.wait().await;
    }

    #[tokio::test]
    async fn queued_frames_charge_overhead_and_limit_batch_count() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        {
            let mut st = session.inner.lock().unwrap();
            for id in 1..=frame::MAX_BATCH_FRAMES as u32 + 7 {
                assert!(session.queue_frame_locked(&mut st, frame::FrameType::CLOSE, id, &[]));
            }
            let expected_cost = (frame::MAX_BATCH_FRAMES + 7) as i64
                * (frame::HEADER_SIZE as i64 + QUEUE_ITEM_COST);
            assert_eq!(st.pending_cost, expected_cost);
            assert_eq!(st.pending_items, (frame::MAX_BATCH_FRAMES + 7) as i64);
        }
        let cancel = CancellationToken::new();
        let outcome = session.poll(&cancel, 0).await.unwrap();
        assert_eq!(outcome.next_cursor, 1);
        let frames = frame::parse_all(&outcome.body, frame::MAX_PAYLOAD).unwrap();
        assert_eq!(frames.len(), frame::MAX_BATCH_FRAMES);
        session.close();
    }

    #[tokio::test]
    async fn concurrent_uplink_is_rejected_and_newest_poll_wins() {
        let session = plain_session(config::Limits::default(), config::CarrierMode::Https);
        let cancel = CancellationToken::new();
        let first = {
            let session = session.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move { session.poll(&cancel, 0).await })
        };
        wait_for(|| session.inner.lock().unwrap().down_active).await;
        let second = {
            let session = session.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move { session.poll(&cancel, 0).await })
        };
        let superseded = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(superseded.body.is_empty());
        assert_eq!(superseded.next_cursor, 0);
        {
            let mut st = session.inner.lock().unwrap();
            assert!(session.queue_frame_locked(
                &mut st,
                frame::FrameType::WINDOW,
                1,
                &frame::window_payload(2)
            ));
        }
        let delivered = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!delivered.body.is_empty());
        assert_eq!(delivered.next_cursor, 1);
        assert!(!session.is_closed());
        {
            let mut st = session.inner.lock().unwrap();
            st.up_active = true;
        }
        assert_eq!(
            session.process_up(1, &frame::encode(frame::FrameType::OPEN, 13, &[])),
            Err(SessionError::Concurrent)
        );
        {
            let mut st = session.inner.lock().unwrap();
            st.up_active = false;
        }
        session.close();
        session.wait().await;
    }

    #[tokio::test]
    async fn evicted_lane_releases_budget_and_ignores_late_frames() {
        let limits = config::Limits {
            max_closed_stream_ids: 4,
            ..config::Limits::default()
        };
        let session = test_session(limits, config::CarrierMode::HttpsLanes);
        let total = 7u32;
        for id in 1..=total {
            session
                .process_up_lane(id, 1, &frame::encode(frame::FrameType::OPEN, id, &[]))
                .unwrap();
            wait_for(|| {
                let st = session.inner.lock().unwrap();
                !st.streams.contains_key(&id)
                    && (st.closed_streams.contains_key(&id) || !st.carrier_lanes.contains_key(&id))
            })
            .await;
        }
        let evicted = {
            let st = session.inner.lock().unwrap();
            (1..=total)
                .filter(|id| !st.carrier_lanes.contains_key(id))
                .count()
        };
        assert!(evicted > 0, "no lane was evicted");
        for id in 1..=total {
            let alive = session
                .inner
                .lock()
                .unwrap()
                .carrier_lanes
                .contains_key(&id);
            if !alive {
                continue;
            }
            let cancel = CancellationToken::new();
            let mut cursor = 0u64;
            loop {
                let outcome = session.poll_lane(&cancel, id, cursor).await.unwrap();
                if outcome.lane_closed {
                    break;
                }
                assert!(
                    !outcome.body.is_empty(),
                    "lane {id} returned an empty batch"
                );
                cursor = outcome.next_cursor;
            }
        }
        {
            let st = session.inner.lock().unwrap();
            assert_eq!(
                st.pending_cost, 0,
                "session budget leaked after lane eviction"
            );
            assert_eq!(
                st.pending_items, 0,
                "session budget leaked after lane eviction"
            );
        }
        let late = frame::encode(frame::FrameType::DATA, 1, b"late");
        assert_eq!(session.process_up_lane(1, 7, &late), Ok(7));
        assert!(!session.is_closed());
        session.close();
        session.wait().await;
    }
}
