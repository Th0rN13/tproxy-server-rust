use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, FromRequestParts};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::future::BoxFuture;
use futures_util::{SinkExt, StreamExt};
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, TE,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderValue, Method, Request, Response, StatusCode, Uri};

const KEEP_ALIVE: http::header::HeaderName = http::header::HeaderName::from_static("keep-alive");
const PROXY_AUTHENTICATE: http::header::HeaderName =
    http::header::HeaderName::from_static("proxy-authenticate");
const PROXY_AUTHORIZATION: http::header::HeaderName =
    http::header::HeaderName::from_static("proxy-authorization");
use tokio_util::sync::CancellationToken;

use crate::bridge;
use crate::config::{self, ConfigError};
use crate::frame;
use crate::session::manager::Manager;
use crate::session::{Session, SessionError};
use crate::token::read_token_key;

use secrets::{SecretScan, bearer_token, canonical_uint};
use site::StaticSite;

mod secrets;
mod site;

const WEB_SOCKET_PROTOCOL_PREFIX: &str = "tproxy-v1.";
const WEB_SOCKET_LANE_PROTOCOL_PREFIX: &str = "tproxy-lane-v1.";
const MAX_CREATE_BODY_BYTES: usize = 64;
const DEFAULT_BODY_READ_DEADLINE_MS: u64 = 30_000;
const NOT_FOUND_BODY: &str = "404 page not found\n";

type CustomPublicHandler =
    Arc<dyn Fn(Request<Body>) -> BoxFuture<'static, Response<Body>> + Send + Sync>;

enum PublicSource {
    Site(StaticSite),
    Upstream(
        Box<
            hyper_util::client::legacy::Client<
                hyper_util::client::legacy::connect::HttpConnector,
                Body,
            >,
        >,
    ),
    Custom(CustomPublicHandler),
}

pub struct Server {
    config: config::Config,
    base: String,
    manager: Arc<Manager>,
    public: PublicSource,
    body_read_deadline_ms: AtomicU64,
    legacy_token_drain: AtomicBool,
}

impl Server {
    pub fn new(value: config::Config) -> Result<Arc<Server>, ConfigError> {
        Self::build(value, None)
    }

    #[cfg(test)]
    pub(crate) fn new_with(
        value: config::Config,
        custom: Option<CustomPublicHandler>,
    ) -> Result<Arc<Server>, ConfigError> {
        Self::build(value, custom)
    }

    fn build(
        value: config::Config,
        custom: Option<CustomPublicHandler>,
    ) -> Result<Arc<Server>, ConfigError> {
        let token_key = read_token_key(&value.token_key_file)
            .map_err(|error| ConfigError(error.to_string()))?;
        crate::session::validate_budget(&value.limits)?;
        let base = config::base(&value.base_path);
        let legacy_token_drain = value.legacy_token_drain;
        let public = if let Some(handler) = custom {
            PublicSource::Custom(handler)
        } else if !value.public_dir.as_os_str().is_empty() {
            PublicSource::Site(
                StaticSite::load(&value.public_dir)
                    .map_err(|error| ConfigError(error.to_string()))?,
            )
        } else {
            let client =
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .build_http::<Body>();
            PublicSource::Upstream(Box::new(client))
        };
        Ok(Arc::new(Self {
            base,
            manager: Manager::new(value.clone(), token_key),
            public,
            body_read_deadline_ms: AtomicU64::new(DEFAULT_BODY_READ_DEADLINE_MS),
            legacy_token_drain: AtomicBool::new(legacy_token_drain),
            config: value,
        }))
    }

    pub fn manager(&self) -> &Arc<Manager> {
        &self.manager
    }

    pub fn config(&self) -> &config::Config {
        &self.config
    }

    #[cfg(test)]
    pub(crate) fn set_legacy_token_drain(&self, value: bool) {
        self.legacy_token_drain.store(value, Ordering::Relaxed);
    }

    pub fn admin_handler(self: &Arc<Self>) -> axum::Router {
        let readyz_server = self.clone();
        let metrics_server = self.clone();
        axum::Router::new()
            .route(
                "/healthz",
                axum::routing::get(|| async {
                    Response::builder()
                        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                        .body(Body::from(
                            "ok
",
                        ))
                        .unwrap()
                }),
            )
            .route(
                "/readyz",
                axum::routing::get(move || {
                    let server = readyz_server.clone();
                    async move {
                        let config = server.config().clone();
                        for profile in &config.profiles {
                            let connected = tokio::time::timeout(
                                config.timeouts.backend_dial.value(),
                                tokio::net::TcpStream::connect(&profile.backend),
                            )
                            .await;
                            let healthy = matches!(connected, Ok(Ok(_)));
                            if !healthy {
                                return Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                                    .body(Body::from(
                                        "backend unavailable
",
                                    ))
                                    .unwrap();
                            }
                        }
                        Response::builder()
                            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                            .body(Body::from(
                                "ready
",
                            ))
                            .unwrap()
                    }
                }),
            )
            .route(
                "/metrics",
                axum::routing::get(move || {
                    let server = metrics_server.clone();
                    async move {
                        let metrics = server.manager().metrics();
                        let capacity = server.manager().capacity();
                        Response::builder()
                            .header(CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body(Body::from(metrics_text(&metrics, &capacity)))
                            .unwrap()
                    }
                }),
            )
    }

    pub fn handler(self: &Arc<Self>) -> axum::Router {
        let server = self.clone();
        axum::Router::new().fallback_service(tower::service_fn(move |request: Request<Body>| {
            let server = server.clone();
            async move { Ok::<_, std::convert::Infallible>(server.serve_http(request).await) }
        }))
    }

    async fn serve_http(self: Arc<Self>, request: Request<Body>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        if !self.has_internal_secret(&parts) {
            return self.serve_public(parts, body).await;
        }
        self.serve_internal(parts, body).await
    }

    async fn serve_internal(
        self: Arc<Self>,
        parts: http::request::Parts,
        body: Body,
    ) -> Response<Body> {
        if !self.host_matches(&parts) {
            return not_found_response();
        }
        if let Some(suffix) = self.transport_suffix(parts.uri.path()) {
            return self.serve_api(parts, body, suffix).await;
        }
        if self.bridge_profile(&parts).is_some() {
            return self.serve_bridge(&parts).await;
        }
        not_found_response()
    }

    fn host_matches(&self, parts: &http::request::Parts) -> bool {
        let Some(host) = parts
            .headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let hostname = &self.config.public_hostname;
        host == hostname || host == format!("{hostname}:443")
    }

    fn transport_suffix(&self, request_path: &str) -> Option<&'static str> {
        let suffix = request_path.strip_prefix(&self.base)?;
        if request_path.contains('%') {
            return None;
        }
        match suffix {
            "api/v1/session" => Some("api/v1/session"),
            "api/v1/up" => Some("api/v1/up"),
            "api/v1/down" => Some("api/v1/down"),
            "api/v1/ws" => Some("api/v1/ws"),
            _ => None,
        }
    }

    fn bridge_profile(&self, parts: &http::request::Parts) -> Option<Arc<config::Profile>> {
        if parts.method != Method::GET || parts.uri.path() != self.base {
            return None;
        }
        let query = parts.uri.query()?;
        if query.len() != "bridge=".len() + 43 {
            return None;
        }
        let text = query.strip_prefix("bridge=")?;
        let value = URL_SAFE_NO_PAD.decode(text).ok()?;
        self.manager.match_capability(&value)
    }

    fn has_internal_secret(&self, parts: &http::request::Parts) -> bool {
        let mut scan = SecretScan::new(&self.manager);
        let authorization: Vec<&str> = parts
            .headers
            .get_all(AUTHORIZATION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        let websocket_protocols: Vec<String> = parts
            .headers
            .get_all("sec-websocket-protocol")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_string)
            .collect();
        if scan.carrier_credential(
            &authorization,
            &websocket_protocols,
            self.legacy_token_drain.load(Ordering::Relaxed),
        ) {
            return true;
        }
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("");
        if scan.contains(path_and_query.as_bytes()) {
            return true;
        }
        if let Some(host) = parts.headers.get(HOST)
            && scan.contains(host.as_bytes())
        {
            return true;
        }
        for (name, value) in parts.headers.iter() {
            if scan.contains(name.as_str().as_bytes()) || scan.contains(value.as_bytes()) {
                return true;
            }
        }
        false
    }

    async fn serve_bridge(&self, parts: &http::request::Parts) -> Response<Body> {
        let Some(profile) = self.bridge_profile(parts) else {
            return not_found_response();
        };
        let Ok(client_ip) = client_ip(parts) else {
            return not_found_response();
        };
        let Ok(token) = self.manager.issue_bootstrap(&profile, &client_ip) else {
            return not_found_response();
        };
        let Ok(page) = bridge::render(
            &self.config.public_hostname,
            &self.config.base_path,
            &token,
            profile.carrier_mode.as_str(),
            self.config.limits.carrier_batch_bytes,
        ) else {
            return not_found_response();
        };
        Response::builder()
            .status(StatusCode::OK)
            .header(CACHE_CONTROL, "no-store")
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header("Content-Security-Policy", page.csp)
            .header("Referrer-Policy", "no-referrer")
            .header("X-Content-Type-Options", "nosniff")
            .header("X-DNS-Prefetch-Control", "off")
            .header("Permissions-Policy", bridge::PERMISSIONS_POLICY)
            .header(CONTENT_LENGTH, page.body.len().to_string())
            .body(if parts.method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(page.body)
            })
            .unwrap()
    }

    async fn serve_api(
        self: Arc<Self>,
        parts: http::request::Parts,
        body: Body,
        suffix: &'static str,
    ) -> Response<Body> {
        if parts.uri.query().is_some()
            || parts.headers.get_all(AUTHORIZATION).iter().count() > 1
            || parts
                .headers
                .get_all("sec-websocket-protocol")
                .iter()
                .count()
                > 1
            || (parts.headers.get("cookie").is_some() && suffix != "api/v1/ws")
        {
            return not_found_response();
        }
        let Ok(client_ip) = client_ip(&parts) else {
            return not_found_response();
        };
        if suffix == "api/v1/ws" {
            return self.serve_web_socket(parts, body).await;
        }
        let Some(authentication) = parts.headers.get(AUTHORIZATION) else {
            return not_found_response();
        };
        let Some(token) = authentication
            .to_str()
            .ok()
            .and_then(bearer_token)
            .map(str::to_string)
        else {
            return not_found_response();
        };
        match suffix {
            "api/v1/session" => self.serve_session(parts, body, &token, &client_ip).await,
            "api/v1/up" => self.serve_up(parts, body, &token).await,
            "api/v1/down" => self.serve_down(parts, body, &token).await,
            _ => not_found_response(),
        }
    }

    async fn serve_session(
        self: Arc<Self>,
        parts: http::request::Parts,
        body: Body,
        token: &str,
        client_ip: &str,
    ) -> Response<Body> {
        if parts.method == Method::DELETE {
            let empty = parts.headers.get(CONTENT_TYPE).is_none()
                && empty_body(body, self.body_read_deadline()).await;
            if !empty {
                return not_found_response();
            }
            if self.manager.close_token(token).is_err() {
                return not_found_response();
            }
            return Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap();
        }
        if parts.method != Method::POST || !binary_content_type(parts.headers.get(CONTENT_TYPE)) {
            return not_found_response();
        }
        if !self.manager.has_bootstrap(token) {
            return not_found_response();
        }
        let Ok(hello) = read_body(body, MAX_CREATE_BODY_BYTES, self.body_read_deadline()).await
        else {
            return not_found_response();
        };
        match self.manager.create(token, client_ip, &hello) {
            Ok(result) => Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/octet-stream")
                .header(CONTENT_LENGTH, result.welcome.len().to_string())
                .header("X-Session-Token", result.token)
                .header("X-Carrier-Mode", result.session.carrier_mode().as_str())
                .header("X-Down-Cursor", "0")
                .body(Body::from(result.welcome))
                .unwrap(),
            Err(SessionError::Limit) => retry_after_response(),
            Err(_) => not_found_response(),
        }
    }

    async fn serve_up(
        self: Arc<Self>,
        parts: http::request::Parts,
        body: Body,
        token: &str,
    ) -> Response<Body> {
        if parts.method != Method::POST || !binary_content_type(parts.headers.get(CONTENT_TYPE)) {
            return not_found_response();
        }
        let Some(sequence) = header_uint(parts.headers.get("x-up-seq")).filter(|value| *value > 0)
        else {
            return not_found_response();
        };
        let Ok(session) = self.manager.get(token) else {
            return not_found_response();
        };
        let Ok(frames) = read_body(
            body,
            self.config.limits.max_body_bytes,
            self.body_read_deadline(),
        )
        .await
        else {
            return not_found_response();
        };
        let result = match session.carrier_mode() {
            config::CarrierMode::Https => {
                if parts.headers.get("x-lane-id").is_some() {
                    return not_found_response();
                }
                session.process_up(sequence, &frames)
            }
            config::CarrierMode::HttpsLanes => {
                let Some(lane) = lane_id(&parts) else {
                    return not_found_response();
                };
                session.process_up_lane(lane, sequence, &frames)
            }
            _ => return not_found_response(),
        };
        match result {
            Ok(ack) => Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("X-Up-Ack", ack.to_string())
                .body(Body::empty())
                .unwrap(),
            Err(SessionError::Backpressure) | Err(SessionError::Concurrent) => {
                retry_after_response()
            }
            Err(_) => not_found_response(),
        }
    }

    async fn serve_down(
        self: Arc<Self>,
        parts: http::request::Parts,
        body: Body,
        token: &str,
    ) -> Response<Body> {
        if parts.method != Method::POST || parts.headers.get(CONTENT_TYPE).is_some() {
            return not_found_response();
        }
        let Some(cursor) = header_uint(parts.headers.get("x-down-cursor")) else {
            return not_found_response();
        };
        let Ok(session) = self.manager.get(token) else {
            return not_found_response();
        };
        if !empty_body(body, self.body_read_deadline()).await {
            return not_found_response();
        }
        let cancel = CancellationToken::new();
        let result = match session.carrier_mode() {
            config::CarrierMode::Https => {
                if parts.headers.get("x-lane-id").is_some() {
                    return not_found_response();
                }
                session
                    .poll(&cancel, cursor)
                    .await
                    .map(|outcome| (outcome.body, outcome.next_cursor, false))
            }
            config::CarrierMode::HttpsLanes => {
                let Some(lane) = lane_id(&parts) else {
                    return not_found_response();
                };
                session
                    .poll_lane(&cancel, lane, cursor)
                    .await
                    .map(|outcome| (outcome.body, outcome.next_cursor, outcome.lane_closed))
            }
            _ => return not_found_response(),
        };
        let (frames, next, lane_closed) = match result {
            Ok(result) => result,
            Err(SessionError::Concurrent) => return retry_after_response(),
            Err(_) => return not_found_response(),
        };
        let mut builder = Response::builder()
            .header(CACHE_CONTROL, "no-store")
            .header("X-Down-Cursor", next.to_string());
        if lane_closed {
            builder = builder.header("X-Lane-Closed", "1");
        }
        if frames.is_empty() {
            return builder
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap();
        }
        builder
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, frames.len().to_string())
            .body(Body::from(frames))
            .unwrap()
    }

    async fn serve_web_socket(
        self: Arc<Self>,
        mut parts: http::request::Parts,
        body: Body,
    ) -> Response<Body> {
        if parts.method != Method::GET || parts.headers.get(AUTHORIZATION).is_some() {
            return not_found_response();
        }
        let mut protocols: Vec<String> = Vec::new();
        for value in parts.headers.get_all("sec-websocket-protocol") {
            let Some(value) = value.to_str().ok() else {
                return not_found_response();
            };
            protocols.extend(
                value
                    .split(',')
                    .map(|item| item.trim().trim_matches('"').to_string()),
            );
        }
        if protocols.len() != 1 {
            return not_found_response();
        }
        let Some((token, lane_id, lanes, true)) = web_socket_credentials(&protocols[0]) else {
            return not_found_response();
        };
        if bearer_token(&format!("Bearer {token}")).is_none() {
            return not_found_response();
        }
        let Ok(session) = self.manager.get(token) else {
            return not_found_response();
        };
        let mode_matches = if lanes {
            session.carrier_mode() == config::CarrierMode::WebSocketLanes
        } else {
            session.carrier_mode() == config::CarrierMode::WebSocket
        };
        if !mode_matches || !empty_body(body, self.body_read_deadline()).await {
            return not_found_response();
        }
        let acquired = if lanes {
            session.acquire_websocket_lane(lane_id)
        } else {
            session.acquire_websocket()
        };
        if !acquired {
            return not_found_response();
        }
        enum Release {
            Lane(Box<dyn FnOnce() + Send>),
            Session(Box<dyn FnOnce() + Send>),
        }
        impl Release {
            fn run(self) {
                match self {
                    Release::Lane(run) => run(),
                    Release::Session(run) => run(),
                }
            }
        }
        let release = if lanes {
            let session = session.clone();
            Release::Lane(Box::new(move || session.release_websocket_lane(lane_id)))
        } else {
            let session = session.clone();
            Release::Session(Box::new(move || session.close()))
        };
        let Ok(upgrade) =
            <WebSocketUpgrade as FromRequestParts<()>>::from_request_parts(&mut parts, &()).await
        else {
            release.run();
            return not_found_response();
        };
        let idle = 2 * self.config.timeouts.long_poll.value();
        let max_message_size = self.config.limits.max_body_bytes;
        upgrade
            .max_message_size(max_message_size)
            .protocols(protocols.clone())
            .on_upgrade(move |socket| async move {
                handle_web_socket(session, socket, lane_id, lanes, idle).await;
                release.run();
            })
    }

    async fn serve_public(
        self: Arc<Self>,
        parts: http::request::Parts,
        body: Body,
    ) -> Response<Body> {
        match &self.public {
            PublicSource::Custom(handler) => handler(Request::from_parts(parts, body)).await,
            PublicSource::Upstream(client) => {
                proxy_public(parts, body, client, &self.config.public_upstream).await
            }
            PublicSource::Site(site) => serve_site(site, &parts, &self.config.static_routes),
        }
    }

    fn body_read_deadline(&self) -> Duration {
        Duration::from_millis(self.body_read_deadline_ms.load(Ordering::Relaxed))
    }
}

async fn handle_web_socket(
    session: Arc<Session>,
    socket: WebSocket,
    lane_id: u32,
    lanes: bool,
    idle: Duration,
) {
    let (mut sender, mut receiver) = socket.split();
    let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel::<Message>(16);
    let read_session = session.clone();
    let mut read_task = tokio::spawn(async move {
        let mut sequence = 1u64;
        loop {
            let message = tokio::time::timeout(idle, receiver.next())
                .await
                .map_err(|_| ())
                .and_then(|message| message.ok_or(()));
            let Ok(Ok(message)) = message else {
                return;
            };
            match message {
                Message::Binary(data) => {
                    if data.is_empty() {
                        return;
                    }
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                    loop {
                        let process = if lanes {
                            read_session.process_up_lane(lane_id, sequence, &data)
                        } else {
                            read_session.process_up(sequence, &data)
                        };
                        match process {
                            Ok(ack) if ack == sequence => {
                                sequence += 1;
                                break;
                            }
                            Err(SessionError::Backpressure) => {
                                if tokio::time::Instant::now() >= deadline {
                                    return;
                                }
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            _ => return,
                        }
                    }
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ => return,
            }
        }
    });
    let mut write_task = tokio::spawn(async move {
        let cancel = CancellationToken::new();
        let mut cursor = 0u64;
        loop {
            let outcome = if lanes {
                session.poll_lane(&cancel, lane_id, cursor).await
            } else {
                session.poll(&cancel, cursor).await
            };
            let Ok(outcome) = outcome else {
                return;
            };
            if outcome.lane_closed {
                return;
            }
            let message = if outcome.body.is_empty() {
                Message::Ping(bytes::Bytes::new())
            } else {
                cursor = outcome.next_cursor;
                Message::Binary(bytes::Bytes::from(outcome.body))
            };
            if tokio::time::timeout(Duration::from_secs(30), outgoing_tx.send(message))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    loop {
        tokio::select! {
            message = outgoing_rx.recv() => match message {
                Some(message) => {
                    if sender.send(message).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            _ = &mut read_task => break,
            _ = &mut write_task => break,
        }
    }
    read_task.abort();
    write_task.abort();
}

fn serve_site(
    site: &StaticSite,
    parts: &http::request::Parts,
    static_routes: &str,
) -> Response<Body> {
    let legacy = static_routes == "legacy";
    if parts.method == Method::GET || parts.method == Method::HEAD {
        let path = parts.uri.path();
        if path == "/" {
            return serve_entry(parts, &site.index, StatusCode::OK);
        }
        if let Some(entry) = site.resolve(path, legacy) {
            return serve_entry(parts, &entry, StatusCode::OK);
        }
    }
    serve_entry(parts, &site.not_found, StatusCode::NOT_FOUND)
}

fn serve_entry(
    parts: &http::request::Parts,
    entry: &site::StaticEntry,
    status: StatusCode,
) -> Response<Body> {
    let mut builder = Response::builder().header(CONTENT_TYPE, entry.content_type.clone());
    if status == StatusCode::OK {
        builder = builder
            .header("ETag", entry.etag.clone())
            .header("Accept-Ranges", "bytes")
            .header("Last-Modified", http_date(entry.mod_time));
        if not_modified(parts, entry) {
            return builder
                .status(StatusCode::NOT_MODIFIED)
                .body(Body::empty())
                .unwrap();
        }
        match range_request(parts, entry) {
            Some(Ok((start, end))) => {
                let slice = entry.body[start..end].to_vec();
                return builder
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(
                        "Content-Range",
                        format!("bytes {start}-{}/{}", end - 1, entry.body.len()),
                    )
                    .header(CONTENT_LENGTH, slice.len().to_string())
                    .body(Body::from(slice))
                    .unwrap();
            }
            Some(Err(_unsatisfiable)) => {
                return builder
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Content-Range", format!("bytes */{}", entry.body.len()))
                    .body(Body::empty())
                    .unwrap();
            }
            None => {}
        }
        return builder
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, entry.body.len().to_string())
            .body(if parts.method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(entry.body.clone())
            })
            .unwrap();
    }
    builder
        .status(status)
        .header(CONTENT_LENGTH, entry.body.len().to_string())
        .body(if parts.method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(entry.body.clone())
        })
        .unwrap()
}

fn not_modified(parts: &http::request::Parts, entry: &site::StaticEntry) -> bool {
    if let Some(match_header) = header_str(parts.headers.get("if-none-match")) {
        return match_header == "*" || contains_etag(match_header, &entry.etag);
    }
    if let Some(since) = header_str(parts.headers.get("if-modified-since"))
        && let Some(parsed) = parse_http_date(since)
    {
        return !(entry.mod_time > parsed);
    }
    false
}

fn contains_etag(header: &str, etag: &str) -> bool {
    header.split(',').any(|candidate| candidate.trim() == etag)
}

fn range_request(
    parts: &http::request::Parts,
    entry: &site::StaticEntry,
) -> Option<Result<(usize, usize), bool>> {
    let range = header_str(parts.headers.get("range"))?;
    if let Some(if_range) = header_str(parts.headers.get("if-range"))
        && if_range != entry.etag
        && parse_http_date(if_range) != Some(entry.mod_time)
    {
        return None;
    }
    let specification = range.strip_prefix("bytes=")?;
    let (first, last) = specification.split_once('-')?;
    let size = entry.body.len();
    if first.is_empty() {
        let suffix: usize = last.parse().ok()?;
        if suffix == 0 {
            return Some(Err(true));
        }
        return Some(Ok((size.saturating_sub(suffix), size)));
    }
    let start: usize = first.parse().ok()?;
    let end = if last.is_empty() {
        size
    } else {
        last.parse::<usize>().ok()?.saturating_add(1).min(size)
    };
    if start >= size {
        return Some(Err(true));
    }
    if start >= end {
        return None;
    }
    Some(Ok((start, end)))
}

fn not_found_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .header(CONTENT_LENGTH, NOT_FOUND_BODY.len().to_string())
        .body(Body::from(NOT_FOUND_BODY))
        .unwrap()
}

fn retry_after_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(CACHE_CONTROL, "no-store")
        .header("Retry-After", "1")
        .body(Body::empty())
        .unwrap()
}

async fn proxy_public(
    mut parts: http::request::Parts,
    body: Body,
    client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Body,
    >,
    upstream: &str,
) -> Response<Body> {
    for name in [
        CONNECTION,
        KEEP_ALIVE,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        parts.headers.remove(name);
    }
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let Ok(uri) = format!("{upstream}{path_and_query}").parse::<Uri>() else {
        return bad_gateway();
    };
    parts.uri = uri;
    match client.request(Request::from_parts(parts, body)).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            for name in [
                CONNECTION,
                KEEP_ALIVE,
                PROXY_AUTHENTICATE,
                PROXY_AUTHORIZATION,
                TE,
                TRANSFER_ENCODING,
                UPGRADE,
            ] {
                parts.headers.remove(name);
            }
            Response::from_parts(parts, Body::new(body))
        }
        Err(_) => bad_gateway(),
    }
}

fn bad_gateway() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, "Bad Gateway\n".len().to_string())
        .body(Body::from("Bad Gateway\n"))
        .unwrap()
}

fn client_ip(parts: &http::request::Parts) -> Result<String, ()> {
    let Some(connect_info) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
        return Err(());
    };
    let peer = connect_info.0.ip();
    if !peer.is_loopback() {
        return Err(());
    }
    let Some(forwarded) = header_str(parts.headers.get("x-forwarded-for")) else {
        return Ok(peer.to_string());
    };
    if forwarded.contains(',') || forwarded.trim() != forwarded {
        return Err(());
    }
    let parsed: IpAddr = forwarded.parse().map_err(|_| ())?;
    Ok(parsed.to_string())
}

fn lane_id(parts: &http::request::Parts) -> Option<u32> {
    header_uint(parts.headers.get("x-lane-id"))
        .filter(|lane| *lane > 0 && *lane <= u64::from(frame::MAX_STREAM_ID))
        .map(|lane| lane as u32)
}

fn metrics_text(
    metrics: &crate::session::manager::Metrics,
    capacity: &crate::session::manager::Capacity,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "tproxy_sessions_live {}", capacity.sessions);
    let _ = writeln!(out, "tproxy_streams_live {}", capacity.streams);
    let _ = writeln!(
        out,
        "tproxy_backend_dials_in_flight {}",
        capacity.backend_dials_in_flight
    );
    let _ = writeln!(out, "tproxy_pending_bytes {}", capacity.pending_bytes);
    let _ = writeln!(out, "tproxy_pending_items {}", capacity.pending_items);
    let _ = writeln!(
        out,
        "tproxy_sessions_created_total {}",
        metrics.sessions_created
    );
    let _ = writeln!(
        out,
        "tproxy_sessions_closed_total {}",
        metrics.sessions_closed
    );
    let _ = writeln!(
        out,
        "tproxy_streams_opened_total {}",
        metrics.streams_opened
    );
    let _ = writeln!(
        out,
        "tproxy_streams_rejected_total {}",
        metrics.streams_rejected
    );
    let _ = writeln!(
        out,
        "tproxy_backend_dial_failures_total {}",
        metrics.backend_dial_failures
    );
    let _ = writeln!(out, "tproxy_bytes_up_total {}", metrics.bytes_up);
    let _ = writeln!(out, "tproxy_bytes_down_total {}", metrics.bytes_down);
    let _ = writeln!(out, "tproxy_limit_hits_total {}", metrics.limit_hits);
    out
}

fn header_str(value: Option<&HeaderValue>) -> Option<&str> {
    value.and_then(|value| value.to_str().ok())
}

fn header_uint(value: Option<&HeaderValue>) -> Option<u64> {
    canonical_uint(header_str(value)?)
}

fn binary_content_type(value: Option<&HeaderValue>) -> bool {
    let Some(value) = header_str(value) else {
        return false;
    };
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/octet-stream")
}

async fn read_body(body: Body, limit: usize, deadline: Duration) -> Result<Vec<u8>, ()> {
    let mut stream = body.into_data_stream();
    let read = async {
        let mut collected: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ())?;
            if collected.len() + chunk.len() > limit {
                return Err(());
            }
            collected.extend_from_slice(&chunk);
        }
        if collected.is_empty() {
            return Err(());
        }
        Ok(collected)
    };
    tokio::time::timeout(deadline, read).await.map_err(|_| ())?
}

async fn empty_body(body: Body, deadline: Duration) -> bool {
    let mut stream = body.into_data_stream();
    match tokio::time::timeout(deadline, stream.next()).await {
        Err(_) => false,
        Ok(None) => true,
        Ok(Some(Ok(chunk))) => chunk.is_empty(),
        Ok(Some(Err(_))) => false,
    }
}

pub(crate) fn web_socket_credentials(protocol: &str) -> Option<(&str, u32, bool, bool)> {
    if let Some(token) = protocol.strip_prefix(WEB_SOCKET_PROTOCOL_PREFIX) {
        return if token.is_empty() {
            None
        } else {
            Some((token, 0, false, true))
        };
    }
    let rest = protocol.strip_prefix(WEB_SOCKET_LANE_PROTOCOL_PREFIX)?;
    let (token, lane_text) = rest.split_once('.')?;
    if token.is_empty() {
        return None;
    }
    let lane = canonical_uint(lane_text)?;
    if lane == 0 || lane > u64::from(frame::MAX_STREAM_ID) {
        return None;
    }
    Some((token, lane as u32, true, true))
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn http_date(time: std::time::SystemTime) -> String {
    let seconds = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_http_date(text: &str) -> Option<std::time::SystemTime> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month = MONTHS.iter().position(|value| *value == parts[2])? as i64 + 1;
    let year: i64 = parts[3].parse().ok()?;
    let time: Vec<&str> = parts[4].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: i64 = time[0].parse().ok()?;
    let minute: i64 = time[1].parse().ok()?;
    let second: i64 = time[2].parse().ok()?;
    if !(1..=9_999).contains(&year)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    if seconds < 0 {
        return None;
    }
    std::time::SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenClass;
    use futures_util::FutureExt;
    use rand::RngCore;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_HOST: &str = "proxy.example.com";
    const TEST_SECRET: &str = "000102030405060708090a0b0c0d0e0f";

    fn hex_bytes(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "tproxy-server-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn test_config(backend: &str) -> config::Config {
        let directory = temp_dir("site");
        std::fs::write(
            directory.join("index.html"),
            "<!doctype html><title>Operator Site</title><p>ordinary site</p>",
        )
        .unwrap();
        std::fs::write(
            directory.join("404.html"),
            "<!doctype html><title>Not found</title><p>Operator Site</p>",
        )
        .unwrap();
        std::fs::write(
            directory.join("about.html"),
            "<!doctype html><title>About</title>",
        )
        .unwrap();
        std::fs::write(
            directory.join("favicon.svg"),
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
        )
        .unwrap();
        let mut value = config::Config::default();
        let token_key = temp_dir("token-key").join("token.key");
        std::fs::write(&token_key, [1u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        value.token_key_file = token_key;
        value.public_hostname = TEST_HOST.to_string();
        value.public_dir = directory;
        value.timeouts.long_poll = config::Duration::from_millis(500);
        value.timeouts.backend_dial = config::Duration::from_secs(1);
        value.profiles.push(config::Profile {
            name: "default".to_string(),
            backend: backend.to_string(),
            carrier_mode: config::CarrierMode::Https,
            capability: config::derive_capability(TEST_HOST, "", &hex_bytes(TEST_SECRET)),
            limits: config::ProfileLimits::default(),
        });
        value
    }

    fn new_test_server(backend: &str) -> (Arc<Server>, Vec<u8>) {
        let value = test_config(backend);
        let index = b"<!doctype html><title>Operator Site</title><p>ordinary site</p>".to_vec();
        (Server::new(value).unwrap(), index)
    }

    async fn echo_backend() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let Ok((connection, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (mut read_half, mut write_half) = connection.into_split();
                    let mut buffer = vec![0u8; 65536];
                    loop {
                        match read_half.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => {
                                if write_half.write_all(&buffer[..read]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        address
    }

    async fn hosted(server: Arc<Server>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = server.handler();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        address
    }

    fn http_client()
    -> hyper_util::client::legacy::Client<hyper_util::client::legacy::connect::HttpConnector, Body>
    {
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http()
    }

    type Headers = Vec<(&'static str, String)>;

    async fn send(
        client: &hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            Body,
        >,
        method: Method,
        address: SocketAddr,
        target: &str,
        host: &str,
        headers: Headers,
        body: Option<Vec<u8>>,
    ) -> Response<Vec<u8>> {
        let uri = format!("http://{address}{target}");
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, host);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder.body(Body::from(body.unwrap_or_default())).unwrap();
        let response = client.request(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let collected = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        Response::from_parts(parts, collected.to_vec())
    }

    fn api_headers(token: &str, body: Option<&[u8]>) -> Headers {
        let mut headers: Headers = vec![
            ("X-Forwarded-For", "198.51.100.7".to_string()),
            ("Origin", format!("https://{TEST_HOST}")),
            ("Authorization", format!("Bearer {token}")),
        ];
        if body.is_some() {
            headers.push(("Content-Type", "application/octet-stream".to_string()));
        }
        headers
    }

    fn capability_string() -> String {
        config::capability_string(config::derive_capability(
            TEST_HOST,
            "",
            &hex_bytes(TEST_SECRET),
        ))
    }

    fn fingerprint_headers(response: &Response<Vec<u8>>) -> String {
        let mut names: Vec<&str> = response.headers().keys().map(|key| key.as_str()).collect();
        names.sort();
        names.dedup();
        let mut joined = String::new();
        for name in names {
            let values: Vec<String> = response
                .headers()
                .get_all(name)
                .iter()
                .map(|value| value.to_str().unwrap_or_default().to_string())
                .collect();
            if name == "date" {
                continue;
            }
            joined.push_str(&format!("{name}: {}\n", values.join(", ")));
        }
        joined
    }

    #[test]
    fn web_socket_credentials_shapes() {
        let token = "A".repeat(43);
        let tests = [
            (
                format!("tproxy-v1.{token}"),
                Some((token.clone(), 0u32, false)),
            ),
            (
                format!("tproxy-lane-v1.{token}.17"),
                Some((token.clone(), 17, true)),
            ),
            (format!("tproxy-lane-v1.{token}.0"), None),
            (format!("tproxy-lane-v1.{token}.017"), None),
            (format!("tproxy-lane-v1.{token}.16777216"), None),
            (format!("tproxy-lane-v1.{token}.17.extra"), None),
        ];
        for (protocol, want) in tests {
            let got = web_socket_credentials(&protocol)
                .map(|(token, lane, lanes, _)| (token.to_string(), lane, lanes));
            assert_eq!(got, want, "credentials for {protocol:?}");
        }
    }

    async fn direct_request(
        server: &Arc<Server>,
        method: Method,
        target: &str,
        headers: Headers,
        body: Vec<u8>,
    ) -> Response<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("http://{TEST_HOST}{target}"))
            .header(HOST, TEST_HOST);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let mut request = builder.body(Body::from(body)).unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::from([127, 0, 0, 1]),
            1234,
        )));
        server.clone().serve_http(request).await
    }

    #[tokio::test]
    async fn authentic_secrets_never_reach_public_handler() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let counter = forwarded.clone();
        let handler: CustomPublicHandler = Arc::new(move |_| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(Body::empty())
                    .unwrap()
            }
            .boxed()
        });
        let value = test_config("127.0.0.1:1");
        let server = Server::new_with(value.clone(), Some(handler)).unwrap();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "127.0.0.1")
            .unwrap();
        let created = server
            .manager()
            .create(
                &bootstrap,
                "127.0.0.1",
                &frame::encode(frame::FrameType::HELLO, 0, &[1]),
            )
            .unwrap();
        let capability = capability_string();
        for secret in [&capability, bootstrap.as_str(), created.token.as_str()] {
            for target in [
                format!("/wrong/{secret}"),
                format!("/?bridge={secret}&extra=1"),
                format!("/?bridge=wrong&bridge={secret}"),
                format!("/?bridge={secret};bad=%zz"),
                format!("/?bridge=%{:02x}{}", secret.as_bytes()[0], &secret[1..]),
                format!("/api/v1/up?bridge={secret}"),
            ] {
                let response =
                    direct_request(&server, Method::HEAD, &target, Vec::new(), Vec::new()).await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "target {target}");
                assert_eq!(
                    response.headers().get(CACHE_CONTROL),
                    Some(&HeaderValue::from_static("no-store"))
                );
            }
            for name in ["Authorization", "Cookie", "Referer", "X-Unexpected"] {
                let response = direct_request(
                    &server,
                    Method::POST,
                    "/wrong",
                    vec![(name, format!("random, Bearer {secret}, malformed"))],
                    b"body".to_vec(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "header {name}");
                assert_eq!(
                    response.headers().get(CACHE_CONTROL),
                    Some(&HeaderValue::from_static("no-store"))
                );
            }
            for protocol in [
                format!("chat, tproxy-v1.{secret}"),
                format!("tproxy-lane-v1.{secret}.bad"),
            ] {
                let response = direct_request(
                    &server,
                    Method::GET,
                    "/api/v1/ws",
                    vec![("Sec-WebSocket-Protocol", protocol)],
                    Vec::new(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                assert_eq!(
                    response.headers().get(CACHE_CONTROL),
                    Some(&HeaderValue::from_static("no-store"))
                );
            }
        }
        for target in [
            "/api/v1/session",
            "/api/v1/up",
            "/api/v1/down",
            "/api/v1/ws",
        ] {
            let response = direct_request(
                &server,
                Method::POST,
                target,
                vec![("Authorization", format!("Bearer {}", created.token))],
                Vec::new(),
            )
            .await;
            assert_eq!(
                response.headers().get(HOST),
                None,
                "host header spoof check"
            );
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "target {target}");
        }
        assert_eq!(
            forwarded.load(Ordering::Relaxed),
            0,
            "authentic secret reached public handler"
        );
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn secrets_found_at_every_offset_inside_base64_runs() {
        let value = test_config("127.0.0.1:1");
        let server = Server::new(value.clone()).unwrap();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "127.0.0.1")
            .unwrap();
        let capability = capability_string();
        let filler = "Zq9_-xY0aB3cD4eF5gH6";
        for secret in [&capability, bootstrap.as_str()] {
            for before in 0..9usize {
                for after in 0..6usize {
                    let text = format!("x {}{secret}{} y", &filler[..before], &filler[..after]);
                    assert!(
                        server.has_internal_secret(&header_request(&text)),
                        "secret missed with {before} before and {after} after"
                    );
                    let truncated = format!(
                        "{}{} {}{}",
                        &filler[..before],
                        &secret[..42],
                        &secret[1..],
                        &filler[..after]
                    );
                    assert!(
                        !server.has_internal_secret(&header_request(&truncated)),
                        "truncated secret matched"
                    );
                }
            }
        }
        server.manager().shutdown().await;
    }

    fn header_request(value: &str) -> http::request::Parts {
        let builder = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{TEST_HOST}/"))
            .header(HOST, TEST_HOST)
            .header("X-Unexpected", value);
        let request = builder.body(Body::empty()).unwrap();
        let (parts, _) = request.into_parts();
        parts
    }

    #[tokio::test]
    async fn untagged_tokens_fail_locally_after_upgrade() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let counter = forwarded.clone();
        let handler: CustomPublicHandler = Arc::new(move |_| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::empty())
                    .unwrap()
            }
            .boxed()
        });
        let value = test_config("127.0.0.1:1");
        let server = Server::new_with(value.clone(), Some(handler)).unwrap();
        let key = [1u8; 32];
        let other_key = [9u8; 32];
        for kind in [TokenClass::Bootstrap, TokenClass::Session] {
            let token = sign_untagged_token(key, kind);
            assert_eq!(
                server.manager().classify_token(&token),
                TokenClass::External
            );
            for target in ["/api/v1/session", "/api/v1/up", "/api/v1/down"] {
                let response = direct_request(
                    &server,
                    Method::POST,
                    target,
                    vec![("Authorization", format!("Bearer {token}"))],
                    b"frames".to_vec(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "target {target}");
                assert_eq!(
                    response.headers().get(CACHE_CONTROL),
                    Some(&HeaderValue::from_static("no-store"))
                );
            }
            for protocol in [
                format!("tproxy-v1.{token}"),
                format!("tproxy-lane-v1.{token}.1"),
            ] {
                let response = direct_request(
                    &server,
                    Method::GET,
                    "/api/v1/ws",
                    vec![("Sec-WebSocket-Protocol", protocol)],
                    Vec::new(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                assert_eq!(
                    response.headers().get(CACHE_CONTROL),
                    Some(&HeaderValue::from_static("no-store"))
                );
            }
            for public in [sign_untagged_token(other_key, kind), "A".repeat(43)] {
                let response = direct_request(
                    &server,
                    Method::POST,
                    "/api/v1/up",
                    vec![("Authorization", format!("Bearer {public}"))],
                    b"frames".to_vec(),
                )
                .await;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            }
        }
        assert_eq!(forwarded.load(Ordering::Relaxed), 4);
        server.manager().shutdown().await;
    }

    fn sign_untagged_token(key: [u8; 32], kind: TokenClass) -> String {
        use hmac::Mac;
        let mut token = [0u8; 32];
        rand::rng().fill_bytes(&mut token[..16]);
        let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(b"tproxy-server-token-v1\x00");
        mac.update(&[kind as u8]);
        mac.update(&token[..16]);
        token[16..].copy_from_slice(&mac.finalize().into_bytes()[..16]);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
    }

    #[tokio::test]
    async fn malformed_delete_does_not_close_session() {
        let value = test_config("127.0.0.1:1");
        let server = Server::new(value.clone()).unwrap();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "127.0.0.1")
            .unwrap();
        let created = server
            .manager()
            .create(
                &bootstrap,
                "127.0.0.1",
                &frame::encode(frame::FrameType::HELLO, 0, &[1]),
            )
            .unwrap();
        let response = direct_request(
            &server,
            Method::DELETE,
            "/api/v1/session",
            vec![("Authorization", format!("Bearer {}", created.token))],
            b"unexpected body".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(server.manager().get(&created.token).is_ok());
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn legacy_drain_contains_old_tokens_until_clients_reload() {
        let forwarded = Arc::new(AtomicUsize::new(0));
        let counter = forwarded.clone();
        let handler: CustomPublicHandler = Arc::new(move |_| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(Body::empty())
                    .unwrap()
            }
            .boxed()
        });
        let value = test_config("127.0.0.1:1");
        let server = Server::new_with(value, Some(handler)).unwrap();
        for (name, value_text) in [
            ("Authorization", format!("Bearer {}", "A".repeat(43))),
            (
                "Sec-WebSocket-Protocol",
                format!("tproxy-v1.{}", "A".repeat(43)),
            ),
        ] {
            server.set_legacy_token_drain(true);
            let response = direct_request(
                &server,
                Method::POST,
                "/api/v1/up",
                vec![(name, value_text.clone())],
                b"legacy body".to_vec(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "header {name}");
            assert_eq!(
                response.headers().get(CACHE_CONTROL),
                Some(&HeaderValue::from_static("no-store"))
            );
            server.set_legacy_token_drain(false);
            let response = direct_request(
                &server,
                Method::POST,
                "/api/v1/up",
                vec![(name, value_text)],
                b"legacy body".to_vec(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }
        assert_eq!(forwarded.load(Ordering::Relaxed), 2);
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn bridge_limit_fails_locally() {
        let backend = echo_backend().await;
        let mut value = test_config(&backend);
        value.limits.max_bootstraps_global = 1;
        value.limits.new_bootstraps_burst = 1;
        value.limits.new_bootstraps_per_minute = 1;
        let server = Server::new(value).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();
        let capability = capability_string();
        let first = send(
            &client,
            Method::GET,
            address,
            &format!("/?bridge={capability}"),
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        let body = first.body().clone();
        assert_eq!(first.status(), StatusCode::OK);
        assert!(body.windows(11).any(|window| window == b"tproxy-init"));
        let second = send(
            &client,
            Method::GET,
            address,
            &format!("/?bridge={capability}"),
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        let body = second.body().clone();
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
        assert!(!body.windows(11).any(|window| window == b"tproxy-init"));
        assert_eq!(
            second.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        server.manager().shutdown().await;
    }

    #[test]
    fn http_date_parser_bounds_extreme_values() {
        assert_eq!(
            parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(std::time::SystemTime::UNIX_EPOCH)
        );
        assert!(parse_http_date("Wed, 21 Oct 9999 07:28:00 GMT").is_some());
        for broken in [
            "Sat, 31 Oct 99999999999999 12:00:00 GMT",
            "Sat, 31 Oct 2026 99999999999:00:00 GMT",
            "Sat, 31 Oct 2026 12:99999999999:00 GMT",
            "Sat, 31 Oct 10000 12:00:00 GMT",
            "Sat, 31 Oct 2026 24:00:00 GMT",
            "Sat, 31 Oct 2026 12:61:00 GMT",
            "Sat, 32 Oct 2026 12:00:00 GMT",
        ] {
            assert_eq!(parse_http_date(broken), None);
        }
    }

    #[tokio::test]
    async fn bridge_range_overflow_is_clamped() {
        let backend = echo_backend().await;
        let (server, index) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();
        let response = send(
            &client,
            Method::GET,
            address,
            "/",
            TEST_HOST,
            vec![("Range", format!("bytes=0-{}", usize::MAX))],
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("Content-Range")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 0-{}/{}", index.len() - 1, index.len())
        );
        assert_eq!(response.body().len(), index.len());
    }

    #[tokio::test]
    async fn bridge_range_response_has_valid_content_range() {
        let backend = echo_backend().await;
        let (server, index) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();
        let response = send(
            &client,
            Method::GET,
            address,
            "/",
            TEST_HOST,
            vec![("Range", "bytes=0-9".to_string())],
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("Content-Range")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 0-9/{}", index.len())
        );
        assert_eq!(response.body().len(), 10);
    }

    #[tokio::test]
    async fn probing_parity_across_api_and_static_paths() {
        let backend = echo_backend().await;
        let (server, index) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();

        let decorations: Vec<(&str, Headers)> = vec![
            ("plain", Vec::new()),
            ("origin", vec![("Origin", format!("https://{TEST_HOST}"))]),
            ("cookie", vec![("Cookie", "session=1".to_string())]),
            (
                "upgrade",
                vec![
                    ("Connection", "Upgrade".to_string()),
                    ("Upgrade", "websocket".to_string()),
                    ("Sec-WebSocket-Version", "13".to_string()),
                    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==".to_string()),
                    (
                        "Sec-WebSocket-Protocol",
                        format!("tproxy-v1.{}", "A".repeat(43)),
                    ),
                ],
            ),
            (
                "encoding",
                vec![("Accept-Encoding", "gzip, br".to_string())],
            ),
            (
                "bearer",
                vec![
                    ("Origin", format!("https://{TEST_HOST}")),
                    ("Authorization", format!("Bearer {}", "A".repeat(43))),
                    ("Content-Type", "application/octet-stream".to_string()),
                ],
            ),
        ];
        let api_paths = [
            "/api/v1/session",
            "/api/v1/up",
            "/api/v1/down",
            "/api/v1/ws",
            "/api/v1/nope",
        ];
        let miss_paths = ["/nonexistent", "/api/nope"];
        let root_queries = [
            "",
            "?x=1",
            "?bridge=short",
            &format!("?bridge={}", "A".repeat(43)),
            &format!("?bridge={}&x=1", "A".repeat(43)),
        ];
        for method in [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::OPTIONS,
            Method::DELETE,
        ] {
            for (name, headers) in &decorations {
                let reference = send(
                    &client,
                    method.clone(),
                    address,
                    "/nonexistent",
                    TEST_HOST,
                    headers.clone(),
                    Some(b"payload".to_vec()),
                )
                .await;
                assert_eq!(
                    reference.status(),
                    StatusCode::NOT_FOUND,
                    "{method} /nonexistent ({name})"
                );
                let reference_shape = (
                    reference.status(),
                    fingerprint_headers(&reference),
                    reference.body().clone(),
                );
                for target in api_paths.iter().chain(miss_paths.iter()) {
                    let got = send(
                        &client,
                        method.clone(),
                        address,
                        target,
                        TEST_HOST,
                        headers.clone(),
                        Some(b"payload".to_vec()),
                    )
                    .await;
                    let got_shape = (got.status(), fingerprint_headers(&got), got.body().clone());
                    assert_eq!(
                        got_shape, reference_shape,
                        "{method} {target} ({name}) differs from a static miss"
                    );
                }
                let root = send(
                    &client,
                    method.clone(),
                    address,
                    "/",
                    TEST_HOST,
                    headers.clone(),
                    Some(b"payload".to_vec()),
                )
                .await;
                if method == Method::GET || method == Method::HEAD {
                    assert_eq!(root.status(), StatusCode::OK, "{method} / ({name})");
                    if method == Method::GET {
                        assert_eq!(root.body(), &index, "GET / did not return the index");
                    }
                } else {
                    let root_shape = (
                        root.status(),
                        fingerprint_headers(&root),
                        root.body().clone(),
                    );
                    assert_eq!(
                        root_shape, reference_shape,
                        "{method} / differs from {method} /nonexistent"
                    );
                }
                for query in root_queries {
                    let got = send(
                        &client,
                        method.clone(),
                        address,
                        &format!("/{query}"),
                        TEST_HOST,
                        headers.clone(),
                        Some(b"payload".to_vec()),
                    )
                    .await;
                    let got_shape = (got.status(), fingerprint_headers(&got), got.body().clone());
                    let want_shape = (
                        root.status(),
                        fingerprint_headers(&root),
                        root.body().clone(),
                    );
                    assert_eq!(
                        got_shape, want_shape,
                        "{method} /{query} ({name}) differs from {method} /"
                    );
                }
            }
        }
        let about = send(
            &client,
            Method::GET,
            address,
            "/about",
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(about.status(), StatusCode::OK);
        assert!(
            String::from_utf8_lossy(about.body()).contains("About"),
            "/about did not resolve to about.html"
        );
        let favicon = send(
            &client,
            Method::GET,
            address,
            "/favicon.ico",
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(favicon.status(), StatusCode::OK);
        assert_eq!(
            favicon.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("image/svg+xml"))
        );
        assert!(fingerprint_headers(&about).contains("accept-ranges: bytes"));
        assert!(fingerprint_headers(&about).contains("etag:"));
        let conditional = send(
            &client,
            Method::GET,
            address,
            "/about",
            TEST_HOST,
            vec![(
                "If-Modified-Since",
                http_date(std::time::SystemTime::now() + Duration::from_secs(3600)),
            )],
            None,
        )
        .await;
        assert_eq!(conditional.status(), StatusCode::NOT_MODIFIED);
        let traversal = send(
            &client,
            Method::GET,
            address,
            "/../index.html",
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        assert!(
            traversal.status() == StatusCode::NOT_FOUND || traversal.status() == StatusCode::OK,
            "path traversal returned {}",
            traversal.status()
        );
        assert!(
            !fingerprint_headers(&about).contains("content-security-policy:"),
            "public response unexpectedly imposes a shared CSP"
        );
        let with_port = send(
            &client,
            Method::GET,
            address,
            "/",
            &format!("{TEST_HOST}:443"),
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(with_port.status(), StatusCode::OK);
        assert_eq!(with_port.body(), &index);
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn public_fallback_and_carrier_round_trip() {
        let backend = echo_backend().await;
        let (server, index) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();
        let capability = capability_string();

        let wrong = send(
            &client,
            Method::GET,
            address,
            "/?bridge=wrong&extra=1",
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::OK);
        assert_eq!(wrong.body(), &index);

        for query in [
            format!("bridge={capability}&extra=1"),
            format!("bridge={capability}&bridge={capability}"),
            format!(
                "/?bridge=%{:02x}{}",
                capability.as_bytes()[0],
                &capability[1..]
            ),
        ] {
            let fallback = send(
                &client,
                Method::GET,
                address,
                &format!("/{query}"),
                TEST_HOST,
                Vec::new(),
                None,
            )
            .await;
            assert!(
                fallback.status() == StatusCode::NOT_FOUND || fallback.body() != &index,
                "augmented valid bridge query returned the public index"
            );
        }
        let bridge_response = send(
            &client,
            Method::GET,
            address,
            &format!("/?bridge={capability}"),
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        let bridge_body = bridge_response.body().clone();
        assert_eq!(bridge_response.status(), StatusCode::OK);
        assert!(
            bridge_body
                .windows(11)
                .any(|window| window == b"tproxy-init"),
            "bridge response failed"
        );
        assert!(
            !bridge_body
                .windows(TEST_SECRET.len())
                .any(|window| window == TEST_SECRET.as_bytes()),
            "bridge response contained the profile secret"
        );
        assert_eq!(
            bridge_response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let csp = bridge_response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        for directive in [
            "frame-ancestors http://127.0.0.1:*",
            "worker-src 'none'",
            "media-src 'none'",
            "sandbox allow-same-origin allow-scripts",
        ] {
            assert!(csp.contains(directive), "missing CSP directive {directive}");
        }
        assert_eq!(
            bridge_response.headers().get("x-dns-prefetch-control"),
            Some(&HeaderValue::from_static("off"))
        );
        let permissions = bridge_response
            .headers()
            .get("permissions-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(permissions.contains("autoplay=()"));
        assert!(permissions.contains("clipboard-read=()"));
        for header in [
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "set-cookie",
            "x-frame-options",
        ] {
            assert!(
                bridge_response.headers().get(header).is_none(),
                "bridge response must not send {header}"
            );
        }
        let bootstrap = extract_bootstrap(&bridge_body);

        let hello = frame::encode(frame::FrameType::HELLO, 0, &[1]);
        let cookie_response = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            [
                api_headers(&bootstrap, Some(&hello)),
                vec![("Cookie", "unexpected=value".to_string())],
            ]
            .concat(),
            Some(hello.clone()),
        )
        .await;
        assert_eq!(cookie_response.status(), StatusCode::NOT_FOUND);

        let created = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            [
                api_headers(&bootstrap, Some(&hello)),
                vec![("X-Forwarded-For", "198.51.100.8".to_string())],
            ]
            .concat(),
            Some(hello.clone()),
        )
        .await;
        let welcome = created.body().clone();
        assert_eq!(created.status(), StatusCode::OK);
        assert_eq!(welcome, frame::encode(frame::FrameType::WELCOME, 0, &[]));
        let session_token = created
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!session_token.is_empty());

        let repeated = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            [
                api_headers(&bootstrap, Some(&hello)),
                vec![("X-Forwarded-For", "198.51.100.9".to_string())],
            ]
            .concat(),
            Some(hello),
        )
        .await;
        assert_eq!(repeated.status(), StatusCode::OK);
        assert_eq!(
            repeated.headers().get("x-session-token"),
            created.headers().get("x-session-token"),
            "bootstrap retry was not idempotent"
        );

        let stream_id = 17u32;
        let second_stream_id = 18u32;
        let mut uplink = frame::encode(frame::FrameType::OPEN, stream_id, &[]);
        uplink.extend_from_slice(&frame::encode(
            frame::FrameType::DATA,
            stream_id,
            b"round trip",
        ));
        uplink.extend_from_slice(&frame::encode(
            frame::FrameType::OPEN,
            second_stream_id,
            &[],
        ));
        uplink.extend_from_slice(&frame::encode(
            frame::FrameType::DATA,
            second_stream_id,
            b"second stream",
        ));
        let up = send(
            &client,
            Method::POST,
            address,
            "/api/v1/up",
            TEST_HOST,
            [
                api_headers(&session_token, Some(&uplink)),
                vec![("X-Up-Seq", "1".to_string())],
            ]
            .concat(),
            Some(uplink),
        )
        .await;
        assert_eq!(up.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            up.headers().get("x-up-ack"),
            Some(&HeaderValue::from_static("1"))
        );

        let (first_body, replay_base, first_cursor) = poll_for_data(
            &client,
            address,
            &session_token,
            "0",
            &[
                (stream_id, b"round trip"),
                (second_stream_id, b"second stream"),
            ],
        )
        .await;
        let replayed = send(
            &client,
            Method::POST,
            address,
            "/api/v1/down",
            TEST_HOST,
            [
                api_headers(&session_token, None),
                vec![("X-Down-Cursor", replay_base.clone())],
            ]
            .concat(),
            None,
        )
        .await;
        assert_eq!(replayed.status(), StatusCode::OK);
        assert_eq!(
            replayed
                .headers()
                .get("x-down-cursor")
                .and_then(|value| value.to_str().ok()),
            Some(first_cursor.as_str())
        );
        assert_eq!(replayed.body(), &first_body);

        let closed = send(
            &client,
            Method::DELETE,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(&session_token, None),
            None,
        )
        .await;
        assert_eq!(closed.status(), StatusCode::NO_CONTENT);
        let closed_again = send(
            &client,
            Method::DELETE,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(&session_token, None),
            None,
        )
        .await;
        assert_eq!(closed_again.status(), StatusCode::NO_CONTENT);
        server.manager().shutdown().await;
    }

    fn extract_bootstrap(body: &[u8]) -> String {
        let marker = b"bootstrap=\"";
        let start = body
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("no bootstrap in the bridge page")
            + marker.len();
        String::from_utf8(body[start..start + 43].to_vec()).unwrap()
    }

    async fn poll_for_data(
        client: &hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            Body,
        >,
        address: SocketAddr,
        token: &str,
        cursor: &str,
        expected: &[(u32, &[u8])],
    ) -> (Vec<u8>, String, String) {
        let mut received: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut cursor = cursor.to_string();
        for _ in 0..8 {
            let response = send(
                client,
                Method::POST,
                address,
                "/api/v1/down",
                TEST_HOST,
                [
                    api_headers(token, None),
                    vec![("X-Down-Cursor", cursor.clone())],
                ]
                .concat(),
                None,
            )
            .await;
            let body = response.body().clone();
            if response.status() == StatusCode::NO_CONTENT {
                continue;
            }
            assert_eq!(response.status(), StatusCode::OK);
            let next = response
                .headers()
                .get("x-down-cursor")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let frames = frame::parse_all(&body, frame::MAX_PAYLOAD).unwrap();
            for value in frames {
                if value.frame_type != frame::FrameType::DATA {
                    continue;
                }
                if !expected.iter().any(|(id, _)| *id == value.stream_id) {
                    continue;
                }
                match received.iter_mut().find(|(id, _)| *id == value.stream_id) {
                    Some(entry) => entry.1.extend_from_slice(value.payload),
                    None => received.push((value.stream_id, value.payload.to_vec())),
                }
            }
            let complete = expected.iter().all(|(id, payload)| {
                received
                    .iter()
                    .any(|(received_id, data)| received_id == id && data == *payload)
            });
            if complete {
                return (body, cursor, next);
            }
            cursor = next;
        }
        panic!("poll did not receive the expected data");
    }

    #[tokio::test]
    async fn api_rejects_unknown_bearer_as_public_404() {
        let backend = echo_backend().await;
        let (server, _) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();
        let response = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            vec![
                ("X-Forwarded-For", "198.51.100.7".to_string()),
                ("Authorization", format!("Bearer {}", "A".repeat(43))),
                ("Origin", "https://wrong.example".to_string()),
                ("Content-Type", "application/octet-stream".to_string()),
            ],
            Some(frame::encode(frame::FrameType::HELLO, 0, &[1])),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            String::from_utf8_lossy(response.body()).contains("Operator Site"),
            "invalid API request did not receive the ordinary public 404"
        );
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn session_authentication_does_not_depend_on_origin() {
        let backend = echo_backend().await;
        let (server, _) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&server.config().profiles[0], "198.51.100.7")
            .unwrap();
        let hello = frame::encode(frame::FrameType::HELLO, 0, &[1]);
        let mut headers = api_headers(&bootstrap, Some(&hello));
        headers.retain(|(name, _)| *name != "Origin");
        let created = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            headers.clone(),
            Some(hello.clone()),
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK);
        let session_token = created
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(!session_token.is_empty());
        let retried = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            [
                api_headers(&bootstrap, Some(&hello)),
                vec![("Origin", "https://wrong.example".to_string())],
            ]
            .concat(),
            Some(hello),
        )
        .await;
        assert_eq!(retried.status(), StatusCode::OK);
        assert_eq!(
            retried.headers().get("x-session-token"),
            created.headers().get("x-session-token")
        );
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn uplink_backpressure_is_retryable() {
        let backend = echo_backend().await;
        let mut value = test_config(&backend);
        value.limits.max_streams_per_session = 1;
        value.limits.max_pending_per_session = 5500;
        value.limits.max_pending_items_per_session = 64;
        let server = Server::new(value.clone()).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "198.51.100.7")
            .unwrap();
        let created = server
            .manager()
            .create(
                &bootstrap,
                "198.51.100.7",
                &frame::encode(frame::FrameType::HELLO, 0, &[1]),
            )
            .unwrap();
        let mut body = frame::encode(frame::FrameType::OPEN, 23, &[]);
        body.extend_from_slice(&frame::encode(frame::FrameType::DATA, 23, &vec![1u8; 512]));
        let response = send(
            &client,
            Method::POST,
            address,
            "/api/v1/up",
            TEST_HOST,
            [
                api_headers(&created.token, Some(&body)),
                vec![("X-Up-Seq", "1".to_string())],
            ]
            .concat(),
            Some(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get("retry-after"),
            Some(&HeaderValue::from_static("1"))
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(server.manager().get(&created.token).is_ok());
        let retry = frame::encode(frame::FrameType::OPEN, 23, &[]);
        let retried = send(
            &client,
            Method::POST,
            address,
            "/api/v1/up",
            TEST_HOST,
            [
                api_headers(&created.token, Some(&retry)),
                vec![("X-Up-Seq", "1".to_string())],
            ]
            .concat(),
            Some(retry),
        )
        .await;
        assert_eq!(retried.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            retried.headers().get("x-up-ack"),
            Some(&HeaderValue::from_static("1"))
        );
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn session_capacity_overload_is_retryable() {
        let backend = echo_backend().await;
        let mut value = test_config(&backend);
        value.limits.max_sessions_global = 1;
        value.limits.new_sessions_burst = 10;
        value.limits.new_sessions_per_minute = 600;
        let server = Server::new(value.clone()).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();
        let first_bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "198.51.100.7")
            .unwrap();
        let first = server
            .manager()
            .create(
                &first_bootstrap,
                "198.51.100.7",
                &frame::encode(frame::FrameType::HELLO, 0, &[1]),
            )
            .unwrap();
        let second_bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "198.51.100.7")
            .unwrap();
        let hello = frame::encode(frame::FrameType::HELLO, 0, &[1]);
        let overloaded = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(&second_bootstrap, Some(&hello)),
            Some(hello.clone()),
        )
        .await;
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            overloaded.headers().get("retry-after"),
            Some(&HeaderValue::from_static("1"))
        );
        assert_eq!(
            overloaded.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        first.session.close();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while server.manager().capacity().sessions != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "closed session did not release capacity"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let retried = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(&second_bootstrap, Some(&hello)),
            Some(hello),
        )
        .await;
        assert_eq!(retried.status(), StatusCode::OK);
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn https_lanes_round_trip_independently() {
        let backend = echo_backend().await;
        let mut value = test_config(&backend);
        value.profiles[0].carrier_mode = config::CarrierMode::HttpsLanes;
        let server = Server::new(value.clone()).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "198.51.100.7")
            .unwrap();
        let created = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(
                &bootstrap,
                Some(&frame::encode(frame::FrameType::HELLO, 0, &[1])),
            ),
            Some(frame::encode(frame::FrameType::HELLO, 0, &[1])),
        )
        .await;
        assert_eq!(created.status(), StatusCode::OK);
        assert_eq!(
            created.headers().get("x-carrier-mode"),
            Some(&HeaderValue::from_static("https-lanes"))
        );
        let token = created
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        for (id, payload) in [(31u32, "first lane"), (32, "second lane")] {
            let mut body = frame::encode(frame::FrameType::OPEN, id, &[]);
            body.extend_from_slice(&frame::encode(
                frame::FrameType::DATA,
                id,
                payload.as_bytes(),
            ));
            let response = send(
                &client,
                Method::POST,
                address,
                "/api/v1/up",
                TEST_HOST,
                [
                    api_headers(&token, Some(&body)),
                    vec![("X-Up-Seq", "1".to_string()), ("X-Lane-ID", id.to_string())],
                ]
                .concat(),
                Some(body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                response.headers().get("x-up-ack"),
                Some(&HeaderValue::from_static("1"))
            );
        }
        for (id, payload) in [(31u32, "first lane"), (32, "second lane")] {
            let mut cursor = "0".to_string();
            let mut received = Vec::new();
            for _ in 0..8 {
                if received == payload.as_bytes() {
                    break;
                }
                let response = send(
                    &client,
                    Method::POST,
                    address,
                    "/api/v1/down",
                    TEST_HOST,
                    [
                        api_headers(&token, None),
                        vec![
                            ("X-Down-Cursor", cursor.clone()),
                            ("X-Lane-ID", id.to_string()),
                        ],
                    ]
                    .concat(),
                    None,
                )
                .await;
                let body = response.body().clone();
                if response.status() == StatusCode::NO_CONTENT {
                    continue;
                }
                assert_eq!(response.status(), StatusCode::OK);
                cursor = response
                    .headers()
                    .get("x-down-cursor")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let frames = frame::parse_all(&body, frame::MAX_PAYLOAD).unwrap();
                for value in frames {
                    assert_eq!(value.stream_id, id, "lane {id} received stream");
                    if value.frame_type == frame::FrameType::DATA {
                        received.extend_from_slice(value.payload);
                    }
                }
            }
            assert_eq!(
                received,
                payload.as_bytes(),
                "lane {id} did not echo its payload"
            );
        }
        server.manager().shutdown().await;
    }

    fn ws_request(
        address: SocketAddr,
        host: &str,
        protocol: &str,
    ) -> tokio_tungstenite::tungstenite::http::Request<()> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = format!("ws://{address}/api/v1/ws")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            http::header::HOST,
            http::HeaderValue::from_str(host).unwrap(),
        );
        request.headers_mut().insert(
            "sec-websocket-protocol",
            http::HeaderValue::from_str(protocol).unwrap(),
        );
        request
    }

    #[tokio::test]
    async fn websocket_carrier_round_trip() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let backend = echo_backend().await;
        let mut value = test_config(&backend);
        value.profiles[0].carrier_mode = config::CarrierMode::WebSocket;
        let server = Server::new(value.clone()).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "198.51.100.7")
            .unwrap();
        let created = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(
                &bootstrap,
                Some(&frame::encode(frame::FrameType::HELLO, 0, &[1])),
            ),
            Some(frame::encode(frame::FrameType::HELLO, 0, &[1])),
        )
        .await;
        let token = created
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(created.status(), StatusCode::OK);
        assert_eq!(
            created.headers().get("x-carrier-mode"),
            Some(&HeaderValue::from_static("websocket"))
        );
        let protocol = format!("tproxy-v1.{token}");
        let (mut socket, response) =
            tokio_tungstenite::connect_async(ws_request(address, TEST_HOST, &protocol))
                .await
                .unwrap();
        assert_eq!(
            response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok()),
            Some(protocol.as_str()),
            "websocket did not authenticate its subprotocol"
        );
        let stream_id = 41u32;
        let payload = b"websocket round trip";
        let mut body = frame::encode(frame::FrameType::OPEN, stream_id, &[]);
        body.extend_from_slice(&frame::encode(frame::FrameType::DATA, stream_id, payload));
        socket.send(Message::Binary(body)).await.unwrap();
        let mut received = Vec::new();
        while received != payload {
            let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap();
            match message {
                Some(Ok(Message::Binary(data))) => {
                    let frames = frame::parse_all(&data, frame::MAX_PAYLOAD).unwrap();
                    for value in frames {
                        if value.frame_type == frame::FrameType::DATA
                            && value.stream_id == stream_id
                        {
                            received.extend_from_slice(value.payload);
                        }
                    }
                }
                Some(Ok(_)) => {}
                other => panic!("websocket read failed: {other:?}"),
            }
        }
        socket.close(None).await.ok();
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn websocket_lanes_remain_independent() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let backend = echo_backend().await;
        let mut value = test_config(&backend);
        value.profiles[0].carrier_mode = config::CarrierMode::WebSocketLanes;
        let server = Server::new(value.clone()).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&value.profiles[0], "198.51.100.7")
            .unwrap();
        let created = send(
            &client,
            Method::POST,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(
                &bootstrap,
                Some(&frame::encode(frame::FrameType::HELLO, 0, &[1])),
            ),
            Some(frame::encode(frame::FrameType::HELLO, 0, &[1])),
        )
        .await;
        let token = created
            .headers()
            .get("x-session-token")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            created.headers().get("x-carrier-mode"),
            Some(&HeaderValue::from_static("websocket-lanes"))
        );
        let dial_lane = |lane_id: u32| {
            let protocol = format!("tproxy-lane-v1.{token}.{lane_id}");
            ws_request(address, TEST_HOST, &protocol)
        };
        let (mut first, first_response) = tokio_tungstenite::connect_async(dial_lane(51))
            .await
            .unwrap();
        assert_eq!(
            first_response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok()),
            Some(format!("tproxy-lane-v1.{token}.51").as_str())
        );
        let (mut second, _) = tokio_tungstenite::connect_async(dial_lane(52))
            .await
            .unwrap();
        let first_payload = b"first websocket lane";
        let mut first_body = frame::encode(frame::FrameType::OPEN, 51, &[]);
        first_body.extend_from_slice(&frame::encode(frame::FrameType::DATA, 51, first_payload));
        first.send(Message::Binary(first_body)).await.unwrap();
        let second_payload = b"second websocket lane";
        let mut second_body = frame::encode(frame::FrameType::OPEN, 52, &[]);
        second_body.extend_from_slice(&frame::encode(frame::FrameType::DATA, 52, second_payload));
        second.send(Message::Binary(second_body)).await.unwrap();
        let read_payload = async |socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
                                  lane_id: u32,
                                  expected: &[u8]| {
            let mut received = Vec::new();
            while received != expected {
                let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
                    .await
                    .unwrap();
                match message {
                    Some(Ok(Message::Binary(data))) => {
                        let frames = frame::parse_all(&data, frame::MAX_PAYLOAD).unwrap();
                        for value in frames {
                            assert_eq!(value.stream_id, lane_id, "lane {lane_id} received stream");
                            if value.frame_type == frame::FrameType::DATA {
                                received.extend_from_slice(value.payload);
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    other => panic!("websocket read failed: {other:?}"),
                }
            }
        };
        read_payload(&mut first, 51, first_payload).await;
        read_payload(&mut second, 52, second_payload).await;
        first
            .send(Message::Binary(frame::encode(
                frame::FrameType::DATA,
                151,
                b"cross-lane",
            )))
            .await
            .unwrap();
        loop {
            match tokio::time::timeout(Duration::from_secs(2), first.next())
                .await
                .unwrap()
            {
                None | Some(Err(_)) => break,
                Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {}
            }
        }
        let follow_up = b"still independent";
        second
            .send(Message::Binary(frame::encode(
                frame::FrameType::DATA,
                52,
                follow_up,
            )))
            .await
            .unwrap();
        read_payload(&mut second, 52, follow_up).await;
        assert!(
            server.manager().get(&token).is_ok(),
            "closing one websocket lane closed the parent session"
        );
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn dynamic_public_upstream_and_transport_coexist() {
        use std::sync::Mutex as StdMutex;

        let backend = echo_backend().await;
        let requests: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let recorder = requests.clone();
        let public_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_address = public_listener.local_addr().unwrap();
        let public_app = axum::Router::new().fallback_service(tower::service_fn(
            move |request: Request<Body>| {
                let recorder = recorder.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let data = http_body_util::BodyExt::collect(body)
                        .await
                        .unwrap()
                        .to_bytes();
                    recorder.lock().unwrap().push(format!(
                        "{} {} {} {} {}",
                        parts.method,
                        parts
                            .uri
                            .path_and_query()
                            .map(|value| value.as_str().to_string())
                            .unwrap_or_default(),
                        parts
                            .headers
                            .get(HOST)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default(),
                        parts
                            .headers
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default(),
                        String::from_utf8_lossy(&data)
                    ));
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::IM_A_TEAPOT)
                            .header("X-Public-Application", "yes")
                            .body(Body::from("dynamic site"))
                            .unwrap(),
                    )
                }
            },
        ));
        tokio::spawn(async move {
            axum::serve(public_listener, public_app).await.unwrap();
        });
        let mut value = test_config(&backend);
        value.public_dir = Default::default();
        value.public_upstream = format!("http://{public_address}");
        let server = Server::new(value).unwrap();
        let address = hosted(server.clone()).await;
        let client = http_client();

        for target in [
            "/article?id=7",
            "/?bridge=not-a-capability",
            "/api/v1/session",
        ] {
            let response = send(
                &client,
                Method::GET,
                address,
                target,
                TEST_HOST,
                vec![("X-Forwarded-For", "198.51.100.7".to_string())],
                None,
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::IM_A_TEAPOT,
                "target {target}"
            );
            assert_eq!(
                response.headers().get("x-public-application"),
                Some(&HeaderValue::from_static("yes"))
            );
            assert_eq!(response.body(), b"dynamic site");
        }
        let invalid_carrier = send(
            &client,
            Method::POST,
            address,
            "/api/v1/up",
            TEST_HOST,
            vec![
                ("X-Forwarded-For", "198.51.100.7".to_string()),
                ("Origin", format!("https://{TEST_HOST}")),
                ("Authorization", format!("Bearer {}", "A".repeat(43))),
                ("Content-Type", "application/octet-stream".to_string()),
                ("X-Up-Seq", "1".to_string()),
            ],
            Some(b"opaque carrier data".to_vec()),
        )
        .await;
        assert_eq!(invalid_carrier.status(), StatusCode::IM_A_TEAPOT);
        let capability = capability_string();
        let bridge = send(
            &client,
            Method::GET,
            address,
            &format!("/?bridge={capability}"),
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(bridge.status(), StatusCode::OK);
        assert!(bridge.headers().get("x-public-application").is_none());
        assert!(
            String::from_utf8_lossy(bridge.body()).contains("api/v1/session"),
            "valid bridge was delegated to the public application"
        );
        assert_eq!(requests.lock().unwrap().len(), 4);
        for (index, entry) in requests.lock().unwrap().iter().enumerate() {
            assert!(
                entry.contains(&format!(" {TEST_HOST} ")),
                "public application did not receive the original Host: {entry}"
            );
            if index == 3 {
                assert!(entry.contains("Bearer"));
                assert!(entry.contains("opaque carrier data"));
            }
        }
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn admin_surface_is_separate() {
        let backend = echo_backend().await;
        let (server, _) = new_test_server(&backend);
        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_address = admin_listener.local_addr().unwrap();
        let admin_server = server.clone();
        tokio::spawn(async move {
            axum::serve(admin_listener, admin_server.admin_handler())
                .await
                .unwrap();
        });
        let address = hosted(server.clone()).await;
        let client = http_client();

        let health = send(
            &client,
            Method::GET,
            admin_address,
            "/healthz",
            "127.0.0.1",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(health.body(), b"ok\n");

        let ready = send(
            &client,
            Method::GET,
            admin_address,
            "/readyz",
            "127.0.0.1",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(ready.status(), StatusCode::OK);
        assert_eq!(
            ready.body(),
            b"ready
"
        );

        let metrics = send(
            &client,
            Method::GET,
            admin_address,
            "/metrics",
            "127.0.0.1",
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(metrics.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(metrics.body()).to_string();
        for name in [
            "tproxy_streams_live",
            "tproxy_backend_dials_in_flight",
            "tproxy_pending_bytes",
            "tproxy_streams_rejected_total",
            "tproxy_backend_dial_failures_total",
        ] {
            assert!(
                body.contains(&format!("{name} ")),
                "metrics output omitted {name}"
            );
        }

        let public_profiling = send(
            &client,
            Method::GET,
            address,
            "/debug/pprof/",
            TEST_HOST,
            Vec::new(),
            None,
        )
        .await;
        assert_eq!(public_profiling.status(), StatusCode::NOT_FOUND);
        server.manager().shutdown().await;
    }

    #[tokio::test]
    async fn racing_uplink_is_retryable_and_session_closes() {
        let backend = echo_backend().await;
        let (server, _) = new_test_server(&backend);
        let address = hosted(server.clone()).await;
        let client = http_client();
        let bootstrap = server
            .manager()
            .issue_bootstrap(&server.config().profiles[0], "198.51.100.7")
            .unwrap();
        let created = server
            .manager()
            .create(
                &bootstrap,
                "198.51.100.7",
                &frame::encode(frame::FrameType::HELLO, 0, &[1]),
            )
            .unwrap();
        let mut first = frame::encode(frame::FrameType::OPEN, 5, &[]);
        first.extend_from_slice(&frame::encode(frame::FrameType::DATA, 5, b"ping"));
        let up = send(
            &client,
            Method::POST,
            address,
            "/api/v1/up",
            TEST_HOST,
            [
                api_headers(&created.token, Some(&first)),
                vec![("X-Up-Seq", "1".to_string())],
            ]
            .concat(),
            Some(first),
        )
        .await;
        assert_eq!(up.status(), StatusCode::NO_CONTENT);
        created.session.set_up_active_for_test(true);
        let racing = frame::encode(frame::FrameType::DATA, 5, b"more");
        let response = send(
            &client,
            Method::POST,
            address,
            "/api/v1/up",
            TEST_HOST,
            [
                api_headers(&created.token, Some(&racing)),
                vec![("X-Up-Seq", "2".to_string())],
            ]
            .concat(),
            Some(racing),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get("retry-after"),
            Some(&HeaderValue::from_static("1"))
        );
        created.session.set_up_active_for_test(false);
        let closing = send(
            &client,
            Method::DELETE,
            address,
            "/api/v1/session",
            TEST_HOST,
            api_headers(&created.token, None),
            None,
        )
        .await;
        assert_eq!(closing.status(), StatusCode::NO_CONTENT);
        server.manager().shutdown().await;
    }
}
