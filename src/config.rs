use std::fmt;
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

pub const MAX_BASE_PATH_LENGTH: usize = 128;
pub const MAX_CARRIER_BATCH_BYTES: usize = 2 * 1024 * 1024;

const CAPABILITY_CONTEXT: &str = "tdesktop-web-proxy-bridge-v1\n";
const CAPABILITY_CONTEXT_V2: &str = "tdesktop-web-proxy-bridge-v2\n";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

fn error<T>(message: impl fmt::Display) -> Result<T, ConfigError> {
    Err(ConfigError(message.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierMode {
    Https,
    HttpsLanes,
    WebSocket,
    WebSocketLanes,
}

impl CarrierMode {
    pub fn parse(text: &str) -> Result<CarrierMode, ConfigError> {
        Ok(match text {
            "" | "https" => CarrierMode::Https,
            "https-lanes" => CarrierMode::HttpsLanes,
            "websocket" => CarrierMode::WebSocket,
            "websocket-lanes" => CarrierMode::WebSocketLanes,
            other => {
                return error(format!(
                    "carrier_mode must be https, https-lanes, websocket, or websocket-lanes, got {other:?}"
                ));
            }
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CarrierMode::Https => "https",
            CarrierMode::HttpsLanes => "https-lanes",
            CarrierMode::WebSocket => "websocket",
            CarrierMode::WebSocketLanes => "websocket-lanes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(std::time::Duration);

impl Duration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(std::time::Duration::from_secs(secs))
    }

    pub const fn from_minutes(mins: u64) -> Self {
        Self(std::time::Duration::from_secs(mins * 60))
    }

    pub const fn value(self) -> std::time::Duration {
        self.0
    }
}

pub fn parse_go_duration(text: &str) -> Result<Duration, String> {
    let mut rest = text;
    let negative = if let Some(value) = rest.strip_prefix('-') {
        rest = value;
        true
    } else if let Some(value) = rest.strip_prefix('+') {
        rest = value;
        false
    } else {
        false
    };
    if rest == "0" {
        return Ok(Duration::from_secs(0));
    }
    if rest.is_empty() {
        return Err(format!("invalid duration {text:?}"));
    }
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (int_part, after) = rest.split_at(digits_end);
        let mut frac_digits = "";
        if let Some(value) = after.strip_prefix('.') {
            let frac_end = value
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(value.len());
            frac_digits = &value[..frac_end];
            rest = &value[frac_end..];
        } else {
            rest = after;
        }
        if int_part.is_empty() && frac_digits.is_empty() {
            return Err(format!("invalid duration {text:?}"));
        }
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];
        let nanos: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(format!("invalid duration unit {unit:?}")),
        };
        let int_value: u128 = if int_part.is_empty() {
            0
        } else {
            int_part
                .parse()
                .map_err(|_| format!("invalid duration {text:?}"))?
        };
        let chunk = int_value
            .checked_mul(nanos)
            .ok_or_else(|| format!("duration {text:?} overflows"))?;
        let frac_value: u128 = if frac_digits.is_empty() {
            0
        } else {
            let scale = 10u128
                .checked_pow(frac_digits.len() as u32)
                .ok_or_else(|| format!("duration {text:?} overflows"))?;
            frac_digits
                .parse::<u128>()
                .map_err(|_| format!("invalid duration {text:?}"))?
                .checked_mul(nanos)
                .ok_or_else(|| format!("duration {text:?} overflows"))?
                / scale
        };
        total = total
            .checked_add(chunk)
            .and_then(|value| value.checked_add(frac_value))
            .ok_or_else(|| format!("duration {text:?} overflows"))?;
    }
    if negative {
        return Err(format!("negative duration {text:?} is not allowed"));
    }
    Ok(Duration(std::time::Duration::from_nanos(total as u64)))
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        parse_go_duration(&text).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_frame_payload: usize,
    pub carrier_batch_bytes: usize,
    pub max_streams_per_session: usize,
    pub max_closed_stream_ids: usize,
    pub max_pending_per_session: usize,
    pub max_pending_global: usize,
    pub max_pending_items_per_session: usize,
    pub max_pending_items_global: usize,
    pub max_sessions_per_ip: usize,
    pub max_sessions_global: usize,
    pub max_streams_global: usize,
    pub max_backend_dials_in_flight: usize,
    pub new_sessions_per_minute: usize,
    pub new_sessions_burst: usize,
    pub new_streams_per_minute: usize,
    pub new_streams_burst: usize,
    pub max_bootstraps_per_ip: usize,
    pub max_bootstraps_global: usize,
    pub new_bootstraps_per_minute: usize,
    pub new_bootstraps_burst: usize,
    pub max_profiles: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_body_bytes: 2 * 1024 * 1024,
            max_frame_payload: 1024 * 1024,
            carrier_batch_bytes: 2 * 1024 * 1024,
            max_streams_per_session: 128,
            max_closed_stream_ids: 4096,
            max_pending_per_session: 32 * 1024 * 1024,
            max_pending_global: 512 * 1024 * 1024,
            max_pending_items_per_session: 16 * 1024,
            max_pending_items_global: 256 * 1024,
            max_sessions_per_ip: 0,
            max_sessions_global: 128,
            max_streams_global: 4096,
            max_backend_dials_in_flight: 256,
            new_sessions_per_minute: 600,
            new_sessions_burst: 128,
            new_streams_per_minute: 6000,
            new_streams_burst: 512,
            max_bootstraps_per_ip: 0,
            max_bootstraps_global: 512,
            new_bootstraps_per_minute: 1200,
            new_bootstraps_burst: 256,
            max_profiles: 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timeouts {
    pub backend_dial: Duration,
    pub long_poll: Duration,
    pub reconnect_grace: Duration,
    pub bootstrap_lifetime: Duration,
    pub read_header: Duration,
    pub idle: Duration,
    pub shutdown: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            backend_dial: Duration::from_secs(5),
            long_poll: Duration::from_secs(25),
            reconnect_grace: Duration::from_minutes(2),
            bootstrap_lifetime: Duration::from_minutes(2),
            read_header: Duration::from_secs(10),
            idle: Duration::from_secs(75),
            shutdown: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub public_hostname: String,
    pub base_path: String,
    pub listen: String,
    pub admin_listen: String,
    pub public_dir: PathBuf,
    pub public_upstream: String,
    pub static_routes: String,
    pub token_key_file: PathBuf,
    pub profiles_file: PathBuf,
    pub enable_pprof: bool,
    pub limits: Limits,
    pub timeouts: Timeouts,
    #[serde(skip)]
    pub profiles: Vec<Profile>,
    #[serde(skip)]
    pub legacy_token_drain: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            public_hostname: String::new(),
            base_path: String::new(),
            listen: "127.0.0.1:8080".to_string(),
            admin_listen: "127.0.0.1:8081".to_string(),
            public_dir: PathBuf::new(),
            public_upstream: String::new(),
            static_routes: "legacy".to_string(),
            token_key_file: PathBuf::from("token.key"),
            profiles_file: PathBuf::new(),
            enable_pprof: false,
            limits: Limits::default(),
            timeouts: Timeouts::default(),
            profiles: Vec::new(),
            legacy_token_drain: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileLimits {
    pub max_sessions: usize,
    pub max_streams: usize,
    pub max_backend_dials_in_flight: usize,
    pub new_sessions_per_minute: usize,
    pub new_sessions_burst: usize,
    pub new_streams_per_minute: usize,
    pub new_streams_burst: usize,
    pub max_streams_per_session: usize,
    pub max_pending_per_session: usize,
}

impl ProfileLimits {
    pub fn with_defaults(self, global: &Limits) -> ProfileLimits {
        let mut result = self;
        if result.max_sessions == 0 {
            result.max_sessions = global.max_sessions_global;
        }
        if result.max_streams == 0 {
            result.max_streams = global.max_streams_global;
        }
        if result.max_backend_dials_in_flight == 0 {
            result.max_backend_dials_in_flight =
                global.max_backend_dials_in_flight.min(result.max_streams);
        }
        if result.new_sessions_per_minute == 0 {
            result.new_sessions_per_minute = global.new_sessions_per_minute;
        }
        if result.new_sessions_burst == 0 {
            result.new_sessions_burst = global.new_sessions_burst;
        }
        if result.new_streams_per_minute == 0 {
            result.new_streams_per_minute = global.new_streams_per_minute;
        }
        if result.new_streams_burst == 0 {
            result.new_streams_burst = global.new_streams_burst;
        }
        if result.max_streams_per_session == 0 {
            result.max_streams_per_session = global.max_streams_per_session.min(result.max_streams);
        }
        if result.max_pending_per_session == 0 {
            result.max_pending_per_session = global.max_pending_per_session;
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub backend: String,
    pub carrier_mode: CarrierMode,
    pub capability: [u8; 32],
    pub limits: ProfileLimits,
}

pub fn load(path: &Path, profiles_override: Option<&Path>) -> Result<Config, ConfigError> {
    let input = std::fs::read_to_string(path)
        .map_err(|err| ConfigError(format!("decode config: {err}")))?;
    let mut result: Config =
        serde_json::from_str(&input).map_err(|err| ConfigError(format!("decode config: {err}")))?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    if !result.public_dir.as_os_str().is_empty() && result.public_dir.is_relative() {
        result.public_dir = directory.join(&result.public_dir);
    }
    if !result.profiles_file.as_os_str().is_empty() && result.profiles_file.is_relative() {
        result.profiles_file = directory.join(&result.profiles_file);
    }
    if result.token_key_file.is_relative() {
        result.token_key_file = directory.join(&result.token_key_file);
    }
    if let Some(override_path) = profiles_override.filter(|value| !value.as_os_str().is_empty()) {
        result.profiles_file = override_path.to_path_buf();
    }
    result.validate()?;
    result.profiles = load_profiles(
        &result.profiles_file,
        &result.public_hostname,
        &result.base_path,
        &result.limits,
    )?;
    Ok(result)
}

impl Config {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.static_routes != "exact" && self.static_routes != "legacy" {
            return error("static_routes must be exact or legacy");
        }
        validate_hostname(&self.public_hostname)
            .map_err(|err| ConfigError(format!("public_hostname: {err}")))?;
        validate_base_path(&self.base_path)
            .map_err(|err| ConfigError(format!("base_path: {err}")))?;
        validate_loopback_address(&self.listen)
            .map_err(|err| ConfigError(format!("listen: {err}")))?;
        validate_loopback_address(&self.admin_listen)
            .map_err(|err| ConfigError(format!("admin_listen: {err}")))?;
        if self.listen == self.admin_listen {
            return error("listen and admin_listen must differ");
        }
        if self.public_dir.as_os_str().is_empty() == self.public_upstream.is_empty() {
            return error("exactly one of public_dir or public_upstream is required");
        }
        if !self.public_dir.as_os_str().is_empty() {
            let info = std::fs::metadata(&self.public_dir).map_err(|_| {
                ConfigError(format!(
                    "public_dir is not a directory: {}",
                    self.public_dir.display()
                ))
            })?;
            if !info.is_dir() {
                return error(format!(
                    "public_dir is not a directory: {}",
                    self.public_dir.display()
                ));
            }
            if !self.public_dir.join("index.html").exists() {
                return error("public_dir must contain index.html");
            }
        } else {
            validate_public_upstream(&self.public_upstream)
                .map_err(|err| ConfigError(format!("public_upstream: {err}")))?;
        }
        if self.profiles_file.as_os_str().is_empty() {
            return error("profiles_file is required");
        }
        let limits = &self.limits;
        if limits.max_header_bytes < 4096
            || limits.max_body_bytes < 1024
            || limits.max_frame_payload == 0
            || limits.max_frame_payload > 1024 * 1024
            || limits.carrier_batch_bytes < 256 * 1024
            || limits.carrier_batch_bytes > limits.max_body_bytes
        {
            return error("invalid HTTP or frame limits");
        }
        if limits.carrier_batch_bytes > MAX_CARRIER_BATCH_BYTES {
            return error(
                "carrier_batch_bytes must not exceed the 2 MiB desktop loopback message cap",
            );
        }
        for value in [
            limits.max_streams_per_session,
            limits.max_closed_stream_ids,
            limits.max_pending_per_session,
            limits.max_pending_global,
            limits.max_pending_items_per_session,
            limits.max_pending_items_global,
            limits.max_sessions_global,
            limits.max_streams_global,
            limits.max_backend_dials_in_flight,
            limits.new_sessions_per_minute,
            limits.new_sessions_burst,
            limits.new_streams_per_minute,
            limits.new_streams_burst,
            limits.max_bootstraps_global,
            limits.new_bootstraps_per_minute,
            limits.new_bootstraps_burst,
            limits.max_profiles,
        ] {
            if value == 0 {
                return error("all resource limits must be positive");
            }
        }
        if limits.max_pending_global < limits.max_pending_per_session
            || limits.max_pending_items_global < limits.max_pending_items_per_session
            || limits.max_sessions_global < limits.max_sessions_per_ip
            || limits.max_streams_global < limits.max_streams_per_session
            || limits.max_streams_global < limits.max_backend_dials_in_flight
            || limits.max_bootstraps_global < limits.max_bootstraps_per_ip
        {
            return error("global limits must not be smaller than per-session or per-IP limits");
        }
        for value in [
            self.timeouts.backend_dial,
            self.timeouts.long_poll,
            self.timeouts.reconnect_grace,
            self.timeouts.bootstrap_lifetime,
            self.timeouts.read_header,
            self.timeouts.idle,
            self.timeouts.shutdown,
        ] {
            if value.value().is_zero() {
                return error("all timeouts must be positive");
            }
        }
        Ok(())
    }
}

pub fn validate_hostname(host: &str) -> Result<(), ConfigError> {
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.contains([':', '/', '@', '?', '#', '[', ']'])
    {
        return error(
            "must be a DNS hostname without scheme, port, path, query, fragment, or trailing dot",
        );
    }
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return error("IP addresses and single-label names are not allowed");
    }
    if host.bytes().any(|byte| byte > 127) {
        return error("use the lowercase ASCII IDNA A-label form");
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return error("invalid DNS label");
        }
        if label
            .bytes()
            .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-')
        {
            return error("hostname must be lowercase ASCII/IDNA");
        }
    }
    Ok(())
}

pub fn validate_base_path(path: &str) -> Result<(), ConfigError> {
    if path.is_empty() {
        return Ok(());
    }
    if path.len() > MAX_BASE_PATH_LENGTH {
        return error(format!("must be at most {MAX_BASE_PATH_LENGTH} characters"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return error("must not start or end with \"/\"");
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return error("must not contain an empty segment");
        }
        for (index, byte) in segment.bytes().enumerate() {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => {}
                b'-' | b'_' if index > 0 => {}
                _ => return error("segments must match [A-Za-z0-9][A-Za-z0-9_-]*"),
            }
        }
    }
    Ok(())
}

pub fn base(base_path: &str) -> String {
    if base_path.is_empty() {
        return "/".to_string();
    }
    format!("/{base_path}/")
}

pub fn derive_capability(host: &str, base_path: &str, secret: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac accepts any key length");
    if base_path.is_empty() {
        mac.update(CAPABILITY_CONTEXT.as_bytes());
        mac.update(host.as_bytes());
    } else {
        mac.update(CAPABILITY_CONTEXT_V2.as_bytes());
        mac.update(host.as_bytes());
        mac.update(b"\n");
        mac.update(base_path.as_bytes());
    }
    mac.finalize().into_bytes().into()
}

pub fn capability_string(capability: [u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(capability)
}

pub fn decode_secret(value: &str) -> Result<Vec<u8>, ConfigError> {
    let value = value.trim();
    let decoded = if value.len() == 32 || value.len() == 34 {
        decode_hex(value).ok_or_else(|| {
            ConfigError("secret must decode to 16 bytes, optionally prefixed with dd".to_string())
        })?
    } else {
        let mut result = None;
        for engine in [URL_SAFE_NO_PAD, base64::engine::general_purpose::URL_SAFE] {
            if let Ok(bytes) = engine.decode(value) {
                result = Some(bytes);
                break;
            }
        }
        match result {
            Some(bytes) => bytes,
            None => return error("secret must decode to 16 bytes, optionally prefixed with dd"),
        }
    };
    if decoded.len() != 16 && decoded.len() != 17 {
        return error("secret must decode to 16 bytes, optionally prefixed with dd");
    }
    if decoded.len() == 17 && decoded[0] != 0xdd {
        return error("17-byte secret must use the dd prefix");
    }
    Ok(decoded)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut result = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks(2) {
        let high = (*pair.first()? as char).to_digit(16)?;
        let low = (*pair.last()? as char).to_digit(16)?;
        result.push((high * 16 + low) as u8);
    }
    Some(result)
}

fn validate_loopback_address(address: &str) -> Result<(), ConfigError> {
    let socket: std::net::SocketAddr = address
        .parse()
        .map_err(|_| ConfigError("must use a numeric loopback address".to_string()))?;
    if !socket.ip().is_loopback() {
        return error("must use a numeric loopback address");
    }
    if socket.port() < 1 {
        return error("invalid port");
    }
    Ok(())
}

fn validate_public_upstream(raw: &str) -> Result<(), ConfigError> {
    if raw.len() < 7 || !raw[..7].eq_ignore_ascii_case("http://") {
        return error("must use http on a numeric loopback address");
    }
    let rest = &raw[7..];
    if rest.contains(['/', '?', '#', '@']) {
        return error("must contain only scheme, loopback address, and port");
    }
    validate_loopback_address(rest)
}

fn load_profiles(
    path: &Path,
    host: &str,
    base_path: &str,
    limits: &Limits,
) -> Result<Vec<Profile>, ConfigError> {
    let info =
        std::fs::metadata(path).map_err(|err| ConfigError(format!("profiles_file: {err}")))?;
    let extra_permissions = unix_extra_permissions(&info);
    let credential_read_only = is_systemd_credential(path) && extra_permissions & 0o033 == 0;
    if extra_permissions != 0 && !credential_read_only {
        return error("profiles_file must not be readable or writable by group or others");
    }
    let mut input = std::fs::read(path).map_err(|err| ConfigError(format!("{err}")))?;
    let parsed: ProfileFile = serde_json::from_slice(&input)
        .map_err(|err| ConfigError(format!("decode profiles: {err}")))?;
    input.iter_mut().for_each(|byte| *byte = 0);
    if parsed.profiles.is_empty() || parsed.profiles.len() > limits.max_profiles {
        return error(format!(
            "profiles must contain between 1 and {} entries",
            limits.max_profiles
        ));
    }
    let mut names = std::collections::HashSet::new();
    let mut capabilities = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(parsed.profiles.len());
    for entry in parsed.profiles {
        if entry.name.is_empty() || entry.name.len() > 64 {
            return error("profile name must contain 1-64 characters");
        }
        if !names.insert(entry.name.clone()) {
            return error(format!("duplicate profile name {:?}", entry.name));
        }
        validate_loopback_address(&entry.backend)
            .map_err(|err| ConfigError(format!("profile {:?} backend: {err}", entry.name)))?;
        let carrier_mode = CarrierMode::parse(&entry.carrier_mode)
            .map_err(|err| ConfigError(format!("profile {:?} {err}", entry.name)))?;
        validate_profile_limits(&entry.limits, limits)
            .map_err(|err| ConfigError(format!("profile {:?}: {err}", entry.name)))?;
        let profile_limits = entry.limits.with_defaults(limits);
        let mut secret = decode_secret(&entry.secret)
            .map_err(|err| ConfigError(format!("profile {:?}: {err}", entry.name)))?;
        let capability = derive_capability(host, base_path, &secret);
        secret.iter_mut().for_each(|byte| *byte = 0);
        if !capabilities.insert(capability) {
            return error(format!("duplicate capability for profile {:?}", entry.name));
        }
        result.push(Profile {
            name: entry.name,
            backend: entry.backend,
            carrier_mode,
            capability,
            limits: profile_limits,
        });
    }
    Ok(result)
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ProfileFile {
    profiles: Vec<ProfileInput>,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ProfileInput {
    name: String,
    secret: String,
    backend: String,
    carrier_mode: String,
    limits: ProfileLimits,
}

fn validate_profile_limits(value: &ProfileLimits, global: &Limits) -> Result<(), ConfigError> {
    let checks = [
        (
            "max_sessions",
            value.max_sessions,
            global.max_sessions_global,
        ),
        ("max_streams", value.max_streams, global.max_streams_global),
        (
            "max_backend_dials_in_flight",
            value.max_backend_dials_in_flight,
            global.max_backend_dials_in_flight,
        ),
        (
            "new_sessions_per_minute",
            value.new_sessions_per_minute,
            global.new_sessions_per_minute,
        ),
        (
            "new_sessions_burst",
            value.new_sessions_burst,
            global.new_sessions_burst,
        ),
        (
            "new_streams_per_minute",
            value.new_streams_per_minute,
            global.new_streams_per_minute,
        ),
        (
            "new_streams_burst",
            value.new_streams_burst,
            global.new_streams_burst,
        ),
        (
            "max_streams_per_session",
            value.max_streams_per_session,
            global.max_streams_per_session,
        ),
        (
            "max_pending_per_session",
            value.max_pending_per_session,
            global.max_pending_per_session,
        ),
    ];
    for (name, limit_value, limit) in checks {
        if limit_value > limit {
            return error(format!("{name} must be between 0 and {limit}"));
        }
    }
    let resolved = value.with_defaults(global);
    if resolved.max_streams_per_session > resolved.max_streams {
        return error("max_streams_per_session must not exceed max_streams");
    }
    if resolved.max_backend_dials_in_flight > resolved.max_streams {
        return error("max_backend_dials_in_flight must not exceed max_streams");
    }
    Ok(())
}

#[cfg(unix)]
fn unix_extra_permissions(info: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    info.permissions().mode() & 0o077
}

#[cfg(not(unix))]
fn unix_extra_permissions(_info: &std::fs::Metadata) -> u32 {
    0
}

fn is_systemd_credential(path: &Path) -> bool {
    let Ok(directory) = std::env::var("CREDENTIALS_DIRECTORY") else {
        return false;
    };
    if directory.is_empty() {
        return false;
    }
    let directory = PathBuf::from(&directory);
    if !directory.is_absolute() {
        return false;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    absolute
        .parent()
        .map(|parent| clean_path(parent) == clean_path(&directory))
        .unwrap_or(false)
}

fn clean_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tproxy-config-{}-{}-{}",
            tag,
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn capability_vectors() {
        let tests = [
            (
                "000102030405060708090a0b0c0d0e0f",
                "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk",
            ),
            (
                "dd000102030405060708090a0b0c0d0e0f",
                "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA",
            ),
        ];
        for (secret, want) in tests {
            let secret = decode_secret(secret).unwrap();
            assert_eq!(
                capability_string(derive_capability("proxy.example.com", "", &secret)),
                want
            );
        }
    }

    #[test]
    fn hostname_validation() {
        let valid = vec![
            "site.example".to_string(),
            "xn--bcher-kva.example".to_string(),
            "a.b.example".to_string(),
            format!("{}.example", "a".repeat(63)),
        ];
        for host in valid {
            assert!(validate_hostname(&host).is_ok(), "rejected {host:?}");
        }
        let invalid = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "[::1]".to_string(),
            "HTTPS://site.example".to_string(),
            "Site.example".to_string(),
            "bücher.example".to_string(),
            "site.example.".to_string(),
            "site.example:443".to_string(),
            "site/example".to_string(),
            "site\\example".to_string(),
            "site..example".to_string(),
            "-site.example".to_string(),
            "site-.example".to_string(),
            "site_example.com".to_string(),
            format!("{}.example", "a".repeat(64)),
            format!("{}.aa", "a.".repeat(127)),
        ];
        for host in invalid {
            assert!(validate_hostname(&host).is_err(), "accepted {host:?}");
        }
    }

    #[test]
    fn public_source_validation() {
        let mut value = Config {
            public_hostname: "proxy.example.com".to_string(),
            profiles_file: PathBuf::from("profiles.json"),
            ..Config::default()
        };
        assert!(value.validate().is_err());
        for upstream in ["http://127.0.0.1:3000", "http://[::1]:3000"] {
            value.public_upstream = upstream.to_string();
            assert!(
                value.validate().is_ok(),
                "valid public upstream {upstream:?} was rejected"
            );
        }
        for upstream in [
            "https://127.0.0.1:3000",
            "http://localhost:3000",
            "http://192.0.2.1:3000",
            "http://127.0.0.1",
            "http://127.0.0.1:3000/path",
            "http://user@127.0.0.1:3000",
        ] {
            value.public_upstream = upstream.to_string();
            assert!(
                value.validate().is_err(),
                "invalid public upstream {upstream:?} was accepted"
            );
        }
        let directory = temp_dir("public-source");
        write_file(&directory.join("index.html"), "site");
        value.public_dir = directory.clone();
        value.public_upstream = "http://127.0.0.1:3000".to_string();
        assert!(value.validate().is_err());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn plain_secret_may_begin_with_ee() {
        let secret = decode_secret("ee0102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(secret.len(), 16);
        assert_eq!(secret[0], 0xee);
    }

    #[test]
    fn load_applies_defaults_and_relative_paths() {
        let directory = temp_dir("load-defaults");
        let public = directory.join("public");
        std::fs::create_dir_all(&public).unwrap();
        write_file(&public.join("index.html"), "site");
        write_file(
            &directory.join("profiles.json"),
            r#"{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398","carrier_mode":"https-lanes"}]}"#,
        );
        write_file(
            &directory.join("config.json"),
            r#"{"public_hostname":"proxy.example.com","public_dir":"public","profiles_file":"profiles.json"}"#,
        );
        let loaded = load(&directory.join("config.json"), None).unwrap();
        assert_eq!(loaded.token_key_file, directory.join("token.key"));
        assert_eq!(loaded.static_routes, "legacy");
        assert_eq!(loaded.public_dir, public);
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.limits.max_body_bytes, 2 * 1024 * 1024);
        assert_eq!(loaded.profiles[0].carrier_mode, CarrierMode::HttpsLanes);
        let profile_limits = loaded.profiles[0].limits;
        assert_eq!(
            profile_limits.max_sessions,
            loaded.limits.max_sessions_global
        );
        assert_eq!(profile_limits.max_streams, loaded.limits.max_streams_global);
        assert_eq!(
            profile_limits.max_backend_dials_in_flight,
            loaded.limits.max_backend_dials_in_flight
        );
        assert_eq!(
            profile_limits.new_sessions_per_minute,
            loaded.limits.new_sessions_per_minute
        );
        assert_eq!(
            profile_limits.new_streams_per_minute,
            loaded.limits.new_streams_per_minute
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn profile_carrier_mode_defaults_and_validation() {
        let directory = temp_dir("carrier-mode");
        let public = directory.join("public");
        std::fs::create_dir_all(&public).unwrap();
        write_file(&public.join("index.html"), "site");
        let profiles_path = directory.join("profiles.json");
        let config_path = directory.join("config.json");
        write_file(
            &config_path,
            r#"{"public_hostname":"proxy.example.com","public_dir":"public","profiles_file":"profiles.json"}"#,
        );
        let write_profiles = |carrier: &str| {
            write_file(
                &profiles_path,
                &format!(
                    r#"{{"profiles":[{{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398"{carrier}}}]}}"#
                ),
            );
        };
        write_profiles("");
        let loaded = load(&config_path, None).unwrap();
        assert_eq!(loaded.profiles[0].carrier_mode, CarrierMode::Https);
        for carrier in [
            CarrierMode::Https,
            CarrierMode::HttpsLanes,
            CarrierMode::WebSocket,
            CarrierMode::WebSocketLanes,
        ] {
            write_profiles(&format!(r#","carrier_mode":"{}""#, carrier.as_str()));
            let loaded = load(&config_path, None).unwrap();
            assert_eq!(loaded.profiles[0].carrier_mode, carrier);
        }
        write_profiles(r#","carrier_mode":"unknown""#);
        assert!(load(&config_path, None).is_err());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn profile_stream_defaults_respect_profile_ceiling() {
        let global = Limits::default();
        let resolved = ProfileLimits {
            max_streams: 32,
            ..ProfileLimits::default()
        }
        .with_defaults(&global);
        assert_eq!(resolved.max_streams_per_session, 32);
        assert_eq!(resolved.max_backend_dials_in_flight, 32);
        assert_eq!(resolved.max_sessions, global.max_sessions_global);
        assert_eq!(
            resolved.new_streams_per_minute,
            global.new_streams_per_minute
        );
    }

    #[test]
    fn profile_limits_cannot_exceed_global_ceilings() {
        let global = Limits::default();
        assert!(
            validate_profile_limits(
                &ProfileLimits {
                    max_streams: global.max_streams_global + 1,
                    ..ProfileLimits::default()
                },
                &global
            )
            .is_err()
        );
        assert!(
            validate_profile_limits(
                &ProfileLimits {
                    max_streams: 16,
                    max_streams_per_session: 17,
                    ..ProfileLimits::default()
                },
                &global
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_accepts_systemd_credential_read_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = temp_dir("credentials");
        let public = directory.join("public");
        std::fs::create_dir_all(&public).unwrap();
        write_file(&public.join("index.html"), "site");
        let credentials = directory.join("credentials");
        std::fs::create_dir_all(&credentials).unwrap();
        let profiles = credentials.join("profiles.json");
        write_file(
            &profiles,
            r#"{"profiles":[{"name":"default","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:2398"}]}"#,
        );
        std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o444)).unwrap();
        unsafe {
            std::env::set_var("CREDENTIALS_DIRECTORY", &credentials);
        }
        write_file(
            &directory.join("config.json"),
            r#"{"public_hostname":"proxy.example.com","public_dir":"public","profiles_file":"credentials/profiles.json"}"#,
        );
        assert!(load(&directory.join("config.json"), None).is_ok());
        unsafe {
            std::env::set_var("CREDENTIALS_DIRECTORY", "");
        }
        assert!(load(&directory.join("config.json"), None).is_err());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn carrier_batch_must_fit_desktop_loopback_cap() {
        let directory = temp_dir("carrier-batch");
        write_file(&directory.join("index.html"), "index");
        let profiles = directory.join("profiles.json");
        write_file(
            &profiles,
            r#"{"profiles":[{"name":"a","secret":"000102030405060708090a0b0c0d0e0f","backend":"127.0.0.1:443"}]}"#,
        );
        let write = |batch: usize, body: usize| -> PathBuf {
            let path = directory.join("config.json");
            write_file(
                &path,
                &format!(
                    r#"{{"public_hostname":"proxy.example.com","public_dir":"{}","profiles_file":"{}","limits":{{"carrier_batch_bytes":{},"max_body_bytes":{}}}}}"#,
                    directory.display().to_string().replace('\\', "\\\\"),
                    profiles.display().to_string().replace('\\', "\\\\"),
                    batch,
                    body
                ),
            );
            path
        };
        assert!(load(&write(3 * 1024 * 1024, 4 * 1024 * 1024), None).is_err());
        assert!(load(&write(2 * 1024 * 1024, 4 * 1024 * 1024), None).is_ok());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn default_reconnect_grace_is_short() {
        assert_eq!(
            Config::default().timeouts.reconnect_grace.value().as_secs(),
            120
        );
    }

    #[test]
    fn validate_base_path_rules() {
        let valid = vec![
            "".to_string(),
            "a".to_string(),
            "dobry-cola-super-app".to_string(),
            "MixedCase".to_string(),
            "two/segments".to_string(),
            "a/b/c9_x-y".to_string(),
            "kecjyr5ti4qtvquhyva43e5h24".to_string(),
            "a".repeat(MAX_BASE_PATH_LENGTH),
        ];
        for path in valid {
            assert!(
                validate_base_path(&path).is_ok(),
                "base path {path:?} was rejected"
            );
        }
        let invalid = vec![
            "/leading".to_string(),
            "trailing/".to_string(),
            "empty//segment".to_string(),
            "-lead".to_string(),
            "_lead".to_string(),
            "a/-lead".to_string(),
            "dot.ted".to_string(),
            "..".to_string(),
            "with space".to_string(),
            "per%20cent".to_string(),
            "unicode-é".to_string(),
            "a".repeat(MAX_BASE_PATH_LENGTH + 1),
        ];
        for path in invalid {
            assert!(
                validate_base_path(&path).is_err(),
                "base path {path:?} was accepted"
            );
        }
    }

    #[test]
    fn base_is_always_slash_delimited() {
        assert_eq!(base(""), "/");
        assert_eq!(base("a/b"), "/a/b/");
    }

    #[test]
    fn derive_capability_binds_the_base_path() {
        let host = "proxy.example.com";
        let path = "dobry-cola-super-app";
        let tests = [
            (
                "000102030405060708090a0b0c0d0e0f",
                "",
                "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk",
            ),
            (
                "dd000102030405060708090a0b0c0d0e0f",
                "",
                "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA",
            ),
            (
                "000102030405060708090a0b0c0d0e0f",
                path,
                "hHz99Xs93EN1j91G9gpNepXwGNNt5YdAFkEVk_LlqdQ",
            ),
            (
                "dd000102030405060708090a0b0c0d0e0f",
                path,
                "TGUkZaevsavLbHvlNWipnRoYxgzZ51ioWvbxgGT3wHo",
            ),
        ];
        for (secret, base_path, want) in tests {
            let secret = decode_hex(secret).unwrap();
            assert_eq!(
                capability_string(derive_capability(host, base_path, &secret)),
                want
            );
        }
        let secret = decode_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_ne!(
            derive_capability(host, "one", &secret),
            derive_capability(host, "two", &secret)
        );
    }
}
