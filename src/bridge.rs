use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde_json::json;

use crate::config;

pub(crate) struct Page {
    pub(crate) body: Vec<u8>,
    pub(crate) nonce: String,
    pub(crate) csp: String,
}

pub(crate) const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";

pub(crate) fn render(
    hostname: &str,
    base_path: &str,
    bootstrap_token: &str,
    carrier_mode: &str,
    batch_bytes: usize,
) -> Result<Page, String> {
    config::validate_hostname(hostname).map_err(|error| error.to_string())?;
    config::validate_base_path(base_path).map_err(|error| error.to_string())?;
    if batch_bytes == 0 || batch_bytes > config::MAX_CARRIER_BATCH_BYTES {
        return Err("carrier batch size out of range".to_string());
    }
    let carrier = config::CarrierMode::parse(carrier_mode).map_err(|error| error.to_string())?;
    let mut nonce_bytes = [0u8; 18];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let base_json = json!("https://".to_string() + hostname + &config::base(base_path)).to_string();
    let token_json = json!(bootstrap_token).to_string();
    let carrier_json = json!(carrier.as_str()).to_string();
    let template = include_str!("../assets/bridge.html");
    let body = template
        .replace("__NONCE__", &nonce)
        .replace("__RELAY_BASE__", &base_json)
        .replace("__BOOTSTRAP__", &token_json)
        .replace("__CARRIER_MODE__", &carrier_json)
        .replace("__BATCH_LIMIT__", &batch_bytes.to_string());
    if body.contains("__NONCE__")
        || body.contains("__RELAY_BASE__")
        || body.contains("__BOOTSTRAP__")
        || body.contains("__CARRIER_MODE__")
        || body.contains("__BATCH_LIMIT__")
    {
        return Err("bridge template replacement failed".to_string());
    }
    let csp = [
        "default-src 'none'",
        "base-uri 'none'",
        "child-src 'none'",
        &format!("connect-src 'self' wss://{hostname}"),
        "font-src 'none'",
        "form-action 'none'",
        "frame-ancestors http://127.0.0.1:*",
        "frame-src 'none'",
        "img-src 'none'",
        "manifest-src 'none'",
        "media-src 'none'",
        "object-src 'none'",
        &format!("script-src 'nonce-{nonce}'"),
        "style-src 'none'",
        "worker-src 'none'",
        "sandbox allow-same-origin allow-scripts",
    ]
    .join("; ");
    Ok(Page {
        body: body.into_bytes(),
        nonce,
        csp,
    })
}
