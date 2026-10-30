use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::web_socket_credentials;
use crate::session::manager::Manager;
use crate::token::{self, TokenClass, TokenClassifier};

pub(crate) fn bearer_token(value: &str) -> Option<&str> {
    let token = value.strip_prefix("Bearer ")?;
    if value.matches(' ').count() != 1 {
        return None;
    }
    let decoded = token::decode_lenient(token)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != token {
        return None;
    }
    Some(token)
}

pub(crate) fn canonical_uint(value: &str) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) || value.starts_with('+') {
        return None;
    }
    let result: u64 = value.parse().ok()?;
    (result.to_string() == value).then_some(result)
}

pub(crate) struct SecretScan<'a> {
    manager: &'a Manager,
    classifier: Option<TokenClassifier>,
}

impl<'a> SecretScan<'a> {
    pub(crate) fn new(manager: &'a Manager) -> Self {
        Self {
            manager,
            classifier: None,
        }
    }

    pub(crate) fn carrier_credential(
        &mut self,
        authorization: &[&str],
        websocket_protocols: &[String],
        drain: bool,
    ) -> bool {
        for value in authorization {
            if let Some(token) = bearer_token(value)
                && (drain || self.signed(token))
            {
                return true;
            }
        }
        for value in websocket_protocols {
            for protocol in value.split(',') {
                if let Some((token, _, _, true)) = web_socket_credentials(protocol.trim())
                    && bearer_token(&format!("Bearer {token}")).is_some()
                    && (drain || self.signed(token))
                {
                    return true;
                }
            }
        }
        false
    }

    fn signed(&mut self, token: &str) -> bool {
        let Some(decoded) = token::decode_lenient(token) else {
            return false;
        };
        decoded.len() == 32 && self.classifier().signed(&decoded)
    }

    fn classifier(&mut self) -> &mut TokenClassifier {
        self.classifier
            .get_or_insert_with(|| self.manager.token_classifier())
    }

    pub(crate) fn contains(&mut self, text: &[u8]) -> bool {
        let decoded;
        let data: &[u8] = if text.contains(&b'%') {
            decoded = decode_escapes(text);
            &decoded
        } else {
            text
        };
        let mut start = 0;
        for index in 0..=data.len() {
            if index < data.len() && is_base64_byte(data[index]) {
                continue;
            }
            if self.contains_in_run(&data[start..index]) {
                return true;
            }
            start = index + 1;
        }
        false
    }

    fn contains_in_run(&mut self, run: &[u8]) -> bool {
        const WINDOW_CHARS: usize = 43;
        const WINDOW_BYTES: usize = 32;
        if run.len() < WINDOW_CHARS {
            return false;
        }
        for phase in 0..4 {
            if phase + WINDOW_CHARS > run.len() {
                break;
            }
            let mut chars = &run[phase..];
            if chars.len() % 4 == 1 {
                chars = &chars[..chars.len() - 1];
            }
            let Ok(text) = std::str::from_utf8(chars) else {
                continue;
            };
            let Some(decoded) = token::decode_lenient(text) else {
                continue;
            };
            let mut offset = 0;
            while offset + WINDOW_BYTES <= decoded.len() {
                let value = &decoded[offset..offset + WINDOW_BYTES];
                if self.classifier().classify(value) != TokenClass::External
                    || self.manager.match_capability(value).is_some()
                {
                    return true;
                }
                offset += 3;
            }
        }
        false
    }
}

fn decode_escapes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Some(byte) = hex_pair(&bytes[index + 1..index + 3])
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

fn hex_pair(bytes: &[u8]) -> Option<u8> {
    let high = (*bytes.first()? as char).to_digit(16)?;
    let low = (*bytes.get(1)? as char).to_digit(16)?;
    Some((high * 16 + low) as u8)
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_uppercase()
        || byte.is_ascii_digit()
        || byte == b'-'
        || byte == b'_'
}
