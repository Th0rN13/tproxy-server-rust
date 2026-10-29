use std::io::Read;
use std::path::Path;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const TOKEN_BYTES: usize = 32;
const TOKEN_RANDOM_BYTES: usize = 12;
const TOKEN_NONCE_BYTES: usize = 16;

const TOKEN_CONTEXT: &[u8] = b"tproxy-server-token-v1\x00";
const TOKEN_FILTER_CONTEXT: &[u8] = b"tproxy-server-token-filter-v1\x00";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenClass {
    External = 0,
    Bootstrap = 1,
    Session = 2,
}

pub struct TokenClassifier {
    filter: Aes128,
    key: [u8; TOKEN_BYTES],
}

impl TokenClassifier {
    pub fn new(key: &[u8; TOKEN_BYTES]) -> Self {
        Self {
            filter: filter_block(key),
            key: *key,
        }
    }

    fn token_mac(&self, kind: TokenClass, nonce: &[u8]) -> [u8; 16] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(TOKEN_CONTEXT);
        mac.update(&[kind as u8]);
        mac.update(nonce);
        let sum = mac.finalize().into_bytes();
        sum[..16].try_into().unwrap()
    }

    fn classify_signed(&self, decoded: &[u8]) -> TokenClass {
        let nonce = &decoded[..TOKEN_NONCE_BYTES];
        let given = &decoded[TOKEN_NONCE_BYTES..];
        if ct_equal(given, &self.token_mac(TokenClass::Bootstrap, nonce)) {
            return TokenClass::Bootstrap;
        }
        if ct_equal(given, &self.token_mac(TokenClass::Session, nonce)) {
            return TokenClass::Session;
        }
        TokenClass::External
    }

    pub fn signed(&self, decoded: &[u8]) -> bool {
        decoded.len() == TOKEN_BYTES && self.classify_signed(decoded) != TokenClass::External
    }

    pub fn classify(&self, decoded: &[u8]) -> TokenClass {
        if decoded.len() != TOKEN_BYTES {
            return TokenClass::External;
        }
        let tag = filter_tag(&self.filter, &decoded[..TOKEN_RANDOM_BYTES]);
        if !ct_equal(&decoded[TOKEN_RANDOM_BYTES..TOKEN_NONCE_BYTES], &tag) {
            return TokenClass::External;
        }
        self.classify_signed(decoded)
    }
}

fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (first, second) in a.iter().zip(b) {
        diff |= first ^ second;
    }
    diff == 0
}

fn filter_block(key: &[u8; TOKEN_BYTES]) -> Aes128 {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(TOKEN_FILTER_CONTEXT);
    let sum = mac.finalize().into_bytes();
    Aes128::new_from_slice(&sum[..16]).expect("aes-128 key is 16 bytes")
}

fn filter_tag(filter: &Aes128, random: &[u8]) -> [u8; 4] {
    let mut block = GenericArray::from([0u8; 16]);
    block[..TOKEN_RANDOM_BYTES].copy_from_slice(&random[..TOKEN_RANDOM_BYTES]);
    filter.encrypt_block(&mut block);
    block[..4].try_into().unwrap()
}

pub fn new_token(key: &[u8; TOKEN_BYTES], kind: TokenClass) -> (String, [u8; TOKEN_BYTES]) {
    let mut input = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut input[..TOKEN_RANDOM_BYTES]);
    let classifier = TokenClassifier::new(key);
    let tag = filter_tag(&classifier.filter, &input[..TOKEN_RANDOM_BYTES]);
    input[TOKEN_RANDOM_BYTES..TOKEN_NONCE_BYTES].copy_from_slice(&tag);
    let mac = classifier.token_mac(kind, &input[..TOKEN_NONCE_BYTES]);
    input[TOKEN_NONCE_BYTES..].copy_from_slice(&mac);
    (URL_SAFE_NO_PAD.encode(input), Sha256::digest(input).into())
}

fn lenient_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    )
}

pub fn classify_token(key: &[u8; TOKEN_BYTES], token: &str) -> TokenClass {
    let Ok(decoded) = lenient_base64().decode(token) else {
        return TokenClass::External;
    };
    TokenClassifier::new(key).classify(&decoded)
}

pub fn token_hash(token: &str) -> Option<[u8; TOKEN_BYTES]> {
    let decoded = lenient_base64().decode(token).ok()?;
    if decoded.len() != TOKEN_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != token {
        return None;
    }
    Some(Sha256::digest(&decoded).into())
}

pub fn read_token_key(path: &Path) -> std::io::Result<[u8; TOKEN_BYTES]> {
    let file = std::fs::File::open(path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("token_key_file: {err} (provision a persistent 32-byte key before starting the relay)"),
        )
    })?;
    let info = file.metadata()?;
    if !info.is_file() || info.len() != TOKEN_BYTES as u64 {
        return Err(std::io::Error::other(
            "token_key_file must be a regular file containing exactly 32 random bytes",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "token_key_file must not be accessible by group or others",
            ));
        }
    }
    let mut key = [0u8; TOKEN_BYTES];
    (&file).read_exact(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn decode(token: &str) -> [u8; TOKEN_BYTES] {
        URL_SAFE_NO_PAD.decode(token).unwrap().try_into().unwrap()
    }

    fn previous_release_class(key: &[u8; TOKEN_BYTES], token: &str) -> TokenClass {
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(token) else {
            return TokenClass::External;
        };
        if decoded.len() != TOKEN_BYTES {
            return TokenClass::External;
        }
        for kind in [TokenClass::Bootstrap, TokenClass::Session] {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
            mac.update(TOKEN_CONTEXT);
            mac.update(&[kind as u8]);
            mac.update(&decoded[..TOKEN_NONCE_BYTES]);
            let sum = mac.finalize().into_bytes();
            if decoded[TOKEN_NONCE_BYTES..] == sum[..16] {
                return kind;
            }
        }
        TokenClass::External
    }

    #[test]
    fn token_layout_matches_previous_release_formula() {
        let key = [1u8; TOKEN_BYTES];
        for kind in [TokenClass::Bootstrap, TokenClass::Session] {
            let (token, hash) = new_token(&key, kind);
            assert_eq!(token.len(), 43);
            let decoded = decode(&token);
            assert_eq!(Sha256::digest(decoded).to_vec(), hash.to_vec());
            assert_eq!(previous_release_class(&key, &token), kind);
            assert_eq!(classify_token(&key, &token), kind);
        }
    }

    #[test]
    fn classify_rejects_tampered_tokens() {
        let key = [1u8; TOKEN_BYTES];
        let (token, _) = new_token(&key, TokenClass::Session);
        let mut decoded = decode(&token);
        for index in 0..TOKEN_BYTES {
            decoded[index] ^= 1;
            assert_eq!(
                classify_token(&key, &encode(&decoded)),
                TokenClass::External
            );
            decoded[index] ^= 1;
        }
    }

    #[test]
    fn signed_recognizes_untagged_legacy_tokens() {
        let key = [1u8; TOKEN_BYTES];
        let (tagged, _) = new_token(&key, TokenClass::Session);
        assert!(TokenClassifier::new(&key).signed(&decode(&tagged)));

        let mut legacy = [7u8; TOKEN_BYTES];
        let classifier = TokenClassifier::new(&key);
        let mac = classifier.token_mac(TokenClass::Bootstrap, &legacy[..TOKEN_NONCE_BYTES]);
        legacy[TOKEN_NONCE_BYTES..].copy_from_slice(&mac);
        assert_eq!(classifier.classify(&legacy), TokenClass::External);
        assert!(classifier.signed(&legacy));
    }

    #[test]
    fn token_hash_requires_canonical_encoding() {
        let key = [1u8; TOKEN_BYTES];
        let (token, hash) = new_token(&key, TokenClass::Session);
        assert_eq!(token_hash(&token), Some(hash));

        let alphabet = base64::alphabet::URL_SAFE.as_str();
        let alphabet: Vec<char> = alphabet.chars().collect();
        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        let index = alphabet.iter().position(|c| *c == chars[last]).unwrap();
        chars[last] = alphabet[(index & !0b11) | 0b01];
        let variant: String = chars.into_iter().collect();
        assert_ne!(variant, token);
        assert_eq!(token_hash(&variant), None);
        assert_eq!(classify_token(&key, &variant), TokenClass::Session);

        assert_eq!(token_hash(""), None);
        assert_eq!(token_hash(&"A".repeat(42)), None);
        assert_eq!(token_hash(&format!("{}=", "A".repeat(43))), None);
    }

    #[cfg(unix)]
    #[test]
    fn token_key_requires_private_persistent_file() {
        let dir = std::env::temp_dir().join(format!("tproxy-token-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.key");
        assert!(read_token_key(&path).is_err());
        use std::os::unix::fs::PermissionsExt;
        for size in [0usize, 31, 33, 32] {
            std::fs::write(&path, vec![7u8; size]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let key = read_token_key(&path);
            assert_eq!(key.is_ok(), size == 32);
            if size == 32 {
                assert_eq!(key.unwrap(), [7u8; 32]);
            }
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_token_key(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
