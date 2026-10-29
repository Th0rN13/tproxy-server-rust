use thiserror::Error;

pub const HEADER_SIZE: usize = 8;
pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const INITIAL_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
pub const DATA_CHUNK: usize = 64 * 1024;
pub const MAX_STREAM_ID: u32 = 0xFFFFFF;
pub const MAX_BATCH_FRAMES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameType(pub u8);

impl FrameType {
    pub const OPEN: FrameType = FrameType(0x01);
    pub const DATA: FrameType = FrameType(0x02);
    pub const CLOSE: FrameType = FrameType(0x03);
    pub const WINDOW: FrameType = FrameType(0x04);
    pub const PING: FrameType = FrameType(0x05);
    pub const PONG: FrameType = FrameType(0x06);
    pub const HELLO: FrameType = FrameType(0x10);
    pub const WELCOME: FrameType = FrameType(0x11);
    pub const BYE: FrameType = FrameType(0x1F);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub frame_type: FrameType,
    pub stream_id: u32,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    #[error("incomplete frame")]
    Incomplete,
    #[error("frame payload exceeds limit")]
    PayloadTooLarge,
    #[error("frame batch contains too many frames")]
    TooManyFrames,
    #[error("empty frame batch")]
    EmptyBatch,
    #[error("invalid HELLO frame")]
    InvalidHello,
    #[error("WINDOW payload must be four bytes")]
    WindowPayload,
    #[error("WINDOW delta must be nonzero")]
    WindowDelta,
    #[error("{0}")]
    InvalidShape(String),
}

pub fn encode(frame_type: FrameType, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    assert!(stream_id <= MAX_STREAM_ID, "stream id exceeds 24 bits");
    let mut result = Vec::with_capacity(HEADER_SIZE + payload.len());
    result.push(frame_type.0);
    result.push((stream_id >> 16) as u8);
    result.push((stream_id >> 8) as u8);
    result.push(stream_id as u8);
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    result.extend_from_slice(payload);
    result
}

pub fn parse_all(input: &[u8], max_payload: usize) -> Result<Vec<Frame<'_>>, FrameError> {
    let max_payload = if max_payload == 0 || max_payload > MAX_PAYLOAD {
        MAX_PAYLOAD
    } else {
        max_payload
    };
    let mut frames = Vec::with_capacity(4);
    let mut rest = input;
    while !rest.is_empty() {
        if frames.len() == MAX_BATCH_FRAMES {
            return Err(FrameError::TooManyFrames);
        }
        if rest.len() < HEADER_SIZE {
            return Err(FrameError::Incomplete);
        }
        let length = u32::from_be_bytes(rest[4..8].try_into().unwrap()) as usize;
        if length > max_payload {
            return Err(FrameError::PayloadTooLarge);
        }
        let full = HEADER_SIZE + length;
        if full > rest.len() {
            return Err(FrameError::Incomplete);
        }
        frames.push(Frame {
            frame_type: FrameType(rest[0]),
            stream_id: u32::from(rest[1]) << 16 | u32::from(rest[2]) << 8 | u32::from(rest[3]),
            payload: &rest[HEADER_SIZE..full],
        });
        rest = &rest[full..];
    }
    if frames.is_empty() {
        return Err(FrameError::EmptyBatch);
    }
    Ok(frames)
}

pub fn parse_hello(input: &[u8]) -> Result<(), FrameError> {
    let frames = parse_all(input, MAX_PAYLOAD)?;
    let &[value] = frames.as_slice() else {
        return Err(FrameError::InvalidHello);
    };
    if value.frame_type != FrameType::HELLO || value.stream_id != 0 || value.payload != [1] {
        return Err(FrameError::InvalidHello);
    }
    Ok(())
}

pub fn window_amount(payload: &[u8]) -> Result<u32, FrameError> {
    let amount = u32::from_be_bytes(payload.try_into().map_err(|_| FrameError::WindowPayload)?);
    if amount == 0 {
        return Err(FrameError::WindowDelta);
    }
    Ok(amount)
}

pub fn window_payload(amount: u32) -> [u8; 4] {
    amount.to_be_bytes()
}

pub fn validate_client_shape(value: Frame<'_>) -> Result<(), FrameError> {
    if value.stream_id == 0 {
        if value.frame_type != FrameType::PONG || value.payload.len() > 64 {
            return Err(shape_error(value.frame_type, "is invalid on stream zero"));
        }
        return Ok(());
    }
    if value.frame_type == FrameType::OPEN || value.frame_type == FrameType::CLOSE {
        if !value.payload.is_empty() {
            return Err(shape_error(value.frame_type, "requires an empty payload"));
        }
        return Ok(());
    }
    if value.frame_type == FrameType::DATA {
        if value.payload.is_empty() {
            return Err(FrameError::InvalidShape(
                "DATA payload must be nonempty".to_string(),
            ));
        }
        return Ok(());
    }
    if value.frame_type == FrameType::WINDOW {
        return window_amount(value.payload).map(|_| ());
    }
    Err(shape_error(value.frame_type, "is invalid client-to-relay"))
}

fn shape_error(frame_type: FrameType, reason: &str) -> FrameError {
    FrameError::InvalidShape(format!("frame type {:#x} {}", frame_type.0, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_header_layout() {
        assert_eq!(
            encode(FrameType::OPEN, 1, &[]),
            [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode(FrameType::DATA, 0x010203, b"abc"),
            [
                0x02, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x03, b'a', b'b', b'c'
            ]
        );
        assert_eq!(window_payload(0x01020304), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn round_trip() {
        let mut input = encode(FrameType::OPEN, MAX_STREAM_ID, &[]);
        input.extend_from_slice(&encode(FrameType::DATA, 7, b"payload"));
        let frames = parse_all(&input, MAX_PAYLOAD).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].stream_id, MAX_STREAM_ID);
        assert_eq!(frames[1].payload, b"payload");
    }

    #[test]
    fn rejects_partial_and_oversized() {
        let full = encode(FrameType::DATA, 1, b"x");
        assert_eq!(
            parse_all(&full[..HEADER_SIZE], MAX_PAYLOAD),
            Err(FrameError::Incomplete)
        );
        let wide = encode(FrameType::DATA, 1, b"xx");
        assert_eq!(parse_all(&wide, 1), Err(FrameError::PayloadTooLarge));
    }

    #[test]
    fn hello_and_window() {
        assert!(parse_hello(&encode(FrameType::HELLO, 0, &[1])).is_ok());
        assert!(parse_hello(&encode(FrameType::HELLO, 0, &[2])).is_err());
        assert!(window_amount(&[0, 0, 0, 0]).is_err());
    }

    #[test]
    fn rejects_excessive_frame_count() {
        let mut input = Vec::new();
        for _ in 0..MAX_BATCH_FRAMES + 1 {
            input.extend_from_slice(&encode(FrameType::CLOSE, 1, &[]));
        }
        assert!(parse_all(&input, MAX_PAYLOAD).is_err());
    }

    #[test]
    fn empty_batch_rejected() {
        assert_eq!(parse_all(&[], MAX_PAYLOAD), Err(FrameError::EmptyBatch));
    }

    #[test]
    fn unknown_type_passes_parse_rejected_by_shape() {
        let batch = encode(FrameType(0x99), 0, &[]);
        let frames = parse_all(&batch, MAX_PAYLOAD).unwrap();
        assert_eq!(frames[0].frame_type, FrameType(0x99));
        assert!(validate_client_shape(frames[0]).is_err());
    }

    #[test]
    fn client_shape_rules() {
        fn frame<'a>(frame_type: FrameType, stream_id: u32, payload: &'a [u8]) -> Frame<'a> {
            Frame {
                frame_type,
                stream_id,
                payload,
            }
        }
        assert!(validate_client_shape(frame(FrameType::PONG, 0, &[0; 64])).is_ok());
        assert!(validate_client_shape(frame(FrameType::PONG, 0, &[0; 65])).is_err());
        assert!(validate_client_shape(frame(FrameType::DATA, 0, b"x")).is_err());
        assert!(validate_client_shape(frame(FrameType::OPEN, 5, b"")).is_ok());
        assert!(validate_client_shape(frame(FrameType::CLOSE, 5, b"x")).is_err());
        assert!(validate_client_shape(frame(FrameType::DATA, 5, b"")).is_err());
        assert!(validate_client_shape(frame(FrameType::WINDOW, 5, &window_payload(1))).is_ok());
        assert!(validate_client_shape(frame(FrameType::PING, 5, b"")).is_err());
    }
}
