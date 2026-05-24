//! Binary wire frame uploaded to / downloaded from a Drive file body.
//!
//! Layout (big-endian for multi-byte ints):
//!
//! ```text
//! | ver: u8 | kind: u8 | sid: [u8; 16] | seq: u64 | payload_len: u32 | payload[payload_len] |
//! ```
//!
//! The full file body is `HEADER_LEN + payload_len` bytes. Senders MUST
//! chunk above [`MAX_PAYLOAD`]; receivers reject anything larger so a
//! malformed upload can't OOM the polling task.

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Current wire version. Bump on any layout change.
pub const WIRE_VERSION: u8 = 1;

/// Fixed-size header: 1 (ver) + 1 (kind) + 16 (sid) + 8 (seq) + 4 (len) = 30 bytes.
pub const HEADER_LEN: usize = 30;

/// Largest payload accepted on the wire (4 MiB). Single Drive uploads
/// can carry far more, but the per-frame AEAD seal happens in-memory
/// on both sides — a 4 MiB cap is the soft RAM ceiling we accept on
/// the mipsel-musl router target.
pub const MAX_PAYLOAD: u32 = 4 * 1024 * 1024;

/// Session identifier — 16 random bytes, base32-encoded in the
/// filename grammar.
pub type SessionId = [u8; 16];

/// Frame variants. `repr(u8)` so the wire byte maps trivially.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// One-shot session opener carrying the client's ephemeral X25519
    /// pubkey + session cookie. The Hello body is NOT AEAD-sealed
    /// (it's the key-agreement input); every subsequent frame is.
    Hello = 0x01,
    /// Real-destination dial request: payload = host string + u16 port.
    Connect = 0x02,
    /// Application data (the bulk of all traffic).
    Data = 0x03,
    /// Half-close — writer-side EOF for this direction.
    Eof = 0x04,
    /// Full session close. Peer drops state on receipt.
    Close = 0x05,
    /// Peer-readable error report. Payload is a UTF-8 reason string.
    Error = 0x06,
}

impl FrameKind {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Connect),
            0x03 => Some(Self::Data),
            0x04 => Some(Self::Eof),
            0x05 => Some(Self::Close),
            0x06 => Some(Self::Error),
            _ => None,
        }
    }
}

/// Decoded wire frame. `payload` owns its bytes (we copy out of the
/// input slice on decode — the input may be a borrowed HTTP body that
/// outlives this frame for the round-trip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub version: u8,
    pub kind: FrameKind,
    pub sid: SessionId,
    pub seq: u64,
    pub payload: Bytes,
}

impl WireFrame {
    /// Encode the frame onto the wire. Caller hands the returned
    /// buffer to the AEAD layer (the body the relay/client uploads is
    /// `AEAD(WireFrame::encode())`).
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u8(self.version);
        buf.put_u8(self.kind as u8);
        buf.put_slice(&self.sid);
        buf.put_u64(self.seq);
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);
        buf
    }

    /// Decode a frame from a wire byte slice. Wire-level only —
    /// upstream layers verify the AEAD tag before calling this.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < HEADER_LEN {
            return Err(DecodeError::TooShort(input.len()));
        }
        let mut cursor = input;
        let version = cursor.get_u8();
        if version != WIRE_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let kind_byte = cursor.get_u8();
        let kind = FrameKind::from_u8(kind_byte).ok_or(DecodeError::UnknownKind(kind_byte))?;
        let mut sid: SessionId = [0u8; 16];
        cursor.copy_to_slice(&mut sid);
        let seq = cursor.get_u64();
        let len = cursor.get_u32();
        if len > MAX_PAYLOAD {
            return Err(DecodeError::PayloadTooLarge(len));
        }
        if cursor.remaining() < len as usize {
            return Err(DecodeError::PayloadTruncated {
                declared: len,
                available: cursor.remaining(),
            });
        }
        let payload = Bytes::copy_from_slice(&cursor[..len as usize]);
        Ok(Self {
            version,
            kind,
            sid,
            seq,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort(usize),
    UnsupportedVersion(u8),
    UnknownKind(u8),
    PayloadTooLarge(u32),
    PayloadTruncated { declared: u32, available: usize },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => {
                write!(f, "frame too short ({n} bytes; need at least {HEADER_LEN})")
            }
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported wire version {v} (this build supports {WIRE_VERSION})"
            ),
            Self::UnknownKind(b) => write!(f, "unknown frame kind 0x{b:02x}"),
            Self::PayloadTooLarge(n) => {
                write!(f, "payload length {n} exceeds maximum {MAX_PAYLOAD}")
            }
            Self::PayloadTruncated {
                declared,
                available,
            } => write!(
                f,
                "declared payload {declared} bytes but buffer has {available}"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_with(kind: FrameKind, payload: &[u8]) -> WireFrame {
        WireFrame {
            version: WIRE_VERSION,
            kind,
            sid: [0xab; 16],
            seq: 7,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn roundtrip_all_kinds() {
        for kind in [
            FrameKind::Hello,
            FrameKind::Connect,
            FrameKind::Data,
            FrameKind::Eof,
            FrameKind::Close,
            FrameKind::Error,
        ] {
            let f = frame_with(kind, b"hello world");
            let wire = f.encode();
            let decoded = WireFrame::decode(&wire).expect("decode roundtrip");
            assert_eq!(decoded, f);
        }
    }

    #[test]
    fn decode_rejects_short_input() {
        let buf = [0u8; HEADER_LEN - 1];
        let err = WireFrame::decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::TooShort(HEADER_LEN - 1));
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut buf = frame_with(FrameKind::Data, b"x").encode();
        buf[0] = 0xff;
        let err = WireFrame::decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::UnsupportedVersion(0xff));
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let mut buf = frame_with(FrameKind::Data, b"x").encode();
        buf[1] = 0x7f;
        let err = WireFrame::decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::UnknownKind(0x7f));
    }

    #[test]
    fn decode_rejects_payload_too_large() {
        // Forge a header that advertises a payload above MAX_PAYLOAD.
        let mut buf = BytesMut::new();
        buf.put_u8(WIRE_VERSION);
        buf.put_u8(FrameKind::Data as u8);
        buf.put_slice(&[0u8; 16]);
        buf.put_u64(0);
        buf.put_u32(MAX_PAYLOAD + 1);
        let err = WireFrame::decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::PayloadTooLarge(MAX_PAYLOAD + 1));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut buf = BytesMut::new();
        buf.put_u8(WIRE_VERSION);
        buf.put_u8(FrameKind::Data as u8);
        buf.put_slice(&[0u8; 16]);
        buf.put_u64(0);
        buf.put_u32(10);
        buf.put_slice(b"only5"); // 5 < declared 10
        let err = WireFrame::decode(&buf).unwrap_err();
        assert_eq!(
            err,
            DecodeError::PayloadTruncated {
                declared: 10,
                available: 5,
            }
        );
    }

    #[test]
    fn empty_payload_is_legal() {
        let f = frame_with(FrameKind::Eof, b"");
        let wire = f.encode();
        assert_eq!(wire.len(), HEADER_LEN);
        let decoded = WireFrame::decode(&wire).expect("empty payload round-trips");
        assert_eq!(decoded, f);
    }
}
