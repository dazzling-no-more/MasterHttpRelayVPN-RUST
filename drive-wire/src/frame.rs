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
    PayloadTruncated {
        declared: u32,
        available: usize,
    },
    // ── Batch-level errors (multi-frame file body, v2 wire format) ──
    /// Body didn't start with the batch magic `b"RG2B"`.
    BatchBadMagic,
    /// Batch declared a count outside the allowed range
    /// (1..=`MAX_BATCH_FRAMES`).
    BatchBadCount(u8),
    /// One frame's length header pointed past the end of the body.
    BatchFrameTruncated {
        index: u8,
        declared: u32,
        remaining: usize,
    },
    /// A nested frame failed to decode.
    BatchFrameDecode {
        index: u8,
        inner: Box<DecodeError>,
    },
    /// Trailing bytes after the declared frame count — body is
    /// malformed (the batcher pads nothing; any leftover is suspicious).
    BatchTrailingBytes(usize),
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
            Self::BatchBadMagic => write!(
                f,
                "batch body doesn't start with magic {BATCH_MAGIC:?} (corrupt or v1 body in v2 path)"
            ),
            Self::BatchBadCount(n) => write!(
                f,
                "batch count {n} out of allowed range 1..={MAX_BATCH_FRAMES}"
            ),
            Self::BatchFrameTruncated {
                index,
                declared,
                remaining,
            } => write!(
                f,
                "batch frame {index} declared length {declared} but only {remaining} bytes remain"
            ),
            Self::BatchFrameDecode { index, inner } => {
                write!(f, "batch frame {index}: {inner}")
            }
            Self::BatchTrailingBytes(n) => {
                write!(f, "batch has {n} trailing bytes after declared frame count")
            }
        }
    }
}

// --------------------------------------------------------------------
// Batch — multi-frame file body (v2 wire format)
// --------------------------------------------------------------------

/// Magic bytes prefixing every batched file body. Lets the parser
/// fail fast on a corrupt or unrelated body before doing length math.
/// Picked to be unambiguously not-a-WireFrame (a v1 frame would start
/// with `WIRE_VERSION = 0x01` not `'R' = 0x52`).
pub const BATCH_MAGIC: &[u8; 4] = b"RG2B";

/// Hard cap on frames packed into a single Drive file. 256 keeps the
/// per-batch worst-case memory pressure bounded (256 × MAX_PAYLOAD =
/// 1 GiB theoretical, but in practice each frame is ≤16 KiB — the
/// LOCAL_SOCKET_READ_BUFFER cap — so realistic batch bodies are
/// ≤4 MiB).
pub const MAX_BATCH_FRAMES: u8 = 255;

/// 4 (magic) + 1 (count) = 5 bytes of fixed batch overhead, plus
/// 4 bytes per-frame for the length prefix.
pub const BATCH_HEADER_LEN: usize = 5;

/// Per-frame overhead inside a batch (`u32` length prefix).
pub const BATCH_PER_FRAME_OVERHEAD: usize = 4;

/// A batch of 1..=`MAX_BATCH_FRAMES` `WireFrame`s sharing one Drive file
/// upload. All frames in a batch must share the same `sid` (carried
/// in the filename), and their `seq`s should form a contiguous
/// monotonically-increasing run starting at the file's filename seq.
/// The seq invariant isn't enforced at the codec level (the receiver's
/// replay window does the strict check per-frame); we trust the
/// sender to emit a coherent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub frames: Vec<WireFrame>,
}

impl Batch {
    /// Encode the batch into a single byte buffer ready for AEAD
    /// sealing. Layout:
    ///
    /// ```text
    /// | magic = "RG2B" | count: u8 | (len: u32_be | WireFrame_bytes)* count |
    /// ```
    pub fn encode(&self) -> BytesMut {
        debug_assert!(!self.frames.is_empty(), "Batch must contain ≥1 frame");
        debug_assert!(
            self.frames.len() <= MAX_BATCH_FRAMES as usize,
            "Batch count {} exceeds cap {}",
            self.frames.len(),
            MAX_BATCH_FRAMES,
        );
        let payload_cap = self
            .frames
            .iter()
            .map(|f| BATCH_PER_FRAME_OVERHEAD + HEADER_LEN + f.payload.len())
            .sum::<usize>();
        let mut buf = BytesMut::with_capacity(BATCH_HEADER_LEN + payload_cap);
        buf.put_slice(BATCH_MAGIC);
        buf.put_u8(self.frames.len() as u8);
        for frame in &self.frames {
            let encoded = frame.encode();
            buf.put_u32(encoded.len() as u32);
            buf.put_slice(&encoded);
        }
        buf
    }

    /// Decode a batch from a buffer (post-AEAD-open). Strict — any
    /// length mismatch, oversized frame, or trailing bytes is an
    /// error; we don't tolerate partial batches because there's no
    /// recoverable path (the sender doesn't pad, doesn't pipeline
    /// half-batches).
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < BATCH_HEADER_LEN {
            return Err(DecodeError::TooShort(input.len()));
        }
        if &input[..4] != BATCH_MAGIC {
            return Err(DecodeError::BatchBadMagic);
        }
        let mut cursor = &input[4..];
        let count = cursor.get_u8();
        if count == 0 || count > MAX_BATCH_FRAMES {
            return Err(DecodeError::BatchBadCount(count));
        }
        let mut frames = Vec::with_capacity(count as usize);
        for index in 0..count {
            if cursor.remaining() < BATCH_PER_FRAME_OVERHEAD {
                return Err(DecodeError::BatchFrameTruncated {
                    index,
                    declared: 0,
                    remaining: cursor.remaining(),
                });
            }
            let frame_len = cursor.get_u32();
            if cursor.remaining() < frame_len as usize {
                return Err(DecodeError::BatchFrameTruncated {
                    index,
                    declared: frame_len,
                    remaining: cursor.remaining(),
                });
            }
            let frame_bytes = &cursor[..frame_len as usize];
            let frame =
                WireFrame::decode(frame_bytes).map_err(|inner| DecodeError::BatchFrameDecode {
                    index,
                    inner: Box::new(inner),
                })?;
            cursor.advance(frame_len as usize);
            frames.push(frame);
        }
        if cursor.has_remaining() {
            return Err(DecodeError::BatchTrailingBytes(cursor.remaining()));
        }
        Ok(Self { frames })
    }

    /// Convenience: single-frame batch (the common case during the
    /// migration period and for control frames like Connect, Eof,
    /// Close, Error that the coalescer typically flushes immediately).
    pub fn single(frame: WireFrame) -> Self {
        Self {
            frames: vec![frame],
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

    // ---- Batch ------------------------------------------------------

    fn frame_at(seq: u64, kind: FrameKind, payload: &[u8]) -> WireFrame {
        WireFrame {
            version: WIRE_VERSION,
            kind,
            sid: [0xab; 16],
            seq,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn batch_single_frame_round_trips() {
        let batch = Batch::single(frame_at(0, FrameKind::Connect, b"example.com:443"));
        let encoded = batch.encode();
        let decoded = Batch::decode(&encoded).expect("decode roundtrip");
        assert_eq!(decoded, batch);
    }

    #[test]
    fn batch_multi_frame_round_trips() {
        let batch = Batch {
            frames: vec![
                frame_at(5, FrameKind::Data, b"first"),
                frame_at(6, FrameKind::Data, b"second longer payload"),
                frame_at(7, FrameKind::Eof, b""),
            ],
        };
        let encoded = batch.encode();
        let decoded = Batch::decode(&encoded).expect("decode roundtrip");
        assert_eq!(decoded, batch);
        assert_eq!(decoded.frames.len(), 3);
    }

    #[test]
    fn batch_decode_rejects_wrong_magic() {
        let mut bad = Batch::single(frame_at(0, FrameKind::Data, b"x")).encode();
        bad[0] = b'X';
        let err = Batch::decode(&bad).unwrap_err();
        assert_eq!(err, DecodeError::BatchBadMagic);
    }

    #[test]
    fn batch_decode_rejects_zero_count() {
        let mut buf = BytesMut::new();
        buf.put_slice(BATCH_MAGIC);
        buf.put_u8(0);
        let err = Batch::decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::BatchBadCount(0));
    }

    #[test]
    fn batch_decode_rejects_truncated_frame() {
        let mut buf = BytesMut::new();
        buf.put_slice(BATCH_MAGIC);
        buf.put_u8(1);
        buf.put_u32(1000); // declared length way past buffer end
        buf.put_slice(&[0u8; 10]);
        let err = Batch::decode(&buf).unwrap_err();
        match err {
            DecodeError::BatchFrameTruncated {
                index: 0,
                declared: 1000,
                ..
            } => {}
            other => panic!("expected BatchFrameTruncated, got {other:?}"),
        }
    }

    #[test]
    fn batch_decode_rejects_trailing_bytes() {
        let mut buf = Batch::single(frame_at(0, FrameKind::Data, b"x")).encode();
        buf.put_slice(b"garbage");
        let err = Batch::decode(&buf).unwrap_err();
        assert_eq!(err, DecodeError::BatchTrailingBytes(7));
    }

    #[test]
    fn batch_decode_rejects_bad_inner_frame() {
        // Wrap a frame with bogus version inside the batch envelope.
        let mut buf = BytesMut::new();
        buf.put_slice(BATCH_MAGIC);
        buf.put_u8(1);
        // Build a fake "frame" with WIRE_VERSION+1 (unsupported).
        let mut bad_frame = BytesMut::new();
        bad_frame.put_u8(0xff);
        bad_frame.put_u8(FrameKind::Data as u8);
        bad_frame.put_slice(&[0u8; 16]);
        bad_frame.put_u64(0);
        bad_frame.put_u32(0);
        buf.put_u32(bad_frame.len() as u32);
        buf.put_slice(&bad_frame);
        let err = Batch::decode(&buf).unwrap_err();
        match err {
            DecodeError::BatchFrameDecode { index: 0, inner } => {
                assert_eq!(*inner, DecodeError::UnsupportedVersion(0xff));
            }
            other => panic!("expected BatchFrameDecode, got {other:?}"),
        }
    }
}
