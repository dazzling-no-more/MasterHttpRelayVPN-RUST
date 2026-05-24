//! Drive filename grammar for the direction-prefixed mailbox.
//!
//! Three shapes:
//!
//! ```text
//! h_<sid_b32>_0          one-shot session opener (Hello)
//! c2r_<sid_b32>_<seq>    client-to-relay frame (uploaded by client)
//! r2c_<sid_b32>_<seq>    relay-to-client frame (uploaded by relay)
//! ```
//!
//! `<sid_b32>` is the 16-byte [`SessionId`] encoded in RFC 4648 base32
//! (no padding, lowercase). `<seq>` is decimal `u64`.
//!
//! Drive listing comes back sorted lexicographically and `seq=10` <
//! `seq=2` lex-wise, so consumers MUST re-sort numerically by `seq`
//! before applying frames. The filename grammar deliberately has NO
//! per-direction filename suffix beyond the prefix — consumers
//! disambiguate by parsing the prefix, not by querying Drive with two
//! separate `name contains` clauses.

use crate::frame::SessionId;

pub const PREFIX_HELLO: &str = "h_";
pub const PREFIX_C2R: &str = "c2r_";
pub const PREFIX_R2C: &str = "r2c_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `c2r_*` — uploaded by client, polled by relay.
    ClientToRelay,
    /// `r2c_*` — uploaded by relay, polled by client.
    RelayToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilenameKind {
    Hello,
    Frame(Direction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveFilename {
    pub kind: FilenameKind,
    pub sid: SessionId,
    /// Always `0` for Hello; monotonic per direction for Frame.
    pub seq: u64,
}

impl DriveFilename {
    /// Render to wire form: `<prefix><sid_b32>_<seq>`.
    pub fn format(&self) -> String {
        let prefix = match self.kind {
            FilenameKind::Hello => PREFIX_HELLO,
            FilenameKind::Frame(Direction::ClientToRelay) => PREFIX_C2R,
            FilenameKind::Frame(Direction::RelayToClient) => PREFIX_R2C,
        };
        format!("{}{}_{}", prefix, encode_sid_b32(&self.sid), self.seq)
    }
}

/// Parse a Drive filename. Returns `None` on any malformed input;
/// callers treat unparseable names as foreign files (don't crash,
/// don't delete). Hello-prefixed names with `seq != 0` are rejected
/// — Hello is one-shot by construction.
pub fn parse_filename(name: &str) -> Option<DriveFilename> {
    let (kind, rest) = if let Some(r) = name.strip_prefix(PREFIX_C2R) {
        (FilenameKind::Frame(Direction::ClientToRelay), r)
    } else if let Some(r) = name.strip_prefix(PREFIX_R2C) {
        (FilenameKind::Frame(Direction::RelayToClient), r)
    } else if let Some(r) = name.strip_prefix(PREFIX_HELLO) {
        (FilenameKind::Hello, r)
    } else {
        return None;
    };
    // `rsplit_once('_')` finds the LAST underscore so a sid containing
    // no `_` is fine (b32 alphabet excludes `_`, so the sid section
    // never has one — the only `_` is the seq separator we wrote).
    let (sid_b32, seq_str) = rest.rsplit_once('_')?;
    let sid = decode_sid_b32(sid_b32)?;
    let seq: u64 = seq_str.parse().ok()?;
    if matches!(kind, FilenameKind::Hello) && seq != 0 {
        return None;
    }
    Some(DriveFilename { kind, sid, seq })
}

// ---- RFC 4648 base32 (lowercase, no padding) ------------------------
//
// Hand-rolled rather than pulling a `base32` crate: drive-wire is the
// "minimal deps" shared crate (see Cargo.toml comment). 50-odd lines
// is cheaper than another transitive dep in every cross-compile.

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// 16 bytes (128 bits) → 26 base32 chars. The final char carries 3
/// payload bits + 2 zero pad bits (no `=` written).
fn encode_sid_b32(sid: &SessionId) -> String {
    let mut out = String::with_capacity(26);
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;
    for &byte in sid {
        buffer = (buffer << 8) | (byte as u64);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits_in_buffer > 0 {
        let idx = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn decode_sid_b32(s: &str) -> Option<SessionId> {
    if s.len() != 26 {
        return None;
    }
    let mut out: SessionId = [0u8; 16];
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;
    let mut out_idx: usize = 0;
    for c in s.bytes() {
        let v = decode_b32_char(c)?;
        buffer = (buffer << 5) | (v as u64);
        bits_in_buffer += 5;
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            if out_idx >= 16 {
                return None;
            }
            out[out_idx] = ((buffer >> bits_in_buffer) & 0xff) as u8;
            out_idx += 1;
        }
    }
    if out_idx != 16 {
        return None;
    }
    Some(out)
}

fn decode_b32_char(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_b32_roundtrip_zeros_and_max() {
        for sid in [[0u8; 16], [0xff; 16], [0xa5; 16]] {
            let encoded = encode_sid_b32(&sid);
            assert_eq!(encoded.len(), 26);
            assert_eq!(decode_sid_b32(&encoded), Some(sid));
        }
    }

    #[test]
    fn parse_format_roundtrip_for_each_kind() {
        let sid: SessionId = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
            0xf6, 0xf7,
        ];
        for (kind, seq) in [
            (FilenameKind::Hello, 0u64),
            (FilenameKind::Frame(Direction::ClientToRelay), 42),
            (FilenameKind::Frame(Direction::RelayToClient), 1 << 60),
        ] {
            let want = DriveFilename { kind, sid, seq };
            let name = want.format();
            let got = parse_filename(&name).expect("roundtrip");
            assert_eq!(got, want);
        }
    }

    #[test]
    fn parse_accepts_uppercase_b32() {
        // Drive itself preserves case, but defensive parsing accepts
        // case-folded names so a hand-edited filename or a future
        // storage edge that folds case doesn't drop the session.
        let lower = DriveFilename {
            kind: FilenameKind::Frame(Direction::ClientToRelay),
            sid: [0x11; 16],
            seq: 3,
        }
        .format();
        let upper = lower.replace("c2r_", "c2r_").to_string(); // prefix stays lowercase
        let mid: String = lower
            .chars()
            .enumerate()
            .map(|(i, c)| {
                // Upper-case the sid section only (between the `c2r_` prefix
                // and the trailing `_3`).
                if i >= "c2r_".len() && c.is_ascii_alphabetic() {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(parse_filename(&upper).is_some());
        assert!(parse_filename(&mid).is_some());
    }

    #[test]
    fn parse_rejects_unknown_prefix() {
        assert!(parse_filename("foo_aaaaaaaaaaaaaaaaaaaaaaaaaa_1").is_none());
        assert!(parse_filename("c2r").is_none());
        assert!(parse_filename("").is_none());
        assert!(parse_filename("h").is_none());
    }

    #[test]
    fn parse_rejects_hello_with_nonzero_seq() {
        let sid_b32 = encode_sid_b32(&[0u8; 16]);
        let bad = format!("{PREFIX_HELLO}{sid_b32}_1");
        assert!(parse_filename(&bad).is_none());
    }

    #[test]
    fn parse_rejects_malformed_sid() {
        // sid section length wrong.
        assert!(parse_filename("c2r_abc_1").is_none());
        // sid section contains chars outside the b32 alphabet.
        let bad_sid = "0".repeat(26);
        assert!(parse_filename(&format!("c2r_{bad_sid}_1")).is_none());
    }

    #[test]
    fn parse_rejects_malformed_seq() {
        let sid_b32 = encode_sid_b32(&[1u8; 16]);
        assert!(parse_filename(&format!("c2r_{sid_b32}_notanumber")).is_none());
        assert!(parse_filename(&format!("c2r_{sid_b32}_-1")).is_none());
    }

    #[test]
    fn lex_sort_diverges_from_numeric_sort_above_seq_9() {
        // Pin the invariant the doc comment promises: lex order is
        // wrong for seq >= 10, so consumers MUST re-sort numerically.
        let sid_b32 = encode_sid_b32(&[7u8; 16]);
        let mut names = vec![format!("c2r_{sid_b32}_10"), format!("c2r_{sid_b32}_2")];
        names.sort();
        // Lex order puts "10" before "2" — the bug consumers must guard against.
        assert!(names[0].ends_with("_10"));
        assert!(names[1].ends_with("_2"));
    }
}
