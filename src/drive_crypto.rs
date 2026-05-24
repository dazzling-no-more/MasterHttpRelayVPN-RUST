//! Drive-mode cryptography: X25519 key agreement → HKDF-SHA256 key
//! derivation → ChaCha20-Poly1305 AEAD with bound (sid, seq) AAD.
//!
//! ## Architecture
//!
//! Each session has its own pair of directional AEAD keys derived
//! once at Hello time. The relay holds a long-lived X25519 keypair
//! (`RelaySecret`); its public half (`RelayPubkey`, bech32m-encoded)
//! is shipped out-of-band to the client. Per session, the client
//! mints an ephemeral X25519 keypair + a random 16-byte cookie,
//! computes `shared = DH(esk_c, epk_r)`, and runs HKDF with the
//! cookie as salt and `"c2r|" || sid` / `"r2c|" || sid` as info to
//! produce two independent 32-byte directional keys. The relay
//! receives `(epk_c, cookie)` in the Hello body, performs the
//! symmetric `DH(esk_r, epk_c)`, and derives the same keys.
//!
//! ## AEAD construction
//!
//! Per frame:
//!   - key   = `k_c2r` or `k_r2c` depending on direction
//!   - nonce = `seq.to_le_bytes() || [0u8; 4]` (12 bytes; IETF ChaCha20)
//!   - aad   = `sid || seq.to_be_bytes()` (24 bytes)
//!   - msg   = the [`drive_wire::frame::WireFrame`] bytes
//!
//! The AAD binds the sid and seq to the ciphertext: even if an
//! attacker rewrites the filename to point at a different session's
//! AEAD body, the tag check fails (the body's key is wrong AND the
//! AAD's sid doesn't match the new filename). The nonce includes
//! seq, so seq-reuse within a session would catastrophically reuse
//! a (key, nonce) pair — the [`ReplayWindow`] guards against that.
//!
//! ## Replay window
//!
//! Strict monotonic per direction: a frame is rejected if its seq
//! is `<=` the highest seq this side has accepted. Drive's
//! `files.list` returns entries in `createdTime` order which is
//! lex-sortable but NOT numeric-sortable above seq=9, so consumers
//! sort by parsed `seq` (numeric) before applying. Strict monotonic
//! breaks down only if Drive's eventual consistency delivers a
//! batch out of strict creation order between two listing calls;
//! v2 is expected to widen to a sliding 64-frame window. See the
//! plan file for the trade-off.

use std::fmt;

use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
// `rand` 0.8 re-exports the `rand_core` traits at its crate root, and
// `rand` is already a top-level dep — using the re-export avoids
// pulling `rand_core` separately and saves us pinning two
// rand_core-major versions in lockstep on a future rand bump.
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

pub use drive_wire::frame::SessionId;

/// Human-readable part of the bech32m-encoded relay public key.
/// Picked for low collision with existing HRPs (BIP-173 reserved
/// list, lightning, etc.) and to be plainly readable in error
/// messages: "rahgozar drive relay".
pub const RELAY_PUBKEY_HRP: &str = "rgdr";

/// Length of the encoded Hello body (`epk_c || cookie || sid`).
/// `sid` was added in v2 (was `HELLO_BODY_LEN = 48` in v1, pre-deploy)
/// so the body commits to the session-id it claims via the filename.
/// Without this commitment a malicious folder participant could
/// upload a Hello body that decodes successfully and the relay would
/// trust the filename-derived sid blindly; with it, the relay
/// verifies `parsed.sid == filename_sid` before deriving session keys,
/// catching filename-parser bugs and any future scope-widened Drive
/// folder where multiple writers may exist.
pub const HELLO_BODY_LEN: usize = 64;

// --------------------------------------------------------------------
// Relay long-lived keypair (X25519)
// --------------------------------------------------------------------

/// Long-lived X25519 secret held by the relay. Published as a
/// 32-byte file (`relay.key`) under tight filesystem permissions on
/// the VPS; never appears on the wire.
pub struct RelaySecret(StaticSecret);

impl RelaySecret {
    /// Mint a fresh keypair. Used by the `rahgozar-drive-relay
    /// keygen` subcommand once at install time.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        Self(StaticSecret::random_from_rng(&mut rng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> RelayPubkey {
        RelayPubkey(X25519PublicKey::from(&self.0))
    }
}

/// The relay's published public key. Round-trips through bech32m so
/// a one-character typo in the user's config fails parsing instead
/// of silently producing a Diffie-Hellman with the wrong peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPubkey(X25519PublicKey);

impl RelayPubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(X25519PublicKey::from(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }

    /// Render as `rgdr1...` (bech32m). The output is ~63 chars,
    /// always lowercase, with a built-in 6-char checksum that catches
    /// any single-character typo.
    pub fn to_bech32m(&self) -> String {
        let hrp = Hrp::parse_unchecked(RELAY_PUBKEY_HRP);
        bech32::encode::<Bech32m>(hrp, self.0.as_bytes())
            .expect("32-byte payload always fits within bech32m's size cap")
    }

    /// Parse a bech32m-encoded `rgdr1...` string back to a public
    /// key. Returns `Err` on checksum failure, wrong HRP, or wrong
    /// payload length.
    ///
    /// Decoding is strict Bech32m to match the Android validator and
    /// avoid platform-dependent acceptance of relay keys.
    pub fn from_bech32m(s: &str) -> Result<Self, PubkeyParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(PubkeyParseError::Empty);
        }
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| PubkeyParseError::BadEncoding(e.to_string()))?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != RELAY_PUBKEY_HRP {
            return Err(PubkeyParseError::WrongHrp {
                got: hrp.to_string(),
                expected: RELAY_PUBKEY_HRP,
            });
        }
        if data.len() != 32 {
            return Err(PubkeyParseError::WrongLength {
                got: data.len(),
                expected: 32,
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        if !x25519_public_key_is_contributory(&bytes) {
            return Err(PubkeyParseError::LowOrder);
        }
        Ok(Self::from_bytes(bytes))
    }
}

/// Deterministic probe used only to reject low-order Montgomery
/// public keys before they reach the session key schedule. The value
/// is not secret; any clamped scalar would produce the identity when
/// multiplied by a low-order input.
const CONTRIBUTORY_PROBE_SCALAR: [u8; 32] = [0x42; 32];

fn x25519_public_key_is_contributory(bytes: &[u8; 32]) -> bool {
    let probe = StaticSecret::from(CONTRIBUTORY_PROBE_SCALAR);
    let public = X25519PublicKey::from(*bytes);
    probe.diffie_hellman(&public).was_contributory()
}

/// Parse failures for a user-supplied relay public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubkeyParseError {
    Empty,
    BadEncoding(String),
    WrongHrp { got: String, expected: &'static str },
    WrongLength { got: usize, expected: usize },
    LowOrder,
}

impl fmt::Display for PubkeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "relay pubkey is empty"),
            Self::BadEncoding(e) => write!(
                f,
                "relay pubkey is not valid bech32m (checksum / charset / structure): {e}"
            ),
            Self::WrongHrp { got, expected } => write!(
                f,
                "relay pubkey has HRP '{got}' but expected '{expected}' — \
                 did you paste a key from a different tool?"
            ),
            Self::WrongLength { got, expected } => write!(
                f,
                "relay pubkey decodes to {got} bytes but X25519 keys are exactly {expected} bytes"
            ),
            Self::LowOrder => write!(
                f,
                "relay pubkey is a low-order X25519 point and would derive a predictable shared secret"
            ),
        }
    }
}

impl std::error::Error for PubkeyParseError {}

// --------------------------------------------------------------------
// Hello body — first frame of every session
// --------------------------------------------------------------------

/// Body of the `h_<sid>_0` file: the client's ephemeral X25519
/// public key plus the per-session HKDF salt. Sent in the clear
/// (it IS the key-agreement input); every subsequent frame is
/// AEAD-sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloBody {
    pub client_ephemeral_pubkey: [u8; 32],
    pub cookie: [u8; 16],
    /// The session-id the client claims for this Hello. The relay
    /// verifies this matches the sid parsed from the `h_<sid>_0`
    /// filename before accepting the Hello — without this commitment
    /// the body could appear under any filename and the relay would
    /// derive keys against the wrong sid.
    pub sid: SessionId,
}

impl HelloBody {
    pub fn encode(&self) -> [u8; HELLO_BODY_LEN] {
        let mut out = [0u8; HELLO_BODY_LEN];
        out[..32].copy_from_slice(&self.client_ephemeral_pubkey);
        out[32..48].copy_from_slice(&self.cookie);
        out[48..64].copy_from_slice(&self.sid);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HelloDecodeError> {
        if bytes.len() != HELLO_BODY_LEN {
            return Err(HelloDecodeError::WrongLength {
                got: bytes.len(),
                expected: HELLO_BODY_LEN,
            });
        }
        let mut client_ephemeral_pubkey = [0u8; 32];
        client_ephemeral_pubkey.copy_from_slice(&bytes[..32]);
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&bytes[32..48]);
        let mut sid = [0u8; 16];
        sid.copy_from_slice(&bytes[48..64]);
        Ok(Self {
            client_ephemeral_pubkey,
            cookie,
            sid,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloDecodeError {
    WrongLength {
        got: usize,
        expected: usize,
    },
    /// The sid declared inside the encoded HelloBody doesn't match
    /// the sid parsed from the `h_<sid>_0` filename. Returned by
    /// [`SessionKeys::relay_accept`] when it cross-checks the two.
    SidMismatch {
        filename: SessionId,
        body: SessionId,
    },
}

impl fmt::Display for HelloDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got, expected } => write!(
                f,
                "hello body must be exactly {expected} bytes (epk_c || cookie || sid); got {got}"
            ),
            Self::SidMismatch { filename, body } => write!(
                f,
                "hello body sid {body:02x?} does not match filename sid {filename:02x?}"
            ),
        }
    }
}

impl std::error::Error for HelloDecodeError {}

// --------------------------------------------------------------------
// Session key derivation (HKDF-SHA256)
// --------------------------------------------------------------------

/// Both directional AEAD keys for a single session, plus the sid
/// they're bound to.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub sid: SessionId,
    /// AEAD key used for `c2r_*` frames (client encrypts with, relay
    /// decrypts with). The relay derives the same value via its own
    /// half of the DH agreement.
    pub k_c2r: [u8; 32],
    /// AEAD key for `r2c_*` frames (relay encrypts with, client
    /// decrypts with).
    pub k_r2c: [u8; 32],
}

impl SessionKeys {
    /// Client side: mint an ephemeral keypair + cookie, derive the
    /// session keys against the relay's public key, hand back the
    /// keys plus the Hello body for upload.
    ///
    /// Consumes the ephemeral secret on `diffie_hellman` so it can't
    /// be reused across sessions even by accident.
    pub fn client_initiate<R: RngCore + CryptoRng>(
        relay_pubkey: &RelayPubkey,
        sid: SessionId,
        mut rng: R,
    ) -> Result<(Self, HelloBody), KeyAgreementError> {
        let esk = EphemeralSecret::random_from_rng(&mut rng);
        let epk = X25519PublicKey::from(&esk);
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);
        let shared = esk.diffie_hellman(&relay_pubkey.0);
        ensure_contributory(&shared)?;
        let (k_c2r, k_r2c) = derive_directional_keys(shared.as_bytes(), &cookie, &sid);
        let hello = HelloBody {
            client_ephemeral_pubkey: epk.to_bytes(),
            cookie,
            sid,
        };
        Ok((Self { sid, k_c2r, k_r2c }, hello))
    }

    /// Relay side: derive the same session keys from an inbound
    /// Hello body, using the relay's long-lived secret. Verifies that
    /// the body's declared sid matches the sid parsed from the
    /// `h_<sid>_0` filename (passed in as `sid`) — a mismatch is
    /// either a buggy client implementation or a malicious folder
    /// participant trying to confuse the filename parser; either way,
    /// refuse to derive keys.
    pub fn relay_accept(
        relay_secret: &RelaySecret,
        sid: SessionId,
        hello: &HelloBody,
    ) -> Result<Self, RelayAcceptError> {
        if hello.sid != sid {
            return Err(RelayAcceptError::SidMismatch {
                filename: sid,
                body: hello.sid,
            });
        }
        let peer_epk = X25519PublicKey::from(hello.client_ephemeral_pubkey);
        let shared = relay_secret.0.diffie_hellman(&peer_epk);
        ensure_contributory(&shared).map_err(RelayAcceptError::KeyAgreement)?;
        let (k_c2r, k_r2c) = derive_directional_keys(shared.as_bytes(), &hello.cookie, &sid);
        Ok(Self { sid, k_c2r, k_r2c })
    }
}

/// Error returned by [`SessionKeys::relay_accept`]. Distinguishes
/// "sid in body doesn't match filename" from "X25519 contributory
/// check failed" so logs / metrics can tell apart attacker-side
/// foul play from a legitimate-client crypto error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAcceptError {
    SidMismatch {
        filename: SessionId,
        body: SessionId,
    },
    KeyAgreement(KeyAgreementError),
}

impl fmt::Display for RelayAcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SidMismatch { filename, body } => write!(
                f,
                "hello body sid {body:02x?} does not match filename sid {filename:02x?}"
            ),
            Self::KeyAgreement(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RelayAcceptError {}

fn ensure_contributory(shared: &x25519_dalek::SharedSecret) -> Result<(), KeyAgreementError> {
    if shared.was_contributory() {
        Ok(())
    } else {
        Err(KeyAgreementError::NonContributorySharedSecret)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAgreementError {
    NonContributorySharedSecret,
}

impl fmt::Display for KeyAgreementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonContributorySharedSecret => write!(
                f,
                "X25519 key exchange produced an all-zero/non-contributory shared secret"
            ),
        }
    }
}

impl std::error::Error for KeyAgreementError {}

fn derive_directional_keys(
    shared: &[u8; 32],
    cookie: &[u8; 16],
    sid: &SessionId,
) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(cookie), shared);
    // 4 prefix bytes + 16 sid bytes = 20-byte info each direction.
    let mut info_c2r = [0u8; 20];
    info_c2r[..4].copy_from_slice(b"c2r|");
    info_c2r[4..].copy_from_slice(sid);
    let mut info_r2c = [0u8; 20];
    info_r2c[..4].copy_from_slice(b"r2c|");
    info_r2c[4..].copy_from_slice(sid);

    let mut k_c2r = [0u8; 32];
    hk.expand(&info_c2r, &mut k_c2r)
        .expect("HKDF-Expand of 32 bytes is always within the SHA-256 cap (255 * 32 bytes)");
    let mut k_r2c = [0u8; 32];
    hk.expand(&info_r2c, &mut k_r2c)
        .expect("HKDF-Expand of 32 bytes is always within the SHA-256 cap (255 * 32 bytes)");
    (k_c2r, k_r2c)
}

// --------------------------------------------------------------------
// AEAD seal / open
// --------------------------------------------------------------------

/// Per-direction ChaCha20-Poly1305 instance. Cheap to construct; not
/// shared across directions because the two keys differ. `Clone` is
/// cheap (key schedule is reused under the hood); it's derived so
/// the spawn-detached upload tasks in the c2r / r2c batchers can own
/// their own copy of the cipher without contention.
#[derive(Clone)]
pub struct AeadCipher {
    inner: ChaCha20Poly1305,
}

impl AeadCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            inner: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    /// Seal the wire-encoded frame bytes for upload as a Drive file
    /// body. Nonce + AAD are derived deterministically from
    /// (sid, seq) — same on both ends, both rebuild them from the
    /// filename grammar without any wire overhead.
    pub fn seal(&self, sid: &SessionId, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let nonce = build_nonce(seq);
        let aad = build_aad(sid, seq);
        self.inner
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            // `encrypt` returns `Err` only if the plaintext is too
            // big to address with a 32-bit length (~4 GiB) — never
            // for frames sized below our [`drive_wire::frame::MAX_PAYLOAD`].
            .expect("ChaCha20Poly1305 seal cannot fail for sub-4-GiB plaintext")
    }

    /// Open a sealed body. Tag failure surfaces as `Err(AeadError)`
    /// without distinguishing which AAD/nonce/key piece was wrong —
    /// the standard AEAD opacity rule (revealing why the tag failed
    /// would leak ciphertext bits).
    pub fn open(&self, sid: &SessionId, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = build_nonce(seq);
        let aad = build_aad(sid, seq);
        self.inner
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| AeadError::TagMismatch)
    }
}

/// AEAD open failure. Single variant on purpose — see [`AeadCipher::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    TagMismatch,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TagMismatch => write!(
                f,
                "AEAD tag check failed (key, nonce, AAD, or ciphertext was tampered)"
            ),
        }
    }
}

impl std::error::Error for AeadError {}

/// 12-byte ChaCha20-Poly1305 nonce: `seq.to_le_bytes() || [0u8; 4]`.
/// Little-endian per IETF ChaCha20 (RFC 8439); the trailing zero
/// pad makes the 8-byte seq fit the 12-byte nonce slot with the most
/// significant bytes always zero (we treat seq as a 64-bit counter
/// with the high 32 bits reserved for future use — e.g. a session
/// generation if v2 widens the wire format).
fn build_nonce(seq: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&seq.to_le_bytes());
    Nonce::from(bytes)
}

/// 24-byte AAD: `sid (16) || seq.to_be_bytes() (8)`. Big-endian seq
/// here (vs little-endian in the nonce) is intentional — the AAD's
/// goal is unambiguous binding, NOT byte-for-byte equality with the
/// nonce; using a different encoding documents the role.
fn build_aad(sid: &SessionId, seq: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..16].copy_from_slice(sid);
    aad[16..].copy_from_slice(&seq.to_be_bytes());
    aad
}

// --------------------------------------------------------------------
// Replay window
// --------------------------------------------------------------------

/// Strict-monotonic seq tracker. One per direction per session.
///
/// Drive's `files.list` can surface files out of numeric order (lexicographic
/// listing, pagination, and eventual consistency at batch boundaries), so
/// delivery paths use [`check_next`](Self::check_next) and leave future
/// frames in Drive until the missing earlier sequence appears.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    last_seen: Option<u64>,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { last_seen: None }
    }

    /// Read-only check: returns `Ok` if `seq` strictly exceeds the
    /// highest previously accepted seq, `Err` otherwise. Does NOT
    /// mutate state.
    ///
    /// Pair with [`commit`](Self::commit) on the success path:
    /// callers must `check` *before* the work that can fail
    /// (download / AEAD open / dispatch) and `commit` only *after*
    /// the work has succeeded. Advancing pre-delivery would
    /// permanently lock out the same seq on retry — a transient
    /// download failure would then cause the next poll to
    /// (incorrectly) treat the redelivered file as a replay and
    /// silently drop bytes.
    pub fn check(&self, seq: u64) -> Result<(), ReplayError> {
        match self.last_seen {
            Some(prev) if seq <= prev => Err(ReplayError {
                seq,
                last_accepted: prev,
            }),
            _ => Ok(()),
        }
    }

    /// Strict in-order check: the first accepted frame must be seq 0,
    /// and every later frame must be exactly `last_seen + 1`.
    ///
    /// A future frame is not a replay; callers should leave it in Drive
    /// and retry on a later poll when the missing earlier frame becomes
    /// visible. A replay/duplicate can be discarded.
    pub fn check_next(&self, seq: u64) -> Result<(), StrictSeqError> {
        let expected = match self.last_seen {
            None => 0,
            Some(prev) => match prev.checked_add(1) {
                Some(next) => next,
                None => {
                    return Err(StrictSeqError::Replay(ReplayError {
                        seq,
                        last_accepted: prev,
                    }));
                }
            },
        };
        if seq == expected {
            Ok(())
        } else if seq < expected {
            let last_accepted = expected - 1;
            Err(StrictSeqError::Replay(ReplayError { seq, last_accepted }))
        } else {
            Err(StrictSeqError::Future { seq, expected })
        }
    }

    /// Advance the window to `seq` if it exceeds the current high
    /// water mark. Idempotent — committing a seq <= the current
    /// value is a no-op (so re-entry into the success path after a
    /// concurrent advance doesn't underflow).
    ///
    /// Callers MUST have called [`check`](Self::check) with the same
    /// `seq` earlier in the work unit; per-sid serialisation on the
    /// poll worker guarantees no other commit can race in between.
    pub fn commit(&mut self, seq: u64) {
        self.last_seen = match self.last_seen {
            Some(prev) => Some(prev.max(seq)),
            None => Some(seq),
        };
    }

    /// One-shot check + advance. Equivalent to `check(seq)?` then
    /// `commit(seq)`. Kept for tests and for paths where commit-on-
    /// check is genuinely correct (e.g. inside the same critical
    /// section as the work it gates). NEVER use this on the
    /// poll-worker delivery path — see [`check`](Self::check) for
    /// why pre-delivery advance is unsound.
    pub fn check_and_advance(&mut self, seq: u64) -> Result<(), ReplayError> {
        self.check(seq)?;
        self.commit(seq);
        Ok(())
    }

    /// Last accepted seq, or `None` if no frames have been processed.
    pub fn last_seen(&self) -> Option<u64> {
        self.last_seen
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayError {
    pub seq: u64,
    pub last_accepted: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictSeqError {
    Replay(ReplayError),
    Future { seq: u64, expected: u64 },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "replay rejected: seq {} <= last accepted seq {} (frame is either a duplicate or out-of-order)",
            self.seq, self.last_accepted
        )
    }
}

impl std::error::Error for ReplayError {}

impl fmt::Display for StrictSeqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StrictSeqError::Replay(e) => e.fmt(f),
            StrictSeqError::Future { seq, expected } => write!(
                f,
                "future frame: seq {} arrived before expected seq {}",
                seq, expected
            ),
        }
    }
}

impl std::error::Error for StrictSeqError {}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // `rand::rngs::OsRng` re-exported through the `rand` crate root
    // here for the same reason the production code above does.
    use rand::rngs::OsRng;

    fn fixed_sid() -> SessionId {
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    }

    // ---- Bech32m round-trip + parse rejections ---------------------

    #[test]
    fn relay_pubkey_bech32m_roundtrip() {
        let relay_secret = RelaySecret::generate(OsRng);
        let pk = relay_secret.public_key();
        let encoded = pk.to_bech32m();
        assert!(encoded.starts_with("rgdr1"));
        // 32 bytes ≈ 52 base32-chars; + "rgdr" (4) + "1" + 6 checksum = 63.
        assert_eq!(encoded.len(), 63);
        let decoded = RelayPubkey::from_bech32m(&encoded).expect("roundtrip");
        assert_eq!(decoded.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn relay_pubkey_parse_rejects_empty() {
        assert_eq!(RelayPubkey::from_bech32m(""), Err(PubkeyParseError::Empty));
        assert_eq!(
            RelayPubkey::from_bech32m("   "),
            Err(PubkeyParseError::Empty)
        );
    }

    #[test]
    fn relay_pubkey_parse_rejects_wrong_hrp() {
        // Mint a valid 32-byte payload, encode under the WRONG HRP.
        let bytes = [0x42u8; 32];
        let wrong_hrp = Hrp::parse_unchecked("ln");
        let s = bech32::encode::<Bech32m>(wrong_hrp, &bytes).unwrap();
        let err = RelayPubkey::from_bech32m(&s).unwrap_err();
        assert!(
            matches!(err, PubkeyParseError::WrongHrp { ref got, expected } if got == "ln" && expected == RELAY_PUBKEY_HRP)
        );
    }

    #[test]
    fn relay_pubkey_parse_rejects_wrong_length() {
        // 16 bytes — half a real pubkey — encoded with the right HRP.
        let hrp = Hrp::parse_unchecked(RELAY_PUBKEY_HRP);
        let short_payload = [0u8; 16];
        let s = bech32::encode::<Bech32m>(hrp, &short_payload).unwrap();
        let err = RelayPubkey::from_bech32m(&s).unwrap_err();
        assert!(matches!(
            err,
            PubkeyParseError::WrongLength {
                got: 16,
                expected: 32
            }
        ));
    }

    #[test]
    fn relay_pubkey_parse_rejects_single_char_typo() {
        let secret = RelaySecret::generate(OsRng);
        let pk = secret.public_key();
        let mut s = pk.to_bech32m();
        // Flip a character in the data section (skip the "rgdr1" prefix).
        let pos = 10;
        let c = s.as_bytes()[pos];
        let flipped = if c == b'a' { b'b' } else { b'a' };
        unsafe {
            s.as_bytes_mut()[pos] = flipped;
        }
        let err = RelayPubkey::from_bech32m(&s).unwrap_err();
        assert!(matches!(err, PubkeyParseError::BadEncoding(_)));
    }

    #[test]
    fn relay_pubkey_parse_rejects_legacy_bech32_checksum() {
        let secret = RelaySecret::generate(OsRng);
        let pk = secret.public_key();
        let hrp = Hrp::parse_unchecked(RELAY_PUBKEY_HRP);
        let s = bech32::encode::<bech32::Bech32>(hrp, &pk.to_bytes()).unwrap();

        let err = RelayPubkey::from_bech32m(&s).unwrap_err();
        assert!(matches!(err, PubkeyParseError::BadEncoding(_)));
    }

    #[test]
    fn relay_pubkey_parse_accepts_trimmed_whitespace() {
        let secret = RelaySecret::generate(OsRng);
        let pk = secret.public_key();
        let s = format!("   {}\n", pk.to_bech32m());
        let parsed = RelayPubkey::from_bech32m(&s).expect("whitespace-padded input must parse");
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn relay_pubkey_parse_rejects_low_order_identity() {
        let hrp = Hrp::parse_unchecked(RELAY_PUBKEY_HRP);
        let s = bech32::encode::<Bech32m>(hrp, &[0u8; 32]).unwrap();
        assert_eq!(
            RelayPubkey::from_bech32m(&s),
            Err(PubkeyParseError::LowOrder)
        );
    }

    // ---- Hello body codec ------------------------------------------

    #[test]
    fn hello_body_roundtrip() {
        let body = HelloBody {
            client_ephemeral_pubkey: [0xab; 32],
            cookie: [0xcd; 16],
            sid: [0xef; 16],
        };
        let encoded = body.encode();
        assert_eq!(encoded.len(), HELLO_BODY_LEN);
        let decoded = HelloBody::decode(&encoded).expect("roundtrip");
        assert_eq!(decoded, body);
    }

    #[test]
    fn hello_body_decode_rejects_wrong_length() {
        // 64 is now the valid length; everything else must fail.
        for n in [0usize, 32, 47, 48, 49, 63, 65, 80, 128] {
            let bytes = vec![0u8; n];
            assert!(
                matches!(
                    HelloBody::decode(&bytes),
                    Err(HelloDecodeError::WrongLength { .. })
                ),
                "expected WrongLength for n={n}, got {:?}",
                HelloBody::decode(&bytes)
            );
        }
    }

    // ---- Key agreement: both sides derive the same keys ------------

    #[test]
    fn client_and_relay_derive_matching_session_keys() {
        let relay_secret = RelaySecret::generate(OsRng);
        let relay_pk = relay_secret.public_key();
        let sid = fixed_sid();

        let (client_keys, hello) =
            SessionKeys::client_initiate(&relay_pk, sid, OsRng).expect("client initiate");
        let relay_keys =
            SessionKeys::relay_accept(&relay_secret, sid, &hello).expect("relay accept");

        assert_eq!(client_keys.sid, relay_keys.sid);
        assert_eq!(client_keys.k_c2r, relay_keys.k_c2r);
        assert_eq!(client_keys.k_r2c, relay_keys.k_r2c);
        // The two directional keys MUST differ — if they were equal,
        // a frame's c2r ciphertext could decrypt as r2c, defeating
        // the per-direction nonce-space separation.
        assert_ne!(client_keys.k_c2r, client_keys.k_r2c);
    }

    #[test]
    fn client_rejects_non_contributory_relay_pubkey() {
        let relay_pk = RelayPubkey::from_bytes([0u8; 32]);
        let err = SessionKeys::client_initiate(&relay_pk, fixed_sid(), OsRng).unwrap_err();
        assert_eq!(err, KeyAgreementError::NonContributorySharedSecret);
    }

    #[test]
    fn relay_rejects_non_contributory_client_ephemeral_pubkey() {
        let relay_secret = RelaySecret::generate(OsRng);
        let sid = fixed_sid();
        let hello = HelloBody {
            client_ephemeral_pubkey: [0u8; 32],
            cookie: [0x55; 16],
            sid,
        };
        let err = SessionKeys::relay_accept(&relay_secret, sid, &hello).unwrap_err();
        assert_eq!(
            err,
            RelayAcceptError::KeyAgreement(KeyAgreementError::NonContributorySharedSecret)
        );
    }

    #[test]
    fn relay_rejects_hello_with_sid_mismatch() {
        // Body claims sid_a, filename declares sid_b → reject without
        // even doing the DH. Catches the "attacker uploads a Hello
        // body under the wrong filename to confuse the relay's key
        // derivation" pre-image.
        let relay_secret = RelaySecret::generate(OsRng);
        let relay_pk = relay_secret.public_key();
        let sid_a = [0x11u8; 16];
        let sid_b = [0x22u8; 16];
        let (_client_keys, hello) =
            SessionKeys::client_initiate(&relay_pk, sid_a, OsRng).expect("client initiate");
        // Hand the body to relay_accept with the WRONG filename sid.
        let err = SessionKeys::relay_accept(&relay_secret, sid_b, &hello).unwrap_err();
        match err {
            RelayAcceptError::SidMismatch { filename, body } => {
                assert_eq!(filename, sid_b);
                assert_eq!(body, sid_a);
            }
            other => panic!("expected SidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn different_cookies_produce_different_keys() {
        // Same DH inputs but different cookies must produce different
        // keys — the cookie is the HKDF salt, so this is its job.
        let relay_secret = RelaySecret::generate(OsRng);
        let relay_pk = relay_secret.public_key();
        let sid = fixed_sid();

        // Force two sessions through `client_initiate` and verify
        // they don't collide. With 16 random bytes per cookie, the
        // collision probability is ~2^-128 per draw, so this test
        // effectively pins "cookies are actually randomised".
        let (k1, _) = SessionKeys::client_initiate(&relay_pk, sid, OsRng).expect("session 1");
        let (k2, _) = SessionKeys::client_initiate(&relay_pk, sid, OsRng).expect("session 2");
        assert_ne!(k1.k_c2r, k2.k_c2r);
        assert_ne!(k1.k_r2c, k2.k_r2c);
    }

    #[test]
    fn different_sids_produce_different_keys_same_dh() {
        // Pin the sid binding in HKDF info: two sessions with the
        // same DH agreement + same cookie but different sids must
        // produce different keys.
        let relay_secret = RelaySecret::generate(OsRng);
        let shared = [0x11u8; 32];
        let cookie = [0x22u8; 16];
        let sid_a: SessionId = [0xaa; 16];
        let sid_b: SessionId = [0xbb; 16];

        let (ka_c2r, ka_r2c) = derive_directional_keys(&shared, &cookie, &sid_a);
        let (kb_c2r, kb_r2c) = derive_directional_keys(&shared, &cookie, &sid_b);
        assert_ne!(ka_c2r, kb_c2r);
        assert_ne!(ka_r2c, kb_r2c);
        // Avoid the unused-variable lint when running tests with
        // a future stricter rustc.
        let _ = relay_secret;
    }

    // ---- AEAD seal/open --------------------------------------------

    fn fixed_session() -> (SessionKeys, RelaySecret) {
        let relay_secret = RelaySecret::generate(OsRng);
        let relay_pk = relay_secret.public_key();
        let sid = fixed_sid();
        let (keys, _hello) = SessionKeys::client_initiate(&relay_pk, sid, OsRng).expect("keys");
        (keys, relay_secret)
    }

    #[test]
    fn aead_roundtrip_c2r_and_r2c() {
        let (keys, _) = fixed_session();
        for (dir_name, key) in [("c2r", &keys.k_c2r), ("r2c", &keys.k_r2c)] {
            let cipher = AeadCipher::new(key);
            let plaintext = b"hello world from rahgozar drive";
            let ct = cipher.seal(&keys.sid, 0, plaintext);
            // Ciphertext is plaintext + 16-byte AEAD tag.
            assert_eq!(ct.len(), plaintext.len() + 16, "{dir_name}");
            let pt = cipher
                .open(&keys.sid, 0, &ct)
                .unwrap_or_else(|_| panic!("{dir_name} open"));
            assert_eq!(pt, plaintext, "{dir_name}");
        }
    }

    #[test]
    fn aead_open_rejects_tampered_ciphertext() {
        let (keys, _) = fixed_session();
        let cipher = AeadCipher::new(&keys.k_c2r);
        let mut ct = cipher.seal(&keys.sid, 0, b"payload");
        // Flip a bit in the body (not the tag).
        ct[0] ^= 0x01;
        assert_eq!(cipher.open(&keys.sid, 0, &ct), Err(AeadError::TagMismatch));
    }

    #[test]
    fn aead_open_rejects_wrong_sid_in_aad() {
        let (keys, _) = fixed_session();
        let cipher = AeadCipher::new(&keys.k_c2r);
        let ct = cipher.seal(&keys.sid, 0, b"payload");
        // Same key + same seq, but a different sid in AAD → tag mismatch.
        let other_sid: SessionId = [0xff; 16];
        assert_eq!(cipher.open(&other_sid, 0, &ct), Err(AeadError::TagMismatch));
    }

    #[test]
    fn aead_open_rejects_wrong_seq_in_aad() {
        let (keys, _) = fixed_session();
        let cipher = AeadCipher::new(&keys.k_c2r);
        let ct = cipher.seal(&keys.sid, 7, b"payload");
        // Same key + same sid, but a different seq → both nonce
        // and AAD diverge → tag mismatch.
        assert_eq!(cipher.open(&keys.sid, 8, &ct), Err(AeadError::TagMismatch));
    }

    #[test]
    fn aead_open_rejects_wrong_key() {
        let (keys, _) = fixed_session();
        let send_cipher = AeadCipher::new(&keys.k_c2r);
        let recv_cipher = AeadCipher::new(&keys.k_r2c); // wrong direction
        let ct = send_cipher.seal(&keys.sid, 0, b"payload");
        assert_eq!(
            recv_cipher.open(&keys.sid, 0, &ct),
            Err(AeadError::TagMismatch)
        );
    }

    // ---- Replay window ---------------------------------------------

    #[test]
    fn replay_window_accepts_first_frame_at_any_seq() {
        let mut rw = ReplayWindow::new();
        assert_eq!(rw.check_and_advance(0), Ok(()));
        assert_eq!(rw.last_seen(), Some(0));

        let mut rw2 = ReplayWindow::new();
        assert_eq!(rw2.check_and_advance(1_000_000), Ok(()));
        assert_eq!(rw2.last_seen(), Some(1_000_000));
    }

    #[test]
    fn replay_window_strict_check_requires_first_seq_zero() {
        let rw = ReplayWindow::new();
        assert_eq!(rw.check_next(0), Ok(()));
        assert_eq!(
            rw.check_next(1),
            Err(StrictSeqError::Future {
                seq: 1,
                expected: 0,
            })
        );
    }

    #[test]
    fn replay_window_strict_check_distinguishes_future_from_replay() {
        let mut rw = ReplayWindow::new();
        assert_eq!(rw.check_next(0), Ok(()));
        rw.commit(0);

        assert_eq!(rw.check_next(1), Ok(()));
        assert_eq!(
            rw.check_next(2),
            Err(StrictSeqError::Future {
                seq: 2,
                expected: 1,
            })
        );
        assert_eq!(
            rw.check_next(0),
            Err(StrictSeqError::Replay(ReplayError {
                seq: 0,
                last_accepted: 0,
            }))
        );
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut rw = ReplayWindow::new();
        rw.check_and_advance(5).unwrap();
        assert_eq!(
            rw.check_and_advance(5),
            Err(ReplayError {
                seq: 5,
                last_accepted: 5,
            })
        );
        // State must not advance on a rejected frame.
        assert_eq!(rw.last_seen(), Some(5));
    }

    #[test]
    fn replay_window_rejects_out_of_order() {
        let mut rw = ReplayWindow::new();
        rw.check_and_advance(10).unwrap();
        assert_eq!(
            rw.check_and_advance(3),
            Err(ReplayError {
                seq: 3,
                last_accepted: 10,
            })
        );
        assert_eq!(rw.last_seen(), Some(10));
    }

    #[test]
    fn replay_window_accepts_strict_monotonic_sequence() {
        let mut rw = ReplayWindow::new();
        for seq in 0..50u64 {
            assert_eq!(rw.check_and_advance(seq), Ok(()), "seq={seq}");
        }
        assert_eq!(rw.last_seen(), Some(49));
    }

    // ---- check / commit split (delivery-failure rollback) ----------

    #[test]
    fn check_is_read_only_does_not_advance() {
        // The whole point of the new split: check() must not mutate.
        // Two checks at the same seq without an intervening commit
        // both succeed — that's the safety property the poll-worker
        // delivery path relies on for retry-safe replays.
        let rw = ReplayWindow::new();
        assert_eq!(rw.check(5), Ok(()));
        assert_eq!(
            rw.check(5),
            Ok(()),
            "check must be idempotent + non-mutating"
        );
        assert_eq!(rw.last_seen(), None, "check must not advance state");
    }

    #[test]
    fn check_then_commit_advances_window() {
        // Happy path: check passes, work succeeds, commit advances.
        // A subsequent check at the same seq must now fail (it's
        // been delivered).
        let mut rw = ReplayWindow::new();
        assert_eq!(rw.check(5), Ok(()));
        rw.commit(5);
        assert_eq!(rw.last_seen(), Some(5));
        assert_eq!(
            rw.check(5),
            Err(ReplayError {
                seq: 5,
                last_accepted: 5,
            })
        );
    }

    #[test]
    fn check_without_commit_allows_retry() {
        // The exact scenario the review flagged: check accepts seq=7,
        // download fails before delivery, no commit happens — next
        // poll must accept the same seq=7 again. Without the split,
        // pre-advance would lock it out and silently drop bytes.
        let mut rw = ReplayWindow::new();
        assert_eq!(rw.check(7), Ok(()));
        // Simulated delivery failure: we DON'T call commit.
        // Next attempt:
        assert_eq!(rw.check(7), Ok(()), "redelivery must be allowed");
        rw.commit(7);
        // After delivery completes on the retry, future seqs <= 7
        // are correctly rejected.
        assert_eq!(
            rw.check(7),
            Err(ReplayError {
                seq: 7,
                last_accepted: 7,
            })
        );
    }

    #[test]
    fn commit_takes_max_and_is_idempotent() {
        // commit() is `last_seen = max(last_seen, seq)`: committing a
        // smaller seq after a larger one is a no-op, and committing
        // the same seq twice is harmless. Both properties matter
        // because the poll worker's per-sid serialisation isn't an
        // *absolute* guarantee — a future change might let two
        // workers race here and we don't want it to underflow the
        // window.
        let mut rw = ReplayWindow::new();
        rw.commit(10);
        rw.commit(5); // smaller — must not regress
        assert_eq!(rw.last_seen(), Some(10));
        rw.commit(10); // same — must be no-op
        assert_eq!(rw.last_seen(), Some(10));
        rw.commit(11); // larger — advances
        assert_eq!(rw.last_seen(), Some(11));
    }
}
