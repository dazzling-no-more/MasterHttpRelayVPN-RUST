//! Wire format types for the Drive-mailbox transport.
//!
//! Two layers live here:
//!   - [`frame`]    — binary-packed `WireFrame` (the encrypted payload
//!                    body uploaded to / downloaded from Drive).
//!   - [`filename`] — direction-prefixed Drive filename grammar
//!                    (`h_<sid>_0`, `c2r_<sid>_<seq>`, `r2c_<sid>_<seq>`).
//!
//! Path-depended by both the rahgozar client (`src/drive_client.rs`)
//! and the `rahgozar-drive-relay` binary so the two cannot drift.

#![forbid(unsafe_code)]

pub mod filename;
pub mod frame;
