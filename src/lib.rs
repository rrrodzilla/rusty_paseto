//! This crate is a Rust port of Paragonie Security's [PASETO] protocol for creating
//! Platform-Agnostic Security Tokens.  The crate currently supports v2 local token creation and
//! decryption with additional versions and purposes to come.
//!
//! [PASETO]: https://github.com/paseto-standard/paseto-spec

#![doc(html_no_source)]
#![warn(missing_crate_level_docs)]
mod crypto;
mod keys;
mod v2;

pub use keys::{HexKey, Key192Bit, Key256Bit, V2LocalSharedKey};
pub use v2::{Footer, Payload, V2LocalDecryptedString, V2LocalToken, V2LocalTokenParseError};
