//! This crate is a Rust port of Paragonie Security's [PASETO] protocol for creating
//! Platform-Agnostic Security Tokens.  The crate currently supports v2 local token creation and
//! decryption with additional versions and purposes to come.
//!
//! [PASETO]: https://github.com/paseto-standard/paseto-spec

mod crypto;
mod keys;
mod v2;

pub use keys::{HexKey, Key192Bit, Key256Bit, V2SymmetricKey};
pub use v2::{Footer, Payload, V2LocalToken, V2LocalTokenDecrypted, V2LocalTokenParseError};
