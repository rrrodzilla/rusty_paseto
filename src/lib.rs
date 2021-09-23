//! This crate is a Rust port of Paragonie Security's [PASETO] protocol for creating
//! Platform-Agnostic Security Tokens.  The crate currently supports v2 local token creation and
//! decryption with additional versions and purposes to come.
//!
//! [PASETO]: https://github.com/paseto-standard/paseto-spec

#![doc(html_no_source)]
#![warn(missing_crate_level_docs)]

//all the various types
mod common;
mod crypto;
mod decrypted_tokens;
mod errors;
mod headers;
mod keys;
mod tokens;
mod traits;
mod untrusted_tokens;

pub mod v2 {
  pub use crate::common::{Footer, Payload};
  pub use crate::errors::PasetoTokenParseError;
  pub use crate::keys::{HexKey, Key256Bit};
  pub mod local {
    pub use crate::decrypted_tokens::V2LocalDecryptedToken;
    pub use crate::keys::V2LocalSharedKey;
    pub use crate::tokens::v2::V2LocalToken;
  }
}
