//! This crate is a Rust port of Paragonie Security's [PASETO] protocol for creating
//! Platform-Agnostic Security Tokens.  The crate currently supports v2 local token creation and
//! decryption with additional versions and purposes to come.
//!
//! [PASETO]: https://github.com/paseto-standard/paseto-spec

#![doc(html_no_source)]
#![warn(rustdoc::missing_crate_level_docs)]

extern crate erased_serde;

//all the various types
mod builders;
mod claims;
mod common;
mod crypto;
mod decrypted_tokens;
mod errors;
mod headers;
mod keys;
mod parsers;
mod tokens;
mod traits;
mod untrusted_tokens;

pub mod v2 {
  pub use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  pub use crate::common::{Footer, Payload, PurposeLocal, Version2};
  pub use crate::errors::{PasetoTokenParseError, TokenBuilderError};
  pub use crate::keys::{HexKey, Key, Key256Bit};
  pub mod local {
    pub use crate::builders::TokenBuilder;
    pub use crate::decrypted_tokens::DecryptedToken;
    pub use crate::parsers::GenericTokenParser;
    pub use crate::tokens::Token;
  }
}
