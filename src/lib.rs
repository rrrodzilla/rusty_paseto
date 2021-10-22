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
mod paseto_builder;
mod paseto_parser;
mod tokens;
mod traits;
mod untrusted_tokens;

pub mod protocols {

  pub use crate::common::{PurposeLocal, Version2};
}
pub mod generic_tokens {
  pub use crate::common::{Footer, Payload};
  pub use crate::decrypted_tokens::GenericTokenDecrypted;
  pub use crate::keys::{HexKey, Key, Key256Bit};
  pub use crate::tokens::GenericToken;
}

pub mod generic_builders {
  pub use crate::builders::GenericTokenBuilder;
  pub use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  pub use crate::parsers::GenericTokenParser;

  pub use crate::errors::{GenericTokenBuilderError, PasetoTokenParseError};
}
pub mod prelude {
  pub use crate::paseto_builder::PasetoTokenBuilder;
  pub use crate::paseto_parser::PasetoTokenParser;
}
