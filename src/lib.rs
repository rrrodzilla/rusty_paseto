//! # rusty_paseto
//!
//! A type-driven, ergonomic implementation of the [PASETO](https://github.com/paseto-standard/paseto-spec) protocol for secure stateless tokens.
//!
//! ### PASETO: Platform-Agnostic Security Tokens
//!
//! Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
//! [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).
//!
//! ## Installation
//!
//! Add `rusty_paseto = "0.1.14"` to your Cargo.toml
//!
//! ## Getting Started
//!
//! Here's the most basic token you can create:
//! ```rust
//! use rusty_paseto::prelude::*;
//!
//! // create a key specifying the PASETO version and purpose
//! let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");
//! // use a default token builder
//! let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default().build(&key)?;
//! # Ok::<(),GenericTokenBuilderError>(())
//!   ```
//! The token variable will contain a PASETO tokenized string resembling something similar to the following:
//! "v2.local.97TTOvgwIxNGd9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ"
//!
//! ### A few key properties about default tokens
//!
//! * It contains a claim to expire the token in 24 hours
//! * It contains a claim indicating when it was created

#![doc(html_no_source)]
#![deny(rustdoc::missing_crate_level_docs)]

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

pub mod generic_tokens {
  pub use crate::common::{Footer, Payload};
  pub use crate::common::{PurposeLocal, Version2};
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
  pub use crate::common::{PurposeLocal, Version2};
  pub use crate::parsers::GenericTokenParser;

  pub use crate::errors::{GenericTokenBuilderError, PasetoTokenParseError};
}
pub mod prelude {
  pub use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  pub use crate::common::Footer;
  pub use crate::common::{PurposeLocal, Version2};
  pub use crate::errors::{GenericTokenBuilderError, PasetoTokenParseError};
  pub use crate::keys::{HexKey, Key, Key256Bit};
  pub use crate::paseto_builder::PasetoTokenBuilder;
  pub use crate::paseto_parser::PasetoTokenParser;
}
