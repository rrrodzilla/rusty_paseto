//  #![doc(html_no_source)]
//  #![deny(rustdoc::missing_crate_level_docs)]
//  #![warn(missing_docs)]
//  #![warn(rustdoc::missing_doc_code_examples)]

//! Secure stateless [PASETO: Platform-Agnostic Security Tokens](https://github.com/paseto-standard/paseto-spec)
//!
//! This crate is a type-driven, ergonomic implementation of the [PASETO](https://github.com/paseto-standard/paseto-spec) protocol for secure stateless tokens.
//!
//! > "Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
//! [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)."
//! > -- [PASETO Specification](https://github.com/paseto-standard/paseto-spec)
//!
//!
//! # Usage
//!
//! ```text
//! // in Cargo.toml
//! [dependencies]
//! rusty_paseto = "0.1.14"
//! ```
//!
//! ```
//! // at the top of your source file
//! use rusty_paseto::prelude::*;
//! ```
//! # Examples: Building and parsing tokens
//!
//! Here's a basic, default token:
//! ```
//! use rusty_paseto::prelude::*;
//!
//! // create a key specifying the PASETO version and purpose
//! let key = Key::<V2, Local>::from(b"wubbalubbadubdubwubbalubbadubdub");
//! // use a default token builder with the same PASETO version and purpose
//! let token = PasetoTokenBuilder::<V2, Local>::default().build(&key)?;
//! // token is a String in the form: "v2.local.encoded-payload"
//!
//! // or the key uses the Version and Purpose provided to the builder when used directly:
//! let another_token = PasetoTokenBuilder::<V2, Local>::default()
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```
//!
//! ## A default token
//!
//! * Has no [footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs)
//! * Expires in **1 hour** after creation (due to an included default ExpirationClaim)
//! * Contains an IssuedAtClaim indicating when it was created
//!
//!
//! You can parse and validate an existing token with the following:
//! ```
//! # use rusty_paseto::prelude::*;
//! # let key = Key::<V2, Local>::from(b"wubbalubbadubdubwubbalubbadubdub");
//! # // use a default token builder with the same PASETO version and purpose
//! # let token = PasetoTokenBuilder::<V2, Local>::default().build(&key).unwrap();
//! // now we can parse and validate the token with a parser that returns a serde_json::Value
//! let json_value = PasetoTokenParser::<V2, Local>::default().parse(&token, &key)?;
//!
//! //the ExpirationClaim
//! assert!(json_value["exp"].is_string());
//! //the IssuedAtClaim
//! assert!(json_value["iat"].is_string());
//!
//! # Ok::<(),PasetoTokenParseError>(())
//! ```
//!
//! ## A default parser
//!
//! * Validates the token structure and decryptes/decodes the content as needed
//! * Validates the [footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs) if
//! one was provided
//! * Verifies the token hasn't expired based on the ExpirationClaim if one was provided
//!
//! ## A token with a footer
//!
//! PASETO tokens can have an [optional footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs).  In rusty_paseto we have strict types for most things.  
//! So we can extend the previous example to add a footer to the token by using code like the
//! following:
//! ```rust
//! use rusty_paseto::prelude::*;
//!
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   // note how we set the footer here
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! // token is now a String in the form: "v2.local.encoded-payload.footer"
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```
//! And parse it by passing in the same expected footer
//! ```
//! # use rusty_paseto::prelude::*;
//! # let key = Key::<V2, Local>::from(b"wubbalubbadubdubwubbalubbadubdub");
//! # // use a default token builder with the same PASETO version and purpose
//! # let token = PasetoTokenBuilder::<V2, Local>::default()
//! #   .set_footer(Footer::from("Sometimes science is more art than science"))
//! #   .build(&key).unwrap();
//! // now we can parse and validate the token with a parser that returns a serde_json::Value
//! let json_value = PasetoTokenParser::<V2, Local>::default()
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .parse(&token, &key)?;
//!
//! //the ExpirationClaim
//! assert!(json_value["exp"].is_string());
//! //the IssuedAtClaim
//! assert!(json_value["iat"].is_string());
//!
//! # Ok::<(),PasetoTokenParseError>(())
//! ```
//!
//! ## Setting a different expiration time
//!
//! As mentioned, default tokens expire **1 hour** from creation time.  You can set your own
//! expiration time by adding an ExpirationClaim which takes an ISO 8601 compliant datetime string.
//! #### Note: *claims taking an ISO 8601 string use the TryFrom trait and return a Result<(), GenericTokenBuilderError>*
//! ```rust
//! # use rusty_paseto::prelude::*;
//! # use chrono::{Utc, Duration};
//! // must include
//! use std::convert::TryFrom;
//!
//! // real-world example using the chrono crate to expire 5 minutes from now
//! let in_5_minutes = (Utc::now() + Duration::minutes(5)).to_rfc3339();
//!
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   // note the TryFrom implmentation for ExpirationClaim
//!   //.set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
//!   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! // token is a String in the form: "v2.local.encoded-payload.footer"
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```

//!
//! ## Tokens that never expire
//!
//! A **1 hour** ExpirationClaim is set by default because the use case for non-expiring tokens in the world of security tokens is fairly limited.
//! Omitting an expiration claim or forgetting to require one when processing them
//! is almost certainly an oversight rather than a deliberate choice.  
//!
//! When it is a deliberate choice, you have the opportunity to deliberately remove this claim from the Builder.
//! The method call required to do so ensures readers of the code understand the implicit risk.
//! ```rust
//! # use rusty_paseto::prelude::*;
//! # use chrono::{Utc, Duration};
//! # use std::convert::TryFrom;
//! # let in_5_minutes = (Utc::now() + Duration::minutes(5)).to_rfc3339();
//!
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
//!   // even if you set an expiration claim (as above) it will be ignored
//!   // due to the method call below
//!   .set_no_expiration_danger_acknowledged()
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```
//!
//! ## Setting PASETO Claims
//!
//! The PASETO specification includes [seven reserved claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) which you can set with their explicit types:
//! ```rust
//! # use rusty_paseto::prelude::*;
//! # use chrono::{Utc, Duration};
//! # // must include
//! # use std::convert::TryFrom;
//!
//! # // real-world example using the chrono crate to expire 5 minutes from now
//! # let in_5_minutes = (Utc::now() + Duration::minutes(5)).to_rfc3339();
//! // real-world example using the chrono crate to prevent the token from being used before 2
//! // minutes from now
//! let in_2_minutes = (Utc::now() + Duration::minutes(2)).to_rfc3339();
//!
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   //json payload key: "exp"
//!   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
//!   //json payload key: "iat"
//!   // the IssueAtClaim is automatically set to UTC NOW by default
//!   // but you can override it here
//!   // .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
//!   //json payload key: "nbf"
//!   //don't use this token before two minutes after UTC NOW
//!   .set_claim(NotBeforeClaim::try_from(in_2_minutes)?)
//!   //json payload key: "aud"
//!   .set_claim(AudienceClaim::from("Cromulons"))
//!   //json payload key: "sub"
//!   .set_claim(SubjectClaim::from("Get schwifty"))
//!   //json payload key: "iss"
//!   .set_claim(IssuerClaim::from("Earth Cesium-137"))
//!   //json payload key: "jti"
//!   .set_claim(TokenIdentifierClaim::from("Planet Music - Season 988"))
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```
//!
//! ## Setting your own Custom Claims
//!
//! The CustomClaim struct takes a tuple in the form of `(key: String, value: T)` where T is any
//! serializable type
//! #### Note: *CustomClaims use the TryFrom trait and return a Result<(), GenericTokenBuilderError> if you attempt to use one of the [reserved PASETO keys](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) in your CustomClaim*
//! ```rust
//! # use rusty_paseto::prelude::*;
//! # use chrono::{Utc, Duration};
//! # // must include
//! # use std::convert::TryFrom;
//!
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   .set_claim(CustomClaim::try_from(("Co-star", "Morty Smith"))?)
//!   .set_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```
//! This throws an error:
//! ```should_panic
//! # use rusty_paseto::prelude::*;
//! # use chrono::{Utc, Duration};
//! # // must include
//! # use std::convert::TryFrom;
//! // "exp" is a reserved PASETO claim key, you should use the ExpirationClaim type
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   .set_claim(CustomClaim::try_from(("exp", "Some expiration value"))?)
//!   .build(&Key::from(b"wubbalubbadubdubwubbalubbadubdub"))?;
//!
//! # Ok::<(),GenericTokenBuilderError>(())
//! ```
//! # Validating claims
//! rusty_paseto allows for flexible claim validation at parse time
//!
//! ## Checking claims
//!
//! Let's see how we can check particular claims exist with expected values.
//! ```
//! # use rusty_paseto::prelude::*;
//! # use std::convert::TryFrom;
//!
//! # // create a key specifying the PASETO version and purpose
//! # let key = Key::<V2, Local>::from(b"wubbalubbadubdubwubbalubbadubdub");
//! // use a default token builder with the same PASETO version and purpose
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   .set_claim(SubjectClaim::from("Get schwifty"))
//!   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!   .set_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .build(&key)?;
//!
//! PasetoTokenParser::<V2, Local>::default()
//!   // you can check any claim even custom claims
//!   .check_claim(SubjectClaim::from("Get schwifty"))
//!   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!   .check_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .parse(&token, &key)?;
//!
//! // no need for the assertions below since the check_claim methods
//! // above accomplish the same but at parse time!
//!
//! //assert_eq!(json_value["sub"], "Get schwifty");
//! //assert_eq!(json_value["Contestant"], "Earth");
//! //assert_eq!(json_value["Universe"], 137);
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! # Custom validation
//!
//! What if we have more complex validation requirements? You can pass in a reference to a closure which receives
//! the key and value of the claim you want to validate so you can implement any validation logic
//! you choose.  
//!
//! Let's see how we can validate our tokens only contain universes with prime numbers:
//! ```
//! # use rusty_paseto::prelude::*;
//! # use std::convert::TryFrom;
//!
//! # // create a key specifying the PASETO version and purpose
//! # let key = Key::<V2, Local>::from(b"wubbalubbadubdubwubbalubbadubdub");
//! // use a default token builder with the same PASETO version and purpose
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   .set_claim(SubjectClaim::from("Get schwifty"))
//!   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!   .set_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .build(&key)?;
//!
//! PasetoTokenParser::<V2, Local>::default()
//!   .check_claim(SubjectClaim::from("Get schwifty"))
//!   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!    .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
//!      //let's get the value
//!      let universe = value
//!        .as_u64()
//!        .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;
//!      // we only accept prime universes in this app
//!      if primes::is_prime(universe) {
//!        Ok(())
//!      } else {
//!        Err(PasetoTokenParseError::InvalidClaim(key.to_string()))
//!      }
//!    })
//!   .parse(&token, &key)?;
//!
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! This token will fail to parse with the validation code above:
//! ```should_panic
//! # use rusty_paseto::prelude::*;
//! # use std::convert::TryFrom;
//!
//! # // create a key specifying the PASETO version and purpose
//! # let key = Key::<V2, Local>::from(b"wubbalubbadubdubwubbalubbadubdub");
//! // 136 is not a prime number
//! let token = PasetoTokenBuilder::<V2, Local>::default()
//!   .set_claim(CustomClaim::try_from(("Universe", 136))?)
//!   .build(&key)?;
//!
//!# let json_value = PasetoTokenParser::<V2, Local>::default()
//!#  // you can check any claim even custom claims
//!#   .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
//!#     //let's get the value
//!#     let universe = value
//!#       .as_u64()
//!#       .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;
//!#     // we only accept prime universes in this token
//!#     if primes::is_prime(universe) {
//!#       Ok(())
//!#     } else {
//!#       Err(PasetoTokenParseError::InvalidClaim(key.to_string()))
//!#     }
//!#   })
//!
//!#  .parse(&token, &key)?;
//!
//! # assert_eq!(json_value["Universe"], 136);
//! # Ok::<(),anyhow::Error>(())
//! ```
extern crate ed25519_dalek;
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

pub mod core_tokens {
  pub use crate::common::{Footer, Payload};
  pub use crate::common::{Local, V2};
  pub use crate::decrypted_tokens::GenericTokenDecrypted;
  pub use crate::errors::HeaderParseError;
  pub use crate::keys::{HexKey, Key, Key256Bit};
  pub use crate::tokens::GenericToken;
}

pub mod generic_builders {
  pub use crate::builders::GenericTokenBuilder;
  pub use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  pub use crate::common::{Local, V2};
  pub use crate::parsers::GenericTokenParser;

  pub use crate::errors::{GenericTokenBuilderError, PasetoTokenParseError};
}
pub mod prelude {
  pub use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  pub use crate::common::Footer;
  pub use crate::common::{Local, V2};
  pub use crate::errors::{GenericTokenBuilderError, PasetoTokenParseError};
  pub use crate::keys::{HexKey, Key, Key256Bit};
  pub use crate::paseto_builder::PasetoTokenBuilder;
  pub use crate::paseto_parser::PasetoTokenParser;
}
