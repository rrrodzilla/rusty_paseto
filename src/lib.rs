//#![deny(missing_docs)]
//  #![doc(html_no_source)]
//  #![deny(rustdoc::missing_crate_level_docs)]
//  #![warn(missing_docs)]
#![forbid(unsafe_code)]
//  #![warn(rustdoc::missing_doc_code_examples)]
#![doc(html_logo_url = "https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoCoreArchitecture.png")]

//! Secure stateless [PASETO: Platform-Agnostic Security Tokens](https://github.com/paseto-standard/paseto-spec)
//!
//! This crate is a type-driven, ergonomic implementation of the [PASETO](https://github.com/paseto-standard/paseto-spec) protocol for secure stateless tokens.
//!
//! > "Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
//!> [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)."
//! > -- [PASETO Specification](https://github.com/paseto-standard/paseto-spec)
//!
//!
//! # Usage
//!rusty_paseto is meant to be flexible and configurable for your specific use case.  Whether you want to get started quickly with sensible defaults, create your own version of rusty_paseto in order to customize your own defaults and functionality or just want to use the core PASETO crypto features, the crate is heavily feature gated to allow for your needs.  

//! ## Architecture

//! The rusty_paseto crate architecture is composed of three layers (batteries_included, generic and core) which can be further refined by the PASETO version(s) and purpose(s) required for your needs.  All layers use a common crypto core which includes various cipher crates depending on the version and purpose you choose.  The crate is heavily featured gated to allow you to use only the versions and purposes you need for your app which minimizes download compile times for using rusty_paseto.  A description of each architectural layer, their uses and limitations and how to minimize your required dependencies based on your required PASETO version and purpose follows:
//!
//!
//! <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoPreludeArchitecture.png" width="150" />  <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoGenericArchitecture.png" width="150" /> <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoCoreArchitecture.png" width="150" />

//!
//! batteries_included  --> generic --> core
//!
//! ### default
//! The default feature is the quickest way to get started using rusty_paseto.
//!
//!
//! <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoPreludeArchitecture.png" width="150" />

//!
//! The default feature includes the outermost architectural layer called batteries_included (described below) as well as the two latest PASETO versions (V3 - NIST MODERN, V4 - SODIUM MODERN) and the Public (Asymmetric) and Local (Symmetric) purposed key types for each of these versions.  That should be four specific version and purpose combinations however at the time of this writing I have yet to implement the V3 - Public combination, so there are 3 in the default feature.  Additionally, this feature includes JWT style claims and business rules for your PASETO token (default, but customizable expiration, issued at, not-before times, etc as described in the usage documentation and examples further below).
//!
//! ```toml
//! ## Includes V3 (local) and V4 (local, public) versions, purposes and ciphers.
//!
//! rusty_paseto = "latest"
//! ```
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! // at the top of your source file
//! use rusty_paseto::prelude::*;
//! # }
//! ```
//!
//! ### batteries_included
//!
//! The outermost architectural layer is called batteries_included.  This is what most people will need.  This feature includes JWT style claims and business rules for your PASETO token (default, but customizable expiration, issued at, not-before times, etc as described in the usage documentation and examples below).
//!
//! <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoBatteriesIncludedArchitecture.png" width="150" />
//!
//! You must specify a version and purpose with this feature in order to reduce the size of your dependencies like in the following Cargo.toml entry which only includes the V4 - Local types with batteries_included functionality:
//!
//! ```toml
//! ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
//! ## key types with all claims and default business rules.
//!
//! rusty_paseto = {version = "latest", features = ["batteries_included", "v4_local"] }
//! ```
//! <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoV4LocalArchitecture.png" width="150" />
//!
//! #### Feature gates
//! Valid version/purpose feature combinations are as follows:
//! - "v1_local" (NIST Original Symmetric Encryption)
//! - "v2_local" (Sodium Original Symmetric Encryption)
//! - "v3_local" (NIST Modern Symmetric Encryption)
//! - "v4_local" (Sodium Modern Symmetric Encryption)
//! - "v1_public" (NIST Original Asymmetric Authentication)
//! - "v2_public" (Sodium Original Asymmetric Authentication)
//! - "v3_public" (NIST Modern Asymmetric Authentication)
//! - "v4_public" (Sodium Modern Asymmetric Authentication)
//!
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! // at the top of your source file
//! use rusty_paseto::prelude::*;
//! # }
//! ```
//! ### generic
//!
//! The generic architectural and feature layer allows you to create your own custom version of the batteries_included layer by following the same pattern I've used in the source code to create your own custom builder and parser.  This is probably not what you need as it is for advanced usage.  The feature includes a generic builder and parser along with claims for you to extend.
//!
//! <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoGenericArchitecture.png" width="150" />
//!
//! It includes all the PASETO and custom claims but allows you to create different default claims in your custom builder and parser or use a different time crate or make up your own default business rules.  As with the batteries_included layer, parsed tokens get returned as a serder_json Value. Again, specify the version and purpose to include in the crypto core:
//!
//!
//! ```toml
//! ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
//! ## key types with all claims and default business rules.
//!
//! rusty_paseto = {version = "latest", features = ["generic", "v4_local"] }
//! ```
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! // at the top of your source file
//! use rusty_paseto::generic::*;
//! # }
//! ```
//! ### core
//!
//! The core architectural layer is the most basic PASETO implementation as it accepts a Payload, optional Footer and (if v3 or v4) an optional Implicit Assertion along with the appropriate key to encrypt/sign and decrypt/verify basic strings.  
//!
//! <img src="https://github.com/rrrodzilla/rusty_paseto/raw/main/assets/RustyPasetoCoreArchitecture.png" width="150" />
//!
//! There are no default claims or included claim structures, business rules or anything other than basic PASETO crypto functions.  Serde crates are not included in this feature so it is extremely lightweight.  You can use this when you don't need JWT-esque functionality but still want to leverage the safe cipher combinations and algorithm lucidity afforded by the PASETO specification.
//!
//! ```toml
//! ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
//! ## key types with NO claims, defaults or validation, just basic PASETO
//! ## encrypt/signing and decrypt/verification.
//!
//! rusty_paseto = {version = "latest", features = ["core", "v4_local"] }
//! ```
//!
//!
//! ```
//! // at the top of your source file
//! use rusty_paseto::core::*;
//! ```
//! # Examples
//!
//! ## Building and parsing tokens with batteries_included
//!
//! Here's a basic, default token:
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! use rusty_paseto::prelude::*;
//!
//! // create a key specifying the PASETO version and purpose
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! // use a default token builder with the same PASETO version and purpose
//! let token = PasetoBuilder::<V4, Local>::default().build(&key)?;
//! // token is a String in the form: "v4.local.encoded-payload"
//!
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! ## A default token
//!
//! * Has no [footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs)
//! * Has no [implicit assertion](https://github.com/paseto-standard/paseto-spec/tree/master/docs)
//! for V3 or V4 versioned tokens
//! * Expires in **1 hour** after creation (due to an included default ExpirationClaim)
//! * Contains an IssuedAtClaim defaulting to the current utc time the token was created
//! * Contains a NotBeforeClaim defaulting to the current utc time the token was created
//!
//!
//! You can parse and validate an existing token with the following:
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! # // use a default token builder with the same PASETO version and purpose
//! # let token = PasetoBuilder::<V4, Local>::default().build(&key)?;
//! // now we can parse and validate the token with a parser that returns a serde_json::Value
//! let json_value = PasetoParser::<V4, Local>::default().parse(&token, &key)?;
//!
//! //the ExpirationClaim
//! assert!(json_value["exp"].is_string());
//! //the IssuedAtClaim
//! assert!(json_value["iat"].is_string());
//!
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! ## A default parser
//!
//! * Validates the token structure and decryptes the payload or verifies the signature of the content
//! * Validates the [footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs) if
//! one was provided
//! * Validates the [implicit assertion](https://github.com/paseto-standard/paseto-spec/tree/master/docs) if one was provided (for V3 or V4 versioned tokens only)
//!
//! ## A token with a footer
//!
//! PASETO tokens can have an [optional footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs).  In rusty_paseto we have strict types for most things.  
//! So we can extend the previous example to add a footer to the token by using code like the
//! following:
//! ```rust
//! # #[cfg(feature = "default")]
//! # {
//! use rusty_paseto::prelude::*;
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! let token = PasetoBuilder::<V4, Local>::default()
//!   // note how we set the footer here
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .build(&key)?;
//!
//! // token is now a String in the form: "v4.local.encoded-payload.footer"
//! # }
//!
//! # Ok::<(),anyhow::Error>(())
//! ```
//! And parse it by passing in the same expected footer
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! # // use a default token builder with the same PASETO version and purpose
//! # let token = PasetoBuilder::<V4, Local>::default()
//! #   .set_footer(Footer::from("Sometimes science is more art than science"))
//! #   .build(&key)?;
//! // now we can parse and validate the token with a parser that returns a serde_json::Value
//! let json_value = PasetoParser::<V4, Local>::default()
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .parse(&token, &key)?;
//!
//! //the ExpirationClaim
//! assert!(json_value["exp"].is_string());
//! //the IssuedAtClaim
//! assert!(json_value["iat"].is_string());
//! # }
//!
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//!
//! ## A token with an implicit assertion (V3 or V4 versioned tokens only)
//!
//! Version 3 (V3) and Version 4 (V4) PASETO tokens can have an [optional implicit assertion](https://github.com/paseto-standard/paseto-spec/tree/master/docs).
//! So we can extend the previous example to add an implicit assertion to the token by using code like the
//! following:
//! ```rust
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   // note how we set the implicit assertion here
//!   .set_implicit_assertion(ImplicitAssertion::from("There’s a lesson here, and I’m not going to be the one to figure it out."))
//!   .build(&key)?;
//!
//! // token is now a String in the form: "v4.local.encoded-payload.footer"
//! # }
//!
//! # Ok::<(),anyhow::Error>(())
//! ```
//! And parse it by passing in the same expected implicit assertion
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! # let token = PasetoBuilder::<V4, Local>::default()
//! #   .set_footer(Footer::from("Sometimes science is more art than science"))
//! #   .set_implicit_assertion(ImplicitAssertion::from("There’s a lesson here, and I’m not going to be the one to figure it out."))
//! #   .build(&key)?;
//! // now we can parse and validate the token with a parser that returns a serde_json::Value
//! let json_value = PasetoParser::<V4, Local>::default()
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .set_implicit_assertion(ImplicitAssertion::from("There’s a lesson here, and I’m not going to be the one to figure it out."))
//!   .parse(&token, &key)?;
//!
//! # //the ExpirationClaim
//! # assert!(json_value["exp"].is_string());
//! # //the IssuedAtClaim
//! # assert!(json_value["iat"].is_string());
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! ## Setting a different expiration time
//!
//! As mentioned, default tokens expire **1 hour** from creation time.  You can set your own
//! expiration time by adding an ExpirationClaim which takes an ISO 8601 compliant datetime string.
//! #### Note: *claims taking an ISO 8601 string use the TryFrom trait and return a Result<(),PasetoClaimError>*
//! ```rust
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! // must include
//! use std::convert::TryFrom;
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! // real-world example using the time crate to expire 5 minutes from now
//! # use time::format_description::well_known::Rfc3339;
//! # let in_5_minutes = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).format(&Rfc3339)?;
//!
//! let token = PasetoBuilder::<V4, Local>::default()
//!   // note the TryFrom implmentation for ExpirationClaim
//!   //.set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
//!   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
//!   .set_footer(Footer::from("Sometimes science is more art than science"))
//!   .build(&key)?;
//!
//! // token is a String in the form: "v4.local.encoded-payload.footer"
//! # }
//! # Ok::<(),anyhow::Error>(())
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
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! # use time::format_description::well_known::Rfc3339;
//! # use std::convert::TryFrom;
//! # let in_5_minutes = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).format(&Rfc3339)?;
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
//!   // even if you set an expiration claim (as above) it will be ignored
//!   // due to the method call below
//!   .set_no_expiration_danger_acknowledged()
//!   .build(&key)?;
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! ## Setting PASETO Claims
//!
//! The PASETO specification includes [seven reserved claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) which you can set with their explicit types:
//! ```rust
//! # #[cfg(all(test,feature = "v4_local"))]
//! # {
//! # use rusty_paseto::prelude::*;
//! # use time::format_description::well_known::Rfc3339;
//! # // must include
//! # use std::convert::TryFrom;
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! # // real-world example using the time crate to expire 5 minutes from now
//! # let in_5_minutes = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).format(&Rfc3339)?;
//! // real-world example using the time crate to prevent the token from being used before 2
//! // minutes from now
//! let in_2_minutes = (time::OffsetDateTime::now_utc() + time::Duration::minutes(2)).format(&Rfc3339)?;
//!
//! let token = PasetoBuilder::<V4, Local>::default()
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
//!   .build(&key)?;
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! ## Setting your own Custom Claims
//!
//! The CustomClaim struct takes a tuple in the form of `(key: String, value: T)` where T is any
//! serializable type
//! #### Note: *CustomClaims use the TryFrom trait and return a Result<(), PasetoClaimError> if you attempt to use one of the [reserved PASETO keys](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) in your CustomClaim*
//!
//! ```rust
//! # #[cfg(all(test, feature = "v4_local"))]
//! # {
//! # use rusty_paseto::prelude::*;
//! # use rusty_paseto::core::{V4,Local, Key};
//! # use rusty_paseto::generic::GenericBuilderError;
//! # // must include
//! # use std::convert::TryFrom;
//! # use rusty_paseto::core::PasetoSymmetricKey;
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_claim(CustomClaim::try_from(("Co-star", "Morty Smith"))?)
//!   .set_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .build(&key)?;
//! # Ok::<(),rusty_paseto::generic::GenericBuilderError>(())
//! # }
//! ```
//!
//! This throws an error:
//! ```no_compile
//! # #[cfg(feature = "v4_local")]
//! # {
//! # use rusty_paseto::prelude::*;
//! # // must include
//! # use std::convert::TryFrom;
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! // "exp" is a reserved PASETO claim key, you should use the ExpirationClaim type
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_claim(CustomClaim::try_from(("exp", "Some expiration value"))?)
//!   .build(&key)?;
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//! # Validating claims
//! rusty_paseto allows for flexible claim validation at parse time
//!
//! ## Checking claims
//!
//! Let's see how we can check particular claims exist with expected values.
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! # use std::convert::TryFrom;
//!
//! # // create a key specifying the PASETO version and purpose
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! // use a default token builder with the same PASETO version and purpose
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_claim(SubjectClaim::from("Get schwifty"))
//!   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!   .set_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .build(&key)?;
//!
//! PasetoParser::<V4, Local>::default()
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
//! # }
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
//!
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! # use rusty_paseto::prelude::*;
//! # use std::convert::TryFrom;
//!
//! # // create a key specifying the PASETO version and purpose
//! # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! // use a default token builder with the same PASETO version and purpose
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_claim(SubjectClaim::from("Get schwifty"))
//!   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!   .set_claim(CustomClaim::try_from(("Universe", 137))?)
//!   .build(&key)?;
//!
//! PasetoParser::<V4, Local>::default()
//!   .check_claim(SubjectClaim::from("Get schwifty"))
//!   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
//!    .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
//!      //let's get the value
//!      let universe = value
//!        .as_u64()
//!        .ok_or(PasetoClaimError::Unexpected(key.to_string()))?;
//!      // we only accept prime universes in this app
//!      if primes::is_prime(universe) {
//!        Ok(())
//!      } else {
//!        Err(PasetoClaimError::CustomValidation(key.to_string()))
//!      }
//!    })
//!   .parse(&token, &key)?;
//! # }
//! # Ok::<(),anyhow::Error>(())
//! ```
//!
//! This token will fail to parse with the validation code above:
//!
//! ```no_compile
//! # #[cfg(feature = "v4_local")]
//! # {
//! use rusty_paseto::prelude::*;
//! use std::convert::TryFrom;
//!
//! // create a key specifying the PASETO version and purpose
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
//! // 136 is not a prime number
//! let token = PasetoBuilder::<V4, Local>::default()
//!   .set_claim(CustomClaim::try_from(("Universe", 136))?)
//!   .build(&key)?;
//!
//! let json_value = PasetoParser::<V4, Local>::default()
//!  // you can check any claim even custom claims
//!   .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
//!     // let's get the value
//!     let universe = value
//!       .as_u64()
//!       .ok_or(PasetoClaimError::Unexpected(key.to_string()))?;
//!     // we only accept prime universes in this token
//!     if primes::is_prime(universe) {
//!       Ok(())
//!     } else {
//!       Err(PasetoClaimError::CustomValidation(key.to_string()))
//!     }
//!   })
//!  .parse(&token, &key)?;
//!
//! assert_eq!(json_value["Universe"], 136);
//! # Ok::<(),anyhow::Error>(())
//! # }
//! ```
//!
//! # Acknowledgments
//!
//! If the API of this crate doesn't suit your tastes, check out the other PASETO implementations
//! in the Rust ecosystem which inspired rusty_paseto:
//!
//! - [paseto](https://crates.io/crates/paseto) - by [Cynthia Coan](https://crates.io/users/Mythra)
//! - [pasetors](https://crates.io/crates/pasetors) - by [Johannes](https://crates.io/users/brycx)
//!
//!

// Compile-time checks for incompatible feature combinations
// Multiple public features cause conflicting trait implementations for PasetoError
#[cfg(all(feature = "v3_public", any(feature = "v1_public", feature = "v2_public", feature = "v4_public")))]
compile_error!(
    "Cannot enable v3_public with other public features due to conflicting trait implementations. \n\
     Choose only ONE public feature: v1_public, v2_public, v3_public, or v4_public. \n\
     The PASETO specification recommends using a single version throughout your application. \n\
     See: https://github.com/rrrodzilla/rusty_paseto/issues/48"
);

#[cfg(all(feature = "v1_public", any(feature = "v2_public", feature = "v4_public")))]
compile_error!(
    "Cannot enable multiple public features (v1_public with v2_public or v4_public) due to conflicting trait implementations. \n\
     Choose only ONE public feature: v1_public, v2_public, v3_public, or v4_public. \n\
     The PASETO specification recommends using a single version throughout your application. \n\
     See: https://github.com/rrrodzilla/rusty_paseto/issues/48"
);

#[cfg(all(feature = "v2_public", feature = "v4_public"))]
compile_error!(
    "Cannot enable both v2_public and v4_public due to conflicting trait implementations. \n\
     Choose only ONE public feature: v1_public, v2_public, v3_public, or v4_public. \n\
     The PASETO specification recommends using a single version throughout your application. \n\
     See: https://github.com/rrrodzilla/rusty_paseto/issues/48"
);

//public interface
#[cfg(feature = "core")]
pub mod core;
#[cfg(feature = "generic")]
pub mod generic;
#[cfg(feature = "batteries_included")]
pub mod prelude;
