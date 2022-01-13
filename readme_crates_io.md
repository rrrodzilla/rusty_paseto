# rusty_paseto

A type-driven, ergonomic implementation of the [PASETO](https://github.com/paseto-standard/paseto-spec) protocol for secure stateless tokens.

### PASETO: Platform-Agnostic Security Tokens

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

![unit tests](https://github.com/rrrodzilla/rusty_paseto/actions/workflows/rust.yml/badge.svg)
![GitHub](https://img.shields.io/github/license/rrrodzilla/rusty_paseto?label=License)

## Roadmap and Current Feature Status

| APIs, Tests & Documentation | v1.<br />local| v1.<br />public | v2.<br />local | v2.<br />public |v3.<br />local | v3.<br />public | v4.<br />local | v4.<br />public |
| ------------: | :-----------: | :----------:    |:-----------:   |:-----------:    |:-----------:  |:-----------:    |:-----------:   |:-----------:    |
| PASETO Token Builder		| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| PASETO Token Parser		| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| Flexible Claim Validation	| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| Generic Token Builder		| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| Generic Token Parser		| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| Encryption/Signing		| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| Decryption/Verification	| - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| [PASETO Test vectors](https://github.com/paseto-standard/test-vectors)  | - [x] | - [x] | - [x] | - [x] | - [x] | - [ ] | - [x] | - [x] |
| Documentation			| - [ ] | - [ ] | - [ ] | - [ ] | - [ ] | - [ ] | - [ ] | - [ ] |

| Feature 			| Status | 
| ------------: 		| :-----------: |   
| Feature gates			| - [x] |
| PASERK support		| - [ ] |


 # Usage
rusty_paseto is meant to be flexible and configurable for your specific use case.  Whether you want to get started quickly with sensible defaults, create your own version of rusty_paseto in order to customize your own defaults and functionality or just want to use the core PASETO crypto features, the crate is heavily feature gated to allow for your needs.  

 ## Architecture

 The rusty_paseto crate architecture is composed of three layers (batteries_included, generic and core) which can be further refined by the PASETO version(s) and purpose(s) required for your needs.  All layers use a common crypto core which includes various cipher crates depending on the version and purpose you choose.  The crate is heavily featured gated to allow you to use only the versions and purposes you need for your app which minimizes download compile times for using rusty_paseto.  A description of each architectural layer, their uses and limitations and how to minimize your required dependencies based on your required PASETO version and purpose follows:

 ![paseto_batteries_included_small](https://user-images.githubusercontent.com/24578097/147881895-36878b22-bf17-49e4-98d7-f94920353368.png)  ![paseto_generic_small](https://user-images.githubusercontent.com/24578097/147881907-a765ede6-c8e5-44ff-9845-db53f0634f07.png)  ![paseto_core_small](https://user-images.githubusercontent.com/24578097/147881920-14c52256-1a0c-40be-9f18-759a8c9ad77d.png)

 batteries_included  --> generic --> core

 ### default
 The default feature is the quickest way to get started using rusty_paseto.

 ![paseto_default_small](https://user-images.githubusercontent.com/24578097/147882602-0a88c55e-3ba9-4545-ba99-867406ac9c76.png)

 The default feature includes the outermost architectural layer called batteries_included (described below) as well as the two latest PASETO versions (V3 - NIST MODERN, V4 - SODIUM MODERN) and the Public (Asymmetric) and Local (Symmetric) purposed key types for each of these versions.  That should be four specific version and purpose combinations however at the time of this writing I have yet to implement the V3 - Public combination, so there are 3 in the default feature.  Additionally, this feature includes JWT style claims and business rules for your PASETO token (default, but customizable expiration, issued at, not-before times, etc as described in the usage documentation and examples further below).

 ```toml
 ## Includes V3 (local) and V4 (local, public) versions, purposes and ciphers.

 rusty_paseto = "latest"
 ```
 ```
 // at the top of your source file
 use rusty_paseto::prelude::*;
 ```

 ### batteries_included

 The outermost architectural layer is called batteries_included.  This is what most people will need.  This feature includes JWT style claims and business rules for your PASETO token (default, but customizable expiration, issued at, not-before times, etc as described in the usage documentation and examples below).

 ![paseto_batteries_included_small](https://user-images.githubusercontent.com/24578097/147881895-36878b22-bf17-49e4-98d7-f94920353368.png)

 You must specify a version and purpose with this feature in order to reduce the size of your dependencies like in the following Cargo.toml entry which only includes the V4 - Local types with batteries_included functionality:

 ```toml
 ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
 ## key types with all claims and default business rules.

 rusty_paseto = {version = "latest", features = ["batteries_included", "v4_local"] }
 ```
 ![paseto_batteries_included_v4_local_small](https://user-images.githubusercontent.com/24578097/147882822-46dac1d1-a922-4301-be45-d3341dabfee1.png)

 #### Feature gates
 Valid version/purpose feature combinations are as follows:
 - "v1_local" (NIST Original Symmetric Encryption)
 - "v2_local" (Sodium Original Symmetric Encryption)
 - "v3_local" (NIST Modern Symmetric Encryption)
 - "v4_local" (Sodium Modern Symmetric Encryption)
 - "v1_public" (NIST Original Asymmetric Authentication)
 - "v2_public" (Sodium Original Asymmetric Authentication)
 - *"v3_public" (NIST Modern Asymmetric Authentication)* - **NOT YET IMPLEMENTED**
 - "v4_public" (Sodium Modern Asymmetric Authentication)

 ```
 // at the top of your source file
 use rusty_paseto::prelude::*;
 ```
 ### generic

 The generic architectural and feature layer allows you to create your own custom version of the batteries_included layer by following the same pattern I've used in the source code to create your own custom builder and parser.  This is probably not what you need as it is for advanced usage.  The feature includes a generic builder and parser along with claims for you to extend.

 ![paseto_generic_small](https://user-images.githubusercontent.com/24578097/147881907-a765ede6-c8e5-44ff-9845-db53f0634f07.png)

 It includes all the PASETO and custom claims but allows you to create different default claims in your custom builder and parser or use a different time crate or make up your own default business rules.  As with the batteries_included layer, parsed tokens get returned as a serde_json Value. Again, specify the version and purpose to include in the crypto core:


 ```toml
 ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
 ## key types with all claims and default business rules.

 rusty_paseto = {version = "latest", features = ["generic", "v4_local"] }
 ```
 ```
 // at the top of your source file
 use rusty_paseto::generic::*;
 ```
 ### core

 The core architectural layer is the most basic PASETO implementation as it accepts a Payload, optional Footer and (if v3 or v4) an optional Implicit Assertion along with the appropriate key to encrypt/sign and decrypt/verify basic strings.  

 ![paseto_core_small](https://user-images.githubusercontent.com/24578097/147881920-14c52256-1a0c-40be-9f18-759a8c9ad77d.png)

 There are no default claims or included claim structures, business rules or anything other than basic PASETO crypto functions.  Serde crates are not included in this feature so it is extremely lightweight.  You can use this when you don't need JWT-esque functionality but still want to leverage the safe cipher combinations and algorithm lucidity afforded by the PASETO specification.

 ```toml
 ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
 ## key types with NO claims, defaults or validation, just basic PASETO
 ## encrypt/signing and decrypt/verification.

 rusty_paseto = {version = "latest", features = ["core", "v4_local"] }
 ```


 # Examples

 ## Building and parsing tokens with batteries_included

 Here's a basic, default token:
 ```rust
 use rusty_paseto::prelude::*;

 // create a key specifying the PASETO version and purpose
 let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
 // use a default token builder with the same PASETO version and purpose
 let token = PasetoBuilder::<V4, Local>::default().build(&key)?;
 // token is a String in the form: "v4.local.encoded-payload"

 ```

 ## A default token

 * Has no [footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs)
 * Has no [implicit assertion](https://github.com/paseto-standard/paseto-spec/tree/master/docs)
 for V3 or V4 versioned tokens
 * Expires in **1 hour** after creation (due to an included default ExpirationClaim)
 * Contains an IssuedAtClaim defaulting to the current utc time the token was created
 * Contains a NotBeforeClaim defaulting to the current utc time the token was created


 You can parse and validate an existing token with the following:
 ```rust
 let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
 // now we can parse and validate the token with a parser that returns a serde_json::Value
 let json_value = PasetoParser::<V4, Local>::default().parse(&token, &key)?;

 //the ExpirationClaim
 assert!(json_value["exp"].is_string());
 //the IssuedAtClaim
 assert!(json_value["iat"].is_string());

 ```

 ## A default parser

 * Validates the token structure and decryptes the payload or verifies the signature of the content
 * Validates the [footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs) if
 one was provided
 * Validates the [implicit assertion](https://github.com/paseto-standard/paseto-spec/tree/master/docs) if one was provided (for V3 or V4 versioned tokens only)

 ## A token with a footer

 PASETO tokens can have an [optional footer](https://github.com/paseto-standard/paseto-spec/tree/master/docs).  In rusty_paseto we have strict types for most things.  
 So we can extend the previous example to add a footer to the token by using code like the
 following:
 ```rust
 use rusty_paseto::prelude::*;
 let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
 let token = PasetoBuilder::<V4, Local>::default()
   // note how we set the footer here
   .set_footer(Footer::from("Sometimes science is more art than science"))
   .build(&key)?;

 // token is now a String in the form: "v4.local.encoded-payload.footer"

 ```
 And parse it by passing in the same expected footer
 ```rust
 // now we can parse and validate the token with a parser that returns a serde_json::Value
 let json_value = PasetoParser::<V4, Local>::default()
   .set_footer(Footer::from("Sometimes science is more art than science"))
   .parse(&token, &key)?;

 //the ExpirationClaim
 assert!(json_value["exp"].is_string());
 //the IssuedAtClaim
 assert!(json_value["iat"].is_string());

 ```


 ## A token with an implicit assertion (V3 or V4 versioned tokens only)

 Version 3 (V3) and Version 4 (V4) PASETO tokens can have an [optional implicit assertion](https://github.com/paseto-standard/paseto-spec/tree/master/docs).
 So we can extend the previous example to add an implicit assertion to the token by using code like the
 following:
 ```rust
 use rusty_paseto::prelude::*;
 let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
 let token = PasetoBuilder::<V4, Local>::default()
   .set_footer(Footer::from("Sometimes science is more art than science"))
   // note how we set the implicit assertion here
   .set_implicit_assertion(ImplicitAssertion::from("There’s a lesson here, and I’m not going to be the one to figure it out."))
   .build(&key)?;

 // token is now a String in the form: "v4.local.encoded-payload.footer"

 ```
 And parse it by passing in the same expected implicit assertion at parse time
 ```rust
 // now we can parse and validate the token with a parser that returns a serde_json::Value
 let json_value = PasetoParser::<V4, Local>::default()
   .set_footer(Footer::from("Sometimes science is more art than science"))
   .set_implicit_assertion(ImplicitAssertion::from("There’s a lesson here, and I’m not going to be the one to figure it out."))
   .parse(&token, &key)?;

 ```

 ## Setting a different expiration time

 As mentioned, default tokens expire **1 hour** from creation time.  You can set your own
 expiration time by adding an ExpirationClaim which takes an ISO 8601 (Rfc3339) compliant datetime string.
 #### Note: *claims taking an ISO 8601 (Rfc3339) string use the TryFrom trait and return a Result<(),PasetoClaimError>*
 ```rust
use rusty_paseto::prelude::*;
 // must include
 use std::convert::TryFrom;
 let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
 // real-world example using the time crate to expire 5 minutes from now

 let token = PasetoBuilder::<V4, Local>::default()
   // note the TryFrom implmentation for ExpirationClaim
   //.set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
   .set_footer(Footer::from("Sometimes science is more art than science"))
   .build(&key)?;

 // token is a String in the form: "v4.local.encoded-payload.footer"

 ```


 ## Tokens that never expire

 A **1 hour** ExpirationClaim is set by default because the use case for non-expiring tokens in the world of security tokens is fairly limited.
 Omitting an expiration claim or forgetting to require one when processing them
 is almost certainly an oversight rather than a deliberate choice.  

 When it is a deliberate choice, you have the opportunity to deliberately remove this claim from the Builder.
 The method call required to do so ensures readers of the code understand the implicit risk.
 ```rust
 let token = PasetoBuilder::<V4, Local>::default()
   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
   // even if you set an expiration claim (as above) it will be ignored
   // due to the method call below
   .set_no_expiration_danger_acknowledged()
   .build(&key)?;

 ```

 ## Setting PASETO Claims

 The PASETO specification includes [seven reserved claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) which you can set with their explicit types:
 ```rust
 // real-world example using the time crate to prevent the token from being used before 2
 // minutes from now
 let in_2_minutes = (time::OffsetDateTime::now_utc() + time::Duration::minutes(2)).format(&Rfc3339)?;

 let token = PasetoBuilder::<V4, Local>::default()
   //json payload key: "exp"
   .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
   //json payload key: "iat"
   // the IssueAtClaim is automatically set to UTC NOW by default
   // but you can override it here
   // .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
   //json payload key: "nbf"
   //don't use this token before two minutes after UTC NOW
   .set_claim(NotBeforeClaim::try_from(in_2_minutes)?)
   //json payload key: "aud"
   .set_claim(AudienceClaim::from("Cromulons"))
   //json payload key: "sub"
   .set_claim(SubjectClaim::from("Get schwifty"))
   //json payload key: "iss"
   .set_claim(IssuerClaim::from("Earth Cesium-137"))
   //json payload key: "jti"
   .set_claim(TokenIdentifierClaim::from("Planet Music - Season 988"))
   .build(&key)?;

 ```

 ## Setting your own Custom Claims

 The CustomClaim struct takes a tuple in the form of `(key: String, value: T)` where T is any
 serializable type
 #### Note: *CustomClaims use the TryFrom trait and return a Result<(), PasetoClaimError> if you attempt to use one of the [reserved PASETO keys](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) in your CustomClaim*
 ```rust
 let token = PasetoBuilder::<V4, Local>::default()
   .set_claim(CustomClaim::try_from(("Co-star", "Morty Smith"))?)
   .set_claim(CustomClaim::try_from(("Universe", 137))?)
   .build(&key)?;

 ```
 This throws an error:
 ```rust
 // "exp" is a reserved PASETO claim key, you should use the ExpirationClaim type
 let token = PasetoBuilder::<V4, Local>::default()
   .set_claim(CustomClaim::try_from(("exp", "Some expiration value"))?)
   .build(&key)?;

 ```
 # Validating claims
 rusty_paseto allows for flexible claim validation at parse time

 ## Checking claims

 Let's see how we can check particular claims exist with expected values.
 ```rust
 // use a default token builder with the same PASETO version and purpose
 let token = PasetoBuilder::<V4, Local>::default()
   .set_claim(SubjectClaim::from("Get schwifty"))
   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
   .set_claim(CustomClaim::try_from(("Universe", 137))?)
   .build(&key)?;

 PasetoParser::<V4, Local>::default()
   // you can check any claim even custom claims
   .check_claim(SubjectClaim::from("Get schwifty"))
   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
   .check_claim(CustomClaim::try_from(("Universe", 137))?)
   .parse(&token, &key)?;

 // no need for the assertions below since the check_claim methods
 // above accomplish the same but at parse time!

 //assert_eq!(json_value["sub"], "Get schwifty");
 //assert_eq!(json_value["Contestant"], "Earth");
 //assert_eq!(json_value["Universe"], 137);
 ```

 # Custom validation

 What if we have more complex validation requirements? You can pass in a reference to a closure which receives
 the key and value of the claim you want to validate so you can implement any validation logic
 you choose.  

 Let's see how we can validate our tokens only contain universe values with prime numbers:
 ```rust
 // use a default token builder with the same PASETO version and purpose
 let token = PasetoBuilder::<V4, Local>::default()
   .set_claim(SubjectClaim::from("Get schwifty"))
   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
   .set_claim(CustomClaim::try_from(("Universe", 137))?)
   .build(&key)?;

 PasetoParser::<V4, Local>::default()
   .check_claim(SubjectClaim::from("Get schwifty"))
   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
    .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
      //let's get the value
      let universe = value
        .as_u64()
        .ok_or(PasetoClaimError::Unexpected(key.to_string()))?;
      // we only accept prime universes in this app
      if primes::is_prime(universe) {
        Ok(())
      } else {
        Err(PasetoClaimError::CustomValidation(key.to_string()))
      }
    })
   .parse(&token, &key)?;

 ```

 This token will fail to parse with the validation code above:
 ```rust
 // 136 is not a prime number
 let token = PasetoBuilder::<V4, Local>::default()
   .set_claim(CustomClaim::try_from(("Universe", 136))?)
   .build(&key)?;

 ```

 # Acknowledgments

 If the API of this crate doesn't suit your tastes, check out the other PASETO implementations
 in the Rust ecosystem which inspired rusty_paseto:

 - [paseto](https://crates.io/crates/paseto) - by [Cynthia Coan](https://crates.io/users/Mythra)
 - [pasetors](https://crates.io/crates/pasetors) - by [Johannes](https://crates.io/users/brycx)

# Questions?

File an issue or hit me up on [Twitter](https://twitter.com/rrrodzilla)!
