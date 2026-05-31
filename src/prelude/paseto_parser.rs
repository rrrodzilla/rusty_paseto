use crate::generic::*;
use core::marker::PhantomData;
use serde_json::Value;

#[cfg(feature = "time")]
use time::format_description::well_known::Rfc3339;
///The `PasetoParser` validates and parses PASETO tokens. Created at compile time by specifying a PASETO version and purpose.
///
///This structure validates [PASETO claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md),
///[custom claims](CustomClaim), an optional [footer](Footer) and in the case of V3/V4 tokens, an optional [implicit
///assertion](ImplicitAssertion).
///
///The `PasetoParser` wraps the [`GenericParser`] with JWT style claims and business rules which align
///with the PASETO standard. For most users, this batteries-included struct will be all they need.
///
///**Default Behavior**: `PasetoParser::default()` automatically validates expiration (`exp`) and not-before (`nbf`) claims.
///Expired tokens or tokens used before their `nbf` time return a [`GenericParserError`].
///Use `PasetoParser::new()` to construct a parser without automatic time-based validations.
///
///# Usage
///
///```
///# #[cfg(all(feature = "prelude", feature="v2_local"))]
///# {
///   use rusty_paseto::prelude::*;
///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
///     let footer = Footer::from("some footer");
///     //create a builder, add some claims and then build the token with the key
///     let token = PasetoBuilder::<V2, Local>::default()
///       .set_claim(AudienceClaim::from("customers"))
///       .set_claim(SubjectClaim::from("loyal subjects"))
///       .set_claim(IssuerClaim::from("me"))
///       .set_claim(TokenIdentifierClaim::from("me"))
///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
///       .set_claim(CustomClaim::try_from(("seats", 4))?)
///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
///       .set_footer(footer)
///       .try_encrypt(&key)?;
///     //now let's decrypt the token and verify the values
///     let json = PasetoParser::<V2, Local>::default()
///       .set_footer(footer)
///       .parse(&token, &key)?;
///     assert_eq!(json["aud"], "customers");
///     assert_eq!(json["jti"], "me");
///     assert_eq!(json["iss"], "me");
///     assert_eq!(json["data"], "this is a secret message");
///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
///     assert_eq!(json["sub"], "loyal subjects");
///     assert_eq!(json["pi to 6 digits"], 3.141526);
///     assert_eq!(json["seats"], 4);
///  # }
/// # Ok::<(),anyhow::Error>(())
///   ```
pub struct PasetoParser<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  parser: GenericParser<'a, 'a, Version, Purpose>,
}

impl<'a, Version, Purpose> PasetoParser<'a, Version, Purpose> {
  /// Creates a new parser without automatic time-based validations.
  ///
  /// This method creates a parser without expiration or not-before validation.
  /// For automatic validation of `exp` and `nbf` claims, use [`PasetoParser::default()`] instead.
  ///
  /// Returns a new PASETO parser builder for construction.
  ///
  /// # Errors
  /// none
  ///
  /// # Example (using default with automatic validations)
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     # let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     # let footer = Footer::from("some footer");
  ///     # //create a builder, add some claims and then build the token with the key
  ///     # let token = PasetoBuilder::<V2, Local>::default()
  ///     #  .try_encrypt(&key)?;
  ///     //decrypt and parse claims from the PASETO token string with automatic validation
  ///     let json = PasetoParser::<V2, Local>::default()
  ///       .parse(&token, &key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn new() -> Self {
    PasetoParser::<'a, Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      parser: GenericParser::default(),
    }
  }
  /// Takes a [`PasetoClaim`] and a [`ValidatorFn`] and uses the function to validate the claim during
  /// parsing and after decryption or signature verification.
  ///
  /// Returns a mutable reference to the parser
  ///
  /// # Errors
  /// none
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     # let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     # let footer = Footer::from("some footer");
  ///     # //create a builder, add some claims and then build the token with the key
  ///     # let token = PasetoBuilder::<V2, Local>::default()
  ///      # .try_encrypt(&key)?;
  ///     //decrypt and parse claims from the PASETO token string
  ///     let json = PasetoParser::<V2, Local>::default()
  ///   .validate_claim(ExpirationClaim::default(), &|key, value| {
  ///     //let's get the value
  ///     let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;
  ///     let datetime = iso8601::datetime(val).unwrap();
  ///     # #[cfg(feature = "time")]
  ///     let in_an_hour = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
  ///       .time()
  ///       .hour()
  ///       .to_string();
  ///     # #[cfg(feature = "chrono")]
  ///     # let in_an_hour = (chrono::Utc::now() + chrono::Duration::hours(1))
  ///     #   .format("%H")
  ///     #   .to_string();
  ///     //the claimm should exist
  ///     assert_eq!(key, "exp");
  ///     //hour should match expected
  ///     assert_eq!(datetime.time.hour.to_string(), in_an_hour);
  ///     Ok(())
  ///   })
  ///       .parse(&token, &key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn validate_claim<T: PasetoClaim + 'a + serde::Serialize>(
    &mut self,
    value: T,
    validation_closure: &'static ValidatorFn,
  ) -> &mut Self {
    self.parser.validate_claim(value, validation_closure);
    self
  }
  /// Takes a [`PasetoClaim`] to ensure existence of the claim and it's value during
  /// parsing and after decryption or signature verification.
  ///
  /// Returns a mutable reference to the parser
  ///
  /// # Errors
  /// none
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     # let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     # let footer = Footer::from("some footer");
  ///     # //create a builder, add some claims and then build the token with the key
  ///     # let token = PasetoBuilder::<V2, Local>::default()
  /// # .set_claim(AudienceClaim::from("customers"))
  ///  #      .try_encrypt(&key)?;
  ///     //decrypt and parse claims from the PASETO token string
  ///     let json = PasetoParser::<V2, Local>::default()
  /// .check_claim(AudienceClaim::from("customers"))
  ///       .parse(&token, &key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn check_claim<T: PasetoClaim + 'a + serde::Serialize>(&mut self, value: T) -> &mut Self {
    self.parser.check_claim(value);
    self
  }
  ///Sets an optional [Footer] to use during parsing
  pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
    self.parser.set_footer(footer);
    self
  }

  /// Acknowledge that this parser may accept tokens with no `exp` claim.
  ///
  /// By default, [`PasetoParser::default()`] rejects tokens whose `exp` claim
  /// is missing, null, or not a string — non-expiring tokens are an
  /// elevated risk and must be opted into explicitly. This method mirrors
  /// [`PasetoBuilder::set_no_expiration_danger_acknowledged()`] on the
  /// parsing side: once called, an absent `exp` is treated as a valid
  /// non-expiring token, while a present `exp` is still parsed and
  /// compared against the current time.
  ///
  /// # When to use this
  ///
  /// Use this only when you have a deliberate non-expiring token in your
  /// design (e.g., long-lived API keys that you intend to revoke through
  /// other means). In every other case, leave the default in place and
  /// reject tokens that fail to commit to an expiration.
  ///
  /// # Example
  /// ```
  /// # #[cfg(all(feature = "prelude", feature = "v4_local"))]
  /// # {
  /// # use rusty_paseto::prelude::*;
  /// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  /// // mint a deliberately non-expiring token
  /// let token = PasetoBuilder::<V4, Local>::default()
  ///     .set_no_expiration_danger_acknowledged()
  ///     .build(&key)?;
  ///
  /// // parse with the symmetric opt-in
  /// let _value = PasetoParser::<V4, Local>::default()
  ///     .set_no_expiration_danger_acknowledged()
  ///     .parse(&token, &key)?;
  /// # }
  /// # Ok::<(), anyhow::Error>(())
  /// ```
  pub fn set_no_expiration_danger_acknowledged(&mut self) -> &mut Self {
    // Overwrite the strict exp validator (installed by `default()`) with a
    // permissive one that accepts absent/empty exp values but still
    // validates the expiration time when a value is present.
    self.parser.validate_claim(ExpirationClaim::default(), &|_, value| {
      let val = value.as_str().unwrap_or_default();
      if val.is_empty() {
        return Ok(());
      }
      #[cfg(feature = "time")]
      let expired: bool = {
        let datetime =
          time::OffsetDateTime::parse(val, &Rfc3339).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
        datetime <= time::OffsetDateTime::now_utc()
      };
      #[cfg(feature = "chrono")]
      let expired: bool = {
        let datetime =
          chrono::DateTime::parse_from_rfc3339(val).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
        datetime <= chrono::Utc::now()
      };
      if expired {
        Err(PasetoClaimError::Expired)
      } else {
        Ok(())
      }
    });
    self
  }

  /// Checks that the audience claim (aud) matches the expected value.
  ///
  /// This is a convenience method equivalent to `.check_claim(AudienceClaim::from(value))`.
  ///
  /// # Example
  /// ```
  /// # #[cfg(all(feature = "prelude", feature="v4_local"))]
  /// # {
  /// use rusty_paseto::prelude::*;
  /// let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  /// let token = PasetoBuilder::<V4, Local>::default()
  ///     .audience("customers")
  ///     .build(&key)?;
  /// let json = PasetoParser::<V4, Local>::default()
  ///     .expect_audience("customers")
  ///     .parse(&token, &key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  /// ```
  pub fn expect_audience(mut self, audience: &'a str) -> Self {
    self.check_claim(AudienceClaim::from(audience));
    self
  }

  /// Checks that the issuer claim (iss) matches the expected value.
  ///
  /// This is a convenience method equivalent to `.check_claim(IssuerClaim::from(value))`.
  ///
  /// # Example
  /// ```
  /// # #[cfg(all(feature = "prelude", feature="v4_local"))]
  /// # {
  /// use rusty_paseto::prelude::*;
  /// let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  /// let token = PasetoBuilder::<V4, Local>::default()
  ///     .issuer("my-service")
  ///     .build(&key)?;
  /// let json = PasetoParser::<V4, Local>::default()
  ///     .expect_issuer("my-service")
  ///     .parse(&token, &key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  /// ```
  pub fn expect_issuer(mut self, issuer: &'a str) -> Self {
    self.check_claim(IssuerClaim::from(issuer));
    self
  }

  /// Checks that the subject claim (sub) matches the expected value.
  ///
  /// This is a convenience method equivalent to `.check_claim(SubjectClaim::from(value))`.
  ///
  /// # Example
  /// ```
  /// # #[cfg(all(feature = "prelude", feature="v4_local"))]
  /// # {
  /// use rusty_paseto::prelude::*;
  /// let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  /// let token = PasetoBuilder::<V4, Local>::default()
  ///     .subject("user-123")
  ///     .build(&key)?;
  /// let json = PasetoParser::<V4, Local>::default()
  ///     .expect_subject("user-123")
  ///     .parse(&token, &key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  /// ```
  pub fn expect_subject(mut self, subject: &'a str) -> Self {
    self.check_claim(SubjectClaim::from(subject));
    self
  }
}

impl<'a, Version, Purpose> PasetoParser<'a, Version, Purpose>
where
  Version: ImplicitAssertionCapable,
{
  ///Sets an optional [`ImplicitAssertion`] to use during parsing ([V3], [V4] tokens only)
  pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
    self.parser.set_implicit_assertion(implicit_assertion);
    self
  }
}

impl<'a, Version, Purpose> Default for PasetoParser<'a, Version, Purpose> {
  /// Creates a parser with automatic expiration and not-before validation.
  ///
  /// This default implementation validates:
  /// * Expiration (`exp`) - Returns `PasetoClaimError::Missing("exp")` if the
  ///   claim is absent, null, or not a string, and `PasetoClaimError::Expired`
  ///   if the token has expired. To accept tokens without an `exp` claim, call
  ///   [`PasetoParser::set_no_expiration_danger_acknowledged()`] — the parser
  ///   side mirrors the builder's
  ///   [`PasetoBuilder::set_no_expiration_danger_acknowledged()`].
  /// * Not-before (`nbf`) - When present, returns
  ///   `PasetoClaimError::UseBeforeAvailable` if the token is used before its
  ///   `nbf` time. An absent `nbf` is valid (it means "no lower bound on use").
  ///
  /// Use [`PasetoParser::new()`] to create a parser without these automatic validations.
  fn default() -> Self {
    let mut me = Self::new();
    me.validate_claim(ExpirationClaim::default(), &|_, value| {
      //let's get the expiration claim value
      let val = value.as_str().unwrap_or_default();

      //An absent/empty/non-string `exp` claim is rejected by default. The
      //builder requires an explicit set_no_expiration_danger_acknowledged()
      //to mint non-expiring tokens; the parser side is symmetric — call
      //PasetoParser::set_no_expiration_danger_acknowledged() to opt in to
      //accepting them.
      if val.is_empty() {
        return Err(PasetoClaimError::Missing("exp".to_string()));
      }
      #[cfg(feature = "time")]
      let expired: bool = {
        //turn the value into a datetime
        let datetime =
          time::OffsetDateTime::parse(val, &Rfc3339).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
        datetime <= time::OffsetDateTime::now_utc()
      };
      #[cfg(feature = "chrono")]
      let expired: bool = {
        let datetime =
          chrono::DateTime::parse_from_rfc3339(val).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
        datetime <= chrono::Utc::now()
      };
      if expired {
        Err(PasetoClaimError::Expired)
      } else {
        Ok(())
      }
    })
    .validate_claim(NotBeforeClaim::default(), &|_, value| {
      //let's get the expiration claim value
      let val = value.as_str().unwrap_or_default();
      //if there is no value here, then the user didn't provide the claim so we just move on
      if val.is_empty() {
        return Ok(());
      }
      //otherwise let's continue with the validation
      #[cfg(feature = "time")]
      //turn the value into a datetime
      let not_before_str: Option<String> = {
        let not_before_time =
          time::OffsetDateTime::parse(val, &Rfc3339).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
        //get the current datetime
        let now = time::OffsetDateTime::now_utc();

        //here we do the actual validation check for the not-before claim.
        //RFC 7519 §4.1.5: token is valid when `now >= nbf`, so reject only when
        //`now < nbf`. Using strict `<` here (not `<=`) so that a token with
        //nbf == now is accepted as soon as its activation instant arrives.
        if now < not_before_time {
          Some(not_before_time.to_string())
        } else {
          None
        }
      };
      #[cfg(feature = "chrono")]
      let not_before_str: Option<String> = {
        let not_before_time =
          chrono::DateTime::parse_from_rfc3339(val).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
        let now = chrono::Utc::now();
        if now < not_before_time {
          Some(not_before_time.to_string())
        } else {
          None
        }
      };
      //RFC 7519 §4.1.5: reject only when now < nbf (strict <, so nbf == now is accepted).
      if let Some(not_before_str) = not_before_str {
        Err(PasetoClaimError::UseBeforeAvailable(not_before_str))
      } else {
        Ok(())
      }
    });
    me
  }
}

#[cfg(feature = "v1_local")]
impl<'a> PasetoParser<'a, V1, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V1, Local) encrypted PASETO token string and then validate
  /// claims provided when building the PasetoParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v1_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     let footer = Footer::from("some footer");
  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = ParserBuilder::<V1, Local>::default()
  ///       .set_claim(AudienceClaim::from("customers"))
  ///       .set_claim(SubjectClaim::from("loyal subjects"))
  ///       .set_claim(IssuerClaim::from("me"))
  ///       .set_claim(TokenIdentifierClaim::from("me"))
  ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///       .set_footer(footer)
  ///       .try_encrypt(&key)?;
  ///     //now let's decrypt the token and verify the values
  ///     let json = ParserParser::<V1, Local>::default()
  ///       .set_footer(footer)
  ///       .parse(&token, &key)?;
  ///     assert_eq!(json["aud"], "customers");
  ///     assert_eq!(json["jti"], "me");
  ///     assert_eq!(json["iss"], "me");
  ///     assert_eq!(json["data"], "this is a secret message");
  ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["sub"], "loyal subjects");
  ///     assert_eq!(json["pi to 6 digits"], 3.141526);
  ///     assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn parse(&mut self, token: &'a str, key: &'a PasetoSymmetricKey<V1, Local>) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoSymmetricKey<V1, Local>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v2_local")]
impl<'a> PasetoParser<'a, V2, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V2, Local) encrypted PASETO token string and then validate
  /// claims provided when building the PasetoParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     let footer = Footer::from("some footer");
  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = PasetoBuilder::<V2, Local>::default()
  ///       .set_claim(AudienceClaim::from("customers"))
  ///       .set_claim(SubjectClaim::from("loyal subjects"))
  ///       .set_claim(IssuerClaim::from("me"))
  ///       .set_claim(TokenIdentifierClaim::from("me"))
  ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///       .set_footer(footer)
  ///       .try_encrypt(&key)?;
  ///     //now let's decrypt the token and verify the values
  ///     let json = PasetoParser::<V2, Local>::default()
  ///       .set_footer(footer)
  ///       .parse(&token, &key)?;
  ///     assert_eq!(json["aud"], "customers");
  ///     assert_eq!(json["jti"], "me");
  ///     assert_eq!(json["iss"], "me");
  ///     assert_eq!(json["data"], "this is a secret message");
  ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["sub"], "loyal subjects");
  ///     assert_eq!(json["pi to 6 digits"], 3.141526);
  ///     assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn parse(&mut self, token: &'a str, key: &'a PasetoSymmetricKey<V2, Local>) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoSymmetricKey<V2, Local>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v3_local")]
impl<'a> PasetoParser<'a, V3, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V1, Local) encrypted PASETO token string and then validate
  /// claims provided when building the PasetoParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v3_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     let footer = Footer::from("some footer");
  ///     let implicit_assertion = ImplicitAssertion::from("some assertion");
  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = PasetoBuilder::<V3, Local>::default()
  ///       .set_claim(AudienceClaim::from("customers"))
  ///       .set_claim(SubjectClaim::from("loyal subjects"))
  ///       .set_claim(IssuerClaim::from("me"))
  ///       .set_claim(TokenIdentifierClaim::from("me"))
  ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///       .set_footer(footer)
  ///       .set_implicit_assertion(implicit_assertion)
  ///       .try_encrypt(&key)?;
  ///     //now let's decrypt the token and verify the values
  ///     let json = PasetoParser::<V3, Local>::default()
  ///       .set_footer(footer)
  ///       .set_implicit_assertion(implicit_assertion)
  ///       .parse(&token, &key)?;
  ///     assert_eq!(json["aud"], "customers");
  ///     assert_eq!(json["jti"], "me");
  ///     assert_eq!(json["iss"], "me");
  ///     assert_eq!(json["data"], "this is a secret message");
  ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["sub"], "loyal subjects");
  ///     assert_eq!(json["pi to 6 digits"], 3.141526);
  ///     assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn parse(&mut self, token: &'a str, key: &'a PasetoSymmetricKey<V3, Local>) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoSymmetricKey<V3, Local>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v4_local")]
impl<'a> PasetoParser<'a, V4, Local> {
  /// Given a [`PasetoSymmetricKey`], attempts to decrypt a (V4, Local) encrypted PASETO token string and then validate
  /// claims provided when building the `PasetoParser`.
  ///
  /// Returns a `serde_json` [Value] with the decrypted [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v4_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     let footer = Footer::from("some footer");
  ///     let implicit_assertion = ImplicitAssertion::from("some assertion");
  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = PasetoBuilder::<V4, Local>::default()
  ///       .set_claim(AudienceClaim::from("customers"))
  ///       .set_claim(SubjectClaim::from("loyal subjects"))
  ///       .set_claim(IssuerClaim::from("me"))
  ///       .set_claim(TokenIdentifierClaim::from("me"))
  ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///       .set_footer(footer)
  ///       .set_implicit_assertion(implicit_assertion)
  ///       .try_encrypt(&key)?;
  ///     //now let's decrypt the token and verify the values
  ///     let json = PasetoParser::<V4, Local>::default()
  ///       .set_footer(footer)
  ///       .set_implicit_assertion(implicit_assertion)
  ///       .parse(&token, &key)?;
  ///     assert_eq!(json["aud"], "customers");
  ///     assert_eq!(json["jti"], "me");
  ///     assert_eq!(json["iss"], "me");
  ///     assert_eq!(json["data"], "this is a secret message");
  ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["sub"], "loyal subjects");
  ///     assert_eq!(json["pi to 6 digits"], 3.141526);
  ///     assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```
  pub fn parse(&mut self, token: &'a str, key: &'a PasetoSymmetricKey<V4, Local>) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// This method first parses and validates the token, then deserializes
  /// the claims into the specified type `T`.
  ///
  /// # Type Parameters
  /// - `T`: The target type for deserialization. Must implement [`serde::de::DeserializeOwned`].
  ///
  /// # Errors
  /// Returns [`GenericParserError`] if:
  /// - Token decryption fails
  /// - Claim validation fails
  /// - JSON deserialization into `T` fails
  ///
  /// # Example
  /// ```
  /// # #[cfg(all(feature = "prelude", feature="v4_local"))]
  /// # {
  /// use rusty_paseto::prelude::*;
  /// use serde::Deserialize;
  ///
  /// #[derive(Deserialize)]
  /// struct MyClaims {
  ///     sub: String,
  ///     #[serde(default)]
  ///     user_id: Option<i64>,
  /// }
  ///
  /// let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  /// let token = PasetoBuilder::<V4, Local>::default()
  ///     .subject("user-123")
  ///     .claim("user_id", 42)?
  ///     .build(&key)?;
  ///
  /// let claims: MyClaims = PasetoParser::<V4, Local>::default()
  ///     .parse_into(&token, &key)?;
  ///
  /// assert_eq!(claims.sub, "user-123");
  /// assert_eq!(claims.user_id, Some(42));
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  /// ```
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoSymmetricKey<V4, Local>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v1_public_insecure")]
impl<'a> PasetoParser<'a, V1, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to verify a signed (V1, Public) PASETO token string and then validate
  /// claims provided when building the PasetoParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Deprecated
  ///
  /// V1 PASETO is the legacy version (2048-bit RSA-PSS-SHA384). The PASETO specification recommends V4 for new code. This implementation uses `ring`, which is not affected by the Marvin Attack RUSTSEC-2023-0071 (that advisory targets the `rsa` crate, not used here).
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v1_public_insecure"))]
  ///# {
  ///   # use rusty_paseto::prelude::*;
  ///    //obtain a private key (pk)
  ///   # let private_key = include_bytes!("../../../tests/v1_public_test_vectors_private_key.pk8");
  ///   # let pk: &[u8] = private_key;
  ///    #[allow(deprecated)]
  ///    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);
  ///     let footer = Footer::from("some footer");
  ///     //sign a public V1 token
  ///     #[allow(deprecated)]
  ///     let token = PasetoBuilder::<V1, Public>::default()
  ///       .set_claim(AudienceClaim::from("customers"))
  ///       .set_claim(SubjectClaim::from("loyal subjects"))
  ///       .set_claim(IssuerClaim::from("me"))
  ///       .set_claim(TokenIdentifierClaim::from("me"))
  ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///       .set_footer(footer)
  ///       .try_sign(&private_key)?;
  /// //obtain a public key (pubk)
  ///   #  let public_key = include_bytes!("../../../tests/v1_public_test_vectors_public_key.der");
  ///   #  let pubk: &[u8] = public_key;
  ///     #[allow(deprecated)]
  ///     let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);
  ///     //now let's try to verify it
  ///     #[allow(deprecated)]
  ///     let json = PasetoParser::<V1, Public>::default()
  ///       .set_footer(footer)
  ///       .check_claim(AudienceClaim::from("customers"))
  ///       .check_claim(SubjectClaim::from("loyal subjects"))
  ///       .check_claim(IssuerClaim::from("me"))
  ///       .check_claim(TokenIdentifierClaim::from("me"))
  ///       .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///       .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///       .check_claim(CustomClaim::try_from(("seats", 4))?)
  ///       .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///       .parse(&token, &public_key)?;
  ///     // we can access all the values from the serde Value object returned by the parser
  ///     assert_eq!(json["aud"], "customers");
  ///     assert_eq!(json["jti"], "me");
  ///     assert_eq!(json["iss"], "me");
  ///     assert_eq!(json["data"], "this is a secret message");
  ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  ///     assert_eq!(json["sub"], "loyal subjects");
  ///     assert_eq!(json["pi to 6 digits"], 3.141526);
  ///     assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///```
  #[deprecated(
    since = "0.8.1",
    note = "V1 is the legacy PASETO version (2048-bit RSA-PSS). PASETO spec recommends V4 for new code."
  )]
  #[allow(deprecated)]
  pub fn parse(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V1, Public>,
  ) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  #[deprecated(
    since = "0.8.1",
    note = "V1 is the legacy PASETO version (2048-bit RSA-PSS). PASETO spec recommends V4 for new code."
  )]
  #[allow(deprecated)]
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V1, Public>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v2_public")]
impl<'a> PasetoParser<'a, V2, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to verify a signed (V2, Public) PASETO token string and then validate
  /// claims provided when building the PasetoParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_public"))]
  ///# {
  ///   # use rusty_paseto::prelude::*;
  ///    //obtain a key
  /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);
  /// let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);
  /// let footer = Footer::from("some footer");
  /// //sign a public V2 token
  /// let token = PasetoBuilder::<V2, Public>::default()
  ///   .set_claim(AudienceClaim::from("customers"))
  ///   .set_claim(SubjectClaim::from("loyal subjects"))
  ///   .set_claim(IssuerClaim::from("me"))
  ///   .set_claim(TokenIdentifierClaim::from("me"))
  ///   .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///   .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///   .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///   .set_footer(footer)
  ///   .try_sign(&private_key)?;
  /// //now let's try to verify it
  /// let json = PasetoParser::<V2, Public>::default()
  ///   .set_footer(footer)
  ///   .check_claim(AudienceClaim::from("customers"))
  ///   .check_claim(SubjectClaim::from("loyal subjects"))
  ///   .check_claim(IssuerClaim::from("me"))
  ///   .check_claim(TokenIdentifierClaim::from("me"))
  ///   .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///   .check_claim(CustomClaim::try_from(("seats", 4))?)
  ///   .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///   .parse(&token, &public_key)?;
  /// // we can access all the values from the serde Value object returned by the parser
  /// assert_eq!(json["aud"], "customers");
  /// assert_eq!(json["jti"], "me");
  /// assert_eq!(json["iss"], "me");
  /// assert_eq!(json["data"], "this is a secret message");
  /// assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["sub"], "loyal subjects");
  /// assert_eq!(json["pi to 6 digits"], 3.141526);
  /// assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///```
  pub fn parse(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V2, Public>,
  ) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V2, Public>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v3_public")]
impl<'a> PasetoParser<'a, V3, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to verify a signed (V3, Public) PASETO token string and then validate
  /// claims provided when building the PasetoParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v3_public"))]
  ///# {
  ///   # use rusty_paseto::prelude::*;
  ///    //obtain a key
  /// let private_key = Key::<48>::try_from(
  ///   "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
  /// )?;
  /// let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);
  /// let public_key = Key::<49>::try_from(
  ///   "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
  /// )?;
  /// let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;
  /// let footer = Footer::from("some footer");
  /// let implicit_assertion = ImplicitAssertion::from("some assertion");
  /// //sign a public V3 token
  /// let token = PasetoBuilder::<V3, Public>::default()
  ///   .set_claim(AudienceClaim::from("customers"))
  ///   .set_claim(SubjectClaim::from("loyal subjects"))
  ///   .set_claim(IssuerClaim::from("me"))
  ///   .set_claim(TokenIdentifierClaim::from("me"))
  ///   .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///   .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///   .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///   .set_footer(footer)
  ///   .set_implicit_assertion(implicit_assertion)
  ///   .try_sign(&private_key)?;
  /// //now let's try to verify it
  /// let json = PasetoParser::<V3, Public>::default()
  ///   .set_footer(footer)
  ///   .check_claim(AudienceClaim::from("customers"))
  ///   .set_implicit_assertion(implicit_assertion)
  ///   .check_claim(SubjectClaim::from("loyal subjects"))
  ///   .check_claim(IssuerClaim::from("me"))
  ///   .check_claim(TokenIdentifierClaim::from("me"))
  ///   .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///   .check_claim(CustomClaim::try_from(("seats", 4))?)
  ///   .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///   .parse(&token, &public_key)?;
  /// // we can access all the values from the serde Value object returned by the parser
  /// assert_eq!(json["aud"], "customers");
  /// assert_eq!(json["jti"], "me");
  /// assert_eq!(json["iss"], "me");
  /// assert_eq!(json["data"], "this is a secret message");
  /// assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["sub"], "loyal subjects");
  /// assert_eq!(json["pi to 6 digits"], 3.141526);
  /// assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///```
  pub fn parse(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V3, Public>,
  ) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V3, Public>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(feature = "v4_public")]
impl<'a> PasetoParser<'a, V4, Public> {
  /// Given a [`PasetoAsymmetricPublicKey`], attempts to verify a signed (V4, Public) PASETO token string and then validate
  /// claims provided when building the `PasetoParser`.
  ///
  /// Returns a `serde_json` [Value] with the verified [claims](PasetoClaim).
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v4_public"))]
  ///# {
  ///   # use rusty_paseto::prelude::*;
  /// //create a key
  /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let pk: &[u8] = private_key.as_slice();
  /// let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::try_from(pk)?;
  /// let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
  /// let footer = Footer::from("some footer");
  /// let implicit_assertion = ImplicitAssertion::from("some assertion");
  /// //sign a public V4 token
  /// let token = PasetoBuilder::<V4, Public>::default()
  ///   .set_claim(AudienceClaim::from("customers"))
  ///   .set_claim(SubjectClaim::from("loyal subjects"))
  ///   .set_claim(IssuerClaim::from("me"))
  ///   .set_claim(TokenIdentifierClaim::from("me"))
  ///   .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///   .set_claim(CustomClaim::try_from(("seats", 4))?)
  ///   .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///   .set_footer(footer)
  ///   .set_implicit_assertion(implicit_assertion)
  ///   .try_sign(&private_key)?;
  /// //now let's try to verify it
  /// let json = PasetoParser::<V4, Public>::default()
  ///   .set_footer(footer)
  ///   .set_implicit_assertion(implicit_assertion)
  ///   .check_claim(AudienceClaim::from("customers"))
  ///   .check_claim(SubjectClaim::from("loyal subjects"))
  ///   .check_claim(IssuerClaim::from("me"))
  ///   .check_claim(TokenIdentifierClaim::from("me"))
  ///   .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
  ///   .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
  ///   .check_claim(CustomClaim::try_from(("seats", 4))?)
  ///   .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
  ///   .parse(&token, &public_key)?;
  /// // we can access all the values from the serde Value object returned by the parser
  /// assert_eq!(json["aud"], "customers");
  /// assert_eq!(json["jti"], "me");
  /// assert_eq!(json["iss"], "me");
  /// assert_eq!(json["data"], "this is a secret message");
  /// assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
  /// assert_eq!(json["sub"], "loyal subjects");
  /// assert_eq!(json["pi to 6 digits"], 3.141526);
  /// assert_eq!(json["seats"], 4);
  ///  # }
  /// # Ok::<(),anyhow::Error>(())
  ///```
  pub fn parse(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V4, Public>,
  ) -> Result<Value, GenericParserError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }

  /// Parses and deserializes the token claims into a strongly-typed struct.
  ///
  /// See [`PasetoParser<V4, Local>::parse_into`] for detailed documentation.
  pub fn parse_into<T: serde::de::DeserializeOwned>(
    &mut self,
    token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V4, Public>,
  ) -> Result<T, GenericParserError> {
    let json = self.parse(token, key)?;
    serde_json::from_value(json).map_err(GenericParserError::from)
  }
}

#[cfg(all(test, feature = "v3_public"))]
mod paseto_parser_v3_unit_tests {
  use std::convert::TryFrom;

  use crate::prelude::*;
  use anyhow::Result;

  #[cfg(feature = "v3_public")]
  #[test]
  fn basic_paseto_parser_test_v3_public() -> Result<()> {
    //setup
    let public_key = Key::<49>::try_from(
      "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    )?;
    let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

    let private_key = Key::<48>::try_from(
      "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    )?;
    let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    //create a default builder
    let token = PasetoBuilder::<V3, Public>::default().build(&private_key)?;

    //default parser
    let json = PasetoParser::<V3, Public>::default().parse(&token, &public_key)?;

    //verify the default claims and no others are in the token
    assert!(json["exp"].is_string());
    assert!(json["iat"].is_string());
    assert!(json["nbf"].is_string());
    assert!(json["sub"].is_null());
    assert!(json["iss"].is_null());
    assert!(json["jti"].is_null());
    assert!(json["aud"].is_null());
    assert!(!json["aud"].is_string());
    Ok(())
  }
}

#[cfg(all(test, feature = "v2_local"))]
mod paseto_parser_unit_tests {
  use std::convert::TryFrom;

  use crate::prelude::*;
  use anyhow::Result;

  #[cfg(feature = "time")]
  use time::format_description::well_known::Rfc3339;

  #[cfg(feature = "time")]
  fn rfc3339_from_now_plus_secs(secs: i64) -> String {
    let d = time::Duration::seconds(secs);
    (time::OffsetDateTime::now_utc() + d)
      .format(&Rfc3339)
      .expect("format failed")
  }

  #[cfg(feature = "chrono")]
  fn rfc3339_from_now_plus_secs(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
  }

  fn date_from_rfc3339(s: &str) -> String {
    iso8601::datetime(s).expect("iso8601 parse failed").date.to_string()
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn usage_before_ready_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //let not_before = Utc::now() + Duration::hours(1);
    let not_before = rfc3339_from_now_plus_secs(3600);
    //create a default builder
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(NotBeforeClaim::try_from(not_before)?)
      .build(&key)?;
    let expected_error = format!(
      "{}",
      PasetoParser::<V2, Local>::default().parse(&token, &key).unwrap_err()
    );

    assert!(expected_error.starts_with("The token cannot be used before "));
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn non_expiring_token_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //we're going to set a token expiration date to 10 minutes ago
    let expired = rfc3339_from_now_plus_secs(-600);

    //create a default builder
    let token = PasetoBuilder::<V2, Local>::default()
      //setting our claim
      .set_claim(ExpirationClaim::try_from(expired)?)
      //by setting this we ensure we won't fail
      .set_no_expiration_danger_acknowledged()
      //without the line above this would have errored as an expired token
      .build(&key)?;

    //Both sides must acknowledge non-expiring tokens. The parser's default
    //rejects missing `exp`; the builder's symmetric opt-in only relaxes the
    //builder side, so we apply the parser opt-in here too.
    let token = PasetoParser::<V2, Local>::default()
      .set_no_expiration_danger_acknowledged()
      .parse(&token, &key)?;

    assert!(token["iat"].is_string());
    assert!(token["exp"].is_null());

    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn parser_rejects_missing_exp_by_default() -> Result<()> {
    //Regression test for the security audit finding: an attacker with
    //the signing key could mint a forever-token without `exp`, and the
    //old default parser silently accepted it. The default now rejects
    //missing exp as PasetoClaimError::Missing("exp").

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    //Forge a token with no exp by using the builder's opt-in.
    let token = PasetoBuilder::<V2, Local>::default()
      .set_no_expiration_danger_acknowledged()
      .build(&key)?;

    //The default parser must reject it.
    let result = PasetoParser::<V2, Local>::default().parse(&token, &key);
    assert!(result.is_err(), "default parser must reject a token with no exp claim",);
    let err = format!("{}", result.unwrap_err());
    assert!(
      err.contains("exp"),
      "error should mention the missing exp claim, got: {err}",
    );

    //But it must accept the same token when the caller opts in.
    PasetoParser::<V2, Local>::default()
      .set_no_expiration_danger_acknowledged()
      .parse(&token, &key)?;

    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn expired_token_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let expired = rfc3339_from_now_plus_secs(-600);
    //create a default builder
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(ExpirationClaim::try_from(expired)?)
      .build(&key)?;
    let expected_error = format!(
      "{}",
      PasetoParser::<V2, Local>::default().parse(&token, &key).unwrap_err()
    );

    assert_eq!(expected_error, "This token is expired");
    Ok(())
  }

  #[cfg(feature = "v2_public")]
  #[test]
  fn basic_paseto_parser_test_v2_public() -> Result<()> {
    //setup
    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    let private_key = Key::<64>::try_from(
            "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
        )?;
    let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    //create a default builder
    let token = PasetoBuilder::<V2, Public>::default().build(&private_key)?;

    //default parser
    let json = PasetoParser::<V2, Public>::default().parse(&token, &public_key)?;

    //verify the default claims and no others are in the token
    assert!(json["exp"].is_string());
    assert!(json["iat"].is_string());
    assert!(json["nbf"].is_string());
    assert!(json["sub"].is_null());
    assert!(json["iss"].is_null());
    assert!(json["jti"].is_null());
    assert!(json["aud"].is_null());
    assert!(!json["aud"].is_string());
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn github_issue_29_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a default builder
    let bad_token = "v4.local.1234";

    //default parser
    let json = PasetoParser::<V2, Local>::default().parse(&bad_token, &key);
    assert!(json.is_err());
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn basic_paseto_parser_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a default builder
    let token = PasetoBuilder::<V2, Local>::default().build(&key)?;

    //default parser
    let json = PasetoParser::<V2, Local>::default().parse(&token, &key)?;

    //verify the default claims and no others are in the token
    assert!(json["exp"].is_string());
    assert!(json["iat"].is_string());
    assert!(json["nbf"].is_string());
    assert!(json["sub"].is_null());
    assert!(json["iss"].is_null());
    assert!(json["jti"].is_null());
    assert!(json["aud"].is_null());
    assert!(!json["aud"].is_string());
    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn update_default_issued_at_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let tomorrow = rfc3339_from_now_plus_secs(86400);

    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(IssuedAtClaim::try_from(tomorrow).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    PasetoParser::<V2, Local>::default()
      .validate_claim(IssuedAtClaim::default(), &|key, value| {
        //let's get the value
        let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        //let tomorrow = Utc::now() + Duration::days(1);
        let tomorrow = date_from_rfc3339(&rfc3339_from_now_plus_secs(86400));
        //the claimm should exist
        assert_eq!(key, "iat");
        //date should be tomorrow
        assert_eq!(datetime.date.to_string(), tomorrow);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn check_for_default_issued_at_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    PasetoParser::<V2, Local>::default()
      .validate_claim(IssuedAtClaim::default(), &|key, value| {
        //let's get the value
        let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        //the claimm should exist
        let now = date_from_rfc3339(&rfc3339_from_now_plus_secs(0));
        assert_eq!(key, "iat");
        //date should be today
        assert_eq!(datetime.date.to_string(), now);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn update_default_expiration_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let in_4_days = rfc3339_from_now_plus_secs(4 * 86400);

    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(ExpirationClaim::try_from(in_4_days).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    PasetoParser::<V2, Local>::default()
      .validate_claim(ExpirationClaim::default(), &|key, value| {
        //let's get the value
        let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        //let in_4_days = Utc::now() + Duration::days(4);
        let in_4_days = date_from_rfc3339(&rfc3339_from_now_plus_secs(4 * 86400));
        //the claimm should exist
        assert_eq!(key, "exp");
        //date should be tomorrow
        assert_eq!(datetime.date.to_string(), in_4_days);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn check_for_default_expiration_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, with default ExpirationClaim
    let token = PasetoBuilder::<V2, Local>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    PasetoParser::<V2, Local>::default()
      .validate_claim(ExpirationClaim::default(), &|key, value| {
        //let's get the value
        let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        let in_an_hour = date_from_rfc3339(&rfc3339_from_now_plus_secs(3600));
        //the claimm should exist
        assert_eq!(key, "exp");
        //date should be today (or tomorrow if we're within 1 hour of midnight)
        assert_eq!(datetime.date.to_string(), in_an_hour);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn full_paseto_parser_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let footer = Footer::from("some footer");

    //create a builder, add some claims and then build the token with the key
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(AudienceClaim::from("customers"))
      .set_claim(SubjectClaim::from("loyal subjects"))
      .set_claim(IssuerClaim::from("me"))
      .set_claim(TokenIdentifierClaim::from("me"))
      .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(ExpirationClaim::try_from("2050-01-01T00:00:00+00:00")?)
      .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .set_claim(CustomClaim::try_from(("seats", 4))?)
      .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
      .set_footer(footer)
      .build(&key)?;

    //now let's decrypt the token and verify the values
    let json = PasetoParser::<V2, Local>::default()
      .check_claim(AudienceClaim::from("customers"))
      .check_claim(SubjectClaim::from("loyal subjects"))
      .check_claim(IssuerClaim::from("me"))
      .check_claim(TokenIdentifierClaim::from("me"))
      .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(ExpirationClaim::try_from("2050-01-01T00:00:00+00:00")?)
      .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .check_claim(CustomClaim::try_from(("seats", 4))?)
      .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
      .set_footer(footer)
      .parse(&token, &key)?;

    // we can access all the values from the serde Value object returned by the parser
    assert_eq!(json["aud"], "customers");
    assert_eq!(json["jti"], "me");
    assert_eq!(json["iss"], "me");
    assert_eq!(json["data"], "this is a secret message");
    assert_eq!(json["exp"], "2050-01-01T00:00:00+00:00");
    assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["sub"], "loyal subjects");
    assert_eq!(json["pi to 6 digits"], 3.141526);
    assert_eq!(json["seats"], 4);
    Ok(())
  }
}
