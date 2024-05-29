use crate::generic::*;
use core::marker::PhantomData;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

///The PasetoParser is created at compile time by specifying a PASETO version and purpose and
///providing a key of the same version and purpose. This structure allows setting [PASETO claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md),
///your own [custom claims](CustomClaim), an optional [footer](Footer) and in the case of V3/V4 tokens, an optional [implicit
///assertion](ImplicitAssertion).
///Additionally, a user can
///
///The PasetoBuilder wraps the [GenericBuilder] with JWT style claims and business rules which align
///with the PASETO standard.
/// For most users, this batteries-included struct
/// will be all they need.
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
    /// Creates a new parser. Called by [Default]
    ///
    /// Returns a new PASETO parser builder for construction.
    ///
    /// # Errors
    /// none
    ///
    /// # Example (use default)
    ///```
    ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
    ///# {
    ///   use rusty_paseto::prelude::*;

    ///     # let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    ///     # let footer = Footer::from("some footer");

    ///     # //create a builder, add some claims and then build the token with the key
    ///     # let token = PasetoBuilder::<V2, Local>::default()
    ///     #  .try_encrypt(&key)?;

    ///     //decrypt and parse claims from the PASETO token string
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
    /// Takes a [PasetoClaim] and a [ValidatorFn] and uses the function to validate the claim during
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

    ///     let in_an_hour = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
    ///       .time()
    ///       .hour()
    ///       .to_string();
    ///     //the claimm should exist
    ///     assert_eq!(key, "exp");
    ///     //date should be today
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
    /// Takes a [PasetoClaim] to ensure existence of the claim and it's value during
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

    pub fn check_claim<T: PasetoClaim + 'static + serde::Serialize>(&mut self, value: T) -> &mut Self {
        self.parser.check_claim(value);
        self
    }

    ///Sets an optional [Footer] to use during parsing
    pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
        self.parser.set_footer(footer);
        self
    }
}

impl<'a, Version, Purpose> PasetoParser<'a, Version, Purpose>
    where
        Version: ImplicitAssertionCapable,
{
    ///Sets an optional [ImplicitAssertion] to use during parsing ([V3], [V4] tokens only)
    pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
        self.parser.set_implicit_assertion(implicit_assertion);
        self
    }
}

impl<'a, Version, Purpose> Default for PasetoParser<'a, Version, Purpose> {
    fn default() -> Self {
        let mut me = Self::new();
        me.validate_claim(ExpirationClaim::default(), &|_, value| {
            //let's get the expiration claim value
            let val = value.as_str().unwrap_or_default();

            //check if this is a non-expiring token
            if val.is_empty() {
                //this means the claim wasn't found, which means this is a non-expiring token
                //and we can just skip this validation
                return Ok(());
            }
            //turn the value into a datetime
            let datetime =
                time::OffsetDateTime::parse(val, &Rfc3339).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
            //get the current datetime
            let now = time::OffsetDateTime::now_utc();

            //here we do the actual validation check for the expiration claim
            if datetime <= now {
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
                //turn the value into a datetime
                let not_before_time =
                    time::OffsetDateTime::parse(val, &Rfc3339).map_err(|_| PasetoClaimError::RFC3339Date(val.to_string()))?;
                //get the current datetime
                let now = time::OffsetDateTime::now_utc();

                //here we do the actual validation check for the expiration claim
                if now <= not_before_time {
                    Err(PasetoClaimError::UseBeforeAvailable(not_before_time.to_string()))
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
}

#[cfg(feature = "v4_local")]
impl<'a> PasetoParser<'a, V4, Local> {
    /// Given a [PasetoSymmetricKey], attempts to decrypt a (V4, Local) encrypted PASETO token string and then validate
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
}

#[cfg(feature = "v1_public")]
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
    /// # Example
    ///```
    ///# #[cfg(all(feature = "prelude", feature="v1_public"))]
    ///# {
    ///   # use rusty_paseto::prelude::*;

    ///    //obtain a private key (pk)
    ///   # let private_key = include_bytes!("../../../tests/v1_public_test_vectors_private_key.pk8");
    ///   # let pk: &[u8] = private_key;
    ///    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

    ///     let footer = Footer::from("some footer");

    ///     //sign a public V1 token
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
    ///     let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);
    ///     //now let's try to verify it
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

    pub fn parse(
        &mut self,
        token: &'a str,
        key: &'a PasetoAsymmetricPublicKey<V1, Public>,
    ) -> Result<Value, GenericParserError> {
        //return the full json value to the user
        self.parser.parse(token, key)
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
    ///# #[cfg(all(feature = "prelude", feature="v1_public"))]
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
}

#[cfg(feature = "v4_public")]
impl<'a> PasetoParser<'a, V4, Public> {
    /// Given a [PasetoAsymmetricPrivateKey], attempts to verify a signed (V4, Public) PASETO token string and then validate
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
    ///# #[cfg(all(feature = "prelude", feature="v4_public"))]
    ///# {
    ///   # use rusty_paseto::prelude::*;

    /// //create a key
    /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    /// let pk: &[u8] = private_key.as_slice();
    /// let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

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
    #[cfg(feature="v2_local")]
    use time::format_description::well_known::Rfc3339;

    #[cfg(feature="v2_local")]
    #[test]
    fn usage_before_ready_test() -> Result<()> {
        //create a key

        let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        //let not_before = Utc::now() + Duration::hours(1);
        let not_before = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).format(&Rfc3339)?;
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

    #[cfg(feature="v2_local")]
    #[test]
    fn non_expiring_token_claim_test() -> Result<()> {
        //create a key

        let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        //we're going to set a token expiration date to 10 minutes ago
        let expired = (time::OffsetDateTime::now_utc() + time::Duration::minutes(-10)).format(&Rfc3339)?;

        //create a default builder
        let token = PasetoBuilder::<V2, Local>::default()
            //setting our claim
            .set_claim(ExpirationClaim::try_from(expired)?)
            //by setting this we ensure we won't fail
            .set_no_expiration_danger_acknowledged()
            //without the line above this would have errored as an expired token
            .build(&key)?;

        let token = PasetoParser::<V2, Local>::default().parse(&token, &key)?;

        assert!(token["iat"].is_string());
        assert!(token["exp"].is_null());

        Ok(())
    }

    #[cfg(feature="v2_local")]
    #[test]
    fn expired_token_claim_test() -> Result<()> {
        //create a key

        let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        let expired = (time::OffsetDateTime::now_utc() + time::Duration::minutes(-10)).format(&Rfc3339)?;
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

    #[cfg(feature="v2_public")]
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

    #[cfg(feature="v2_local")]
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


    #[cfg(feature="v2_local")]
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

    #[cfg(feature="v2_local")]
    #[test]
    fn update_default_issued_at_claim_test() -> Result<()> {
        //create a key

        let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        let tomorrow = (time::OffsetDateTime::now_utc() + time::Duration::days(1)).format(&Rfc3339)?;

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
                let tomorrow = (time::OffsetDateTime::now_utc() + time::Duration::days(1))
                    .date()
                    .to_string();
                //the claimm should exist
                assert_eq!(key, "iat");
                //date should be tomorrow
                assert_eq!(datetime.date.to_string(), tomorrow);

                Ok(())
            })
            .parse(&token, &key)?;

        Ok(())
    }

    #[cfg(feature="v2_local")]
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
                let now = time::OffsetDateTime::now_utc().date().to_string();
                assert_eq!(key, "iat");
                //date should be today
                assert_eq!(datetime.date.to_string(), now);

                Ok(())
            })
            .parse(&token, &key)?;

        Ok(())
    }

    #[cfg(feature="v2_local")]
    #[test]
    fn update_default_expiration_claim_test() -> Result<()> {
        //create a key

        let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        let in_4_days = (time::OffsetDateTime::now_utc() + time::Duration::days(4)).format(&Rfc3339)?;

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
                let in_4_days = (time::OffsetDateTime::now_utc() + time::Duration::days(4))
                    .date()
                    .to_string();
                //the claimm should exist
                assert_eq!(key, "exp");
                //date should be tomorrow
                assert_eq!(datetime.date.to_string(), in_4_days);

                Ok(())
            })
            .parse(&token, &key)?;

        Ok(())
    }

    #[cfg(feature="v2_local")]
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

                let in_an_hour = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
                    .time()
                    .hour()
                    .to_string();
                //the claimm should exist
                assert_eq!(key, "exp");
                //date should be today
                assert_eq!(datetime.time.hour.to_string(), in_an_hour);

                Ok(())
            })
            .parse(&token, &key)?;

        Ok(())
    }

    #[cfg(feature="v2_local")]
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
