use super::GenericParserError;
use crate::generic::*;

use core::marker::PhantomData;
use serde_json::Value;
use std::collections::HashMap;

///The GenericParser is created at compile time by specifying a PASETO version and purpose and
///providing a key of the same version and purpose. This structure allows parsing an untrusted token string
///and either decrypting (Local) or verifying the signtature of (Public) PASETO tokens and then
///parsing and validating [PASETO claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md).
///
///The intent of the GenericParser is to allow the user to wrap basic PASETO standard
///functionality with their own custom business rules or ergonomic API. For most users, the batteries-included
///[paseto parser](crate::prelude::PasetoParser) will be all they need. More advanced cases can wrap this
///or the [core](Paseto) struct to accomplish custom functionality.
///
///
///# Usage
///
///```
///# #[cfg(all(feature = "generic", feature="v2_local"))]
///# {
///   use rusty_paseto::generic::*;

///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

///     let footer = Footer::from("some footer");

///     //create a builder, add some claims and then build the token with the key
///     let token = GenericBuilder::<V2, Local>::default()
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
///     let json = GenericParser::<V2, Local>::default()
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

pub struct GenericParser<'a, 'b, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize + 'b>>,
  claim_validators: ValidatorMap,
  footer: Footer<'a>,
  implicit_assertion: ImplicitAssertion<'a>,
}

impl<'a, 'b, Version, Purpose> GenericParser<'a, 'b, Version, Purpose> {
  ///Creates a new parser for building. Called by [Default]
  pub fn new() -> Self {
    GenericParser::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::new(),
      claim_validators: HashMap::new(),
      footer: Default::default(),
      implicit_assertion: Default::default(),
    }
  }
  ///Allows adding multiple [claims](PasetoClaim) at once to be checked during parsing by passing a Hashmap of claim keys and values
  pub fn extend_check_claims(&mut self, value: HashMap<String, Box<dyn erased_serde::Serialize + 'b>>) -> &mut Self {
    self.claims.extend(value);
    self
  }

  ///Allows adding multiple [validators](PasetoClaim) at once to be checked during parsing by passing a [ValidatorMap] of claim keys and values
  pub fn extend_validation_claims(&mut self, value: ValidatorMap) -> &mut Self {
    self.claim_validators.extend(value);
    self
  }

  #[cfg(feature = "serde")]
  fn set_validation_claim<T: PasetoClaim + 'b + serde::Serialize>(
    &mut self,
    value: T,
    validation_closure: Option<&'static ValidatorFn>,
  ) -> &mut Self {
    let key = value.get_key().to_string();
    //first store the claim
    self.claims.insert(key.clone(), Box::new(value));

    //if there's a closure, then store that
    if let Some(closure) = validation_closure {
      self.claim_validators.insert(key, Box::new(closure));
    }
    self
  }

  ///Allows user to pass a [PasetoClaim] along with a [custom function](ValidatorFn) to enable
  ///custom validation algorithms on the claim. The claim can be a reserved claim or a custom
  ///claim.
  #[cfg(feature = "serde")]
  pub fn validate_claim<T: PasetoClaim + 'b + serde::Serialize>(
    &mut self,
    value: T,
    validation_closure: &'static ValidatorFn,
  ) -> &mut Self {
    self.set_validation_claim(value, Some(validation_closure))
  }

  ///Verifies a passed [PasetoClaim] exists
  #[cfg(feature = "serde")]
  pub fn check_claim<T: PasetoClaim + 'b + serde::Serialize>(&mut self, value: T) -> &mut Self {
    self.set_validation_claim(value, None)
  }

  /// Gets an optional [Footer] set during parser building
  pub fn get_footer(&self) -> Footer {
    self.footer
  }
  ///Sets an optional [Footer] to use during parsing
  pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
    self.footer = footer;
    self
  }
}

impl<'a, 'b, Version: ImplicitAssertionCapable, Purpose> GenericParser<'a, 'b, Version, Purpose> {
  ///Sets an optional [ImplicitAssertion] to use during parsing ([V3], [V4] tokens only)
  pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
    self.implicit_assertion = implicit_assertion;
    self
  }

  ///Gets an optional [ImplicitAssertion] to use during parsing ([V3], [V4] tokens only)
  pub fn get_implicit_assertion(&self) -> ImplicitAssertion {
    self.implicit_assertion
  }
}

impl<'a, 'b, Version, Purpose> GenericParser<'a, 'b, Version, Purpose> {
  fn verify_claims(&self, token: &str) -> Result<Value, GenericParserError> {
    let json: Value = serde_json::from_str(token)?;

    // here we want to traverse all of the claims to validate and verify their values
    for (key, box_val) in &self.claims {
      //ensure the claim exists
      //get the raw value of the claim
      let raw = serde_json::to_value(box_val)?;

      //now let's run any custom validation if there is any
      if self.claim_validators.contains_key(key) {
        let box_validator = &self.claim_validators[key];
        let validator = box_validator.as_ref();
        validator(key, &json[&key])?;
      } else {
        //otherwise, simply verify the claim exists and matches the value passed in
        if json[&key] == Value::Null {
          return Err(PasetoClaimError::Missing(key.to_string()).into());
        }

        if raw[&key] != json[&key] {
          return Err(
            PasetoClaimError::Invalid(
              key.to_string(),
              json[&key]
                .as_str()
                .ok_or_else(|| PasetoClaimError::Unexpected(key.to_string()))?
                .into(),
              raw[&key]
                .as_str()
                .ok_or_else(|| PasetoClaimError::Unexpected(key.to_string()))?
                .into(),
            )
            .into(),
          );
        }
      }
    }

    Ok(json)
  }
}

#[cfg(feature = "v1_local")]
impl<'a, 'b> GenericParser<'a, 'b, V1, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V1, Local) encrypted PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v1_local"))]
  ///# {
  ///   use rusty_paseto::generic::*;

  ///     let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

  ///     let footer = Footer::from("some footer");

  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = GenericBuilder::<V1, Local>::default()
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
  ///     let json = GenericParser::<V1, Local>::default()
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

  pub fn parse(
    &self,
    potential_token: &'a str,
    key: &'a PasetoSymmetricKey<V1, Local>,
  ) -> Result<Value, GenericParserError> {
    //decrypt, then validate
    let token = Paseto::<V1, Local>::try_decrypt(potential_token, key, self.get_footer())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v2_local")]
impl<'a, 'b> GenericParser<'a, 'b, V2, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V2, Local) encrypted PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::generic::*;

  ///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

  ///     let footer = Footer::from("some footer");

  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = GenericBuilder::<V2, Local>::default()
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
  ///     let json = GenericParser::<V2, Local>::default()
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

  pub fn parse(
    &mut self,
    potential_token: &'a str,
    key: &'a PasetoSymmetricKey<V2, Local>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token = Paseto::<V2, Local>::try_decrypt(potential_token, key, self.get_footer())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v3_local")]
impl<'a, 'b> GenericParser<'a, 'b, V3, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V3, Local) encrypted PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v3_local"))]
  ///# {
  ///   use rusty_paseto::generic::*;

  ///     let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

  ///     let footer = Footer::from("some footer");
  ///     let implicit_assertion = ImplicitAssertion::from("some assertion");

  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = GenericBuilder::<V3, Local>::default()
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
  ///     let json = GenericParser::<V3, Local>::default()
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

  pub fn parse(
    &mut self,
    potential_token: &'a str,
    key: &'a PasetoSymmetricKey<V3, Local>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token =
      Paseto::<V3, Local>::try_decrypt(potential_token, key, self.get_footer(), self.get_implicit_assertion())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v4_local")]
impl<'a, 'b> GenericParser<'a, 'b, V4, Local> {
  /// Given a [PasetoSymmetricKey], attempts to decrypt a (V4, Local) encrypted PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the decrypted [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v4_local"))]
  ///# {
  ///   use rusty_paseto::generic::*;

  ///     let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

  ///     let footer = Footer::from("some footer");
  ///     let implicit_assertion = ImplicitAssertion::from("some assertion");

  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = GenericBuilder::<V4, Local>::default()
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
  ///     let json = GenericParser::<V4, Local>::default()
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

  pub fn parse(
    &mut self,
    potential_token: &'a str,
    key: &'a PasetoSymmetricKey<V4, Local>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token =
      Paseto::<V4, Local>::try_decrypt(potential_token, key, self.get_footer(), self.get_implicit_assertion())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v1_public")]
impl<'a, 'b> GenericParser<'a, 'b, V1, Public> {
  /// Given a [PasetoAsymmetricPublicKey], attempts to verify a (V1, Public) signed PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v1_public"))]
  ///# {
  ///   # use rusty_paseto::generic::*;

  ///    //obtain a private key (pk)
  ///   # let private_key = include_bytes!("../../../tests/v1_public_test_vectors_private_key.pk8");
  ///   # let pk: &[u8] = private_key;
  ///    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

  ///     let footer = Footer::from("some footer");

  ///     //sign a public V1 token
  ///     let token = GenericBuilder::<V1, Public>::default()
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
  ///     let json = GenericParser::<V1, Public>::default()
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
    potential_token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V1, Public>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token = Paseto::<V1, Public>::try_verify(potential_token, key, self.get_footer())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v2_public")]
impl<'a, 'b> GenericParser<'a, 'b, V2, Public> {
  /// Given a [PasetoAsymmetricPublicKey], attempts to verify a (V2, Public) signed PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v1_public"))]
  ///# {
  ///   # use rusty_paseto::generic::*;

  ///    //obtain a key
  /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

  /// let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

  /// let footer = Footer::from("some footer");

  /// //sign a public V2 token
  /// let token = GenericBuilder::<V2, Public>::default()
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
  /// let json = GenericParser::<V2, Public>::default()
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
    potential_token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V2, Public>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token = Paseto::<V2, Public>::try_verify(potential_token, key, self.get_footer())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v3_public")]
impl<'a, 'b> GenericParser<'a, 'b, V3, Public> {
  /// Given a [PasetoAsymmetricPublicKey], attempts to verify a (V3, Public) signed PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v3_public"))]
  ///# {
  ///   # use rusty_paseto::generic::*;

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
  /// let token = GenericBuilder::<V3, Public>::default()
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
  /// let json = GenericParser::<V3, Public>::default()
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
    potential_token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V3, Public>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token =
      Paseto::<V3, Public>::try_verify(potential_token, key, self.get_footer(), self.get_implicit_assertion())?;

    self.verify_claims(&token)
  }
}

#[cfg(feature = "v4_public")]
impl<'a, 'b> GenericParser<'a, 'b, V4, Public> {
  /// Given a [PasetoAsymmetricPublicKey], attempts to verify a (V4, Public) signed PASETO token string and then validate
  /// claims provided to the GenericParser.
  ///
  /// Returns a serde_json [Value] with the verified [claims](PasetoClaim) and payload on success.
  ///
  /// # Errors
  ///
  /// Returns [`GenericParserError`] for any errors when decrypting the encrypted payload or when validating claims.
  ///
  /// # Example
  ///
  ///```
  ///# #[cfg(all(feature = "generic", feature="v4_public"))]
  ///# {
  ///   # use rusty_paseto::generic::*;

  /// //create a key
  /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let pk: &[u8] = private_key.as_slice();
  /// let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

  /// let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
  /// let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

  /// let footer = Footer::from("some footer");
  /// let implicit_assertion = ImplicitAssertion::from("some assertion");

  /// //sign a public V4 token
  /// let token = GenericBuilder::<V4, Public>::default()
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
  /// let json = GenericParser::<V4, Public>::default()
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
    potential_token: &'a str,
    key: &'a PasetoAsymmetricPublicKey<V4, Public>,
  ) -> Result<Value, GenericParserError> {
    //first we need to verify the token
    let token =
      Paseto::<V4, Public>::try_verify(potential_token, key, self.get_footer(), self.get_implicit_assertion())?;

    self.verify_claims(&token)
  }
}

impl<'a, 'b, Version, Purpose> Default for GenericParser<'a, 'b, Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(all(test, feature = "v2"))]
mod parsers {

  use std::convert::TryFrom;

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[cfg(all(test, feature="v2_public"))]
  #[test]
  fn full_parser_test_v2_public() -> Result<()> {
    //create a key
    let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    //    let key = Key::<V2, Public>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let footer = Footer::from("some footer");

    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V2, Public>::default()
      .set_claim(AudienceClaim::from("customers"))
      .set_claim(SubjectClaim::from("loyal subjects"))
      .set_claim(IssuerClaim::from("me"))
      .set_claim(TokenIdentifierClaim::from("me"))
      .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .set_claim(CustomClaim::try_from(("seats", 4))?)
      .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
      .set_footer(footer)
      .try_sign(&private_key)?;

    //now let's decrypt the token and verify the values
    let json = GenericParser::<V2, Public>::default()
      .check_claim(AudienceClaim::from("customers"))
      .check_claim(SubjectClaim::from("loyal subjects"))
      .check_claim(IssuerClaim::from("me"))
      .check_claim(TokenIdentifierClaim::from("me"))
      .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .check_claim(CustomClaim::try_from(("seats", 4))?)
      .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
      .set_footer(footer)
      .parse(&token, &public_key)?;

    // we can access all the values from the serde Value object returned by the parser
    assert_eq!(json["aud"], "customers");
    assert_eq!(json["jti"], "me");
    assert_eq!(json["iss"], "me");
    assert_eq!(json["data"], "this is a secret message");
    assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["sub"], "loyal subjects");
    assert_eq!(json["pi to 6 digits"], 3.141526);
    assert_eq!(json["seats"], 4);
    Ok(())
  }

  #[cfg(all(test, feature="v2_local"))]
  #[test]
  fn full_parser_test() -> Result<()> {
    //create a key
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let footer = Footer::from("some footer");

    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default()
      .set_claim(AudienceClaim::from("customers"))
      .set_claim(SubjectClaim::from("loyal subjects"))
      .set_claim(IssuerClaim::from("me"))
      .set_claim(TokenIdentifierClaim::from("me"))
      .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .set_claim(CustomClaim::try_from(("seats", 4))?)
      .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
      .set_footer(footer)
      .try_encrypt(&key)?;

    //now let's decrypt the token and verify the values
    let json = GenericParser::<V2, Local>::default()
      .check_claim(AudienceClaim::from("customers"))
      .check_claim(SubjectClaim::from("loyal subjects"))
      .check_claim(IssuerClaim::from("me"))
      .check_claim(TokenIdentifierClaim::from("me"))
      .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
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
    assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["sub"], "loyal subjects");
    assert_eq!(json["pi to 6 digits"], 3.141526);
    assert_eq!(json["seats"], 4);
    Ok(())
  }

  #[cfg(feature="v2_local")]
  #[test]
  fn basic_claim_validation_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default()
      .set_claim(AudienceClaim::from("customers"))
      .try_encrypt(&key)?;

    //now let's decrypt the token and verify the values
    let actual_error_kind = format!(
      "{}",
      GenericParser::<V2, Local>::default()
        .check_claim(AudienceClaim::from("not the same customers"))
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind =
      "The claim 'aud' failed validation.  Expected 'customers' but received 'not the same customers'";
    assert_eq!(expected_error_kind, actual_error_kind);

    Ok(())
  }

  #[cfg(feature="v2_local")]
  #[test]
  fn claim_custom_validator_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default()
      .set_claim(AudienceClaim::from("customers"))
      .try_encrypt(&key)?;

    //now let's decrypt the token and verify the values with a custom validation closure
    let json = GenericParser::<V2, Local>::default()
      .validate_claim(
        //no need to provide a value to check against for the claim when we are using
        //a custom closure since the value will be passed to the closure for evaluation by your
        //validation function
        AudienceClaim::default(),
        &|key, value| {
          //we receive the value of the claim so we can do whatever we like with it
          //get the value of the claim
          let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

          match val {
            "customers" => Ok(()),
            _ => Err(PasetoClaimError::Invalid(key.to_string(), String::from("customers"), val.to_string()).into()),
          }
        },
      )
      .parse(&token, &key)?;

    assert_eq!(json["aud"], "customers");
    Ok(())
  }

  #[cfg(feature="v2_local")]
  #[test]
  fn claim_custom_validator_failure_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default()
      .set_claim(AudienceClaim::from("customers"))
      .try_encrypt(&key)?;

    //now let's decrypt the token and verify the values with a custom validation closure
    let actual_error_kind = format!(
      "{}",
      GenericParser::<V2, Local>::default()
        .validate_claim(
          //no need to provide a value to check against for the claim when we are using
          //a custom closure since the value will be passed to the closure for evaluation by your
          //validation function
          AudienceClaim::default(),
          &|key, value| {
            //we receive the value of the claim so we can do whatever we like with it
            //get the value of the claim
            let val = value.as_str().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

            //let's fail on purpose
            Err(PasetoClaimError::Invalid(key.to_string(), "".to_string(), val.to_string()).into())
          }
        )
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind = "The claim 'aud' failed validation.  Expected '' but received 'customers'";
    assert_eq!(expected_error_kind, actual_error_kind);
    Ok(())
  }

  #[cfg(feature="v2_local")]
  #[test]
  fn custom_claim_custom_validator_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default()
      .set_claim(CustomClaim::try_from(("seats", 4))?)
      .try_encrypt(&key)?;

    //now let's decrypt the token and verify the values with a custom validation closure
    let actual_error_kind = format!(
      "{}",
      GenericParser::<V2, Local>::default()
        .validate_claim(
          //no need to provide a value to check against for the claim when we are using
          //a custom closure since the value will be passed to the closure for evaluation by your
          //validation function
          CustomClaim::try_from("seats")?,
          &|key, value| {
            //we receive the value of the claim so we can do whatever we like with it
            //get the value of the claim
            let val = value.as_u64().ok_or(PasetoClaimError::Unexpected(key.to_string()))?;

            //let's fail on purpose
            Err(PasetoClaimError::Invalid(key.to_string(), "".to_string(), val.to_string()).into())
          }
        )
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind = "The claim 'seats' failed validation.  Expected '' but received '4'";
    assert_eq!(expected_error_kind, actual_error_kind);

    Ok(())
  }

  #[cfg(feature="v2_local")]
  #[test]
  fn missing_claim_validation_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add no claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default().try_encrypt(&key)?;

    //now let's decrypt the token and verify the values
    let actual_error_kind = format!(
      "{}",
      GenericParser::<V2, Local>::default()
        .check_claim(AudienceClaim::from("this claim doesn't exist"))
        .parse(&token, &key)
        .unwrap_err()
    );
    let expected_error_kind = "The expected claim 'aud' was not found in the payload";

    //the claim we're looking for was not in the original token so we receive an error
    assert_eq!(expected_error_kind, actual_error_kind);
    Ok(())
  }
}
