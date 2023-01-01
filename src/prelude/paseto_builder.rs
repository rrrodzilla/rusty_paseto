use crate::generic::*;
use core::marker::PhantomData;
use std::collections::HashSet;
use std::convert::TryFrom;
use time::format_description::well_known::Rfc3339;

///The PasetoBuilder is created at compile time by specifying a PASETO version and purpose and
///providing a key of the same version and purpose. This structure allows setting [PASETO claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md),
///your own [custom claims](CustomClaim), an optional [footer](Footer) and in the case of V3/V4 tokens, an optional [implicit
///assertion](ImplicitAssertion).
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

pub struct PasetoBuilder<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  builder: GenericBuilder<'a, 'a, Version, Purpose>,
  top_level_claims: HashSet<String>,
  dup_top_level_found: (bool, String),
  non_expiring_token: bool,
}

impl<'a, Version, Purpose> PasetoBuilder<'a, Version, Purpose> {
  fn new() -> Self {
    PasetoBuilder::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      builder: GenericBuilder::default(),
      top_level_claims: HashSet::new(),
      non_expiring_token: false,
      dup_top_level_found: (false, String::default()),
    }
  }

  /// Given a [PasetoClaim], attempts to add it to the builder for inclusion in the payload of the
  /// token.
  /// claims provided to the GenericBuilder. Overwrites the default 'nbf' (not before) claim if
  /// provided. Prevents duplicate claims from being added.
  ///
  /// Returns a mutable reference to the builder on success.
  ///
  /// # Errors
  ///
  /// none
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = PasetoBuilder::<V2, Local>::default()
  ///       .set_claim(AudienceClaim::from("customers"))
  ///       .try_encrypt(&key)?;

  ///  #   //now let's decrypt the token and verify the values
  ///  #  let json = PasetoParser::<V2, Local>::default().parse(&token, &key)?;

  ///  # assert_eq!(json["aud"], "customers");
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```

  pub fn set_claim<T: PasetoClaim + erased_serde::Serialize + Sized + 'a>(&mut self, value: T) -> &mut Self {
    //we need to inspect all the claims and verify there are no duplicates
    //overwrite nbf default claim if provided
    if value.get_key() == "nbf" {
      //remove the existing claim
      self.builder.remove_claim(value.get_key());
    }
    if !self.top_level_claims.insert(value.get_key().to_string()) {
      self.dup_top_level_found = (true, value.get_key().to_string());
    }

    self.builder.set_claim(value);
    self
  }

  /// Sets the token to have no expiration date.
  /// A **1 hour** ExpirationClaim is set by default because the use case for non-expiring tokens in the world of security tokens is fairly limited.
  ///  Omitting an expiration claim or forgetting to require one when processing them
  ///  is almost certainly an oversight rather than a deliberate choice.  

  ///  When it is a deliberate choice, you have the opportunity to deliberately remove this claim from the Builder.
  ///  This method call ensures readers of the code understand the implicit risk.
  ///
  /// Returns a mutable reference to the builder on success.
  ///
  /// # Errors
  /// none
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///  let token = PasetoBuilder::<V4, Local>::default()
  ///    .set_claim(ExpirationClaim::try_from(in_5_minutes)?)
  ///    // even if you set an expiration claim (as above) it will be ignored
  ///    // due to the method call below
  ///    .set_no_expiration_danger_acknowledged()
  ///    .build(&key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```

  pub fn set_no_expiration_danger_acknowledged(&mut self) -> &mut Self {
    self.top_level_claims.insert("exp".to_string());
    self.non_expiring_token = true;
    self
  }

  /// Sets an optional [Footer] on the token.
  ///
  /// Returns a mutable reference to the builder on success.
  ///
  /// # Errors
  ///none
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v2_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///  let token = PasetoBuilder::<V2, Local>::default()
  ///    .set_footer(Footer::from("Some footer"))
  ///    .build(&key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```

  pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
    self.builder.set_footer(footer);
    self
  }

  fn verify_ready_to_build(&mut self) -> Result<(), GenericBuilderError> {
    if self.non_expiring_token {
      self.builder.remove_claim("exp");
    }
    //  //raise an error if there were duplicates
    let (dup_found, dup_key) = &self.dup_top_level_found;
    if *dup_found {
      return Err(GenericBuilderError::DuplicateTopLevelPayloadClaim(dup_key.to_string()));
    }
    Ok(())
  }
}
impl<'a, Version, Purpose> PasetoBuilder<'a, Version, Purpose>
where
  Version: ImplicitAssertionCapable,
{
  /// Sets an optional [ImplicitAssertion] on the token. ([V3] or [V4] tokens only)
  ///
  /// Returns a mutable reference to the builder on success.
  ///
  /// # Errors
  ///none
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v3_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;
  ///     let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
  ///  let token = PasetoBuilder::<V3, Local>::default()
  ///    .set_implicit_assertion(ImplicitAssertion::from("Some assertion"))
  ///    .build(&key)?;
  /// # }
  /// # Ok::<(),anyhow::Error>(())
  ///   ```

  pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
    self.builder.set_implicit_assertion(implicit_assertion);
    self
  }
}

impl<'a, Version, Purpose> Default for PasetoBuilder<'a, Version, Purpose> {
  fn default() -> Self {
    //the unwraps in this function should be Infallible
    let mut new_builder = Self::new();
    let now = time::OffsetDateTime::now_utc();
    let in_one_hour = now + time::Duration::hours(1);

    let expiration_time = in_one_hour.format(&Rfc3339).unwrap();
    let current_time = now.format(&Rfc3339).unwrap();
    //set some defaults
    new_builder
      .builder
      .set_claim(ExpirationClaim::try_from(expiration_time).unwrap())
      .set_claim(IssuedAtClaim::try_from(current_time.clone()).unwrap())
      .set_claim(NotBeforeClaim::try_from(current_time).unwrap());

    new_builder
  }
}

#[cfg(feature = "v1_local")]
impl PasetoBuilder<'_, V1, Local> {
  /// Attempts to validate claims meet PASETO standard requirements and then encrypt the token.
  ///
  /// Returns Ok(String) where the string is the encrypted PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or encryption issues.
  ///
  /// # Example
  ///```
  ///# #[cfg(all(feature = "prelude", feature="v1_local"))]
  ///# {
  ///   use rusty_paseto::prelude::*;

  ///     let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

  ///     let footer = Footer::from("some footer");

  ///     //create a builder, add some claims and then build the token with the key
  ///     let token = PasetoBuilder::<V1, Local>::default()
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
  ///       .build(&key)?;

  ///     //now let's decrypt the token and verify the values
  ///     let json = PasetoParser::<V1, Local>::default()
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

  pub fn build(&mut self, key: &PasetoSymmetricKey<V1, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v2_local")]
impl PasetoBuilder<'_, V2, Local> {
  /// Attempts to validate claims meet PASETO standard requirements and then encrypt the token.
  ///
  /// Returns Ok(String) where the string is the encrypted PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or encryption issues.
  ///
  /// # Example
  ///
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

  pub fn build(&mut self, key: &PasetoSymmetricKey<V2, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v3_local")]
impl PasetoBuilder<'_, V3, Local> {
  /// Attempts to validate claims meet PASETO standard requirements and then encrypt the token.
  ///
  /// Returns Ok(String) where the string is the encrypted PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or encryption issues.
  ///
  /// # Example
  ///
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

  pub fn build(&mut self, key: &PasetoSymmetricKey<V3, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v4_local")]
impl PasetoBuilder<'_, V4, Local> {
  /// Attempts to validate claims meet PASETO standard requirements and then encrypt the token.
  ///
  /// Returns Ok(String) where the string is the encrypted PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or encryption issues.
  ///
  /// # Example
  ///
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

  pub fn build(&mut self, key: &PasetoSymmetricKey<V4, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v1_public")]
impl PasetoBuilder<'_, V1, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to validate claims meet PASETO standard requirements and then sign the token.
  ///
  /// Returns Ok(String) where the string is the signed PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or signing issues.
  ///
  /// # Example
  ///
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

  pub fn build(&mut self, key: &PasetoAsymmetricPrivateKey<V1, Public>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_sign(key)
  }
}

#[cfg(feature = "v2_public")]
impl PasetoBuilder<'_, V2, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to validate claims meet PASETO standard requirements and then sign the token.
  ///
  /// Returns Ok(String) where the string is the signed PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or signing issues.
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

  pub fn build(&mut self, key: &PasetoAsymmetricPrivateKey<V2, Public>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_sign(key)
  }
}

#[cfg(feature = "v3_public")]
impl PasetoBuilder<'_, V3, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to validate claims meet PASETO standard requirements and then sign the token.
  ///
  /// Returns Ok(String) where the string is the signed PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or signing issues.
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

  pub fn build(&mut self, key: &PasetoAsymmetricPrivateKey<V3, Public>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_sign(key)
  }
}

#[cfg(feature = "v4_public")]
impl PasetoBuilder<'_, V4, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to validate claims meet PASETO standard requirements and then sign the token.
  ///
  /// Returns Ok(String) where the string is the signed PASETO token.
  ///
  /// # Errors
  /// [GenericBuilderError] if there are [claim](PasetoClaim) or signing issues.
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

  pub fn build(&mut self, key: &PasetoAsymmetricPrivateKey<V4, Public>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_sign(key)
  }
}

#[cfg(all(test, feature = "v2_local"))]
mod paseto_builder {

  use crate::prelude::*;
  use anyhow::Result;
  use std::convert::TryFrom;
  use time::format_description::well_known::Rfc3339;

  #[test]
  fn duplicate_top_level_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let tomorrow = (time::OffsetDateTime::now_utc() + time::Duration::days(1)).format(&Rfc3339)?;

    //let tomorrow = (Utc::now() + Duration::days(1)).to_rfc3339();

    //create a builder, with default IssuedAtClaim
    let expected_error = format!(
      "{}",
      PasetoBuilder::<V2, Local>::default()
        .set_claim(IssuedAtClaim::try_from(tomorrow.as_str()).unwrap())
        .set_claim(IssuedAtClaim::try_from(tomorrow.as_str()).unwrap())
        .build(&key)
        .unwrap_err()
    );

    assert_eq!(
      expected_error,
      "The claim 'iat' appears more than once in the top level payload json"
    );

    Ok(())
  }

  #[test]
  fn update_default_not_before_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let tomorrow = (time::OffsetDateTime::now_utc() + time::Duration::days(1)).format(&Rfc3339)?;

    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(NotBeforeClaim::try_from(tomorrow).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    let token_error = PasetoParser::<V2, Local>::default().parse(&token, &key).err().unwrap();

    assert!(token_error.to_string().starts_with("The token cannot be used before "));

    Ok(())
  }

  #[test]
  fn update_default_issued_at_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    let tomorrow = (time::OffsetDateTime::now_utc() + time::Duration::days(1)).format(&Rfc3339)?;

    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(IssuedAtClaim::try_from(tomorrow.as_str()).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    GenericParser::<V2, Local>::default()
      .validate_claim(IssuedAtClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or_else(|| PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();
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

  #[test]
  fn check_for_default_issued_at_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    GenericParser::<V2, Local>::default()
      .validate_claim(IssuedAtClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or_else(|| PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        let now = time::OffsetDateTime::now_utc().date().to_string();
        //the claimm should exist
        assert_eq!(key, "iat");
        //date should be today
        assert_eq!(datetime.date.to_string(), now);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn update_default_expiration_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //let in_4_days = (Utc::now() + Duration::days(4)).to_rfc3339();
    let in_4_days = (time::OffsetDateTime::now_utc() + time::Duration::days(4)).format(&Rfc3339)?;

    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default()
      .set_claim(ExpirationClaim::try_from(in_4_days).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    GenericParser::<V2, Local>::default()
      .validate_claim(ExpirationClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or_else(|| PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        let in_4_days = (time::OffsetDateTime::now_utc() + time::Duration::days(4))
          .date()
          .to_string();
        //let in_4_days = Utc::now() + Duration::days(4);
        //the claimm should exist
        assert_eq!(key, "exp");
        //date should be tomorrow
        assert_eq!(datetime.date.to_string(), in_4_days);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn check_for_default_expiration_claim_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, with default IssuedAtClaim
    let token = PasetoBuilder::<V2, Local>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    GenericParser::<V2, Local>::default()
      .validate_claim(ExpirationClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or_else(|| PasetoClaimError::Unexpected(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();
        let expires = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
          .date()
          .to_string();

        //let tomorrow = Utc::now() + Duration::hours(1);
        //the claimm should exist
        assert_eq!(key, "exp");
        //date should be today
        assert_eq!(datetime.date.to_string(), expires);

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn full_paseto_builder_test() -> Result<()> {
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
      .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .set_claim(CustomClaim::try_from(("seats", 4))?)
      .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
      .set_footer(footer)
      .build(&key)?;

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
}
