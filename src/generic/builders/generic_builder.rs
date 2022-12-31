use crate::generic::*;
use core::marker::PhantomData;
use std::fmt::Write;
use std::{collections::HashMap, mem::take};

///The GenericBuilder is created at compile time by specifying a PASETO version and purpose and
///providing a key of the same version and purpose. This structure allows setting [PASETO claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md),
///your own [custom claims](CustomClaim), an optional [footer](Footer) and in the case of V3/V4 tokens, an optional [implicit
///assertion](ImplicitAssertion).
///
///The intent of the GenericBuilder is to allow the user to wrap basic PASETO standard
///functionality with their own custom business rules or ergonomic API. For most users, the batteries-included
///[paseto builder](crate::prelude::PasetoBuilder) will be all they need. More advanced cases can wrap this
///or the [core](Paseto) struct to accomplish custom functionality.
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

pub struct GenericBuilder<'a, 'b, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize + 'b>>,
  footer: Option<Footer<'a>>,
  implicit_assertion: Option<ImplicitAssertion<'a>>,
}

impl<'a, 'b, Version, Purpose> GenericBuilder<'a, 'b, Version, Purpose> {
  fn new() -> Self {
    Self {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::with_capacity(10),
      footer: None,
      implicit_assertion: None,
    }
  }

  ///Removes a [claim](PasetoClaim) from the internal list of claims by passed key
  pub fn remove_claim(&mut self, claim_key: &str) -> &mut Self {
    self.claims.remove(claim_key);
    self
  }

  ///Allows adding multiple [claims](PasetoClaim) at once by passing a Hashmap of claim keys and values
  pub fn extend_claims(&mut self, value: HashMap<String, Box<dyn erased_serde::Serialize>>) -> &mut Self {
    self.claims.extend(value);
    self
  }

  ///Adds a [claim](PasetoClaim) to the token builder
  pub fn set_claim<T: 'b + PasetoClaim + erased_serde::Serialize>(&mut self, value: T) -> &mut Self
  where
    'b: 'a,
  {
    self.claims.insert(value.get_key().to_owned(), Box::new(value));
    self
  }

  ///Adds an optional [footer](Footer) to the token builder
  pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
    self.footer = Some(footer);
    self
  }

  fn build_payload_from_claims(&mut self) -> Result<String, GenericBuilderError> {
    //here we need to go through all the claims and serialize them to build a payload
    let mut payload = String::from('{');

    let claims = take(&mut self.claims);

    for claim in claims.into_values() {
      let raw = serde_json::to_string(&claim)?;
      let trimmed = raw.trim_start_matches('{').trim_end_matches('}');
      let _ = write!(payload, "{},", trimmed);
    }

    //get rid of that trailing comma (this feels like a dirty approach, there's probably a better
    //way to do this)
    payload = payload.trim_end_matches(',').to_string();
    payload.push('}');
    Ok(payload)
  }
}

impl<'a, 'b, Version, Purpose> GenericBuilder<'a, 'b, Version, Purpose>
where
  Version: ImplicitAssertionCapable,
{
  ///Adds an optional [implicit assertion](ImplicitAssertion) to the token builder for V3/V4
  ///tokens only
  pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
    eprintln!("Implicit assertion in generic builder: {}", &implicit_assertion);
    self.implicit_assertion = Some(implicit_assertion);
    self
  }
}

impl<Version, Purpose> Default for GenericBuilder<'_, '_, Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(feature = "v1_local")]
impl GenericBuilder<'_, '_, V1, Local> {
  /// Given a [PasetoSymmetricKey], attempts to encrypt a (V1, Local) PASETO token from the data and
  /// claims provided to the GenericBuilder.
  ///
  /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for encryption or during ciphertext encryption.
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

  pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V1, Local>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V1, Local>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));
    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    let random_nonce = Key::<32>::try_new_random()?;
    Ok(token_builder.try_encrypt(key, &PasetoNonce::<V1, Local>::from(&random_nonce))?)
  }
}

#[cfg(feature = "v2_local")]
impl GenericBuilder<'_, '_, V2, Local> {
  /// Given a [PasetoSymmetricKey], attempts to encrypt a (V2, Local) PASETO token from the data and
  /// claims provided to the GenericBuilder.
  ///
  /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for encryption or during ciphertext encryption.
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

  pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V2, Local>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V2, Local>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));
    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }

    Ok(token_builder.try_encrypt(key, &PasetoNonce::<V2, Local>::from(&Key::<24>::try_new_random()?))?)
  }
}

#[cfg(feature = "v3_local")]
impl GenericBuilder<'_, '_, V3, Local> {
  /// Given a [PasetoSymmetricKey], attempts to encrypt a (V3, Local) PASETO token from the data and
  /// claims provided to the GenericBuilder.
  ///
  /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for encryption or during ciphertext encryption.
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

  pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V3, Local>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V3, Local>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));
    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    if let Some(implicit_assertion) = &self.implicit_assertion {
      token_builder.set_implicit_assertion(*implicit_assertion);
    }
    let nonce = Key::<32>::try_new_random()?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);
    Ok(token_builder.try_encrypt(key, &nonce)?)
  }
}

#[cfg(feature = "v4_local")]
impl GenericBuilder<'_, '_, V4, Local> {
  /// Given a [PasetoSymmetricKey], attempts to encrypt a (V4, Local) PASETO token from the data and
  /// claims provided to the GenericBuilder.
  ///
  /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for encryption or during ciphertext encryption.
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

  pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V4, Local>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V4, Local>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));

    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    if let Some(implicit_assertion) = &self.implicit_assertion {
      token_builder.set_implicit_assertion(*implicit_assertion);
    }
    let nonce = Key::<32>::try_new_random()?;
    let nonce = PasetoNonce::<V4, Local>::from(&nonce);
    Ok(token_builder.try_encrypt(key, &nonce)?)
  }
}

#[cfg(feature = "v1_public")]
impl GenericBuilder<'_, '_, V1, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V1], [Public]) PASETO token from the data and
  /// claims provided to the GenericBuilder with an optional [Footer].
  ///
  /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for signing or during signing.
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
  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V1, Public>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V1, Public>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));
    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    Ok(token_builder.try_sign(key)?)
  }
}

#[cfg(feature = "v2_public")]
impl GenericBuilder<'_, '_, V2, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V2], [Public]) PASETO token from the data and
  /// claims provided to the GenericBuilder with an optional [Footer].
  ///
  /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for signing or during signing.
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
  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V2, Public>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V2, Public>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));
    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    Ok(token_builder.try_sign(key)?)
  }
}

#[cfg(feature = "v3_public")]
impl GenericBuilder<'_, '_, V3, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V3], [Public]) PASETO token from the data and
  /// claims provided to the GenericBuilder with an optional [Footer] and an optional
  /// [ImplicitAssertion].
  ///
  /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for signing or during signing.
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
  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V3, Public>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V3, Public>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));

    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    if let Some(implicit_assertion) = &self.implicit_assertion {
      token_builder.set_implicit_assertion(*implicit_assertion);
    }
    Ok(token_builder.try_sign(key)?)
  }
}

#[cfg(feature = "v4_public")]
impl GenericBuilder<'_, '_, V4, Public> {
  /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V4], [Public]) PASETO token from the data and
  /// claims provided to the GenericBuilder with an optional [Footer] and an optional
  /// [ImplicitAssertion].
  ///
  /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
  ///
  /// # Errors
  ///
  /// Returns [`GenericBuilderError`] for any errors when building the token string
  /// for signing or during signing.
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

  pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V4, Public>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V4, Public>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));

    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    if let Some(implicit_assertion) = &self.implicit_assertion {
      token_builder.set_implicit_assertion(*implicit_assertion);
    }
    Ok(token_builder.try_sign(key)?)
  }
}

#[cfg(all(test, feature = "v4_public"))]
mod generic_v4_public_builders {

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[test]
  fn full_generic_v4_public_builder_test() -> Result<()> {
    //create a key
    let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let pk: &[u8] = private_key.as_slice();
    let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

    let footer = Footer::from("some footer");
    let implicit_assertion = ImplicitAssertion::from("some assertion");

    //sign a public V4 token
    let token = GenericBuilder::<V4, Public>::default()
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
      .set_implicit_assertion(implicit_assertion)
      .try_sign(&private_key)?;

    //now let's try to verify it
    let json = GenericParser::<V4, Public>::default()
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
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
}

#[cfg(all(test, feature = "v3_public"))]
mod generic_v3_public_builders {

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[test]
  fn full_generic_v3_public_builder_test() -> Result<()> {
    //create a key
    let private_key = Key::<48>::try_from(
      "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    )?;
    let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    let public_key = Key::<49>::try_from(
      "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    )?;
    let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

    let footer = Footer::from("some footer");
    let implicit_assertion = ImplicitAssertion::from("some assertion");

    //sign a public V3 token
    let token = GenericBuilder::<V3, Public>::default()
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
      .set_implicit_assertion(implicit_assertion)
      .try_sign(&private_key)?;

    //now let's try to verify it
    let json = GenericParser::<V3, Public>::default()
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
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
}

#[cfg(all(test, feature = "v2_public"))]
mod generic_v2_public_builders {

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[test]
  fn full_generic_v2_public_builder_test() -> Result<()> {
    //create a key
    let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    let footer = Footer::from("some footer");

    //sign a public V2 token
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

    //now let's try to verify it
    let json = GenericParser::<V2, Public>::default()
      .set_footer(footer)
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
}

#[cfg(all(test, feature = "v1_public"))]
mod generic_v1_public_builders {

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[test]
  fn full_generic_v1_public_builder_test() -> Result<()> {
    //create a key
    let private_key = include_bytes!("../../../tests/v1_public_test_vectors_private_key.pk8");
    let pk: &[u8] = private_key;
    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

    let public_key = include_bytes!("../../../tests/v1_public_test_vectors_public_key.der");
    let pubk: &[u8] = public_key;
    let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);
    let footer = Footer::from("some footer");

    //sign a public V1 token
    let token = GenericBuilder::<V1, Public>::default()
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

    //now let's try to verify it
    let json = GenericParser::<V1, Public>::default()
      .set_footer(footer)
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
}

#[cfg(all(test, feature = "v3_local"))]
mod generic_v3_local_builders {
  use std::convert::TryFrom;

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[test]
  fn full_generic_v3_local_builder_test() -> Result<()> {
    //create a key
    let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    let footer = Footer::from("some footer");
    let implicit_assertion = ImplicitAssertion::from("some assertion");

    //create a builder, add some claims and then build the token with the key
    let token = GenericBuilder::<V3, Local>::default()
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
      .set_implicit_assertion(implicit_assertion)
      .try_encrypt(&key)?;

    //now let's decrypt the token and verify the values
    let json = GenericParser::<V3, Local>::default()
      .set_footer(footer)
      .set_implicit_assertion(implicit_assertion)
      .parse(&token, &key)?;

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

#[cfg(all(test, feature = "v2_local"))]
mod builders {
  use std::convert::TryFrom;

  use crate::generic::claims::*;
  use crate::generic::*;
  use anyhow::Result;

  #[test]
  fn full_builder_test() -> Result<()> {
    //create a key
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

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
      .set_footer(footer)
      .parse(&token, &key)?;

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

  #[test]
  fn dynamic_claims_test() -> Result<()> {
    //create a key

    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add some claims dynamically
    let mut builder = GenericBuilder::<V2, Local>::default();
    builder.set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?);

    for n in 1..10 {
      builder.set_claim(CustomClaim::try_from((format!("n{}", n), n))?);
    }

    //and then build the token with the key
    let token = builder.try_encrypt(&key)?;

    //now let's decrypt the token and verify the values
    let json = GenericParser::<V2, Local>::default().parse(&token, &key)?;

    for n in 1..10 {
      assert_eq!(json[format!("n{}", n)], n);
    }

    assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");

    Ok(())
  }

  #[test]
  fn test_no_claims() -> Result<()> {
    let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
    //create a builder, add no claims and then build the token with the key
    let token = GenericBuilder::<V2, Local>::default().try_encrypt(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = GenericParser::<V2, Local>::default().parse(&token, &key)?;
    assert_eq!(decrypted.to_string(), "{}");
    Ok(())
  }
}
