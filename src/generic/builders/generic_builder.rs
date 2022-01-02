use crate::generic::*;
use core::marker::PhantomData;
use std::{collections::HashMap, mem::take};

pub struct GenericBuilder<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize>>,
  footer: Option<Footer<'a>>,
  implicit_assertion: Option<ImplicitAssertion<'a>>,
}

impl<'a, Version, Purpose> GenericBuilder<'a, Version, Purpose> {
  fn new() -> Self {
    Self {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::with_capacity(10),
      footer: None,
      implicit_assertion: None,
    }
  }

  pub fn remove_claim(&mut self, claim_key: &str) -> &mut Self {
    self.claims.remove(claim_key);
    self
  }

  pub fn extend_claims(&mut self, value: HashMap<String, Box<dyn erased_serde::Serialize>>) -> &mut Self {
    self.claims.extend(value);
    self
  }

  pub fn set_claim<T: PasetoClaim + erased_serde::Serialize + 'static>(&mut self, value: T) -> &mut Self {
    self.claims.insert(value.get_key().to_owned(), Box::new(value));
    self
  }

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
      payload.push_str(&format!("{},", trimmed));
    }

    //get rid of that trailing comma (this feels like a dirty approach, there's probably a better
    //way to do this)
    payload = payload.trim_end_matches(',').to_string();
    payload.push('}');
    Ok(payload)
  }
}

impl<'a, Version, Purpose> GenericBuilder<'a, Version, Purpose>
where
  Version: ImplicitAssertionCapable,
{
  pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
    self.implicit_assertion = Some(implicit_assertion);
    self
  }
}

impl<Version, Purpose> Default for GenericBuilder<'_, Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(feature = "v1_local")]
impl GenericBuilder<'_, V1, Local> {
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
impl GenericBuilder<'_, V2, Local> {
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
impl GenericBuilder<'_, V3, Local> {
  pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V3, Local>) -> Result<String, GenericBuilderError> {
    let mut token_builder = Paseto::<V3, Local>::builder();

    let payload = self.build_payload_from_claims()?;
    token_builder.set_payload(Payload::from(payload.as_str()));
    if let Some(footer) = &self.footer {
      token_builder.set_footer(*footer);
    }
    let nonce = Key::<32>::try_new_random()?;
    let nonce = PasetoNonce::<V3, Local>::from(&nonce);
    Ok(token_builder.try_encrypt(key, &nonce)?)
  }
}

#[cfg(feature = "v4_local")]
impl GenericBuilder<'_, V4, Local> {
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
impl GenericBuilder<'_, V1, Public> {
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
impl GenericBuilder<'_, V2, Public> {
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

//TODO: V3, Public

#[cfg(feature = "v4_public")]
impl GenericBuilder<'_, V4, Public> {
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
