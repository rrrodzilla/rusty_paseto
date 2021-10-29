use crate::{
  common::{Footer, Payload, PurposeLocal, Version2},
  errors::GenericTokenBuilderError,
  keys::Key,
  tokens::GenericToken,
  traits::PasetoClaim,
};
use core::marker::PhantomData;
use std::{collections::HashMap, mem::take};

pub struct GenericTokenBuilder<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize>>,
  footer: Option<Footer>,
}

impl<Version, Purpose> GenericTokenBuilder<Version, Purpose> {
  fn new() -> Self {
    GenericTokenBuilder::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::with_capacity(10),
      footer: None,
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

  pub fn set_footer(&mut self, footer: Footer) -> &mut Self {
    self.footer = Some(footer);
    self
  }
}

impl<Version, Purpose> Default for GenericTokenBuilder<Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

impl GenericTokenBuilder<Version2, PurposeLocal> {
  pub fn build(&mut self, key: &Key<Version2, PurposeLocal>) -> Result<String, GenericTokenBuilderError> {
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

    Ok(
      GenericToken::<Version2, PurposeLocal>::new(Payload::from(payload.as_str()), key, self.footer.clone())
        .to_string(),
    )
  }
}

#[cfg(test)]
mod builders {
  use std::convert::TryFrom;

  use super::*;
  use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  use crate::common::*;
  use crate::decrypted_tokens::GenericTokenDecrypted;
  use crate::keys::Key;
  use anyhow::Result;
  use serde_json::value::Value;

  #[test]
  fn full_builder_test() -> Result<()> {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(b"wubbalubbadubdubwubbalubbadubdub");
    let footer = Footer::from("some footer");

    //create a builder, add some claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
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
      .set_footer(footer.clone())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(&token, Some(footer), &key)?;
    let json: Value = serde_json::from_str(decrypted.as_ref())?;

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
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims dynamically
    let mut builder = GenericTokenBuilder::<Version2, PurposeLocal>::default();
    builder.set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?);

    for n in 1..10 {
      builder.set_claim(CustomClaim::try_from((format!("n{}", n), n))?);
    }

    //and then build the token with the key
    let token = builder.build(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(&token, None, &key)?;
    let json: Value = serde_json::from_str(decrypted.as_ref())?;

    for n in 1..10 {
      assert_eq!(json[format!("n{}", n)], n);
    }

    assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");

    Ok(())
  }

  #[test]
  fn test_no_claims() -> Result<()> {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add no claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(&token, None, &key)?;
    assert_eq!(decrypted.as_ref(), "{}");
    Ok(())
  }
}
