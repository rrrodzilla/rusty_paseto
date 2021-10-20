use crate::{
  common::{Footer, Payload},
  errors::V2LocalTokenBuilderError,
  keys::V2LocalSharedKey,
  tokens::v2::V2LocalToken,
  traits::PasetoClaim,
};
use core::marker::PhantomData;
use std::{collections::HashMap, mem::take};

pub struct TokenBuilder<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize>>,
  footer: Option<Footer<'a>>,
}

impl<Version, Purpose> TokenBuilder<'_, Version, Purpose> {
  pub fn new() -> Self {
    TokenBuilder::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::with_capacity(10),
      footer: None,
    }
  }

  pub fn set_claim<T: PasetoClaim + erased_serde::Serialize + 'static>(&mut self, value: T) -> &mut Self {
    self.claims.insert(value.get_key().to_owned(), Box::new(value));
    self
  }

  pub fn set_footer(&mut self, footer: Option<Footer<'static>>) -> &mut Self {
    self.footer = footer;
    self
  }
}

impl<Version, Purpose> Default for TokenBuilder<'_, Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

impl<'a, V2, Local> TokenBuilder<'a, V2, Local> {
  pub fn build(&mut self, key: &V2LocalSharedKey) -> Result<String, V2LocalTokenBuilderError> {
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

    Ok(V2LocalToken::new(Payload::from(payload.as_str()), key, self.footer).to_string())
  }
}

#[cfg(test)]
mod builders {
  use std::convert::TryFrom;

  use super::*;
  use crate::claims::{Arbitrary, Audience, Expiration, Subject};
  use crate::common::{Footer, Local, V2};
  use crate::keys::V2LocalSharedKey;
  use crate::v2::local::V2LocalDecryptedToken;
  use anyhow::Result;
  use serde_json::value::Value;

  #[test]
  fn full_builder_test() -> Result<()> {
    //create a key
    let key = V2LocalSharedKey::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims and then build the token with the key
    let token = TokenBuilder::<V2, Local>::default()
      .set_claim(Audience::from("customers"))
      .set_claim(Subject::from("loyal subjects"))
      .set_claim(Expiration::try_from("2019-01-01T00:00:00+00:00")?)
      .set_claim(Arbitrary::try_from(("data", "this is a secret message"))?)
      .set_claim(Arbitrary::try_from(("seats", 4))?)
      .set_claim(Arbitrary::try_from(("any ol' pi", 3.141526))?)
      .set_footer(Some(Footer::from("some footer")))
      .build(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = V2LocalDecryptedToken::parse(&token, Some(Footer::from("some footer")), &key)?;
    let json: Value = serde_json::from_str(decrypted.as_ref())?;

    assert_eq!(json["aud"], "customers");
    assert_eq!(json["data"], "this is a secret message");
    assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    assert_eq!(json["sub"], "loyal subjects");
    assert_eq!(json["any ol' pi"], 3.141526);
    assert_eq!(json["seats"], 4);
    Ok(())
    //TODO: implement like so:
    //let token = TokenParser::<V2, Local>::default()
    //.set_footer(None)
    //.validate_claim(Arbitrary::try_from(("data", "this is a secret message"))?, None)
    //.validate_claim(Arbitrary::try_from(("seats", 4))?, Some(|v: i32| v > 2 ))
    //.parse(rawToken, &key)?;
  }

  #[test]
  fn dynamic_claims_test() -> Result<()> {
    //create a key
    let key = V2LocalSharedKey::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims dynamically
    let mut builder = TokenBuilder::<V2, Local>::default();
    builder.set_claim(Expiration::try_from("2019-01-01T00:00:00+00:00")?);

    for n in 1..10 {
      builder.set_claim(Arbitrary::try_from((format!("n{}", n).as_str(), n))?);
    }

    //and then build the token with the key
    let token = builder.build(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = V2LocalDecryptedToken::parse(&token, None, &key)?;
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
    let key = V2LocalSharedKey::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add no claims and then build the token with the key
    let token = TokenBuilder::<V2, Local>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    let decrypted = V2LocalDecryptedToken::parse(&token, None, &key)?;
    assert_eq!(decrypted.as_ref(), "{}");
    Ok(())
  }
}
