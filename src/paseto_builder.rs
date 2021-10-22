use crate::builders::GenericTokenBuilder;
use crate::{
  common::{Footer, PurposeLocal, Version2},
  errors::GenericTokenBuilderError,
  keys::Key,
  traits::PasetoClaim,
};
use core::marker::PhantomData;
use std::collections::HashMap;
use std::mem::take;

pub struct PasetoTokenBuilder<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize>>,
  footer: Option<Footer<'a>>,
}

impl<'a, Version, Purpose> PasetoTokenBuilder<'a, Version, Purpose> {
  pub fn new() -> Self {
    PasetoTokenBuilder::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::with_capacity(10),
      footer: None,
    }
  }

  pub fn set_claim<T: PasetoClaim + erased_serde::Serialize + Sized + 'static>(&mut self, value: T) -> &mut Self {
    self.claims.insert(value.get_key().to_owned(), Box::new(value));
    self
  }

  pub fn set_footer(&mut self, footer: Option<Footer<'a>>) -> &mut Self {
    self.footer = footer;
    self
  }
}

impl<Version, Purpose> Default for PasetoTokenBuilder<'_, Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

impl PasetoTokenBuilder<'_, Version2, PurposeLocal> {
  pub fn build(&mut self, key: &Key<Version2, PurposeLocal>) -> Result<String, GenericTokenBuilderError> {
    let claims = take(&mut self.claims);

    //create a builder, add some default claims, then add all the user provided claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
      .extend_claims(claims)
      .set_footer(self.footer)
      .build(key)?;

    Ok(token)
  }
}

#[cfg(test)]
mod paseto_builder {

  use super::*;
  use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  use crate::common::*;
  use crate::keys::Key;
  use crate::parsers::GenericTokenParser;
  use anyhow::Result;
  use std::convert::TryFrom;

  #[test]
  fn full_paseto_builder_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let footer = Some(Footer::from("some footer"));

    //create a builder, add some claims and then build the token with the key
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default()
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
    let json = GenericTokenParser::<Version2, PurposeLocal>::default()
      .validate_claim(AudienceClaim::from("customers"), None)
      .validate_claim(SubjectClaim::from("loyal subjects"), None)
      .validate_claim(IssuerClaim::from("me"), None)
      .validate_claim(TokenIdentifierClaim::from("me"), None)
      .validate_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?, None)
      .validate_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?, None)
      .validate_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?, None)
      .validate_claim(CustomClaim::try_from(("data", "this is a secret message"))?, None)
      .validate_claim(CustomClaim::try_from(("seats", 4))?, None)
      .validate_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?, None)
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
