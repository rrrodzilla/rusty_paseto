use crate::decrypted_tokens::GenericTokenDecrypted;
use crate::errors::PasetoTokenParseError;
use crate::{
  common::{Footer, PurposeLocal, Version2},
  keys::Key,
  traits::PasetoClaim,
};
use core::marker::PhantomData;
use serde_json::Value;
use std::{collections::HashMap, mem::take};

pub struct GenericTokenParser<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  claims: HashMap<String, Box<dyn erased_serde::Serialize>>,
  footer: Option<Footer<'a>>,
}

impl<Version, Purpose> GenericTokenParser<'_, Version, Purpose> {
  pub fn new() -> Self {
    GenericTokenParser::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::new(),
      footer: None,
    }
  }

  pub fn validate_claim<T: PasetoClaim + 'static + serde::Serialize>(&mut self, value: T) -> &mut Self {
    self.claims.insert(value.get_key().to_owned(), Box::new(value));
    self
  }

  pub fn set_footer(&mut self, footer: Option<Footer<'static>>) -> &mut Self {
    self.footer = footer;
    self
  }
}

impl<Version, Purpose> Default for GenericTokenParser<'_, Version, Purpose> {
  fn default() -> Self {
    Self::new()
  }
}

impl<'a> GenericTokenParser<'a, Version2, PurposeLocal> {
  pub fn parse(&mut self, token: &'a str, key: &Key<Version2, PurposeLocal>) -> Result<Value, PasetoTokenParseError> {
    let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(token, self.footer, key)?;
    let json: Value = serde_json::from_str(decrypted.as_ref())?;
    // here we want to traverse all of the claims to validate and verify their values
    let claims = take(&mut self.claims);

    for (key, box_val) in claims {
      let raw = serde_json::to_value(&box_val)?;
      if raw[&key] != json[&key] {
        return Err(PasetoTokenParseError::InvalidClaim(key));
      }
    }
    Ok(json)
  }
}

#[cfg(test)]
mod parsers {
  use std::convert::TryFrom;

  use super::*;
  use crate::builders::*;
  use crate::claims::{
    AudienceClaim, CustomClaim, ExpirationClaim, IssuedAtClaim, IssuerClaim, NotBeforeClaim, SubjectClaim,
    TokenIdentifierClaim,
  };
  use crate::common::*;
  use crate::keys::Key;
  use anyhow::Result;
  #[test]
  fn full_parser_test() -> Result<()> {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let footer = Some(Footer::from("some footer"));

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
      .set_footer(footer)
      .build(&key)?;

    //now let's decrypt the token and verify the values
    let json = GenericTokenParser::<Version2, PurposeLocal>::default()
      .set_footer(footer)
      .validate_claim(AudienceClaim::from("customers"))
      .validate_claim(SubjectClaim::from("loyal subjects"))
      .validate_claim(IssuerClaim::from("me"))
      .validate_claim(TokenIdentifierClaim::from("me"))
      .validate_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .validate_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .validate_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
      .validate_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
      .validate_claim(CustomClaim::try_from(("seats", 4))?)
      .validate_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
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

  #[test]
  fn claim_validation_test() {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(AudienceClaim::from("customers"))
      .build(&key)
      .unwrap();

    //now let's decrypt the token and verify the values
    let actual_error_kind = format!(
      "{}",
      GenericTokenParser::<Version2, PurposeLocal>::default()
        .validate_claim(AudienceClaim::from("not the same customers"))
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind = "The claim 'aud' failed validation";
    assert_eq!(expected_error_kind, actual_error_kind);
  }

  #[test]
  fn missing_claim_validation_test() {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add no claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
      .build(&key)
      .unwrap();

    //now let's decrypt the token and verify the values
    let actual_error_kind = format!(
      "{}",
      GenericTokenParser::<Version2, PurposeLocal>::default()
        .validate_claim(AudienceClaim::from("this claim doesn't exist"))
        .parse(&token, &key)
        .unwrap_err()
    );
    let expected_error_kind = "The claim 'aud' failed validation";

    //the claim we're looking for was not in the original token so we receive an error
    assert_eq!(expected_error_kind, actual_error_kind);
  }
}
