use crate::decrypted_tokens::GenericTokenDecrypted;
use crate::errors::PasetoTokenParseError;
use crate::{
  common::{Footer, PurposeLocal, ValidatorFn, ValidatorMap, Version2},
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
  claim_validators: ValidatorMap,
  footer: Option<Footer<'a>>,
}

impl<Version, Purpose> GenericTokenParser<'_, Version, Purpose> {
  pub fn new() -> Self {
    GenericTokenParser::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      claims: HashMap::new(),
      claim_validators: HashMap::new(),
      footer: None,
    }
  }

  pub fn extend_validation_claims(&mut self, value: HashMap<String, Box<dyn erased_serde::Serialize>>) -> &mut Self {
    self.claims.extend(value);
    self
  }

  pub fn validate_claim<T: PasetoClaim + 'static + serde::Serialize>(
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

  pub fn set_footer(&mut self, footer: Footer<'static>) -> &mut Self {
    self.footer = Some(footer);
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
    let claims = take(&mut self.claims);

    // here we want to traverse all of the claims to validate and verify their values
    for (key, box_val) in claims {
      //ensure the claim exists
      //get the raw value of the claim
      let raw = serde_json::to_value(&box_val)?;

      //now let's run any custom validation if there is any
      if self.claim_validators.contains_key(&key) {
        let box_validator = &self.claim_validators[&key];
        let validator = box_validator.as_ref();
        validator(&key, &json[&key])?;
      } else {
        //otherwise, simply verify the claim matches the value passed in
        if raw[&key] != json[&key] {
          return Err(PasetoTokenParseError::InvalidClaim(key));
        }
      }
    }

    //return the full json value to the user
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

  #[test]
  fn basic_claim_validation_test() {
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
        .validate_claim(AudienceClaim::from("not the same customers"), None)
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind = "The claim 'aud' failed validation";
    assert_eq!(expected_error_kind, actual_error_kind);
  }

  #[test]
  fn claim_custom_validator_test() -> Result<()> {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(AudienceClaim::from("customers"))
      .build(&key)
      .unwrap();

    //now let's decrypt the token and verify the values with a custom validation closure
    let json = GenericTokenParser::<Version2, PurposeLocal>::default()
      .validate_claim(
        //no need to provide a value to check against for the claim when we are using
        //a custom closure since the value will be passed to the closure for evaluation by your
        //validation function
        AudienceClaim::default(),
        Some(&|key, value| {
          //we receive the value of the claim so we can do whatever we like with it
          //get the value of the claim
          let val = value
            .as_str()
            .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

          match val {
            "customers" => Ok(()),
            _ => Err(PasetoTokenParseError::CustomClaimValidation(
              key.to_string(),
              val.to_string(),
            )),
          }
        }),
      )
      .parse(&token, &key)?;

    assert_eq!(json["aud"], "customers");
    Ok(())
  }

  #[test]
  fn claim_custom_validator_failure_test() {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(AudienceClaim::from("customers"))
      .build(&key)
      .unwrap();

    //now let's decrypt the token and verify the values with a custom validation closure
    let actual_error_kind = format!(
      "{}",
      GenericTokenParser::<Version2, PurposeLocal>::default()
        .validate_claim(
          //no need to provide a value to check against for the claim when we are using
          //a custom closure since the value will be passed to the closure for evaluation by your
          //validation function
          AudienceClaim::default(),
          Some(&|key, value| {
            //we receive the value of the claim so we can do whatever we like with it
            //get the value of the claim
            let val = value
              .as_str()
              .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

            //let's fail on purpose
            Err(PasetoTokenParseError::CustomClaimValidation(
              key.to_string(),
              val.to_string(),
            ))
          })
        )
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind = "A custom claim validator for claim 'aud' failed for value 'customers'";
    assert_eq!(expected_error_kind, actual_error_kind);
  }

  #[test]
  fn custom_claim_custom_validator_test() -> Result<()> {
    //create a key
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, add some claims and then build the token with the key
    let token = GenericTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(CustomClaim::try_from(("seats", 4))?)
      .build(&key)
      .unwrap();

    //now let's decrypt the token and verify the values with a custom validation closure
    let actual_error_kind = format!(
      "{}",
      GenericTokenParser::<Version2, PurposeLocal>::default()
        .validate_claim(
          //no need to provide a value to check against for the claim when we are using
          //a custom closure since the value will be passed to the closure for evaluation by your
          //validation function
          CustomClaim::try_from("seats")?,
          Some(&|key, value| {
            //we receive the value of the claim so we can do whatever we like with it
            //get the value of the claim
            let val = value
              .as_u64()
              .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

            //let's fail on purpose
            Err(PasetoTokenParseError::CustomClaimValidation(
              key.to_string(),
              val.to_string(),
            ))
          })
        )
        .parse(&token, &key)
        .unwrap_err()
    );

    let expected_error_kind = "A custom claim validator for claim 'seats' failed for value '4'";
    assert_eq!(expected_error_kind, actual_error_kind);

    Ok(())
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
        .validate_claim(AudienceClaim::from("this claim doesn't exist"), None)
        .parse(&token, &key)
        .unwrap_err()
    );
    let expected_error_kind = "The claim 'aud' failed validation";

    //the claim we're looking for was not in the original token so we receive an error
    assert_eq!(expected_error_kind, actual_error_kind);
  }
}
