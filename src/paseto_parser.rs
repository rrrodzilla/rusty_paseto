use crate::generic_builders::{ExpirationClaim, NotBeforeClaim};
use crate::parsers::GenericTokenParser;
use crate::{
  common::{Footer, PurposeLocal, ValidatorFn, Version2},
  errors::PasetoTokenParseError,
  keys::Key,
  traits::PasetoClaim,
};
use chrono::prelude::*;
use core::marker::PhantomData;
use serde_json::Value;

pub struct PasetoTokenParser<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  parser: GenericTokenParser<Version, Purpose>,
}

impl<Version, Purpose> PasetoTokenParser<Version, Purpose> {
  pub fn new() -> Self {
    PasetoTokenParser::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      parser: GenericTokenParser::default(),
    }
  }

  pub fn validate_claim<T: PasetoClaim + 'static + serde::Serialize>(
    &mut self,
    value: T,
    validation_closure: &'static ValidatorFn,
  ) -> &mut Self {
    self.parser.validate_claim(value, validation_closure);
    self
  }

  pub fn check_claim<T: PasetoClaim + 'static + serde::Serialize>(&mut self, value: T) -> &mut Self {
    self.parser.check_claim(value);
    self
  }

  pub fn set_footer(&mut self, footer: Footer) -> &mut Self {
    self.parser.set_footer(footer);
    self
  }
}

impl<Version, Purpose> Default for PasetoTokenParser<Version, Purpose> {
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
      let datetime = DateTime::parse_from_rfc3339(val).map_err(|_| PasetoTokenParseError::InvalidDate)?;
      //get the current datetime
      let now = Utc::now();

      //here we do the actual validation check for the expiration claim
      if datetime <= now {
        Err(PasetoTokenParseError::ExpiredToken)
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
      let not_before_time = DateTime::parse_from_rfc3339(val).map_err(|_| PasetoTokenParseError::InvalidDate)?;
      //get the current datetime
      let now = Utc::now();

      //here we do the actual validation check for the expiration claim
      if now <= not_before_time {
        Err(PasetoTokenParseError::UseBeforeAvailable(not_before_time.to_string()))
      } else {
        Ok(())
      }
    });
    me
  }
}

impl PasetoTokenParser<Version2, PurposeLocal> {
  pub fn parse(&mut self, token: &str, key: &Key<Version2, PurposeLocal>) -> Result<Value, PasetoTokenParseError> {
    //return the full json value to the user
    self.parser.parse(token, key)
  }
}

#[cfg(test)]
mod paseto_parser {

  use std::convert::TryFrom;

  use super::*;
  use crate::claims::*;
  use crate::common::*;
  use crate::keys::Key;
  use crate::prelude::PasetoTokenBuilder;
  use anyhow::Result;
  use chrono::Duration;

  #[test]
  fn usage_before_ready_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    let not_before = Utc::now() + Duration::hours(1);
    //create a default builder
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(NotBeforeClaim::try_from(not_before.to_rfc3339())?)
      .build(&key)?;
    let expected_error = format!("{}", PasetoTokenParser::default().parse(&token, &key).unwrap_err());

    assert!(expected_error.starts_with("The token is not available for use before "));
    Ok(())
  }

  #[test]
  fn non_expiring_token_claim_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //we're going to set a token expiration date to 10 minutes ago
    let expired = Utc::now() + Duration::minutes(-10);

    //create a default builder
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default()
      //setting our claim
      .set_claim(ExpirationClaim::try_from(expired.to_rfc3339())?)
      //by setting this we ensure we won't fail
      .set_no_expiration_danger_acknowledged()
      //without the line above this would have errored as an expired token
      .build(&key)?;

    let token = PasetoTokenParser::default().parse(&token, &key)?;

    assert!(token["iat"].is_string());
    assert!(token["exp"].is_null());

    Ok(())
  }

  #[test]
  fn expired_token_claim_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    let expired = Utc::now() + Duration::minutes(-10);
    //create a default builder
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(ExpirationClaim::try_from(expired.to_rfc3339())?)
      .build(&key)?;
    let expected_error = format!("{}", PasetoTokenParser::default().parse(&token, &key).unwrap_err());

    assert_eq!(expected_error, "The token has expired");
    Ok(())
  }

  #[test]
  fn basic_paseto_parser_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a default builder
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default().build(&key)?;

    //default parser
    let json = PasetoTokenParser::default().parse(&token, &key)?;

    //verify the default claims and no others are in the token
    assert!(json["exp"].is_string());
    assert!(json["iat"].is_string());
    assert!(json["nbf"].is_null());
    assert!(json["sub"].is_null());
    assert!(json["iss"].is_null());
    assert!(json["jti"].is_null());
    assert!(json["aud"].is_null());
    assert!(!json["aud"].is_string());
    Ok(())
  }

  #[test]
  fn update_default_issued_at_claim_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let tomorrow = (Utc::now() + Duration::days(1)).to_rfc3339();

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(IssuedAtClaim::try_from(tomorrow.as_str()).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    PasetoTokenParser::<Version2, PurposeLocal>::default()
      .validate_claim(IssuedAtClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        let tomorrow = Utc::now() + Duration::days(1);
        //the claimm should exist
        assert_eq!(key, "iat");
        //date should be tomorrow
        assert_eq!(datetime.date.to_string(), tomorrow.date().naive_utc().to_string());

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn check_for_default_issued_at_claim_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    PasetoTokenParser::<Version2, PurposeLocal>::default()
      .validate_claim(IssuedAtClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        //the claimm should exist
        assert_eq!(key, "iat");
        //date should be today
        assert_eq!(datetime.date.to_string(), Utc::now().date().naive_utc().to_string());

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn update_default_expiration_claim_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let in_4_days = (Utc::now() + Duration::days(4)).to_rfc3339();

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default()
      .set_claim(ExpirationClaim::try_from(in_4_days).unwrap())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    PasetoTokenParser::<Version2, PurposeLocal>::default()
      .validate_claim(ExpirationClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        let in_4_days = Utc::now() + Duration::days(4);
        //the claimm should exist
        assert_eq!(key, "exp");
        //date should be tomorrow
        assert_eq!(datetime.date.to_string(), in_4_days.date().naive_utc().to_string());

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn check_for_default_expiration_claim_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, with default ExpirationClaim
    let token = PasetoTokenBuilder::<Version2, PurposeLocal>::default().build(&key)?;

    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    PasetoTokenParser::<Version2, PurposeLocal>::default()
      .validate_claim(ExpirationClaim::default(), &|key, value| {
        //let's get the value
        let val = value
          .as_str()
          .ok_or(PasetoTokenParseError::InvalidClaimValueType(key.to_string()))?;

        let datetime = iso8601::datetime(val).unwrap();

        let tomorrow = Utc::now() + Duration::hours(1);
        //the claimm should exist
        assert_eq!(key, "exp");
        //date should be today
        assert_eq!(datetime.date.to_string(), tomorrow.date().naive_utc().to_string());

        Ok(())
      })
      .parse(&token, &key)?;

    Ok(())
  }

  #[test]
  fn full_paseto_parser_test() -> Result<()> {
    let key = Key::<Version2, PurposeLocal>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let footer = Footer::from("some footer");

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
      .set_footer(footer.clone())
      .build(&key)?;

    //now let's decrypt the token and verify the values
    let json = GenericTokenParser::<Version2, PurposeLocal>::default()
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
