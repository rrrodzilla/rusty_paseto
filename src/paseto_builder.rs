use crate::builders::GenericTokenBuilder;
use crate::claims::{ExpirationClaim, IssuedAtClaim};
use crate::{
  common::{Footer, Local, Public, V2},
  errors::GenericTokenBuilderError,
  keys::Key,
  traits::PasetoClaim,
};
use chrono::{prelude::*, Duration};
use core::marker::PhantomData;
use std::collections::HashSet;
use std::convert::TryFrom;

pub struct PasetoTokenBuilder<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  builder: GenericTokenBuilder<Version, Purpose>,
  top_level_claims: HashSet<String>,
  dup_top_level_found: (bool, String),
  non_expiring_token: bool,
}

impl<Version, Purpose> PasetoTokenBuilder<Version, Purpose> {
  fn new() -> Self {
    PasetoTokenBuilder::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      builder: GenericTokenBuilder::default(),
      top_level_claims: HashSet::new(),
      non_expiring_token: false,
      dup_top_level_found: (false, String::default()),
    }
  }

  pub fn set_claim<T: PasetoClaim + erased_serde::Serialize + Sized + 'static>(&mut self, value: T) -> &mut Self {
    //we need to inspect all the claims and verify there are no duplicates
    if !self.top_level_claims.insert(value.get_key().to_string()) {
      self.dup_top_level_found = (true, value.get_key().to_string());
    }

    self.builder.set_claim(value);
    self
  }

  pub fn set_no_expiration_danger_acknowledged(&mut self) -> &mut Self {
    self.top_level_claims.insert("exp".to_string());
    self.non_expiring_token = true;
    self
  }

  pub fn set_footer(&mut self, footer: Footer) -> &mut Self {
    self.builder.set_footer(footer);
    self
  }

  fn verify_ready_to_build(&mut self) -> Result<(), GenericTokenBuilderError> {
    if self.non_expiring_token {
      self.builder.remove_claim("exp");
    }
    //  //raise an error if there were duplicates
    let (dup_found, dup_key) = &self.dup_top_level_found;
    if *dup_found {
      return Err(GenericTokenBuilderError::DuplicateTopLevelPayloadClaim(
        dup_key.to_string(),
      ));
    }
    Ok(())
  }
}

impl<Version, Purpose> Default for PasetoTokenBuilder<Version, Purpose> {
  fn default() -> Self {
    let mut me = Self::new();
    //set some defaults
    me.builder
      .set_claim(ExpirationClaim::try_from((Utc::now() + Duration::hours(1)).to_rfc3339()).unwrap())
      .set_claim(IssuedAtClaim::try_from(Utc::now().to_rfc3339()).unwrap());
    me
  }
}

impl PasetoTokenBuilder<V2, Public> {
  pub fn build(&mut self, key: &Key<V2, Public>) -> Result<String, GenericTokenBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.build(key)
  }
}

impl PasetoTokenBuilder<V2, Local> {
  pub fn build(&mut self, key: &Key<V2, Local>) -> Result<String, GenericTokenBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.build(key)
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
  use crate::decrypted_tokens::BasicTokenDecrypted;
  use crate::errors::PasetoTokenParseError;
  use crate::keys::Key;
  use crate::parsers::GenericTokenParser;
  use anyhow::Result;
  use chrono::Duration;
  use std::convert::TryFrom;

  #[test]
  fn duplicate_top_level_claim_test() -> Result<()> {
    let key = Key::<V2, Local>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let tomorrow = (Utc::now() + Duration::days(1)).to_rfc3339();

    //create a builder, with default IssuedAtClaim
    let expected_error = format!(
      "{}",
      PasetoTokenBuilder::<V2, Local>::default()
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
  fn update_default_issued_at_claim_test() -> Result<()> {
    let key = Key::<V2, Local>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let tomorrow = (Utc::now() + Duration::days(1)).to_rfc3339();

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<V2, Local>::default()
      .set_claim(IssuedAtClaim::try_from(tomorrow.as_str()).unwrap())
      .build(&key)?;

    let decrypted_token = BasicTokenDecrypted::<V2, Local>::parse(&token, None, &key)?;
    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    GenericTokenParser::<V2, Local>::default()
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
      .parse(&decrypted_token)?;

    Ok(())
  }

  #[test]
  fn check_for_default_issued_at_claim_test() -> Result<()> {
    let key = Key::<V2, Local>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<V2, Local>::default().build(&key)?;

    let decrypted_token = BasicTokenDecrypted::<V2, Local>::parse(&token, None, &key)?;
    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    GenericTokenParser::<V2, Local>::default()
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
      .parse(&decrypted_token)?;

    Ok(())
  }

  #[test]
  fn update_default_expiration_claim_test() -> Result<()> {
    let key = Key::<V2, Local>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let in_4_days = (Utc::now() + Duration::days(4)).to_rfc3339();

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<V2, Local>::default()
      .set_claim(ExpirationClaim::try_from(in_4_days).unwrap())
      .build(&key)?;

    let decrypted_token = BasicTokenDecrypted::<V2, Local>::parse(&token, None, &key)?;
    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist and the date should be set to tomorrow
    GenericTokenParser::<V2, Local>::default()
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
      .parse(&decrypted_token)?;

    Ok(())
  }

  #[test]
  fn check_for_default_expiration_claim_test() -> Result<()> {
    let key = Key::<V2, Local>::from(*b"wubbalubbadubdubwubbalubbadubdub");

    //create a builder, with default IssuedAtClaim
    let token = PasetoTokenBuilder::<V2, Local>::default().build(&key)?;

    let decrypted_token = BasicTokenDecrypted::<V2, Local>::parse(&token, None, &key)?;
    //now let's decrypt the token and verify the values
    //the IssuedAtClaim should exist
    GenericTokenParser::<V2, Local>::default()
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
      .parse(&decrypted_token)?;

    Ok(())
  }

  #[test]
  fn full_paseto_builder_test() -> Result<()> {
    let key = Key::<V2, Local>::from(*b"wubbalubbadubdubwubbalubbadubdub");
    let footer = Footer::from("some footer");

    //create a builder, add some claims and then build the token with the key
    let token = PasetoTokenBuilder::<V2, Local>::default()
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

    let decrypted_token = BasicTokenDecrypted::<V2, Local>::parse(&token, Some(footer.clone()), &key)?;
    //now let's decrypt the token and verify the values
    let json = GenericTokenParser::<V2, Local>::default()
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
      .parse(&decrypted_token)?;

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
