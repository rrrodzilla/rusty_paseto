use crate::generic::*;
use core::marker::PhantomData;
use std::collections::HashSet;
use std::convert::TryFrom;
use time::format_description::well_known::Rfc3339;

pub struct PasetoBuilder<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  builder: GenericBuilder<'a, Version, Purpose>,
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

  pub fn set_claim<T: PasetoClaim + erased_serde::Serialize + Sized + 'static>(&mut self, value: T) -> &mut Self {
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

  pub fn set_no_expiration_danger_acknowledged(&mut self) -> &mut Self {
    self.top_level_claims.insert("exp".to_string());
    self.non_expiring_token = true;
    self
  }

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
  pub fn build(&mut self, key: &PasetoSymmetricKey<V1, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v2_local")]
impl PasetoBuilder<'_, V2, Local> {
  pub fn build(&mut self, key: &PasetoSymmetricKey<V2, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v3_local")]
impl PasetoBuilder<'_, V3, Local> {
  pub fn build(&mut self, key: &PasetoSymmetricKey<V3, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v4_local")]
impl PasetoBuilder<'_, V4, Local> {
  pub fn build(&mut self, key: &PasetoSymmetricKey<V4, Local>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_encrypt(key)
  }
}

#[cfg(feature = "v1_public")]
impl PasetoBuilder<'_, V1, Public> {
  pub fn build(&mut self, key: &PasetoAsymmetricPrivateKey<V1, Public>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_sign(key)
  }
}

#[cfg(feature = "v2_public")]
impl PasetoBuilder<'_, V2, Public> {
  pub fn build(&mut self, key: &PasetoAsymmetricPrivateKey<V2, Public>) -> Result<String, GenericBuilderError> {
    self.verify_ready_to_build()?;
    self.builder.try_sign(key)
  }
}

//TODO V3, Public

#[cfg(feature = "v4_public")]
impl PasetoBuilder<'_, V4, Public> {
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
