//what should this look like?
//let builder = v2LocalTokenBuilder::new(V2LocalSharedKey);
//    let claim = AudienceClaim::from("out of this world");
//    builder.add_claim(claim);
//    let token = builder.build();
//    simplest token
//    let token = builder::new().build();

use serde::Serialize;

use crate::{
  common::{Footer, Payload},
  errors::V2LocalTokenBuilderError,
  keys::{Key256Bit, V2LocalSharedKey},
  tokens::v2::V2LocalToken,
  traits::Claim,
};
use core::marker::PhantomData;
use std::default::Default;

pub struct TokenBuilder<'a, Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  footer: Option<Footer<'a>>,
}

impl<'a, Version, Purpose> TokenBuilder<'a, Version, Purpose> {
  pub fn new() -> Self {
    TokenBuilder::<Version, Purpose> {
      version: PhantomData::<Version>,
      purpose: PhantomData::<Purpose>,
      footer: None,
    }
  }

  pub fn set_footer(&mut self, footer: Option<Footer<'a>>) {
    self.footer = footer;
    ()
  }
}

impl<'a, V2, Local> TokenBuilder<'a, V2, Local> {
  pub fn build(&mut self, key: Key256Bit) -> Result<String, V2LocalTokenBuilderError> {
    let key: &V2LocalSharedKey = &key.into();
    let payload = Payload::from("");

    Ok(V2LocalToken::new(payload, key, self.footer).to_string())
  }
}

///// An ergonomic structure for building a v2LocalTokenBuilder
//pub struct V2LocalTokenBuilder<'a> {
//  footer: Option<Footer<'a>>,
//  //    claims: Vec<Box<dyn Claim<T>>>,
//  json: String,
//}

//impl<'a> Default for V2LocalTokenBuilder<'a> {
//  fn default() -> Self {
//    Self::new()
//  }
//}

//impl<'a> V2LocalTokenBuilder<'a> {
//  pub fn new() -> Self {
//    V2LocalTokenBuilder::<'a> {
//      footer: None,
//      //       claims: Vec::new(),
//      json: Default::default(),
//    }
//  }

//  pub fn add_claim<U, T: Claim<U>>(&mut self, claim: T) -> &Self
//  where
//    T: Serialize,
//  {
//    self.json = serde_json::to_string(claim.get_key()).unwrap();
//    //we want to verify we haven't more than one of the
//    //paseto restricted top level keys
//    //    self.claims.push(Box::new(claim));
//    self
//  }

//  pub fn set_footer(&mut self, footer: Option<Footer<'a>>) -> &Self {
//    self.footer = footer;
//    self
//  }

//  pub fn build(&self, key: Key256Bit) -> Result<String, V2LocalTokenBuilderError> {
//    //turn it into a key
//    let key: &V2LocalSharedKey = &key.into();

//    //self.claims.into_iter().map(|claim| format!("{})

//    //   let json = serde_json::to_string(&self.claims[0].get_key())?;
//    //let json = serde_json::to_string(&self.claims)?;

//    let payload = Payload::from(self.json.as_str());

//    //create a local v2 token
//    Ok(V2LocalToken::new(payload, key, self.footer).to_string())
//  }
//}

#[cfg(test)]
mod builders {
  use super::*;
  //use crate::claims::PasetoClaim;
  use crate::common::{Footer, Local, V2};
  use crate::keys::{Key256Bit, V2LocalSharedKey};
  use crate::v2::local::V2LocalDecryptedToken;
  use anyhow::Result;

  #[test]
  fn basic_builder_test() -> Result<()> {
    let mut builder = TokenBuilder::<V2, Local>::new();
    builder.set_footer(Some(Footer::from("universe c137")));
    Ok(())
  }

  //  #[test]
  //  fn test_basic_builder_with_single_arbitrary_claim() -> Result<()> {
  //    //here's a valid 32 byte key
  //    const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";
  //    let key = &V2LocalSharedKey::from(KEY);

  //    //basic builder
  //    let mut builder = V2LocalTokenBuilder::new();

  //    //construct and add a single claim
  //    //    let new_claim = PasetoClaim::try_new("glasses", 4)?;
  //    //    builder.add_claim(new_claim);
  //    //builder.add_claim(PasetoClaim::try_new("wine", "merlot")?);

  //    //build
  //    let token = builder.build(KEY)?;

  //    //now let's decrypt it
  //    let decrypted = V2LocalDecryptedToken::parse(&token.to_string(), None, key)?;

  //    //verify the decrypted payload
  //    assert_eq!(
  //      decrypted.as_ref(),
  //      &serde_json::json!({"wine":"merlot", "glasses":4}).to_string()
  //    );

  //    Ok(())
  //  }

  //  #[test]
  //  fn test_basic_builder_with_single_claim_and_footer() -> Result<()> {
  //    //here's a valid 32 byte key
  //    const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";
  //    let key = &V2LocalSharedKey::from(KEY);

  //    //basic builder
  //    let mut builder = V2LocalTokenBuilder::new();

  //    //construct and add a single claim
  //    //   let claim: AudienceClaim = "I'm Pickle Rick!".into();
  //    //   builder.add_restricted_claim(claim);
  //    builder.set_footer(Some(Footer::from("universe c137")));

  //    //build
  //    let token = builder.build(KEY)?;

  //    //now let's decrypt it
  //    let _decrypted = V2LocalDecryptedToken::parse(&token.to_string(), Some(Footer::from("universe c137")), key)?;

  //    //verify the decrypted payload
  //    //    assert_eq!(
  //    //      decrypted.as_ref(),
  //    //      &serde_json::json!({"aud":"I'm Pickle Rick!"}).to_string()
  //    //    );

  //    Ok(())
  //  }

  //  #[test]
  //  fn test_basic_builder_with_single_claim() -> Result<()> {
  //    //here's a valid 32 byte key
  //    const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";
  //    let key = &V2LocalSharedKey::from(KEY);

  //    //basic builder
  //    let builder = V2LocalTokenBuilder::new();

  //    //construct and add a single claim
  //    //   let claim: AudienceClaim = "I'm Pickle Rick!".into();
  //    //   builder.add_restricted_claim(claim);

  //    //build
  //    let token = builder.build(KEY)?;

  //    //now let's decrypt it
  //    let _decrypted = V2LocalDecryptedToken::parse(&token.to_string(), None, key)?;

  //    //verify the decrypted payload
  //    //    assert_eq!(
  //    //      decrypted.as_ref(),
  //    //      &serde_json::json!({"aud":"I'm Pickle Rick!"}).to_string()
  //    //    );

  //    Ok(())
  //  }

  //  #[test]
  //  fn test_basic_builder() -> Result<()> {
  //    //here's a valid 32 byte key
  //    const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";
  //    let key = &V2LocalSharedKey::from(KEY);

  //    //here's the simplest token you can build, no arbitrary claims, no footer,
  //    //24 hour expiration date
  //    let token = V2LocalTokenBuilder::new().build(KEY)?;
  //    //now let's decrypt it
  //    let _decrypted = V2LocalDecryptedToken::parse(&token.to_string(), None, key)?;

  //    //verify the decrypted and empty payload
  //    //      assert_eq!(decrypted.as_ref(), "{}");

  //    Ok(())
  //  }
}
