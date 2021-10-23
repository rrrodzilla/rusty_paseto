use anyhow::Result;
use rusty_paseto::generic_tokens::{Footer, Key, Key256Bit, Payload, PurposeLocal, Version2};
use rusty_paseto::generic_tokens::{GenericToken, GenericTokenDecrypted};

#[test]
fn basic_usage_test_random_key_and_footer() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &Key::<Version2, PurposeLocal>::new_random();
  let footer = Some(Footer::from("wubbulubbadubdub"));
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = GenericToken::<Version2, PurposeLocal>::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}

#[test]
fn basic_usage_test_random_key_and_no_footer() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &Key::<Version2, PurposeLocal>::new_random();
  let footer = None;
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = GenericToken::<Version2, PurposeLocal>::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}

#[test]
fn basic_usage_test_non_random_key_and_no_footer() -> Result<()> {
  //create a 32 byte key value
  const KEY: Key256Bit = *b"wubbalubbadubdubwubbalubbadubdub";
  //turn it into a key
  let key: &Key<Version2, PurposeLocal> = &KEY.into();
  let footer = None;
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = GenericToken::<Version2, PurposeLocal>::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = GenericTokenDecrypted::<Version2, PurposeLocal>::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}
