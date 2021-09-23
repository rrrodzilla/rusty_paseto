use anyhow::Result;
use rusty_paseto::v2::local::{V2LocalDecryptedString, V2LocalSharedKey, V2LocalToken};
use rusty_paseto::v2::Payload;
use rusty_paseto::v2::{Footer, Key256Bit};

#[test]
fn basic_usage_test_random_key_and_footer() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &V2LocalSharedKey::new_random();
  let footer = Some(Footer::from("wubbulubbadubdub"));
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = V2LocalToken::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = V2LocalDecryptedString::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}

#[test]
fn basic_usage_test_random_key_and_no_footer() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &V2LocalSharedKey::new_random();
  let footer = None;
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = V2LocalToken::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = V2LocalDecryptedString::parse(&token.to_string(), footer, key)?;

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
  let key: &V2LocalSharedKey = &KEY.into();
  let footer = None;
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = V2LocalToken::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = V2LocalDecryptedString::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}
