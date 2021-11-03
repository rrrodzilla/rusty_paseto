use anyhow::Result;
use rusty_paseto::core_tokens::{Footer, Key, Key256Bit, Local, Payload, V2};
use rusty_paseto::core_tokens::{GenericToken, GenericTokenDecrypted};

#[test]
fn basic_usage_test_random_key_and_footer() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &Key::<V2, Local>::new_random();
  let footer = Some(Footer::from("wubbulubbadubdub"));
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = GenericToken::<V2, Local>::new(payload, key, footer.clone());

  //now let's decrypt it
  let decrypted = GenericTokenDecrypted::<V2, Local>::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}

#[test]
fn basic_usage_test_random_key_and_no_footer() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &Key::<V2, Local>::new_random();
  let footer = None;
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = GenericToken::<V2, Local>::new(payload, key, footer.clone());

  //now let's decrypt it
  let decrypted = GenericTokenDecrypted::<V2, Local>::parse(&token.to_string(), footer, key)?;

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
  let key: &Key<V2, Local> = &KEY.into();
  let footer = None;
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = GenericToken::<V2, Local>::new(payload, key, footer.clone());

  //now let's decrypt it
  let decrypted = GenericTokenDecrypted::<V2, Local>::parse(&token.to_string(), footer, key)?;

  //these can be equated directly or you can access the internal values using AsRef
  assert_eq!(decrypted, payload);
  //...like so.
  assert_eq!(decrypted.as_ref(), "I'm Pickle Rick!");

  Ok(())
}
