use anyhow::Result;
use rusty_paseto::{Footer, Payload, V2LocalToken, V2LocalTokenDecrypted, V2SymmetricKey};

#[test]
fn basic_usage_test() -> Result<()> {
  //generate a random key, normally you'll use one of your own creation
  let key = &V2SymmetricKey::new_random();
  let footer = Some(Footer::from("wubbulubbadubdub"));
  let payload = Payload::from("I'm Pickle Rick!");

  //create a local v2 token
  let token = V2LocalToken::new(payload, key, footer);

  //now let's decrypt it
  let decrypted = V2LocalTokenDecrypted::parse(&token.as_ref(), footer, key)?;

  assert_eq!(decrypted, payload);

  Ok(())
}
