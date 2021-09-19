//use rusty_paseto::{get_key_from_hex_string, Footer, Key256BitSize, Message, V2LocalToken, V2SymmetricKey};
//use serde_json::json;

//  #[test]
//  fn test_creating_v2_local_token_with_a_footer_and_hex_key() {
//    const EXPECTED_TOKEN: &str = "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
//    //create the key
//    let key =
//      &get_key_from_hex_string::<Key256BitSize>("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
//        .expect("couldn't convert hex string to 256 bit key");

//    //create a local v2 token in one line
//    let token = V2LocalToken::new(
//      Message::from(
//        json!({"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"})
//          .to_string()
//          .as_str(),
//      ),
//      V2SymmetricKey::from(key),
//      None,
//    );

//    assert_eq!(token.to_string(), EXPECTED_TOKEN);
//  }

//  #[test]
//  fn test_creating_v2_local_token_with_no_footer_and_random_key() {
//    //create a local v2 token in one line with no footer
//    let token = V2LocalToken::new(
//      Message::from("Here's a secret message!"),
//      V2SymmetricKey::from(Key256Bit::from(b"wubbalubbadubdubwubbalubbadubdub")),
//      None,
//    );

//    assert_eq!(token.to_string(), "wubbulubbadubdub");
//  }
