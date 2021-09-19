mod crypto;
mod keys;
mod util;
mod v2;

pub use keys::{get_key_from_hex_string, Key192Bit, Key192BitSize, Key256Bit, Key256BitSize, V2SymmetricKey};
pub use v2::Footer;
pub use v2::Message;
pub use v2::V2LocalToken;

//  #[cfg(test)]
//  mod tests {
//    use crate::keys::V2SymmetricKey;
//    use crate::util::get_random_256_bit_buf;
//    use crate::v2::{Footer, Message, V2LocalToken};

//    //create a local v2 token
//    #[test]
//    fn test_creating_v2_local_token_with_random_key() {
//      let random_buf = &get_random_256_bit_buf();
//      let token = V2LocalToken::new(
//        Message::from("Here's a secret message!"),
//        V2SymmetricKey::from(random_buf),
//        Some(Footer::from("here's a great footer too!")),
//      );

//      assert_eq!(token.to_string(), "wubbulubbadubdub");
//    }
//  }
