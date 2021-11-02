use crate::common::Footer;
use crate::common::Payload;
use crate::errors::PasetoTokenParseError;
use std::convert::AsRef;
use std::str::FromStr;

/// A type alias to simplify usage of this tuple (payload, potential footer)
/// each value in the tuple EXCEPT for the header should be base64 encoded already
//pub(crate) type V2LocalUntrustedEncryptedTokenParts = (String, Option<String>);

/// A private struct for parsing an incoming token string
pub(crate) struct UntrustedEncryptedToken {
  encrypted_token_parts: (String, String, Option<String>),
}

impl AsRef<(String, String, Option<String>)> for UntrustedEncryptedToken {
  fn as_ref(&self) -> &(String, String, Option<String>) {
    &self.encrypted_token_parts
  }
}

impl FromStr for UntrustedEncryptedToken {
  type Err = PasetoTokenParseError;

  /// This is where the real work is done to parse any ole string which may or may not
  /// be a token.  This parsing function doesn't validate or decrypt the token, it merely
  /// ensures it can be broken down into the various parts which constitute a valid token structure
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    //split the string into it's consituent parts
    let potential_parts = s.split('.').collect::<Vec<_>>();

    //first let's see if there are enough parts
    if potential_parts.len() < 3 || potential_parts.len() > 4 {
      return Err(PasetoTokenParseError::IncorrectSize);
    };

    //grab the header
    let potential_header = format!("{}.{}.", potential_parts[0], potential_parts[1]);

    //produce the struct based on whether there is a potential footer or not
    match potential_parts.len() {
      //no footer
      3 => Ok(Self {
        encrypted_token_parts: (Payload::from(potential_parts[2]).to_string(), potential_header, None),
      }),
      //otherwise there must be
      _ => Ok(Self {
        encrypted_token_parts: (
          Payload::from(potential_parts[2]).to_string(),
          potential_header,
          Some(Footer::from(potential_parts[3]).to_string()),
        ),
      }),
    }
  }
}
