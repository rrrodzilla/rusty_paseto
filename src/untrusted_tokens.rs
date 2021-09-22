use crate::common::Footer;
use crate::errors::PasetoTokenParseError;
use crate::headers::Header;
use crate::v2::Payload;
use std::str::FromStr;

/// A type alias to simplify usage of this tuple (payload, potential footer)
/// each value in the tuple EXCEPT for the header should be base64 encoded already
pub(crate) type V2LocalUntrustedEncryptedTokenParts = (String, Option<String>);

/// A private struct for parsing an incoming token string
pub(crate) struct V2LocalUntrustedEncryptedToken(V2LocalUntrustedEncryptedTokenParts);

impl AsRef<V2LocalUntrustedEncryptedTokenParts> for V2LocalUntrustedEncryptedToken {
  fn as_ref(&self) -> &V2LocalUntrustedEncryptedTokenParts {
    &self.0
  }
}

impl FromStr for V2LocalUntrustedEncryptedToken {
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

    //now let's check the header
    //first reconstruct it from the incoming string parts
    let potential_header = format!("{}.{}.", potential_parts[0], potential_parts[1]);
    //if the recreated header is not equal to a valid known Header, then the header is invalid
    if potential_header.ne(Header::default().as_ref()) {
      return Err(PasetoTokenParseError::WrongHeader);
    }

    //produce the struct based on whether there is a potential footer or not
    match potential_parts.len() {
      //no footer
      3 => Ok(Self((Payload::from(potential_parts[2]).to_string(), None))),
      //otherwise there must be
      _ => Ok(Self((
        Payload::from(potential_parts[2]).to_string(),
        Some(Footer::from(potential_parts[3]).to_string()),
      ))),
    }
  }
}
