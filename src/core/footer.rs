use super::*;
use std::fmt;
use std::ops::Deref;

/// Unencrypted text, potentially JSON or some other structured format, typically used for key rotation schemes, packed into the
/// payload as part of the cipher scheme.  
///
/// # Usage
/// ```
/// # #[cfg(feature = "default")]
/// # {
/// # use rusty_paseto::prelude::*;
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// let token = PasetoBuilder::<V4, Local>::default()
///   // note how we set the footer here
///   .set_footer(Footer::from("Sometimes science is more art than science"))
///   .build(&key)?;
///
///    // the footer same footer should be used to parse the token
/// let json_value = PasetoParser::<V4, Local>::default()
///   .set_footer(Footer::from("Sometimes science is more art than science"))
///   .parse(&token, &key)?;
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```
#[derive(Default, Debug, Clone, Copy)]
pub struct Footer<'a>(&'a str);

impl<'a> Base64Encodable<str> for Footer<'a> {}

impl<'a> Deref for Footer<'a> {
  type Target = [u8];

  fn deref(&self) -> &'a Self::Target {
    self.0.as_bytes()
  }
}

impl<'a> AsRef<str> for Footer<'a> {
  fn as_ref(&self) -> &str {
    self.0
  }
}
impl<'a> From<&'a str> for Footer<'a> {
  fn from(s: &'a str) -> Self {
    Self(s)
  }
}
impl<'a> fmt::Display for Footer<'a> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
impl<'a> PartialEq for Footer<'a> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}
impl<'a> Eq for Footer<'a> {}

impl<'a> Footer<'a> {
  /// Extracts the footer from an untrusted PASETO token without cryptographic verification.
  ///
  /// This is a convenience method that parses the token structure and returns the decoded footer
  /// as a UTF-8 string if present. This is useful for key rotation scenarios where you need to
  /// read a key identifier from the footer before you can select the appropriate key for verification.
  ///
  /// Returns `None` if the token does not contain a footer.
  ///
  /// # Security Warning
  ///
  /// ⚠️ **The returned footer is UNTRUSTED** and has NOT been cryptographically verified.
  ///
  /// - **DO** use the footer to select which key to use for verification
  /// - **DO NOT** use the footer contents for any security decisions
  /// - **DO NOT** trust the footer data until after the token has been successfully verified
  ///
  /// The footer is authenticated as part of the PASETO protocol, but this authentication
  /// only happens during the `try_decrypt` or `try_verify` operations. An attacker can craft
  /// a token with arbitrary footer contents, so treat this as hostile input.
  ///
  /// # Errors
  ///
  /// Returns [`PasetoError::IncorrectSize`] if the token format is invalid (not 3-4 dot-separated parts).
  ///
  /// Returns [`PasetoError::PayloadBase64Decode`] if the footer contains invalid base64url encoding.
  ///
  /// Returns [`PasetoError::Utf8Error`] if the decoded footer is not valid UTF-8.
  ///
  /// # Example
  ///
  /// ```
  /// # use rusty_paseto::core::*;
  /// # fn example() -> Result<(), PasetoError> {
  /// // Token with a footer containing a key identifier
  /// let token = "v4.local.payload.eyJraWQiOiJrZXktMSJ9"; // footer: {"kid":"key-1"}
  ///
  /// // Extract the footer to determine which key to use
  /// if let Some(footer_str) = Footer::try_from_token(token)? {
  ///     // Parse the footer to extract key ID (in real code, validate the format)
  ///     // let key = key_store.get_by_kid(&footer_str)?;
  ///
  ///     // Now verify the token with the selected key and the expected footer
  ///     // let payload = Paseto::<V4, Local>::try_decrypt(
  ///     //     token,
  ///     //     &key,
  ///     //     Footer::from(footer_str.as_str()),
  ///     //     None
  ///     // )?;
  /// }
  /// # Ok(())
  /// # }
  /// ```
  pub fn try_from_token(token: &str) -> Result<Option<String>, PasetoError> {
    let untrusted = UntrustedToken::try_parse(token)?;
    untrusted.footer_str()
  }
}

#[cfg(test)]
mod unit_tests {

  use super::*;

  #[test]
  fn test_v2_footer() {
    let footer = Footer::default();
    assert_eq!(footer.as_ref(), "");
    assert!(footer.as_ref().is_empty());
  }

  #[test]
  fn test_set_v2_footer() {
    let footer: Footer = "wubbulubbadubdub".into();
    assert_eq!(footer.as_ref(), "wubbulubbadubdub");
    assert!(!footer.as_ref().is_empty());
  }

  #[test]
  fn test_try_from_token_with_footer() {
    let token = "v4.local.payload.Zm9vdGVy"; // footer = "footer" in base64url
    let footer_str = Footer::try_from_token(token)
      .expect("failed to extract footer")
      .expect("footer should be present");

    assert_eq!(&footer_str, "footer");
  }

  #[test]
  fn test_try_from_token_without_footer() {
    let token = "v4.local.payload";
    let footer_opt = Footer::try_from_token(token).expect("should not error");

    assert!(footer_opt.is_none());
  }

  #[test]
  fn test_try_from_token_invalid_format() {
    let token = "v4.local"; // only 2 parts
    let result = Footer::try_from_token(token);

    assert!(matches!(result, Err(PasetoError::IncorrectSize)));
  }
}
