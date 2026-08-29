//! # Framework-neutral PASETO session-cookie example
//!
//! Demonstrates the security-sensitive parts of using a V4 local PASETO as a
//! session cookie without coupling the crate to a web framework. Adapt
//! `issue_session_token` in your login handler and `verify_session_token` in
//! authentication middleware.
//!
//! The implicit assertion binds the token to server-side session context that
//! is not stored in the token. A copied token will fail validation when the
//! corresponding session binding is unavailable or different.

use rusty_paseto::prelude::*;
use rusty_paseto::{Error, Result};

const COOKIE_NAME: &str = "auth-token";

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionBinding(String);

impl SessionBinding {
  fn new(value: impl Into<String>) -> Self {
    Self(value.into())
  }
}

impl AsRef<str> for SessionBinding {
  fn as_ref(&self) -> &str {
    &self.0
  }
}

fn issue_session_token(
  key: &PasetoSymmetricKey<V4, Local>,
  session_binding: &SessionBinding,
) -> Result<String> {
  PasetoBuilder::<V4, Local>::default()
    .subject("user-123")
    .set_implicit_assertion(ImplicitAssertion::from(session_binding.as_ref()))
    .build(key)
    .map_err(Error::from)
}

fn verify_session_token(
  token: &str,
  key: &PasetoSymmetricKey<V4, Local>,
  session_binding: &SessionBinding,
) -> Result<serde_json::Value> {
  PasetoParser::<V4, Local>::default()
    .expect_subject("user-123")
    .set_implicit_assertion(ImplicitAssertion::from(session_binding.as_ref()))
    .parse(token, key)
    .map_err(Error::from)
}

fn set_cookie_header(token: &str) -> String {
  format!("{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Lax")
}

fn load_paseto_key() -> Result<PasetoSymmetricKey<V4, Local>> {
  let key = match std::env::var("PASETO_KEY") {
    Ok(hex_key) => Key::<32>::try_from(hex_key.as_str()).map_err(Error::from)?,
    Err(std::env::VarError::NotPresent) => {
      eprintln!(
        "PASETO_KEY is unset; generating an ephemeral demonstration key. \
         Production services must load a stable key from a secret manager."
      );
      Key::<32>::try_new_random().map_err(Error::from)?
    }
    Err(std::env::VarError::NotUnicode(_)) => return Err(Error::InvalidKey),
  };

  Ok(PasetoSymmetricKey::<V4, Local>::from(key))
}

fn main() -> Result<()> {
  let key = load_paseto_key()?;

  // In a real application, generate this opaque value during login and keep
  // it in server-side session state. Do not derive it from attacker-controlled
  // cookie data.
  let session_binding = SessionBinding::new("opaque-server-side-session-binding");
  let token = issue_session_token(&key, &session_binding)?;
  let cookie = set_cookie_header(&token);

  // Authentication middleware extracts the cookie value and looks up the
  // server-side session binding before verification.
  let claims = verify_session_token(&token, &key, &session_binding)?;

  println!("Set-Cookie: {cookie}");
  println!("Verified subject: {}", claims["sub"]);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_key() -> PasetoSymmetricKey<V4, Local> {
    PasetoSymmetricKey::from(Key::from(*b"wubbalubbadubdubwubbalubbadubdub"))
  }

  #[test]
  fn issued_token_verifies_only_with_original_session_binding() -> Result<()> {
    let key = test_key();
    let original = SessionBinding::new("original-session");
    let different = SessionBinding::new("different-session");
    let token = issue_session_token(&key, &original)?;

    let claims = verify_session_token(&token, &key, &original)?;
    assert_eq!(claims["sub"], "user-123");
    assert!(verify_session_token(&token, &key, &different).is_err());
    Ok(())
  }

  #[test]
  fn cookie_header_enables_browser_security_attributes() {
    let header = set_cookie_header("token");

    assert!(header.starts_with("auth-token=token;"));
    assert!(header.contains("Secure"));
    assert!(header.contains("HttpOnly"));
    assert!(header.contains("SameSite=Lax"));
  }
}
