use super::*;
use std::str;

/// Represents a PASETO token that has been structurally parsed but **NOT** cryptographically verified.
///
/// This struct provides the ability to extract footer information from PASETO tokens before
/// cryptographic verification. This is essential for key rotation scenarios where the footer
/// contains key identifiers (e.g., `kid` claims) needed to select the correct verification key.
///
/// # Security Warning
///
/// ⚠️ **ALL DATA FROM THIS STRUCT IS UNTRUSTED** ⚠️
///
/// The footer and all other token components have **NOT** been cryptographically verified.
/// - **DO** use footer contents for key selection and lookup
/// - **DO NOT** use footer contents for security decisions
/// - **DO NOT** trust any data until the token has been verified via [Paseto::try_decrypt] or [Paseto::try_verify]
///
/// The footer is authenticated as part of the PASETO token but only validated during the
/// verification process. An attacker could craft a token with any footer contents, so treat
/// this data as hostile input suitable only for selecting which key to attempt verification with.
///
/// # Usage
///
/// ```
/// # use rusty_paseto::core::*;
/// # fn example() -> Result<(), PasetoError> {
/// // Parse the untrusted token to extract the footer
/// let token = "v4.local.payload.eyJraWQiOiJrZXktMSJ9"; // footer: {"kid":"key-1"}
/// let untrusted = UntrustedToken::try_parse(token)?;
///
/// // Extract the footer (UNTRUSTED - only for key lookup)
/// if let Some(footer_str) = untrusted.footer_str()? {
///     // Parse footer to get key identifier
///     // (In real code, validate/sanitize the footer format)
///
///     // Use the key ID to select the appropriate key
///     // let key = key_store.get(kid)?;
///
///     // Now verify the token with the selected key
///     // let payload = Paseto::<V4, Local>::try_decrypt(&token, &key, Footer::from(footer_str), None)?;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct UntrustedToken<'a> {
    version: &'a str,
    purpose: &'a str,
    footer: Option<&'a str>,
}

impl<'a> UntrustedToken<'a> {
    /// Parse a PASETO token string into its structural components without any cryptographic verification.
    ///
    /// This method validates only the basic token format (3-4 dot-separated parts) and performs
    /// **NO** cryptographic operations. The returned struct contains references to the token's
    /// components but provides no guarantees about their validity or authenticity.
    ///
    /// # Security
    ///
    /// ⚠️ This method performs **ZERO** cryptographic verification. All returned data is untrusted.
    ///
    /// # Token Format
    ///
    /// Valid PASETO tokens follow the format:
    /// ```text
    /// v{version}.{purpose}.{payload}[.{footer}]
    /// ```
    ///
    /// - `version`: PASETO protocol version (e.g., "v4")
    /// - `purpose`: Either "local" (symmetric) or "public" (asymmetric)
    /// - `payload`: Base64url-encoded encrypted payload or signature
    /// - `footer`: Optional base64url-encoded footer
    ///
    /// # Errors
    ///
    /// Returns [`PasetoError::IncorrectSize`] if the token does not contain exactly 3 or 4 dot-separated parts.
    ///
    /// # Example
    ///
    /// ```
    /// # use rusty_paseto::core::*;
    /// # fn example() -> Result<(), PasetoError> {
    /// let token = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg";
    ///
    /// let untrusted = UntrustedToken::try_parse(token)?;
    /// assert_eq!(untrusted.version(), "v4");
    /// assert_eq!(untrusted.purpose(), "local");
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_parse(token: &'a str) -> Result<Self, PasetoError> {
        let parts: Vec<&str> = token.split('.').collect();

        // PASETO tokens must have exactly 3 parts (no footer) or 4 parts (with footer)
        let parts_len = parts.len();
        if !(3..=4).contains(&parts_len) {
            return Err(PasetoError::IncorrectSize);
        }

        // Use safe .get() access - these are guaranteed to exist after length validation
        let version = parts.first().ok_or(PasetoError::IncorrectSize)?;
        let purpose = parts.get(1).ok_or(PasetoError::IncorrectSize)?;
        let footer = if parts_len == 4 {
            Some(*parts.get(3).ok_or(PasetoError::IncorrectSize)?)
        } else {
            None
        };

        Ok(Self {
            version,
            purpose,
            footer,
        })
    }

    /// Returns the PASETO version string (e.g., "v4").
    ///
    /// ⚠️ **UNTRUSTED**: This value has not been cryptographically verified.
    ///
    /// # Example
    ///
    /// ```
    /// # use rusty_paseto::core::*;
    /// # fn example() -> Result<(), PasetoError> {
    /// let token = "v4.local.payload";
    /// let untrusted = UntrustedToken::try_parse(token)?;
    /// assert_eq!(untrusted.version(), "v4");
    /// # Ok(())
    /// # }
    /// ```
    pub fn version(&self) -> &str {
        self.version
    }

    /// Returns the PASETO purpose string: either "local" (symmetric) or "public" (asymmetric).
    ///
    /// ⚠️ **UNTRUSTED**: This value has not been cryptographically verified.
    ///
    /// # Example
    ///
    /// ```
    /// # use rusty_paseto::core::*;
    /// # fn example() -> Result<(), PasetoError> {
    /// let token = "v4.local.payload";
    /// let untrusted = UntrustedToken::try_parse(token)?;
    /// assert_eq!(untrusted.purpose(), "local");
    /// # Ok(())
    /// # }
    /// ```
    pub fn purpose(&self) -> &str {
        self.purpose
    }

    /// Returns the raw base64url-encoded footer string if present.
    ///
    /// Returns `None` if the token does not contain a footer (3-part token).
    ///
    /// ⚠️ **UNTRUSTED**: This value has not been cryptographically verified.
    /// Only use for key selection, never for security decisions.
    ///
    /// # Example
    ///
    /// ```
    /// # use rusty_paseto::core::*;
    /// # fn example() -> Result<(), PasetoError> {
    /// // Token with footer
    /// let token_with_footer = "v4.local.payload.Zm9vdGVy";
    /// let untrusted = UntrustedToken::try_parse(token_with_footer)?;
    /// assert!(untrusted.footer_base64().is_some());
    ///
    /// // Token without footer
    /// let token_without_footer = "v4.local.payload";
    /// let untrusted = UntrustedToken::try_parse(token_without_footer)?;
    /// assert!(untrusted.footer_base64().is_none());
    /// # Ok(())
    /// # }
    /// ```
    pub fn footer_base64(&self) -> Option<&str> {
        self.footer
    }

    /// Decodes and returns the footer as raw bytes if present.
    ///
    /// Returns `None` if the token does not contain a footer.
    ///
    /// ⚠️ **UNTRUSTED**: This value has not been cryptographically verified.
    /// Only use for key selection, never for security decisions.
    ///
    /// # Errors
    ///
    /// Returns [`PasetoError::PayloadBase64Decode`] if the footer is present but contains invalid base64url encoding.
    ///
    /// # Example
    ///
    /// ```
    /// # use rusty_paseto::core::*;
    /// # fn example() -> Result<(), PasetoError> {
    /// let token = "v4.local.payload.Zm9vdGVy"; // footer base64: "footer"
    /// let untrusted = UntrustedToken::try_parse(token)?;
    ///
    /// if let Some(footer_bytes) = untrusted.footer_decoded()? {
    ///     assert_eq!(footer_bytes, b"footer");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn footer_decoded(&self) -> Result<Option<Vec<u8>>, PasetoError> {
        match self.footer {
            Some(footer_b64) => {
                let decoded = Footer::from(footer_b64).decode()?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }

    /// Decodes and returns the footer as a UTF-8 string if present.
    ///
    /// Returns `None` if the token does not contain a footer.
    ///
    /// ⚠️ **UNTRUSTED**: This value has not been cryptographically verified.
    /// Only use for key selection, never for security decisions.
    ///
    /// # Errors
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
    /// let token = "v4.local.payload.eyJraWQiOiJrZXktMSJ9"; // {"kid":"key-1"}
    /// let untrusted = UntrustedToken::try_parse(token)?;
    ///
    /// if let Some(footer_str) = untrusted.footer_str()? {
    ///     // footer_str is now "{\"kid\":\"key-1\"}"
    ///     // Parse as JSON to extract key identifier
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn footer_str(&self) -> Result<Option<String>, PasetoError> {
        match self.footer_decoded()? {
            Some(bytes) => {
                let s = str::from_utf8(&bytes)?.to_string();
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_parse_token_with_footer() {
        let token = "v4.local.payload.Zm9vdGVy"; // footer = "footer" in base64url
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        assert_eq!(untrusted.version(), "v4");
        assert_eq!(untrusted.purpose(), "local");
        assert_eq!(untrusted.footer_base64(), Some("Zm9vdGVy"));
    }

    #[test]
    fn test_parse_token_without_footer() {
        let token = "v4.local.payload";
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        assert_eq!(untrusted.version(), "v4");
        assert_eq!(untrusted.purpose(), "local");
        assert!(untrusted.footer_base64().is_none());
    }

    #[test]
    fn test_parse_token_too_few_parts() {
        let token = "v4.local";
        let result = UntrustedToken::try_parse(token);

        assert!(matches!(result, Err(PasetoError::IncorrectSize)));
    }

    #[test]
    fn test_parse_token_too_many_parts() {
        let token = "v4.local.payload.footer.extra";
        let result = UntrustedToken::try_parse(token);

        assert!(matches!(result, Err(PasetoError::IncorrectSize)));
    }

    #[test]
    fn test_footer_decoded() {
        let token = "v4.local.payload.Zm9vdGVy"; // footer = "footer" in base64url
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        let footer_bytes = untrusted
            .footer_decoded()
            .expect("failed to decode footer")
            .expect("footer should be present");

        assert_eq!(footer_bytes, b"footer");
    }

    #[test]
    fn test_footer_decoded_returns_none_when_no_footer() {
        let token = "v4.local.payload";
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        let footer_bytes = untrusted.footer_decoded().expect("should not error");

        assert!(footer_bytes.is_none());
    }

    #[test]
    fn test_footer_str() {
        let token = "v4.local.payload.Zm9vdGVy"; // footer = "footer" in base64url
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        let footer_str = untrusted
            .footer_str()
            .expect("failed to decode footer")
            .expect("footer should be present");

        assert_eq!(&footer_str, "footer");
    }

    #[test]
    fn test_footer_str_json() {
        // {"kid":"key-1"} in base64url
        let token = "v4.local.payload.eyJraWQiOiJrZXktMSJ9";
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        let footer_str = untrusted
            .footer_str()
            .expect("failed to decode footer")
            .expect("footer should be present");

        assert_eq!(&footer_str, r#"{"kid":"key-1"}"#);
    }

    #[test]
    fn test_invalid_base64_in_footer() {
        let token = "v4.local.payload.!!!invalid!!!";
        let untrusted = UntrustedToken::try_parse(token).expect("failed to parse token");

        let result = untrusted.footer_decoded();
        assert!(result.is_err());
    }

    #[test]
    fn test_all_versions() {
        for version in &["v1", "v2", "v3", "v4"] {
            let token = format!("{}.local.payload", version);
            let untrusted = UntrustedToken::try_parse(&token).expect("failed to parse token");
            assert_eq!(untrusted.version(), *version);
        }
    }

    #[test]
    fn test_both_purposes() {
        for purpose in &["local", "public"] {
            let token = format!("v4.{}.payload", purpose);
            let untrusted = UntrustedToken::try_parse(&token).expect("failed to parse token");
            assert_eq!(untrusted.purpose(), *purpose);
        }
    }
}
