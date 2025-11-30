use std::{
    str,
};
use subtle::ConstantTimeEq;
use crate::core::{Base64Encodable, Footer, Header, ImplicitAssertion, ImplicitAssertionCapable, PasetoError, Payload, PurposeTrait, VersionTrait};


/// Used to build and encrypt / decrypt core PASETO tokens
///
/// Given a [Payload], optional [Footer] and optional [`ImplicitAssertion`] ([V3] or [V4] only)
/// returns an encrypted token when [Local] is specified as the purpose or a signed token when
/// [Public] is specified
/// # Example usage
/// ```
/// # #[cfg(feature = "v4_local")]
/// # {
/// # use serde_json::json;
/// use rusty_paseto::core::*;
///
/// let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
/// let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
/// // generate a random nonce with
/// // let nonce = Key::<32>::try_new_random()?;
/// let nonce = PasetoNonce::<V4, Local>::from(&nonce);
///
/// let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
/// let payload = payload.as_str();
/// let payload = Payload::from(payload);
///
/// //create a public v4 token
/// let token = Paseto::<V4, Local>::builder()
///   .set_payload(payload)
///   .try_encrypt(&key, &nonce)?;
///
/// //validate the test vector
/// assert_eq!(token.to_string(), "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg");
///
/// //now let's try to decrypt it
/// let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
/// assert_eq!(payload, json);
/// }
/// # Ok::<(),anyhow::Error>(())
/// ```
#[derive(Default, Copy, Clone)]
pub struct Paseto<'a, Version, Purpose>
    where
        Version: VersionTrait,
        Purpose: PurposeTrait,
{
    pub(crate) header: Header<Version, Purpose>,
    pub(crate) payload: Payload<'a>,
    pub(crate) footer: Option<Footer<'a>>,
    pub(crate) implicit_assertion: Option<ImplicitAssertion<'a>>,
}

impl<'a, Version: VersionTrait, Purpose: PurposeTrait> Paseto<'a, Version, Purpose> {
    /// Returns a builder for creating a PASETO token
    ///
    /// # Example usage
    /// ```
    /// # #[cfg(feature = "v4_local")]
    /// # {
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    ///
    /// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # // generate a random nonce with
    /// # // let nonce = Key::<32>::try_new_random()?;
    /// # let nonce = PasetoNonce::<V4, Local>::from(&nonce);
    ///
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    ///
    /// //create a public v4 token
    /// let token = Paseto::<V4, Local>::builder()
    ///   .set_payload(payload)
    ///   .try_encrypt(&key, &nonce)?;
    ///
    /// # //validate the test vector
    /// # assert_eq!(token.to_string(), "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg");
    ///
    /// # //now let's try to decrypt it
    /// # let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
    /// # assert_eq!(payload, json);
    /// }
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    #[must_use]
    pub fn builder() -> Self {
        Self::default()
    }

    /// Sets the payload for the token
    pub fn set_payload(&mut self, payload: Payload<'a>) -> &mut Self {
        self.payload = payload;
        self
    }

    /// Sets an optional footer for the token
    ///
    /// # Example usage
    /// ```
    /// # #[cfg(feature = "v4_local")]
    /// # {
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    ///
    /// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # // generate a random nonce with
    /// # // let nonce = Key::<32>::try_new_random()?;
    /// # let nonce = PasetoNonce::<V4, Local>::from(&nonce);
    ///
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    ///
    /// // Set the footer with a Footer struct
    /// let token = Paseto::<V4, Local>::builder()
    ///   .set_payload(payload)
    ///   .set_footer(Footer::from("Supah doopah!"))
    ///   .try_encrypt(&key, &nonce)?;
    ///
    /// # //now let's try to decrypt it
    /// # let json = Paseto::<V4, Local>::try_decrypt(&token, &key, Footer::from("Supah doopah!"), None)?;
    /// # assert_eq!(payload, json);
    /// }
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
        self.footer = Some(footer);
        self
    }

    /* BEGIN PRIVATE FUNCTIONS */
    pub(crate) fn format_token(&self, encrypted_payload: &str) -> String {
        let header = &self.header;
        self.footer.map(|f| f.encode()).map_or_else(
            || format!("{header}{encrypted_payload}"),
            |f| format!("{header}{encrypted_payload}.{f}"),
        )
    }

    pub(crate) fn parse_raw_token(
        raw_token: &'a str,
        footer: impl Into<Option<Footer<'a>>> + Copy,
        v: &Version,
        p: &Purpose,
    ) -> Result<Vec<u8>, PasetoError> {
        //split the raw token into parts
        let potential_parts = raw_token.split('.').collect::<Vec<_>>();

        //validate we have 3 or 4 parts
        let parts_len = potential_parts.len();
        if !(3..=4).contains(&parts_len) {
            return Err(PasetoError::IncorrectSize);
        }

        //safely extract parts using .get() - these are guaranteed to exist after length check
        let version_part = potential_parts.first().ok_or(PasetoError::IncorrectSize)?;
        let purpose_part = potential_parts.get(1).ok_or(PasetoError::IncorrectSize)?;
        let payload_part = potential_parts.get(2).ok_or(PasetoError::IncorrectSize)?;

        //verify footer if present (4 parts)
        if parts_len == 4 {
            let footer_part = potential_parts.get(3).ok_or(PasetoError::IncorrectSize)?;
            let footer = footer.into().unwrap_or_default();
            let found_footer = Footer::from(*footer_part);
            if !footer.constant_time_equals(found_footer) {
                return Err(PasetoError::FooterInvalid);
            }
        }

        //grab the header
        let potential_header = format!("{version_part}.{purpose_part}.");
        //we should be able to verify the header using the passed in Version and Purpose
        let expected_header = format!("{v}.{p}.");

        //verify the header using constant-time comparison to prevent timing attacks
        if !bool::from(potential_header.as_bytes().ct_eq(expected_header.as_bytes())) {
            return Err(PasetoError::WrongHeader);
        }

        let encrypted_payload = Payload::from(*payload_part);
        Ok(encrypted_payload.decode()?)
    }
    /* END PRIVATE FUNCTIONS */
}

impl<'a, Version, Purpose> Paseto<'a, Version, Purpose>
    where
        Purpose: PurposeTrait,
        Version: ImplicitAssertionCapable,
{
    /// Sets an optional [`ImplicitAssertion`] for the token
    ///
    /// *NOTE:* Only for [V3] or [V4] tokens
    ///
    /// # Example usage
    /// ```
    /// # #[cfg(feature = "v4_local")]
    /// # {
    /// # use serde_json::json;
    /// # use rusty_paseto::core::*;
    ///
    /// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
    /// # let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
    /// # // generate a random nonce with
    /// # // let nonce = Key::<32>::try_new_random()?;
    /// # let nonce = PasetoNonce::<V4, Local>::from(&nonce);
    ///
    /// # let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
    /// # let payload = payload.as_str();
    /// # let payload = Payload::from(payload);
    ///
    /// // Set the ImplicitAssertion
    /// let token = Paseto::<V4, Local>::builder()
    ///   .set_payload(payload)
    ///   .set_implicit_assertion(ImplicitAssertion::from("Supah doopah!"))
    ///   .try_encrypt(&key, &nonce)?;
    ///
    /// # //now let's try to decrypt it
    /// # let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, ImplicitAssertion::from("Supah doopah!"))?;
    /// # assert_eq!(payload, json);
    /// }
    /// # Ok::<(),anyhow::Error>(())
    /// ```
    pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
        self.implicit_assertion = Some(implicit_assertion);
        self
    }
}
















