#![cfg(feature = "v2_public")]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::core::{Footer, Header, Paseto, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoError, Public, V2};
use crate::core::common::{PreAuthenticationEncoding, RawPayload};

impl<'a> Paseto<'a, V2, Public> {
    /// Attempts to verify a signed V2 Public Paseto
    /// Fails with a PasetoError if the token is malformed or the token cannot be verified with the
    /// passed public key
    pub fn try_verify(
        signature: &'a str,
        public_key: &PasetoAsymmetricPublicKey<V2, Public>,
        footer: impl Into<Option<Footer<'a>>> + Copy,
    ) -> Result<String, PasetoError> {
        // V2 public token structure: message (variable) + signature (64 bytes)
        let sig_len = ed25519_dalek::SIGNATURE_LENGTH;

        let decoded_payload = Self::parse_raw_token(signature, footer, &V2::default(), &Public::default())?;

        // Validate minimum payload size (at least signature length)
        if decoded_payload.len() < sig_len {
            return Err(PasetoError::IncorrectSize);
        }

        let verifying_key: VerifyingKey = VerifyingKey::from_bytes(<&[u8; 32]>::try_from(public_key.as_ref())?)?;

        // Safe slicing with bounds-checked access
        let msg_len = decoded_payload.len().saturating_sub(sig_len);
        let msg = decoded_payload.get(..msg_len).ok_or(PasetoError::IncorrectSize)?;
        let sig_end = msg_len
            .checked_add(sig_len)
            .ok_or(PasetoError::IncorrectSize)?;
        let sig = decoded_payload.get(msg_len..sig_end).ok_or(PasetoError::IncorrectSize)?;

        let signature = Signature::try_from(sig)?;
        let pae = PreAuthenticationEncoding::parse(&[
            &Header::<V2, Public>::default(),
            msg,
            &footer.into().unwrap_or_default(),
        ]);

        verifying_key.verify(&pae, &signature)?;

        Ok(String::from_utf8(Vec::from(msg))?)
    }

    /// Attempts to sign a V2 Public Paseto
    /// Fails with a PasetoError if the token is malformed or the private key can't be parsed
    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V2, Public>) -> Result<String, PasetoError> {
        let footer = self.footer.unwrap_or_default();

        // let keypair = Keypair::from_bytes(key.as_ref())?;
        let signing_key = SigningKey::from_keypair_bytes(<&[u8; 64]>::try_from(key.as_ref())?)?;

        let pae = PreAuthenticationEncoding::parse(&[&self.header, &self.payload, &footer]);

        // let signature = keypair.sign(&pae);
        let signature = signing_key.sign(&pae);
        let raw_payload = RawPayload::<V2, Public>::from(&self.payload, &signature.to_bytes());

        Ok(self.format_token(&raw_payload))
    }
}
