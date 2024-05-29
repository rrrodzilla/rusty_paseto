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
        footer: (impl Into<Option<Footer<'a>>> + Copy),
    ) -> Result<String, PasetoError> {
        let decoded_payload = Self::parse_raw_token(signature, footer, &V2::default(), &Public::default())?;

        let verifying_key: VerifyingKey = VerifyingKey::from_bytes(<&[u8; 32]>::try_from(public_key.as_ref())?)?;

        // let public_key = PublicKey::from_bytes(public_key.as_ref()).map_err(|_| PasetoError::InvalidSignature)?;
        let msg = decoded_payload[..(decoded_payload.len() - ed25519_dalek::SIGNATURE_LENGTH)].as_ref();
        let sig = decoded_payload[msg.len()..msg.len() + ed25519_dalek::SIGNATURE_LENGTH].as_ref();

        let signature = Signature::try_from(sig).map_err(|_| PasetoError::InvalidSignature)?;
        let pae = PreAuthenticationEncoding::parse(&[
            &Header::<V2, Public>::default(),
            msg,
            &footer.into().unwrap_or_default(),
        ]);

        verifying_key.verify(&pae, &signature)?;
        // public_key
        //     .verify(&pae, &signature)
        //     .map_err(|_| PasetoError::InvalidSignature)?;

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
