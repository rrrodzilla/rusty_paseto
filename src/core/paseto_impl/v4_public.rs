#![cfg(feature = "v4_public")]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::core::{Footer, Header, ImplicitAssertion, Paseto, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoError, Public, V4};
use crate::core::common::{PreAuthenticationEncoding, RawPayload};

impl<'a> Paseto<'a, V4, Public> {
    pub fn try_verify(
        signature: &'a str,
        public_key: &PasetoAsymmetricPublicKey<V4, Public>,
        footer: (impl Into<Option<Footer<'a>>> + Copy),
        implicit_assertion: (impl Into<Option<ImplicitAssertion<'a>>> + Copy),
    ) -> Result<String, PasetoError> {
        let decoded_payload = Self::parse_raw_token(signature, footer, &V4::default(), &Public::default())?;

        let verifying_key: VerifyingKey = VerifyingKey::from_bytes(<&[u8; 32]>::try_from(public_key.as_ref())?)?;

        let msg = decoded_payload[..(decoded_payload.len() - ed25519_dalek::SIGNATURE_LENGTH)].as_ref();
        let sig = decoded_payload[msg.len()..msg.len() + ed25519_dalek::SIGNATURE_LENGTH].as_ref();

        let signature = Signature::try_from(sig)?;
        let pae = PreAuthenticationEncoding::parse(&[
            &Header::<V4, Public>::default(),
            msg,
            &footer.into().unwrap_or_default(),
            &implicit_assertion.into().unwrap_or_default(),
        ]);

        verifying_key.verify(&pae, &signature)?;
        // public_key.verify(&pae, &signature)?;

        Ok(String::from_utf8(Vec::from(msg))?)
    }

    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V4, Public>) -> Result<String, PasetoError> {
        let footer = self.footer.unwrap_or_default();
        let assertion = self.implicit_assertion.unwrap_or_default();
        // let secret_key : SecretKey = SecretKey::try_from(key.as_ref())?;
        let signing_key = SigningKey::from_keypair_bytes(<&[u8; 64]>::try_from(key.as_ref())?)?;

        // let keypair = Keypair::from_bytes(key.as_ref())?;

        let pae = PreAuthenticationEncoding::parse(&[&self.header, &self.payload, &footer, &assertion]);


        let signature = signing_key.sign(&pae);

        let raw_payload = RawPayload::<V4, Public>::from(&self.payload, &signature.to_bytes());

        Ok(self.format_token(&raw_payload))
    }
}
