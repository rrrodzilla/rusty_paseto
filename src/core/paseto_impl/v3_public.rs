#![cfg(feature = "v3_public")]

use crate::core::{Footer, Header, ImplicitAssertion, Paseto, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoError, Public, V3};
use crate::core::common::{PreAuthenticationEncoding, RawPayload};
use p384::ecdsa::{
    signature::DigestSigner, signature::DigestVerifier, Signature, SigningKey, VerifyingKey,
};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::PublicKey;
use sha2::Digest;

impl<'a> Paseto<'a, V3, Public> {
    /// Verifies a signed V3 Public Paseto
    pub fn try_verify(
        signature: &'a str,
        public_key: &PasetoAsymmetricPublicKey<V3, Public>,
        footer: (impl Into<Option<Footer<'a>>> + Copy),
        implicit_assertion: (impl Into<Option<ImplicitAssertion<'a>>> + Copy),
    ) -> Result<String, PasetoError> {
        let decoded_payload = Self::parse_raw_token(signature, footer, &V3::default(), &Public::default())?;

        //compress the key
        let compressed_public_key = PublicKey::from_sec1_bytes(public_key.as_ref())
            .map_err(|_| PasetoError::InvalidKey)?
            .to_encoded_point(true);

        let verifying_key =
            VerifyingKey::from_sec1_bytes(compressed_public_key.as_ref()).map_err(|_| PasetoError::InvalidKey)?;
        let msg = decoded_payload[..(decoded_payload.len() - 96)].as_ref();
        let sig = decoded_payload[msg.len()..msg.len() + 96].as_ref();

        let signature = Signature::try_from(sig).map_err(|_| PasetoError::Signature)?;
        let m2 = PreAuthenticationEncoding::parse(&[
            compressed_public_key.as_ref(),
            &Header::<V3, Public>::default(),
            msg,
            &footer.into().unwrap_or_default(),
            &implicit_assertion.into().unwrap_or_default(),
        ]);
        let mut msg_digest = sha2::Sha384::default();
        msg_digest.update(&*m2);
        verifying_key
            .verify_digest(msg_digest, &signature)
            .map_err(|_| PasetoError::InvalidSignature)?;

        Ok(String::from_utf8(Vec::from(msg))?)
    }

    /// Attempts to sign a V3 Public Paseto
    /// Fails with a PasetoError if the token is malformed or the private key isn't in a valid format
    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V3, Public>) -> Result<String, PasetoError> {
        let footer = self.footer.unwrap_or_default();

        let implicit_assertion = self.implicit_assertion.unwrap_or_default();
        let signing_key = SigningKey::from_bytes(key.as_ref().into()).map_err(|_| PasetoError::InvalidKey)?;
        let public_key = VerifyingKey::from(&signing_key).to_encoded_point(true);

        let m2 = PreAuthenticationEncoding::parse(&[
            public_key.as_ref(),
            &self.header,
            &self.payload,
            &footer,
            &implicit_assertion,
        ]);
        let mut msg_digest = sha2::Sha384::new();
        msg_digest.update(&*m2);
        let signature: Signature = signing_key
            .try_sign_digest(msg_digest)?;
        let raw_payload = RawPayload::<V3, Public>::from(&self.payload, &signature.to_bytes());
        Ok(self.format_token(&raw_payload))
    }
}
