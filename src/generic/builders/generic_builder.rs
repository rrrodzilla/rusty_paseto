use core::marker::PhantomData;
use std::collections::HashMap;

use erased_serde::Serialize;
use serde_json::{Map, Value};

use crate::generic::*;

///The GenericBuilder is created at compile time by specifying a PASETO version and purpose and
///providing a key of the same version and purpose. This structure allows setting [PASETO claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md),
///your own [custom claims](CustomClaim), an optional [footer](Footer) and in the case of V3/V4 tokens, an optional [implicit
///assertion](ImplicitAssertion).
///
///The intent of the GenericBuilder is to allow the user to wrap basic PASETO standard
///functionality with their own custom business rules or ergonomic API. For most users, the batteries-included
///[paseto builder](crate::prelude::PasetoBuilder) will be all they need. More advanced cases can wrap this
///or the [core](Paseto) struct to accomplish custom functionality.
///
///# Usage
///
///```
///# #[cfg(all(feature = "generic", feature="v2_local"))]
///# {
///   use rusty_paseto::generic::*;

///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

///     let footer = Footer::from("some footer");

///     //create a builder, add some claims and then build the token with the key
///     let token = GenericBuilder::<V2, Local>::default()
///       .set_claim(AudienceClaim::from("customers"))
///       .set_claim(SubjectClaim::from("loyal subjects"))
///       .set_claim(IssuerClaim::from("me"))
///       .set_claim(TokenIdentifierClaim::from("me"))
///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
///       .set_claim(CustomClaim::try_from(("seats", 4))?)
///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
///       .set_footer(footer)
///       .try_encrypt(&key)?;

///     //now let's decrypt the token and verify the values
///     let json = GenericParser::<V2, Local>::default()
///       .set_footer(footer)
///       .parse(&token, &key)?;

///     assert_eq!(json["aud"], "customers");
///     assert_eq!(json["jti"], "me");
///     assert_eq!(json["iss"], "me");
///     assert_eq!(json["data"], "this is a secret message");
///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
///     assert_eq!(json["sub"], "loyal subjects");
///     assert_eq!(json["pi to 6 digits"], 3.141526);
///     assert_eq!(json["seats"], 4);
///  # }
/// # Ok::<(),anyhow::Error>(())
///   ```

pub struct GenericBuilder<'a, 'b, Version, Purpose> {
    version: PhantomData<Version>,
    purpose: PhantomData<Purpose>,
    claims: HashMap<String, Box<dyn erased_serde::Serialize + 'b>>,
    footer: Option<Footer<'a>>,
    implicit_assertion: Option<ImplicitAssertion<'a>>,
}

impl<'a, 'b, Version, Purpose> GenericBuilder<'a, 'b, Version, Purpose> {
    pub fn new() -> Self {
        Self {
            version: PhantomData::<Version>,
            purpose: PhantomData::<Purpose>,
            claims: HashMap::with_capacity(10),
            footer: None,
            implicit_assertion: None,
        }
    }

    ///Removes a [claim](PasetoClaim) from the internal list of claims by passed key
    pub fn remove_claim(&mut self, claim_key: &str) -> &mut Self {
        self.claims.remove(claim_key);
        self
    }

    ///Allows adding multiple [claims](PasetoClaim) at once by passing a Hashmap of claim keys and values
    pub fn extend_claims(&mut self, value: HashMap<String, Box<dyn erased_serde::Serialize>>) -> &mut Self {
        self.claims.extend(value);
        self
    }

    ///Adds a [claim](PasetoClaim) to the token builder
    pub fn set_claim<T: 'b + PasetoClaim + erased_serde::Serialize>(&mut self, value: T) -> &mut Self
        where
            'b: 'a,
    {
        let key = value.get_key().to_owned();

        // Ignore empty keys
        if key.is_empty() {
            return self;
        }

        // Serialize the claim value to serde_json::Value
        let mut serialized_value = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut serialized_value);
        erased_serde::serialize(&value, &mut serializer).unwrap();
        let value_json: serde_json::Value = serde_json::from_slice(&serialized_value).unwrap();

        // Handle the special case for Null values
        let value = match value_json {
            serde_json::Value::Object(mut obj) => {
                if obj.len() == 1 && obj.contains_key(&key) {
                    obj.remove(&key).unwrap()
                } else {
                    serde_json::Value::Object(obj)
                }
            }
            other => other,
        };

        // Insert the processed claim into the claims map
        self.claims.insert(key, Box::new(value));
        self
    }

    ///Adds an optional [footer](Footer) to the token builder
    pub fn set_footer(&mut self, footer: Footer<'a>) -> &mut Self {
        self.footer = Some(footer);
        self
    }

    /// Builds a JSON payload from the claims
    ///
    /// # Returns
    /// A `Result` containing the JSON payload as a `String` or a `serde_json::Error`
    /// Fixes (issue #39)[https://github.com/rrrodzilla/rusty_paseto/issues/39] reported by @xbb
    pub fn build_payload_from_claims(&mut self) -> Result<String, serde_json::Error> {
        // Take the claims from the builder, replacing it with an empty HashMap
        let claims = std::mem::take(&mut self.claims);

        // Serialize each claim to a serde_json::Value
        let serialized_claims: HashMap<String, Value> = claims
            .into_iter()
            .map(|(k, v)| (k, serde_json::to_value(v).unwrap_or(Value::Null)))
            .collect();

        // Wrap the serialized claims to ensure proper nesting
        let wrapped_claims = wrap_claims(serialized_claims);

        // Convert the wrapped claims to a JSON string
        serde_json::to_string(&wrapped_claims)
    }
}

// Wrap claims in an outer JSON object to ensure proper nesting
//
// # Parameters
// - `claims`: A `HashMap` containing the claims as `serde_json::Value`
//
// # Returns
// A `serde_json::Value` representing the wrapped claims
fn wrap_claims(claims: HashMap<String, Value>) -> Value {
    // Recursively wrap each claim value
    let wrapped: HashMap<String, Value> = claims
        .into_iter()
        .map(|(k, v)| (k, wrap_value(v)))
        .collect();

    // Return the wrapped claims as a JSON object
    Value::Object(Map::from_iter(wrapped))
}

// Recursively wrap values to ensure all values are valid JSON objects
//
// # Parameters
// - `value`: A `serde_json::Value` to be wrapped
//
// # Returns
// A `serde_json::Value` representing the wrapped value
fn wrap_value(value: Value) -> Value {
    match value {
        // If the value is an object, check if it's empty
        Value::Object(map) => {
            if map.is_empty() {
                // Wrap empty map as an empty JSON object
                Value::Object(Map::new())
            } else {
                // Recursively wrap each key-value pair in the map
                Value::Object(map.into_iter().map(|(k, v)| (k, wrap_value(v))).collect())
            }
        }
        // If the value is an array, recursively wrap each element
        Value::Array(arr) => Value::Array(arr.into_iter().map(wrap_value).collect()),
        // If the value is null, return it as is
        Value::Null => Value::Null,
        // For primitive values, return them as is
        other => other,
    }
}


impl<'a, 'b, Version, Purpose> GenericBuilder<'a, 'b, Version, Purpose>
    where
        Version: ImplicitAssertionCapable,
{
    ///Adds an optional [implicit assertion](ImplicitAssertion) to the token builder for V3/V4
    ///tokens only
    pub fn set_implicit_assertion(&mut self, implicit_assertion: ImplicitAssertion<'a>) -> &mut Self {
        self.implicit_assertion = Some(implicit_assertion);
        self
    }
}

impl<Version, Purpose> Default for GenericBuilder<'_, '_, Version, Purpose> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "v1_local")]
impl GenericBuilder<'_, '_, V1, Local> {
    /// Given a [PasetoSymmetricKey], attempts to encrypt a (V1, Local) PASETO token from the data and
    /// claims provided to the GenericBuilder.
    ///
    /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for encryption or during ciphertext encryption.
    ///
    /// # Example
    ///
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v1_local"))]
    ///# {
    ///   use rusty_paseto::generic::*;

    ///     let key = PasetoSymmetricKey::<V1, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    ///     let footer = Footer::from("some footer");

    ///     //create a builder, add some claims and then build the token with the key
    ///     let token = GenericBuilder::<V1, Local>::default()
    ///       .set_claim(AudienceClaim::from("customers"))
    ///       .set_claim(SubjectClaim::from("loyal subjects"))
    ///       .set_claim(IssuerClaim::from("me"))
    ///       .set_claim(TokenIdentifierClaim::from("me"))
    ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///       .set_footer(footer)
    ///       .try_encrypt(&key)?;

    ///     //now let's decrypt the token and verify the values
    ///     let json = GenericParser::<V1, Local>::default()
    ///       .set_footer(footer)
    ///       .parse(&token, &key)?;

    ///     assert_eq!(json["aud"], "customers");
    ///     assert_eq!(json["jti"], "me");
    ///     assert_eq!(json["iss"], "me");
    ///     assert_eq!(json["data"], "this is a secret message");
    ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["sub"], "loyal subjects");
    ///     assert_eq!(json["pi to 6 digits"], 3.141526);
    ///     assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///   ```

    pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V1, Local>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V1, Local>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));
        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        let random_nonce = Key::<32>::try_new_random()?;
        Ok(token_builder.try_encrypt(key, &PasetoNonce::<V1, Local>::from(&random_nonce))?)
    }
}

#[cfg(feature = "v2_local")]
impl GenericBuilder<'_, '_, V2, Local> {
    /// Given a [PasetoSymmetricKey], attempts to encrypt a (V2, Local) PASETO token from the data and
    /// claims provided to the GenericBuilder.
    ///
    /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for encryption or during ciphertext encryption.
    ///
    /// # Example
    ///
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v2_local"))]
    ///# {
    ///   use rusty_paseto::generic::*;

    ///     let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    ///     let footer = Footer::from("some footer");

    ///     //create a builder, add some claims and then build the token with the key
    ///     let token = GenericBuilder::<V2, Local>::default()
    ///       .set_claim(AudienceClaim::from("customers"))
    ///       .set_claim(SubjectClaim::from("loyal subjects"))
    ///       .set_claim(IssuerClaim::from("me"))
    ///       .set_claim(TokenIdentifierClaim::from("me"))
    ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///       .set_footer(footer)
    ///       .try_encrypt(&key)?;

    ///     //now let's decrypt the token and verify the values
    ///     let json = GenericParser::<V2, Local>::default()
    ///       .set_footer(footer)
    ///       .parse(&token, &key)?;

    ///     assert_eq!(json["aud"], "customers");
    ///     assert_eq!(json["jti"], "me");
    ///     assert_eq!(json["iss"], "me");
    ///     assert_eq!(json["data"], "this is a secret message");
    ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["sub"], "loyal subjects");
    ///     assert_eq!(json["pi to 6 digits"], 3.141526);
    ///     assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///   ```

    pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V2, Local>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V2, Local>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));
        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }

        Ok(token_builder.try_encrypt(key, &PasetoNonce::<V2, Local>::from(&Key::<24>::try_new_random()?))?)
    }
}

#[cfg(feature = "v3_local")]
impl GenericBuilder<'_, '_, V3, Local> {
    /// Given a [PasetoSymmetricKey], attempts to encrypt a (V3, Local) PASETO token from the data and
    /// claims provided to the GenericBuilder.
    ///
    /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for encryption or during ciphertext encryption.
    ///
    /// # Example
    ///
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v3_local"))]
    ///# {
    ///   use rusty_paseto::generic::*;

    ///     let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    ///     let footer = Footer::from("some footer");
    ///     let implicit_assertion = ImplicitAssertion::from("some assertion");

    ///     //create a builder, add some claims and then build the token with the key
    ///     let token = GenericBuilder::<V3, Local>::default()
    ///       .set_claim(AudienceClaim::from("customers"))
    ///       .set_claim(SubjectClaim::from("loyal subjects"))
    ///       .set_claim(IssuerClaim::from("me"))
    ///       .set_claim(TokenIdentifierClaim::from("me"))
    ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///       .set_footer(footer)
    ///       .set_implicit_assertion(implicit_assertion)
    ///       .try_encrypt(&key)?;

    ///     //now let's decrypt the token and verify the values
    ///     let json = GenericParser::<V3, Local>::default()
    ///       .set_footer(footer)
    ///       .set_implicit_assertion(implicit_assertion)
    ///       .parse(&token, &key)?;

    ///     assert_eq!(json["aud"], "customers");
    ///     assert_eq!(json["jti"], "me");
    ///     assert_eq!(json["iss"], "me");
    ///     assert_eq!(json["data"], "this is a secret message");
    ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["sub"], "loyal subjects");
    ///     assert_eq!(json["pi to 6 digits"], 3.141526);
    ///     assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///   ```

    pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V3, Local>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V3, Local>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));
        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        if let Some(implicit_assertion) = &self.implicit_assertion {
            token_builder.set_implicit_assertion(*implicit_assertion);
        }
        let nonce = Key::<32>::try_new_random()?;
        let nonce = PasetoNonce::<V3, Local>::from(&nonce);
        Ok(token_builder.try_encrypt(key, &nonce)?)
    }
}

#[cfg(feature = "v4_local")]
impl GenericBuilder<'_, '_, V4, Local> {
    /// Given a [PasetoSymmetricKey], attempts to encrypt a (V4, Local) PASETO token from the data and
    /// claims provided to the GenericBuilder.
    ///
    /// Returns `Ok(String)` on success, where the String is the encrypted PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for encryption or during ciphertext encryption.
    ///
    /// # Example
    ///
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v4_local"))]
    ///# {
    ///   use rusty_paseto::generic::*;

    ///     let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

    ///     let footer = Footer::from("some footer");
    ///     let implicit_assertion = ImplicitAssertion::from("some assertion");

    ///     //create a builder, add some claims and then build the token with the key
    ///     let token = GenericBuilder::<V4, Local>::default()
    ///       .set_claim(AudienceClaim::from("customers"))
    ///       .set_claim(SubjectClaim::from("loyal subjects"))
    ///       .set_claim(IssuerClaim::from("me"))
    ///       .set_claim(TokenIdentifierClaim::from("me"))
    ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///       .set_footer(footer)
    ///       .set_implicit_assertion(implicit_assertion)
    ///       .try_encrypt(&key)?;

    ///     //now let's decrypt the token and verify the values
    ///     let json = GenericParser::<V4, Local>::default()
    ///       .set_footer(footer)
    ///       .set_implicit_assertion(implicit_assertion)
    ///       .parse(&token, &key)?;

    ///     assert_eq!(json["aud"], "customers");
    ///     assert_eq!(json["jti"], "me");
    ///     assert_eq!(json["iss"], "me");
    ///     assert_eq!(json["data"], "this is a secret message");
    ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["sub"], "loyal subjects");
    ///     assert_eq!(json["pi to 6 digits"], 3.141526);
    ///     assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///   ```

    pub fn try_encrypt(&mut self, key: &PasetoSymmetricKey<V4, Local>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V4, Local>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));

        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        if let Some(implicit_assertion) = &self.implicit_assertion {
            token_builder.set_implicit_assertion(*implicit_assertion);
        }
        let nonce = Key::<32>::try_new_random()?;
        let nonce = PasetoNonce::<V4, Local>::from(&nonce);
        Ok(token_builder.try_encrypt(key, &nonce)?)
    }
}

#[cfg(feature = "v1_public")]
impl GenericBuilder<'_, '_, V1, Public> {
    /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V1], [Public]) PASETO token from the data and
    /// claims provided to the GenericBuilder with an optional [Footer].
    ///
    /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for signing or during signing.
    ///
    /// # Example
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v1_public"))]
    ///# {
    ///   # use rusty_paseto::generic::*;

    ///    //obtain a private key (pk)
    ///   # let private_key = include_bytes!("../../../tests/v1_public_test_vectors_private_key.pk8");
    ///   # let pk: &[u8] = private_key;
    ///    let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

    ///     let footer = Footer::from("some footer");

    ///     //sign a public V1 token
    ///     let token = GenericBuilder::<V1, Public>::default()
    ///       .set_claim(AudienceClaim::from("customers"))
    ///       .set_claim(SubjectClaim::from("loyal subjects"))
    ///       .set_claim(IssuerClaim::from("me"))
    ///       .set_claim(TokenIdentifierClaim::from("me"))
    ///       .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///       .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///       .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///       .set_footer(footer)
    ///       .try_sign(&private_key)?;

    /// //obtain a public key (pubk)
    ///   #  let public_key = include_bytes!("../../../tests/v1_public_test_vectors_public_key.der");
    ///   #  let pubk: &[u8] = public_key;
    ///     let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);
    ///     //now let's try to verify it
    ///     let json = GenericParser::<V1, Public>::default()
    ///       .set_footer(footer)
    ///       .check_claim(AudienceClaim::from("customers"))
    ///       .check_claim(SubjectClaim::from("loyal subjects"))
    ///       .check_claim(IssuerClaim::from("me"))
    ///       .check_claim(TokenIdentifierClaim::from("me"))
    ///       .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///       .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///       .check_claim(CustomClaim::try_from(("seats", 4))?)
    ///       .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///       .parse(&token, &public_key)?;
    ///     // we can access all the values from the serde Value object returned by the parser
    ///     assert_eq!(json["aud"], "customers");
    ///     assert_eq!(json["jti"], "me");
    ///     assert_eq!(json["iss"], "me");
    ///     assert_eq!(json["data"], "this is a secret message");
    ///     assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    ///     assert_eq!(json["sub"], "loyal subjects");
    ///     assert_eq!(json["pi to 6 digits"], 3.141526);
    ///     assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///```
    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V1, Public>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V1, Public>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));
        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        Ok(token_builder.try_sign(key)?)
    }
}

#[cfg(feature = "v2_public")]
impl GenericBuilder<'_, '_, V2, Public> {
    /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V2], [Public]) PASETO token from the data and
    /// claims provided to the GenericBuilder with an optional [Footer].
    ///
    /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for signing or during signing.
    ///
    /// # Example
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v1_public"))]
    ///# {
    ///   # use rusty_paseto::generic::*;

    ///    //obtain a key
    /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    /// let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

    /// let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    /// let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

    /// let footer = Footer::from("some footer");

    /// //sign a public V2 token
    /// let token = GenericBuilder::<V2, Public>::default()
    ///   .set_claim(AudienceClaim::from("customers"))
    ///   .set_claim(SubjectClaim::from("loyal subjects"))
    ///   .set_claim(IssuerClaim::from("me"))
    ///   .set_claim(TokenIdentifierClaim::from("me"))
    ///   .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///   .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///   .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///   .set_footer(footer)
    ///   .try_sign(&private_key)?;

    /// //now let's try to verify it
    /// let json = GenericParser::<V2, Public>::default()
    ///   .set_footer(footer)
    ///   .check_claim(AudienceClaim::from("customers"))
    ///   .check_claim(SubjectClaim::from("loyal subjects"))
    ///   .check_claim(IssuerClaim::from("me"))
    ///   .check_claim(TokenIdentifierClaim::from("me"))
    ///   .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///   .check_claim(CustomClaim::try_from(("seats", 4))?)
    ///   .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///   .parse(&token, &public_key)?;
    /// // we can access all the values from the serde Value object returned by the parser
    /// assert_eq!(json["aud"], "customers");
    /// assert_eq!(json["jti"], "me");
    /// assert_eq!(json["iss"], "me");
    /// assert_eq!(json["data"], "this is a secret message");
    /// assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["sub"], "loyal subjects");
    /// assert_eq!(json["pi to 6 digits"], 3.141526);
    /// assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///```
    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V2, Public>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V2, Public>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));
        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        Ok(token_builder.try_sign(key)?)
    }
}

#[cfg(feature = "v3_public")]
impl GenericBuilder<'_, '_, V3, Public> {
    /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V3], [Public]) PASETO token from the data and
    /// claims provided to the GenericBuilder with an optional [Footer] and an optional
    /// [ImplicitAssertion].
    ///
    /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for signing or during signing.
    ///
    /// # Example
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v3_public"))]
    ///# {
    ///   # use rusty_paseto::generic::*;

    ///    //obtain a key
    /// let private_key = Key::<48>::try_from(
    ///   "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
    /// )?;
    /// let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

    /// let public_key = Key::<49>::try_from(
    ///   "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
    /// )?;
    /// let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

    /// let footer = Footer::from("some footer");

    /// let implicit_assertion = ImplicitAssertion::from("some assertion");
    /// //sign a public V3 token
    /// let token = GenericBuilder::<V3, Public>::default()
    ///   .set_claim(AudienceClaim::from("customers"))
    ///   .set_claim(SubjectClaim::from("loyal subjects"))
    ///   .set_claim(IssuerClaim::from("me"))
    ///   .set_claim(TokenIdentifierClaim::from("me"))
    ///   .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///   .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///   .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///   .set_footer(footer)
    ///   .set_implicit_assertion(implicit_assertion)
    ///   .try_sign(&private_key)?;

    /// //now let's try to verify it
    /// let json = GenericParser::<V3, Public>::default()
    ///   .set_footer(footer)
    ///   .check_claim(AudienceClaim::from("customers"))
    ///   .set_implicit_assertion(implicit_assertion)
    ///   .check_claim(SubjectClaim::from("loyal subjects"))
    ///   .check_claim(IssuerClaim::from("me"))
    ///   .check_claim(TokenIdentifierClaim::from("me"))
    ///   .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///   .check_claim(CustomClaim::try_from(("seats", 4))?)
    ///   .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///   .parse(&token, &public_key)?;
    /// // we can access all the values from the serde Value object returned by the parser
    /// assert_eq!(json["aud"], "customers");
    /// assert_eq!(json["jti"], "me");
    /// assert_eq!(json["iss"], "me");
    /// assert_eq!(json["data"], "this is a secret message");
    /// assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["sub"], "loyal subjects");
    /// assert_eq!(json["pi to 6 digits"], 3.141526);
    /// assert_eq!(json["seats"], 4);
    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///```
    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V3, Public>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V3, Public>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));

        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        if let Some(implicit_assertion) = &self.implicit_assertion {
            token_builder.set_implicit_assertion(*implicit_assertion);
        }
        Ok(token_builder.try_sign(key)?)
    }
}

#[cfg(feature = "v4_public")]
impl GenericBuilder<'_, '_, V4, Public> {
    /// Given a [PasetoAsymmetricPrivateKey], attempts to sign a ([V4], [Public]) PASETO token from the data and
    /// claims provided to the GenericBuilder with an optional [Footer] and an optional
    /// [ImplicitAssertion].
    ///
    /// Returns `Ok(String)` on success, where the String is the signed PASETO token, otherwise returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`GenericBuilderError`] for any errors when building the token string
    /// for signing or during signing.
    ///
    /// # Example
    ///
    ///```
    ///# #[cfg(all(feature = "generic", feature="v4_public"))]
    ///# {
    ///   # use rusty_paseto::generic::*;

    /// //create a key
    /// let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    /// let pk: &[u8] = private_key.as_slice();
    /// let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

    /// let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
    /// let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

    /// let footer = Footer::from("some footer");
    /// let implicit_assertion = ImplicitAssertion::from("some assertion");

    /// //sign a public V4 token
    /// let token = GenericBuilder::<V4, Public>::default()
    ///   .set_claim(AudienceClaim::from("customers"))
    ///   .set_claim(SubjectClaim::from("loyal subjects"))
    ///   .set_claim(IssuerClaim::from("me"))
    ///   .set_claim(TokenIdentifierClaim::from("me"))
    ///   .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///   .set_claim(CustomClaim::try_from(("seats", 4))?)
    ///   .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///   .set_footer(footer)
    ///   .set_implicit_assertion(implicit_assertion)
    ///   .try_sign(&private_key)?;

    /// //now let's try to verify it
    /// let json = GenericParser::<V4, Public>::default()
    ///   .set_footer(footer)
    ///   .set_implicit_assertion(implicit_assertion)
    ///   .check_claim(AudienceClaim::from("customers"))
    ///   .check_claim(SubjectClaim::from("loyal subjects"))
    ///   .check_claim(IssuerClaim::from("me"))
    ///   .check_claim(TokenIdentifierClaim::from("me"))
    ///   .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
    ///   .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
    ///   .check_claim(CustomClaim::try_from(("seats", 4))?)
    ///   .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
    ///   .parse(&token, &public_key)?;
    /// // we can access all the values from the serde Value object returned by the parser
    /// assert_eq!(json["aud"], "customers");
    /// assert_eq!(json["jti"], "me");
    /// assert_eq!(json["iss"], "me");
    /// assert_eq!(json["data"], "this is a secret message");
    /// assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
    /// assert_eq!(json["sub"], "loyal subjects");
    /// assert_eq!(json["pi to 6 digits"], 3.141526);
    /// assert_eq!(json["seats"], 4);

    ///  # }
    /// # Ok::<(),anyhow::Error>(())
    ///```

    pub fn try_sign(&mut self, key: &PasetoAsymmetricPrivateKey<V4, Public>) -> Result<String, GenericBuilderError> {
        let mut token_builder = Paseto::<V4, Public>::builder();

        let payload = self.build_payload_from_claims()?;
        token_builder.set_payload(Payload::from(payload.as_str()));

        if let Some(footer) = &self.footer {
            token_builder.set_footer(*footer);
        }
        if let Some(implicit_assertion) = &self.implicit_assertion {
            token_builder.set_implicit_assertion(*implicit_assertion);
        }
        Ok(token_builder.try_sign(key)?)
    }
}

#[cfg(all(test, feature = "v4_public"))]
mod generic_v4_public_builders {
    use anyhow::Result;

    use crate::generic::*;
    use crate::generic::claims::*;

    #[test]
    fn full_generic_v4_public_builder_test() -> Result<()> {
        //create a key
        let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let pk: &[u8] = private_key.as_slice();
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(pk);

        let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

        let footer = Footer::from("some footer");
        let implicit_assertion = ImplicitAssertion::from("some assertion");

        //sign a public V4 token
        let token = GenericBuilder::<V4, Public>::default()
            .set_claim(AudienceClaim::from("customers"))
            .set_claim(SubjectClaim::from("loyal subjects"))
            .set_claim(IssuerClaim::from("me"))
            .set_claim(TokenIdentifierClaim::from("me"))
            .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .set_claim(CustomClaim::try_from(("seats", 4))?)
            .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .try_sign(&private_key)?;

        //now let's try to verify it
        let json = GenericParser::<V4, Public>::default()
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .check_claim(AudienceClaim::from("customers"))
            .check_claim(SubjectClaim::from("loyal subjects"))
            .check_claim(IssuerClaim::from("me"))
            .check_claim(TokenIdentifierClaim::from("me"))
            .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .check_claim(CustomClaim::try_from(("seats", 4))?)
            .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .parse(&token, &public_key)?;
        // we can access all the values from the serde Value object returned by the parser
        assert_eq!(json["aud"], "customers");
        assert_eq!(json["jti"], "me");
        assert_eq!(json["iss"], "me");
        assert_eq!(json["data"], "this is a secret message");
        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["sub"], "loyal subjects");
        assert_eq!(json["pi to 6 digits"], 3.141526);
        assert_eq!(json["seats"], 4);
        Ok(())
    }
}

#[cfg(all(test, feature = "v3_public"))]
mod generic_v3_public_builders {
    use anyhow::Result;

    use crate::generic::*;
    use crate::generic::claims::*;

    #[test]
    fn full_generic_v3_public_builder_test() -> Result<()> {
        //create a key
        let private_key = Key::<48>::try_from(
            "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
        )?;
        let private_key = PasetoAsymmetricPrivateKey::<V3, Public>::from(&private_key);

        let public_key = Key::<49>::try_from(
            "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
        )?;
        let public_key = PasetoAsymmetricPublicKey::<V3, Public>::try_from(&public_key)?;

        let footer = Footer::from("some footer");
        let implicit_assertion = ImplicitAssertion::from("some assertion");

        //sign a public V3 token
        let token = GenericBuilder::<V3, Public>::default()
            .set_claim(AudienceClaim::from("customers"))
            .set_claim(SubjectClaim::from("loyal subjects"))
            .set_claim(IssuerClaim::from("me"))
            .set_claim(TokenIdentifierClaim::from("me"))
            .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .set_claim(CustomClaim::try_from(("seats", 4))?)
            .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .try_sign(&private_key)?;

        //now let's try to verify it
        let json = GenericParser::<V3, Public>::default()
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .check_claim(AudienceClaim::from("customers"))
            .check_claim(SubjectClaim::from("loyal subjects"))
            .check_claim(IssuerClaim::from("me"))
            .check_claim(TokenIdentifierClaim::from("me"))
            .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .check_claim(CustomClaim::try_from(("seats", 4))?)
            .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .parse(&token, &public_key)?;
        // we can access all the values from the serde Value object returned by the parser
        assert_eq!(json["aud"], "customers");
        assert_eq!(json["jti"], "me");
        assert_eq!(json["iss"], "me");
        assert_eq!(json["data"], "this is a secret message");
        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["sub"], "loyal subjects");
        assert_eq!(json["pi to 6 digits"], 3.141526);
        assert_eq!(json["seats"], 4);
        Ok(())
    }
}

#[cfg(all(test, feature = "v2_public"))]
mod generic_v2_public_builders {
    use anyhow::Result;

    use crate::generic::*;
    use crate::generic::claims::*;

    #[test]
    fn full_generic_v2_public_builder_test() -> Result<()> {
        //create a key
        let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let private_key = PasetoAsymmetricPrivateKey::<V2, Public>::from(&private_key);

        let public_key = Key::<32>::try_from("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
        let public_key = PasetoAsymmetricPublicKey::<V2, Public>::from(&public_key);

        let footer = Footer::from("some footer");

        //sign a public V2 token
        let token = GenericBuilder::<V2, Public>::default()
            .set_claim(AudienceClaim::from("customers"))
            .set_claim(SubjectClaim::from("loyal subjects"))
            .set_claim(IssuerClaim::from("me"))
            .set_claim(TokenIdentifierClaim::from("me"))
            .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .set_claim(CustomClaim::try_from(("seats", 4))?)
            .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .set_footer(footer)
            .try_sign(&private_key)?;

        //now let's try to verify it
        let json = GenericParser::<V2, Public>::default()
            .set_footer(footer)
            .check_claim(AudienceClaim::from("customers"))
            .check_claim(SubjectClaim::from("loyal subjects"))
            .check_claim(IssuerClaim::from("me"))
            .check_claim(TokenIdentifierClaim::from("me"))
            .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .check_claim(CustomClaim::try_from(("seats", 4))?)
            .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .parse(&token, &public_key)?;
        // we can access all the values from the serde Value object returned by the parser
        assert_eq!(json["aud"], "customers");
        assert_eq!(json["jti"], "me");
        assert_eq!(json["iss"], "me");
        assert_eq!(json["data"], "this is a secret message");
        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["sub"], "loyal subjects");
        assert_eq!(json["pi to 6 digits"], 3.141526);
        assert_eq!(json["seats"], 4);
        Ok(())
    }
}

#[cfg(all(test, feature = "v1_public"))]
mod generic_v1_public_builders {
    use anyhow::Result;

    use crate::generic::*;
    use crate::generic::claims::*;

    #[test]
    fn full_generic_v1_public_builder_test() -> Result<()> {
        //create a key
        let private_key = include_bytes!("../../../tests/v1_public_test_vectors_private_key.pk8");
        let pk: &[u8] = private_key;
        let private_key = PasetoAsymmetricPrivateKey::<V1, Public>::from(pk);

        let public_key = include_bytes!("../../../tests/v1_public_test_vectors_public_key.der");
        let pubk: &[u8] = public_key;
        let public_key = PasetoAsymmetricPublicKey::<V1, Public>::from(pubk);
        let footer = Footer::from("some footer");

        //sign a public V1 token
        let token = GenericBuilder::<V1, Public>::default()
            .set_claim(AudienceClaim::from("customers"))
            .set_claim(SubjectClaim::from("loyal subjects"))
            .set_claim(IssuerClaim::from("me"))
            .set_claim(TokenIdentifierClaim::from("me"))
            .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .set_claim(CustomClaim::try_from(("seats", 4))?)
            .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .set_footer(footer)
            .try_sign(&private_key)?;

        //now let's try to verify it
        let json = GenericParser::<V1, Public>::default()
            .set_footer(footer)
            .check_claim(AudienceClaim::from("customers"))
            .check_claim(SubjectClaim::from("loyal subjects"))
            .check_claim(IssuerClaim::from("me"))
            .check_claim(TokenIdentifierClaim::from("me"))
            .check_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .check_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .check_claim(CustomClaim::try_from(("seats", 4))?)
            .check_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .parse(&token, &public_key)?;
        // we can access all the values from the serde Value object returned by the parser
        assert_eq!(json["aud"], "customers");
        assert_eq!(json["jti"], "me");
        assert_eq!(json["iss"], "me");
        assert_eq!(json["data"], "this is a secret message");
        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["sub"], "loyal subjects");
        assert_eq!(json["pi to 6 digits"], 3.141526);
        assert_eq!(json["seats"], 4);
        Ok(())
    }
}

#[cfg(all(test, feature = "v3_local"))]
mod generic_v3_local_builders {
    use std::convert::TryFrom;

    use anyhow::Result;

    use crate::generic::*;
    use crate::generic::claims::*;

    #[test]
    fn full_generic_v3_local_builder_test() -> Result<()> {
        //create a key
        let key = PasetoSymmetricKey::<V3, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        let footer = Footer::from("some footer");
        let implicit_assertion = ImplicitAssertion::from("some assertion");

        //create a builder, add some claims and then build the token with the key
        let token = GenericBuilder::<V3, Local>::default()
            .set_claim(AudienceClaim::from("customers"))
            .set_claim(SubjectClaim::from("loyal subjects"))
            .set_claim(IssuerClaim::from("me"))
            .set_claim(TokenIdentifierClaim::from("me"))
            .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .set_claim(CustomClaim::try_from(("seats", 4))?)
            .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .try_encrypt(&key)?;

        //now let's decrypt the token and verify the values
        let json = GenericParser::<V3, Local>::default()
            .set_footer(footer)
            .set_implicit_assertion(implicit_assertion)
            .parse(&token, &key)?;

        assert_eq!(json["aud"], "customers");
        assert_eq!(json["jti"], "me");
        assert_eq!(json["iss"], "me");
        assert_eq!(json["data"], "this is a secret message");
        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["sub"], "loyal subjects");
        assert_eq!(json["pi to 6 digits"], 3.141526);
        assert_eq!(json["seats"], 4);
        Ok(())
    }
}

#[cfg(all(test, feature = "default"))]
mod tests {
    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct TestStruct {
        field1: String,
        field2: i32,
    }

    #[test]
    fn test_custom_claim_serialization() {
        let mut builder = GenericBuilder::<V4, Local>::default();
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        // Create a custom claim with a serializable struct
        let custom_claim = CustomClaim::try_from((
            "custom",
            TestStruct {
                field1: "value1".to_string(),
                field2: 42,
            },
        ))
            .unwrap();

        // Add the custom claim to the builder
        builder.set_claim(custom_claim);

        // Build the token
        let token = builder.try_encrypt(&key).unwrap();

        // Decrypt the token and verify the values
        let json = GenericParser::<V4, Local>::default().parse(&token, &key).unwrap();
        assert_eq!(json["custom"]["field1"], "value1");
        assert_eq!(json["custom"]["field2"], 42);
    }

    #[test]
    fn test_empty_claims() {
        let mut builder = GenericBuilder::<V4, Local>::default();
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        // Build the token with no claims
        let token = builder.try_encrypt(&key).unwrap();

        // Decrypt the token and verify the values
        let json = GenericParser::<V4, Local>::default().parse(&token, &key).unwrap();
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_null_claims() {
        let mut builder = GenericBuilder::<V4, Local>::default();
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        // Create a custom claim with a null value
        let custom_claim = CustomClaim::try_from(("custom", Value::Null)).unwrap();
        builder.set_claim(custom_claim);

        // Build the token
        let token = builder.try_encrypt(&key).unwrap();

        // Decrypt the token and verify the values
        let json = GenericParser::<V4, Local>::default().parse(&token, &key).unwrap();
        assert_eq!(json["custom"], Value::Null);
    }

    #[test]
    fn test_nested_structures() {
        let mut builder = GenericBuilder::<V4, Local>::default();
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        // Create nested claims
        let nested_claim = CustomClaim::try_from((
            "nested",
            serde_json::json!({
                "level1": {
                    "level2": {
                        "field": "value"
                    }
                }
            }),
        ))
            .unwrap();
        builder.set_claim(nested_claim);

        // Build the token
        let token = builder.try_encrypt(&key).unwrap();

        // Decrypt the token and verify the values
        let json = GenericParser::<V4, Local>::default().parse(&token, &key).unwrap();
        assert_eq!(json["nested"]["level1"]["level2"]["field"], "value");
    }

    #[test]
    fn test_multiple_claims() {
        let mut builder = GenericBuilder::<V4, Local>::default();
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        // Create multiple claims
        builder.set_claim(CustomClaim::try_from(("claim1", "value1")).unwrap());
        builder.set_claim(CustomClaim::try_from(("claim2", 42)).unwrap());
        builder.set_claim(CustomClaim::try_from(("claim3", true)).unwrap());

        // Build the token
        let token = builder.try_encrypt(&key).unwrap();

        // Decrypt the token and verify the values
        let json = GenericParser::<V4, Local>::default().parse(&token, &key).unwrap();
        assert_eq!(json["claim1"], "value1");
        assert_eq!(json["claim2"], 42);
        assert_eq!(json["claim3"], true);
    }

    #[test]
    fn test_different_data_types() {
        let mut builder = GenericBuilder::<V4, Local>::default();
        let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        // Create claims with different data types
        builder.set_claim(CustomClaim::try_from(("string", "value")).unwrap());
        builder.set_claim(CustomClaim::try_from(("number", 12345)).unwrap());
        builder.set_claim(CustomClaim::try_from(("boolean", true)).unwrap());
        builder.set_claim(CustomClaim::try_from(("null", Value::Null)).unwrap());

        // Build the token
        let token = builder.try_encrypt(&key).unwrap();

        // Decrypt the token and verify the values
        let json = GenericParser::<V4, Local>::default().parse(&token, &key).unwrap();
        assert_eq!(json["string"], "value");
        assert_eq!(json["number"], 12345);
        assert_eq!(json["boolean"], true);
        assert_eq!(json["null"], Value::Null);
    }
}

#[cfg(all(test, feature = "v2_local"))]
mod builders {
    use std::convert::TryFrom;

    use anyhow::Result;

    use crate::generic::*;
    use crate::generic::claims::*;

    #[test]
    fn full_builder_test() -> Result<()> {
        //create a key
        let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));

        let footer = Footer::from("some footer");

        //create a builder, add some claims and then build the token with the key
        let token = GenericBuilder::<V2, Local>::default()
            .set_claim(AudienceClaim::from("customers"))
            .set_claim(SubjectClaim::from("loyal subjects"))
            .set_claim(IssuerClaim::from("me"))
            .set_claim(TokenIdentifierClaim::from("me"))
            .set_claim(IssuedAtClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(NotBeforeClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?)
            .set_claim(CustomClaim::try_from(("data", "this is a secret message"))?)
            .set_claim(CustomClaim::try_from(("seats", 4))?)
            .set_claim(CustomClaim::try_from(("pi to 6 digits", 3.141526))?)
            .set_footer(footer)
            .try_encrypt(&key)?;

        //now let's decrypt the token and verify the values
        let json = GenericParser::<V2, Local>::default()
            .set_footer(footer)
            .parse(&token, &key)?;

        assert_eq!(json["aud"], "customers");
        assert_eq!(json["jti"], "me");
        assert_eq!(json["iss"], "me");
        assert_eq!(json["data"], "this is a secret message");
        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["iat"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["nbf"], "2019-01-01T00:00:00+00:00");
        assert_eq!(json["sub"], "loyal subjects");
        assert_eq!(json["pi to 6 digits"], 3.141526);
        assert_eq!(json["seats"], 4);
        Ok(())
    }

    #[test]
    fn test_dynamic_claims() -> Result<()> {
        //create a key

        let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        //create a builder, add some claims dynamically
        let mut builder = GenericBuilder::<V2, Local>::default();
        builder.set_claim(ExpirationClaim::try_from("2019-01-01T00:00:00+00:00")?);

        for n in 1..10 {
            builder.set_claim(CustomClaim::try_from((format!("n{}", n), n))?);
        }

        //and then build the token with the key
        let token = builder.try_encrypt(&key)?;

        //now let's decrypt the token and verify the values
        let json = GenericParser::<V2, Local>::default().parse(&token, &key)?;

        for n in 1..10 {
            assert_eq!(json[format!("n{}", n)], n);
        }

        assert_eq!(json["exp"], "2019-01-01T00:00:00+00:00");

        Ok(())
    }

    #[test]
    fn test_no_claims() -> Result<()> {
        let key = PasetoSymmetricKey::<V2, Local>::from(Key::<32>::from(*b"wubbalubbadubdubwubbalubbadubdub"));
        //create a builder, add no claims and then build the token with the key
        let token = GenericBuilder::<V2, Local>::default().try_encrypt(&key)?;

        //now let's decrypt the token and verify the values
        let decrypted = GenericParser::<V2, Local>::default().parse(&token, &key)?;
        assert_eq!(decrypted.to_string(), "{}");
        Ok(())
    }
}
