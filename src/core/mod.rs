//! The **core** architectural layer and feature contains only paseto primitives for lightweight
//! encrypting / decrypting or signing / verification
//!
//! ![paseto_core_small](https://user-images.githubusercontent.com/24578097/147881920-14c52256-1a0c-40be-9f18-759a8c9ad77d.png)
//!
//! The **core** feature requires you to specify the version and purpose
//! ```toml
//! ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
//! ## key types with NO claims, defaults or validation, just basic PASETO
//! ## encrypt/signing and decrypt/verification.
//!
//! rusty_paseto = {version = "latest", features = ["core", "v4_local"] }
//!
//! ```
//! # Example usage
//! ```
//! # #[cfg(feature = "v4_local")]
//! # {
//! # use serde_json::json;
//! use rusty_paseto::core::*;
//!
//! let key = PasetoSymmetricKey::<V4, Local>::from(Key::<32>::try_from("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")?);
//! let nonce = Key::<32>::try_from("0000000000000000000000000000000000000000000000000000000000000000")?;
//! // generate a random nonce with
//! // let nonce = Key::<32>::try_new_random()?;
//! let nonce = PasetoNonce::<V4, Local>::from(&nonce);
//!
//! let payload = json!({"data": "this is a secret message", "exp":"2022-01-01T00:00:00+00:00"}).to_string();
//! let payload = payload.as_str();
//! let payload = Payload::from(payload);
//!
//! //create a public v4 token
//! let token = Paseto::<V4, Local>::builder()
//!   .set_payload(payload)
//!   .try_encrypt(&key, &nonce)?;
//!
//! //validate the test vector
//! assert_eq!(token.to_string(), "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg");
//!
//! //now let's try to decrypt it
//! let json = Paseto::<V4, Local>::try_decrypt(&token, &key, None, None)?;
//! assert_eq!(payload, json);
//! }
//! # Ok::<(),anyhow::Error>(())
//! ```

mod error;
mod footer;
mod header;
mod implicit_assertion;
mod key;
mod paseto;
mod payload;
mod purpose;
mod traits;
mod version;
mod common;
mod paseto_impl;

pub use error::PasetoError;
pub use footer::Footer;
pub(crate) use header::Header;
pub use implicit_assertion::ImplicitAssertion;
pub use key::{Key, PasetoAsymmetricPrivateKey, PasetoAsymmetricPublicKey, PasetoNonce, PasetoSymmetricKey};
pub use paseto::Paseto;
pub use payload::Payload;
pub use purpose::{Local, Public};
pub(crate) use traits::{Base64Encodable, V1orV3, V2orV4};
pub use traits::{ImplicitAssertionCapable, PurposeTrait, VersionTrait};
pub use version::*;
