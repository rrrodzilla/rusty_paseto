//! The generic architectural and feature layer allows you to create your own custom version of the batteries_included layer by following the same pattern I've used in the source code to create your own custom builder and parser.  This is probably not what you need as it is for advanced usage.  The feature includes a generic builder and parser along with claims for you to extend.
//!
//! ![paseto_generic_small](https://user-images.githubusercontent.com/24578097/147881907-a765ede6-c8e5-44ff-9845-db53f0634f07.png)
//!
//! It includes all the PASETO and custom claims but allows you to create different default claims in your custom builder and parser or use a different time crate or make up your own default business rules.  As with the batteries_included layer, parsed tokens get returned as a serder_json Value. Again, specify the version and purpose to include in the crypto core:
//!
//!
//! ```toml
//! ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
//! ## key types with all claims and default business rules.
//!
//! rusty_paseto = {version = "latest", features = ["generic", "v4_local"] }
//! ```
//! ```
//! # #[cfg(feature = "default")]
//! # {
//! // at the top of your source file
//! use rusty_paseto::generic::*;
//! # }
//! ```
//! # Registered Claims

//! Refer to the [PASETO specification](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) to review reserved claims for use within PASETO.
mod builders;
mod claims;
mod parsers;

pub use crate::generic::claims::*;

pub use crate::core::*;

pub use crate::generic::builders::*;

pub use crate::generic::parsers::*;
