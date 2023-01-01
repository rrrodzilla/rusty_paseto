//! The outermost architectural layer is called batteries_included. This layer is implemented in the [prelude](self) module.  This is what most people will need.  
//! This feature includes JWT style claims and business rules for your PASETO token (default, but customizable expiration, issued at, not-before times, etc as described in the usage documentation and examples).
//!
//! ![paseto_batteries_included_small](https://user-images.githubusercontent.com/24578097/147881895-36878b22-bf17-49e4-98d7-f94920353368.png)
//!
//! You must specify a version and purpose with this feature in order to reduce the size of your dependencies like in the following Cargo.toml entry which only includes the V4 - Local types with batteries_included functionality:
//!
//! ```toml
//! ## Includes only v4 modern sodium cipher crypto core and local (symmetric)
//! ## key types with all claims and default business rules.
//!
//! rusty_paseto = {version = "latest", features = ["batteries_included", "v4_local"] }
//! ```
//! ![paseto_batteries_included_v4_local_small](https://user-images.githubusercontent.com/24578097/147882822-46dac1d1-a922-4301-be45-d3341dabfee1.png)
//!
//! #### Feature gates
//! Valid version/purpose feature combinations are as follows:
//! - "v1_local" (NIST Original Symmetric Encryption)
//! - "v2_local" (Sodium Original Symmetric Encryption)
//! - "v3_local" (NIST Modern Symmetric Encryption)
//! - "v4_local" (Sodium Modern Symmetric Encryption)
//! - "v1_public" (NIST Original Asymmetric Authentication)
//! - "v2_public" (Sodium Original Asymmetric Authentication)
//! - "v3_public" (NIST Modern Asymmetric Authentication)
//! - "v4_public" (Sodium Modern Asymmetric Authentication)

mod error;
mod paseto_builder;
mod paseto_parser;

pub use crate::generic::*;
pub use error::GeneralPasetoError;
pub use paseto_builder::PasetoBuilder;
pub use paseto_parser::PasetoParser;
