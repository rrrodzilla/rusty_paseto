#[cfg(any(feature = "v1", doc))]
mod v1;
#[cfg(any(feature = "v2", doc))]
mod v2;
#[cfg(feature = "v3")]
mod v3;
#[cfg(feature = "v4")]
mod v4;

#[cfg(any(feature = "v1", doc))]
pub use v1::V1;
#[cfg(any(feature = "v2", doc))]
pub use v2::V2;
#[cfg(feature = "v3")]
pub use v3::V3;
#[cfg(feature = "v4")]
pub use v4::V4;
