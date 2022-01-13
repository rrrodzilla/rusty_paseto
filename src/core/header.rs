use super::*;
use std::fmt;
use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;

/// The [Header] identifies the [protocol version and cryptographic format](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions) for the token
///
/// [at least one code example that users can copy/paste to try it]
///
#[derive(PartialEq, Debug, Copy, Clone)]
pub(crate) struct Header<Version, Purpose>
where
  Version: VersionTrait,
  Purpose: PurposeTrait,
{
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  header: &'static str,
}

impl<Version: VersionTrait, Purpose: PurposeTrait> Deref for Header<Version, Purpose> {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    self.header.as_bytes()
  }
}

impl<Version, Purpose> AsRef<str> for Header<Version, Purpose>
where
  Version: VersionTrait,
  Purpose: PurposeTrait,
{
  fn as_ref(&self) -> &str {
    self.header
  }
}
//note: ugly workaround to minimize heap allocations and allow the full struct to implement Copy
static V1_LOCAL: &str = "v1.local.";
static V1_PUBLIC: &str = "v1.public.";
static V2_LOCAL: &str = "v2.local.";
static V2_PUBLIC: &str = "v2.public.";
static V3_LOCAL: &str = "v3.local.";
static V3_PUBLIC: &str = "v3.public.";
static V4_LOCAL: &str = "v4.local.";
static V4_PUBLIC: &str = "v4.public.";

impl<Version, Purpose> Default for Header<Version, Purpose>
where
  Version: VersionTrait,
  Purpose: PurposeTrait,
{
  fn default() -> Self {
    let header = match (Version::default().as_ref(), Purpose::default().as_ref()) {
      ("v1", "local") => V1_LOCAL,
      ("v1", "public") => V1_PUBLIC,
      ("v2", "local") => V2_LOCAL,
      ("v2", "public") => V2_PUBLIC,
      ("v3", "local") => V3_LOCAL,
      ("v3", "public") => V3_PUBLIC,
      ("v4", "local") => V4_LOCAL,
      ("v4", "public") => V4_PUBLIC,
      _ => "", //this should never happen
    };
    Self {
      version: PhantomData,
      purpose: PhantomData,
      header,
    }
  }
}

impl<Version, Purpose> Display for Header<Version, Purpose>
where
  Version: VersionTrait,
  Purpose: PurposeTrait,
{
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.header)
  }
}

#[cfg(all(test, any(feature = "v4", feature = "v2")))]
mod unit_tests {

  use super::*;

  fn test_header_equality<S, H>(valid_value: H, header: S)
  where
    S: AsRef<str>,
    H: AsRef<str>,
  {
    assert_eq!(header.as_ref(), valid_value.as_ref());
  }

  #[cfg(feature = "v4_local")]
  #[test]
  fn test_v4_local_header_equality() {
    test_header_equality(Header::<V4, Local>::default(), "v4.local.");
  }

  #[cfg(feature = "v4_public")]
  #[test]
  fn test_v4_public_header_equality() {
    test_header_equality(Header::<V4, Public>::default(), "v4.public.");
  }

  #[cfg(feature = "v2_public")]
  #[test]
  fn test_v2_public_header_equality() {
    test_header_equality(Header::<V2, Public>::default(), "v2.public.");
  }

  #[cfg(feature = "v2_local")]
  #[test]
  fn test_v2_local_header_equality() {
    test_header_equality(Header::<V2, Local>::default(), "v2.local.");
  }
}
