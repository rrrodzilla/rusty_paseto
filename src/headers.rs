use crate::common::{PurposeLocal, PurposePublic, Version2};
use std::fmt::Display;
use std::{fmt, marker::PhantomData};

#[derive(PartialEq, Debug)]
pub(crate) struct Header<Version, Purpose> {
  version: PhantomData<Version>,
  purpose: PhantomData<Purpose>,
  header: String,
}

impl<Version, Purpose> AsRef<str> for Header<Version, Purpose> {
  fn as_ref(&self) -> &str {
    self.header.as_ref()
  }
}

impl Default for Header<Version2, PurposePublic> {
  fn default() -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      header: "v2.public.".to_string(),
    }
  }
}

impl Default for Header<Version2, PurposeLocal> {
  fn default() -> Self {
    Self {
      version: PhantomData,
      purpose: PhantomData,
      header: "v2.local.".to_string(),
    }
  }
}

impl<Version, Purpose> Display for Header<Version, Purpose> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.header)
  }
}

#[cfg(test)]
mod unit_tests {

  use super::*;
  use crate::common::{PurposeLocal, PurposePublic, Version2};

  fn test_header_equality<S, H>(valid_value: H, header: S)
  where
    S: AsRef<str>,
    H: AsRef<str>,
  {
    assert_eq!(header.as_ref(), valid_value.as_ref());
  }

  #[test]
  fn test_v2_public_header_equality() {
    test_header_equality(Header::<Version2, PurposePublic>::default(), "v2.public.");
  }
  #[test]
  fn test_v2_local_header_equality() {
    test_header_equality(Header::<Version2, PurposeLocal>::default(), "v2.local.");
  }
}
