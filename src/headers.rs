pub mod v2 {
  use crate::common::{PurposeLocal, PurposePublic, Version2};
  use std::fmt::Display;
  use std::{fmt, marker::PhantomData};

  #[derive(PartialEq, Debug)]
  pub(crate) struct Header<Version, Purpose> {
    version: PhantomData<Version>,
    purpose: PhantomData<Purpose>,
  }
  impl AsRef<str> for Header<Version2, PurposeLocal> {
    fn as_ref(&self) -> &str {
      "v2.local."
    }
  }
  impl AsRef<str> for Header<Version2, PurposePublic> {
    fn as_ref(&self) -> &str {
      "v2.public."
    }
  }

  impl<Version, Purpose> Default for Header<Version, Purpose> {
    fn default() -> Self {
      Self {
        version: PhantomData,
        purpose: PhantomData,
      }
    }
  }

  impl Display for Header<Version2, PurposeLocal> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{}", self.as_ref())
    }
  }

  impl Display for Header<Version2, PurposePublic> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{}", self.as_ref())
    }
  }

  //#[derive(Default, PartialEq, Debug)]
  //pub(crate) struct V2LocalHeader<'a>(&'a str);
  //impl<'a> AsRef<str> for V2LocalHeader<'a> {
  //  fn as_ref(&self) -> &str {
  //    "v2.local."
  //  }
  //}

  //impl<'a> Display for V2LocalHeader<'a> {
  //  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
  //    write!(f, "{}", self.as_ref())
  //  }
  //}

  //#[derive(Default, PartialEq, Debug)]
  //pub(crate) struct V2PublicHeader<'a>(&'a str);
  //impl<'a> AsRef<str> for V2PublicHeader<'a> {
  //  fn as_ref(&self) -> &str {
  //    "v2.public."
  //  }
  //}

  //impl<'a> Display for V2PublicHeader<'a> {
  //  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
  //    write!(f, "{}", self.as_ref())
  //  }
  //}
}

#[cfg(test)]
mod unit_tests {

  use super::v2::Header;
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
