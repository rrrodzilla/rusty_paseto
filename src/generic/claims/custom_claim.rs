use super::{PasetoClaim, PasetoClaimError};
#[cfg(feature = "serde")]
use serde::ser::SerializeMap;

///A custom PASETO claim which can be created with a key and a value T
/// ## Setting your own Custom Claims
///
/// The CustomClaim struct takes a tuple in the form of `(key: String, value: T)` where T is any
/// serializable type
/// #### Note: *CustomClaims use the TryFrom trait and return a Result<(), PasetoClaimError> if you attempt to use one of the [reserved PASETO keys](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md) in your CustomClaim*
///
/// ```rust
/// # use rusty_paseto::prelude::*;
/// # #[cfg(feature = "default")]
/// # {
/// # // must include
/// # use std::convert::TryFrom;
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// let token = PasetoBuilder::<V4, Local>::default()
///   .set_claim(CustomClaim::try_from(("Co-star", "Morty Smith"))?)
///   .set_claim(CustomClaim::try_from(("Universe", 137))?)
///   .build(&key)?;
/// # }
/// # Ok::<(),GenericBuilderError>(())
/// ```
///
/// This throws an error:
/// ```should_panic
/// # use rusty_paseto::prelude::*;
/// # #[cfg(feature = "default")]
/// # {
/// # // must include
/// # use std::convert::TryFrom;
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// // "exp" is a reserved PASETO claim key, you should use the ExpirationClaim type
/// let token = PasetoBuilder::<V4, Local>::default()
///   .set_claim(CustomClaim::try_from(("exp", "Some expiration value"))?)
///   .build(&key)?;
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```
/// # Validating claims
/// rusty_paseto allows for flexible claim validation at parse time
///
/// ## Checking claims
///
/// Let's see how we can check particular claims exist with expected values.
/// ```
/// # #[cfg(feature = "default")]
/// # {
/// # use rusty_paseto::prelude::*;
/// # use std::convert::TryFrom;
///
/// # // create a key specifying the PASETO version and purpose
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// // use a default token builder with the same PASETO version and purpose
/// let token = PasetoBuilder::<V4, Local>::default()
///   .set_claim(SubjectClaim::from("Get schwifty"))
///   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
///   .set_claim(CustomClaim::try_from(("Universe", 137))?)
///   .build(&key)?;
///
/// PasetoParser::<V4, Local>::default()
///   // you can check any claim even custom claims
///   .check_claim(SubjectClaim::from("Get schwifty"))
///   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
///   .check_claim(CustomClaim::try_from(("Universe", 137))?)
///   .parse(&token, &key)?;
///
/// // no need for the assertions below since the check_claim methods
/// // above accomplish the same but at parse time!
///
/// //assert_eq!(json_value["sub"], "Get schwifty");
/// //assert_eq!(json_value["Contestant"], "Earth");
/// //assert_eq!(json_value["Universe"], 137);
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```
///
/// # Custom validation
///
/// What if we have more complex validation requirements? You can pass in a reference to a closure which receives
/// the key and value of the claim you want to validate so you can implement any validation logic
/// you choose.  
///
/// Let's see how we can validate our tokens only contain universes with prime numbers:
///
/// ```
/// # use rusty_paseto::prelude::*;
/// # #[cfg(feature = "default")]
/// # {
/// # use std::convert::TryFrom;
///
/// # // create a key specifying the PASETO version and purpose
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// // use a default token builder with the same PASETO version and purpose
/// let token = PasetoBuilder::<V4, Local>::default()
///   .set_claim(SubjectClaim::from("Get schwifty"))
///   .set_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
///   .set_claim(CustomClaim::try_from(("Universe", 137))?)
///   .build(&key)?;
///
/// PasetoParser::<V4, Local>::default()
///   .check_claim(SubjectClaim::from("Get schwifty"))
///   .check_claim(CustomClaim::try_from(("Contestant", "Earth"))?)
///    .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
///      //let's get the value
///      let universe = value
///        .as_u64()
///        .ok_or(PasetoClaimError::Unexpected(key.to_string()))?;
///      // we only accept prime universes in this app
///      if primes::is_prime(universe) {
///        Ok(())
///      } else {
///        Err(PasetoClaimError::CustomValidation(key.to_string()))
///      }
///    })
///   .parse(&token, &key)?;
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```
///
/// This token will fail to parse with the validation code above:
/// ```should_panic
/// # #[cfg(feature = "default")]
/// # {
/// # use rusty_paseto::prelude::*;
/// # use std::convert::TryFrom;
///
/// # // create a key specifying the PASETO version and purpose
/// # let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(b"wubbalubbadubdubwubbalubbadubdub"));
/// // 136 is not a prime number
/// let token = PasetoBuilder::<V4, Local>::default()
///   .set_claim(CustomClaim::try_from(("Universe", 136))?)
///   .build(&key)?;
///
///# let json_value = PasetoParser::<V4, Local>::default()
///#  // you can check any claim even custom claims
///#   .validate_claim(CustomClaim::try_from("Universe")?, &|key, value| {
///#     //let's get the value
///#     let universe = value
///#       .as_u64()
///#       .ok_or(PasetoClaimError::Unexpected(key.to_string()))?;
///#     // we only accept prime universes in this token
///#     if primes::is_prime(universe) {
///#       Ok(())
///#     } else {
///#       Err(PasetoClaimError::CustomValidation(key.to_string()))
///#     }
///#   })
///
///#  .parse(&token, &key)?;
///
/// # assert_eq!(json_value["Universe"], 136);
/// # }
/// # Ok::<(),anyhow::Error>(())
/// ```

#[derive(Clone, Debug)]
pub struct CustomClaim<T>((String, T));

impl<T> CustomClaim<T> {
  //TODO: this needs to be refactored to be configurable for eventual compressed token
  //implementations
  pub(self) const RESERVED_CLAIMS: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

  fn check_if_reserved_claim_key(key: &str) -> Result<(), PasetoClaimError> {
    match key {
      key if Self::RESERVED_CLAIMS.contains(&key) => Err(PasetoClaimError::Reserved(key.into())),
      _ => Ok(()),
    }
  }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> PasetoClaim for CustomClaim<T> {
  fn get_key(&self) -> &str {
    &self.0 .0
  }
}

impl TryFrom<&str> for CustomClaim<&str> {
  type Error = PasetoClaimError;

  fn try_from(key: &str) -> Result<Self, Self::Error> {
    Self::check_if_reserved_claim_key(key)?;
    Ok(Self((String::from(key), "")))
  }
}

impl<T> TryFrom<(String, T)> for CustomClaim<T> {
  type Error = PasetoClaimError;

  fn try_from(val: (String, T)) -> Result<Self, Self::Error> {
    Self::check_if_reserved_claim_key(val.0.as_str())?;
    Ok(Self((val.0, val.1)))
  }
}

impl<T> TryFrom<(&str, T)> for CustomClaim<T> {
  type Error = PasetoClaimError;

  fn try_from(val: (&str, T)) -> Result<Self, Self::Error> {
    Self::check_if_reserved_claim_key(val.0)?;
    Ok(Self((String::from(val.0), val.1)))
  }
}

//we want to receive a reference as a tuple
impl<T> AsRef<(String, T)> for CustomClaim<T> {
  fn as_ref(&self) -> &(String, T) {
    &self.0
  }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for CustomClaim<T> {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_key(&self.0 .0)?;
    map.serialize_value(&self.0 .1)?;
    map.end()
  }
}
