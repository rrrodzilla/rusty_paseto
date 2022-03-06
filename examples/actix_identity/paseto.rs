use crate::AppData;
use actix_identity::{IdentityPolicy, RequestIdentity};
use actix_utils::future::{ready, Ready};
use actix_web::{
  dev::{ServiceRequest, ServiceResponse},
  error::{Error, Result},
  web::Data,
};
use rusty_paseto::prelude::*;
pub struct PasetoCookieIdentityPolicy {}

fn validate_auth_token(request: &mut ServiceRequest) -> Result<Option<String>, Error> {
  //try to find the cookie with the auth token, panic if not found
  //ideally we should map the errors to an http not authorized error
  let cookie = request
    .cookie("auth-token")
    .expect("No auth token found in PasetoCookieIdentityPolicy");
  //now grab the token from the cookie
  let token: &str = cookie.value();

  //get the identity from the identity cookie
  let identity = request.get_identity().expect("Couldn't find identity");
  let id = identity.as_str();
  //get the paseto key from the shared state
  let key_val = request.app_data::<Data<AppData>>().unwrap().paseto_key.as_bytes();
  //create a paseto key
  let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(key_val));

  //attempt to parse the token when accessing a secure path, in practice this should also map to an HTTP error
  PasetoParser::<V4, Local>::default()
    .set_implicit_assertion(ImplicitAssertion::from(id))
    .parse(token, &key)
    .map_err(|err_val| println!("{}", err_val))
    .expect("Couldn't validate authentication token");
  println!(
    "Validated auth token in PasetoCookieIdentityPolicy\n  for user {}\n",
    id
  );
  Ok(Some(identity))
}

impl IdentityPolicy for PasetoCookieIdentityPolicy {
  type Future = Ready<Result<Option<String>, Error>>;
  type ResponseFuture = Ready<Result<(), Error>>;

  fn from_request(&self, request: &mut ServiceRequest) -> Self::Future {
    ready(validate_auth_token(request))
  }

  fn to_response<B>(
    &self,
    _identity: Option<String>,
    _changed: bool,
    _response: &mut ServiceResponse<B>,
  ) -> Self::ResponseFuture {
    ready(Ok(()))
  }
}
