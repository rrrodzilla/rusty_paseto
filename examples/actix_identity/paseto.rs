use crate::AppData;
use actix_identity::{IdentityPolicy, RequestIdentity};
use actix_utils::future::{ready, Ready};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorUnauthorized, Error, Result},
    web::Data,
};
use rusty_paseto::prelude::*;

pub struct PasetoCookieIdentityPolicy {}

/// Validates the `auth-token` cookie against the session identity. Returns
/// `Ok(None)` when no usable credential is present (caller treats this as
/// "anonymous") and an `Unauthorized` error when a credential is present but
/// fails verification — this prevents a malformed token from being silently
/// accepted as anonymous.
fn validate_auth_token(request: &mut ServiceRequest) -> Result<Option<String>, Error> {
    // No cookie at all => anonymous; let the handler decide.
    let Some(cookie) = request.cookie("auth-token") else {
        return Ok(None);
    };
    let token = cookie.value();

    // Identity cookie must already be set for the implicit assertion binding
    // to work; if not, treat as anonymous.
    let Some(identity) = request.get_identity() else {
        return Ok(None);
    };
    let id = identity.as_str();

    let data = request
        .app_data::<Data<AppData>>()
        .ok_or_else(|| ErrorUnauthorized("missing app data"))?;
    let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&data.paseto_key));

    PasetoParser::<V4, Local>::default()
        .set_implicit_assertion(ImplicitAssertion::from(id))
        .parse(token, &key)
        .map_err(|e| {
            eprintln!("paseto token rejected: {e}");
            ErrorUnauthorized("invalid token")
        })?;

    println!(
        "Validated auth token in PasetoCookieIdentityPolicy\n  for user {id}\n",
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
