# An example using a paseto token with the actix_identity crate

This example creates a simple actix_web server using the default [CookieIdentityPolicy](https://docs.rs/actix-identity/latest/actix_identity/struct.CookieIdentityPolicy.html) as well as a custom [PasetoCookieIdentityPolicy](https://github.com/rrrodzilla/rusty_paseto/blob/main/examples/actix_identity/paseto.rs).  The [CookieIdentityPolicy](https://docs.rs/actix-identity/latest/actix_identity/struct.CookieIdentityPolicy.html) is used for a an identity cookie.  The latter policy is used to validate a PASETO authentication token that is stored in a separate cookie when the user logs in by making a POST request to the login endpoint.  

When a user makes a request to a secure endpoint `/app/secure`, the [PasetoCookieIdentityPolicy](https://github.com/rrrodzilla/rusty_paseto/blob/main/examples/actix_identity/paseto.rs) validates the PASETO token on each request using the [CookieIdentityPolicy's](https://docs.rs/actix-identity/latest/actix_identity/struct.CookieIdentityPolicy.html) identity as the implicit assertion.  This means if a user comes from a different device or changes their cookies after logging in, the implicit assertion will fail and the PASETO won't be validated.  This example panics when this happens, but in practice you would map the error to a Not Authorized HTTP error.

## Usage

First run `cargo run --example actix_identity" to build and start the web server.

Then run the following command from a separate shell (I'm using [Fish](https://fishshell.com/)) to execute a series of requests that do the following:
```fish
curl http://localhost:8080;curl -X POST http://localhost:8080/login -c ~/cookies; curl http://localhost:8080/app/secure -b ~/cookies; curl -X POST http://localhost:8080/logout -b ~/cookies
```

1) Visits the site as an anonymous user and then,
2) Login the user, creating a paseto token and storing it in a cookie using the identity as the
   implicit assertion and then,
3) Logout the user, forgetting the identity


