# Framework-neutral PASETO session-cookie example

This example shows the security-sensitive portion of using a PASETO V4 local
token as an authenticated session cookie. It deliberately avoids a web
framework so the example does not impose a server dependency graph on the
library.

Run it with:

```console
cargo run --example actix_identity
```

Set `PASETO_KEY` to a 32-byte hex-encoded key to use stable key material. When
the variable is absent, the example generates an ephemeral key suitable only
for the current demonstration process.

The example demonstrates how to:

1. Issue a short-lived V4 local token after authentication.
2. Bind it to opaque, server-side session context using an implicit assertion.
3. Transport it in a `Secure`, `HttpOnly`, `SameSite=Lax` cookie.
4. Verify expiration, subject, and the implicit assertion on each protected
   request.
5. Reject a copied token when it is presented with a different session
   binding.

In a real service, the login handler calls `issue_session_token`, stores the
opaque binding in server-side session state, and writes the returned token to
the cookie. Authentication middleware reads the cookie, retrieves the binding,
and calls `verify_session_token` before forwarding the request.

Production deployments should also use HTTPS, source keys from a secret
manager, rotate keys, enforce CSRF protection, and maintain a revocation or
session-generation mechanism for logout and emergency invalidation. PASETO is
a bearer-token format and does not prevent replay by itself.
