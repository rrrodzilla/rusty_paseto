//! # PASETO + actix-identity Example
//!
//! Demonstrates issuing a PASETO V4 local token at login and validating it on
//! every protected request via a custom `actix-identity` policy.
//!
//! ## ⚠️ Production hardening notes
//!
//! This example is intentionally short and illustrative. Before adapting it to a
//! production deployment, address each of the following:
//!
//! - **Never hardcode keys.** This example loads `PASETO_KEY` and `COOKIE_KEY`
//!   from environment variables and falls back to a fresh random key per
//!   process start when they are absent. A real deployment must persist these
//!   keys in a secret manager (e.g., AWS Secrets Manager, Vault) and rotate
//!   them on schedule.
//! - **Run over HTTPS.** This example sets `secure(false)` for local
//!   development; production cookies must use `secure(true)`.
//! - **`actix-identity` 0.4** (used here) is several majors behind current.
//!   New code should use the current `actix-identity` (and the modern
//!   `IdentityMiddleware` API) — the patterns shown here are still relevant
//!   but the call surface has changed.
//! - **The implicit assertion bound here is the random per-session UUID.**
//!   That binds the token to the session cookie but does not protect against
//!   session-fixation; pair with proper CSRF protection in real apps.
//!
//! ## Running the example
//!
//! ```bash
//! # optional: provide your own keys (otherwise random keys are generated)
//! export PASETO_KEY="...32 bytes..."
//! export COOKIE_KEY="...32 bytes..."
//!
//! cargo run --example actix_identity
//!
//! # then in another shell:
//! curl http://localhost:8080
//! curl -X POST http://localhost:8080/login -c /tmp/cookies
//! curl http://localhost:8080/app/secure -b /tmp/cookies
//! curl -X POST http://localhost:8080/logout -b /tmp/cookies
//! ```

use rusty_paseto::prelude::*;
use actix_web::http::StatusCode;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::web;
use actix_web::{post, get, HttpResponse, HttpServer, App, services};
use actix_identity::{Identity, CookieIdentityPolicy, IdentityService};
use ring::rand::{SecureRandom, SystemRandom};
use time::OffsetDateTime;
use uuid::Uuid;

mod paseto;
use paseto::PasetoCookieIdentityPolicy;

#[get("/secure")]
async fn secure(id: Identity) -> String {
    // access request identity
    if let Some(id) = id.identity() {
        format!("Logged in Secure User: {}\n", id)
    } else {
        "Welcome Anonymous!".to_owned()
    }
}

#[get("/")]
async fn index(id: Identity) -> String {
    // access request identity
    if let Some(id) = id.identity() {
        format!("Welcome! {}", id)
    } else {
        println!("Found new anonymous user\n");
        "Welcome Anonymous!\n".to_owned()
    }
}

#[post("/login")]
async fn login(id: Identity, data: web::Data<AppData>) -> HttpResponse {
    // here you might do whatever checks are needed to authenticate user

    // create a new identity and wrap it in an auth cookie
    let authenticated_user_id = Uuid::new_v4().to_string();
    println!("Logged in user {}\n", authenticated_user_id);

    // bind the token to this session via an implicit assertion (V3/V4 only)
    let assertion = ImplicitAssertion::from(authenticated_user_id.as_str());

    let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(&data.paseto_key));

    let token = match PasetoBuilder::<V4, Local>::default()
        .set_implicit_assertion(assertion)
        .build(&key)
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("paseto build failed: {e}");
            return HttpResponse::InternalServerError().finish();
        }
    };

    // remember new authenticated identity
    id.remember(authenticated_user_id.to_string());

    // return the response creating a new cookie to hold the token
    HttpResponse::build(StatusCode::OK)
        .cookie(
            Cookie::build("auth-token", token)
                .path("/")
                .expires(OffsetDateTime::now_utc())
                // Using `secure(false)` so the example works over HTTP.
                // In production use `secure(true)`.
                .secure(false)
                .http_only(true)
                .same_site(SameSite::Lax)
                .finish(),
        )
        .finish()
}

#[post("/logout")]
async fn logout(id: Identity) -> HttpResponse {
    match id.identity() {
        Some(user) => {
            println!("Logging out user {user}\n");
            let body = format!("Goodbye {user}!\n");
            id.forget();
            HttpResponse::Ok().body(body)
        }
        None => HttpResponse::Unauthorized().finish(),
    }
}

// shared state — the 32-byte PASETO V4 local key
pub(crate) struct AppData {
    pub(crate) paseto_key: [u8; 32],
}

/// Loads a 32-byte key from `var` (hex-encoded), or generates a fresh random
/// key per process start. Panicking only at startup is acceptable for this
/// example; production code should fail-fast at config load with a clear
/// operator-facing error.
fn load_or_generate_key(var: &str) -> [u8; 32] {
    if let Ok(hex_value) = std::env::var(var) {
        match hex::decode(&hex_value) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                println!("Loaded {var} from environment");
                return key;
            }
            Ok(_) => eprintln!("{var} present but not 32 bytes; generating a fresh random key"),
            Err(e) => eprintln!("{var} present but not valid hex ({e}); generating a fresh random key"),
        }
    }

    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).expect("system RNG failure");
    println!(
        "Generated a fresh random {var} for this process — tokens issued now will not validate \
         on the next start. Set {var} (32 bytes hex) for stable keys.",
    );
    key
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load keys once at startup so every worker shares them.
    let paseto_key = load_or_generate_key("PASETO_KEY");
    let cookie_key = load_or_generate_key("COOKIE_KEY");

    HttpServer::new(move || {
        // create cookie identity backend (inside closure, since policy is not Clone)
        let policy = IdentityService::new(
            CookieIdentityPolicy::new(&cookie_key)
                .name("auth-cookie")
                // `secure(false)` is for local HTTP development; in production
                // use HTTPS and `secure(true)`.
                .secure(false),
        );

        // create a paseto cookie policy — using middleware would be cleaner in
        // a real app; this shows the policy approach for clarity
        let paseto_policy = PasetoCookieIdentityPolicy {};

        // paths that are not verified with the paseto token
        let unauthenticated_scope = web::scope("").service(services![index, login, logout]);
        // paths that should verify that a token exists and is valid
        let authenticated_scope = web::scope("/app").wrap(IdentityService::new(paseto_policy)).service(services![secure]);

        // create and run the server
        App::new()
            .app_data(web::Data::new(AppData { paseto_key }))
            .wrap(policy)
            .service(authenticated_scope)
            .service(unauthenticated_scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
