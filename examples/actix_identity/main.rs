
/// This example shows how you might use a PASETO token to store some data in a cookie once the
/// user has been logged in.  
///
/// run the following command from your shell to:
/// 1) visit the site as an anonymous user and then,
/// 2) login the user, creating a paseto token and storing it in a cookie using the identity as the
///    implicit assertion and then,
/// 3) logout the user, forgetting the identity
/// 4) attempting to visit a secure path as a logged out user (will panic)
///
/// curl http://localhost:8080;curl -X POST http://localhost:8080/login -c ~/cookies; curl
/// http://localhost:8080/app/secure -b ~/cookies; curl -X POST http://localhost:8080/logout -b
/// ~/cookies
///
use rusty_paseto::prelude::*;
use actix_web::http::StatusCode;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::web;
use actix_web::{post,get, HttpResponse, HttpServer, App, services};
use actix_identity::{Identity, CookieIdentityPolicy, IdentityService};
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

    //create an implicit assertion (or you could create claim)
    let assertion = ImplicitAssertion::from(authenticated_user_id.as_str());

    //creating a paseto key
          let key_val = data.paseto_key.as_bytes();
      let key = PasetoSymmetricKey::<V4, Local>::from(Key::from(key_val));

      //create a token using the identity as an implicit assertion (you could also use a claim if
      //needed)
let token = PasetoBuilder::<V4, Local>::default()
        .set_implicit_assertion(assertion)
      .build(&key)
      .expect("Couldn't create paseto auth token");

    // remember new authenticated identity
    id.remember(authenticated_user_id.to_string());

    // return the response creating a new cookie to hold the token
     HttpResponse::build(StatusCode::OK).cookie(Cookie::build("auth-token", token).path("/").expires(OffsetDateTime::now_utc()).secure(false).http_only(true).same_site(SameSite::Lax).finish()).finish()

 
}

#[post("/logout")]
async fn logout(id: Identity) -> String {
    println!("Logging out user {}\n", id.identity().expect("Couldn't get identity"));
    //build logout msg
       let logout_msg = format!("Goodbye {}!\n", id.identity().expect("Couldn't get identity")).to_owned();
    // remove identity
    id.forget();
    logout_msg
    
}

//shared state
pub(crate) struct AppData {
    paseto_key: &'static str
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
 HttpServer::new(move || {
    // create cookie identity backend (inside closure, since policy is not Clone)
    let policy = IdentityService::new(CookieIdentityPolicy::new(&[0; 32])
        .name("auth-cookie")
        .secure(false));

    // create a paseto cookie policy, for this use case, however I recommend using a middleware but
     // this shows how you might use a policy instead
     let paseto_policy = PasetoCookieIdentityPolicy {};

     //paths that are not verified with the paseto token
     let unauthenticated_scope = web::scope("").service(services![index, login, logout]);
     //paths that should verify that a token exists and is valid
     let authenticated_scope = web::scope("/app").wrap(IdentityService::new(paseto_policy)).service(services![secure]);

     //create and run the server
    App::new()
        .app_data(web::Data::new(AppData { paseto_key:  "wubbalubbadubdubwubbalubbadubdub"}))
        .wrap(policy)
        // wrap policy into middleware identity middleware
        .service(authenticated_scope)
        .service(unauthenticated_scope)
})     .bind(("127.0.0.1", 8080))?
    .run()
    .await  
}


