use axum::{Router, routing::post};

use sqlx::{Pool, Postgres};
use telebank_backend::{AppState, connect_db::connect_db, routes};
// use tower_http::cors::{Any, CorsLayer};

#[shuttle_runtime::main]
async fn main(
    #[shuttle_runtime::Secrets] secrets: shuttle_runtime::SecretStore,
) -> shuttle_axum::ShuttleAxum {
    let pool: Pool<Postgres> = connect_db(&secrets).await;

    let state = AppState { pool, secrets };

    // let cors = CorsLayer::new()
    //     .allow_methods([Method::GET, Method::POST])
    //     .expose_headers(Any)
    //     .allow_origin(cors_origin.parse::<HeaderValue>().unwrap());

    let router = Router::new()
        .route("/auth/login", post(routes::auth::login_handler))
        .route("/auth/sign-up", post(routes::auth::signup_handler))
        .with_state(state);

    Ok(router.into())
}
