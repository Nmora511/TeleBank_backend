pub mod connect_db;
pub mod routes;
use chrono::NaiveDateTime;
use serde::Deserialize;
use sqlx::{FromRow, Pool, Postgres};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct LoginPayload {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SignUpPayload {
    pub username: String,
    pub email: String,
    pub password: String,
    pub name: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool<Postgres>,
    pub secrets: shuttle_runtime::SecretStore,
}

#[derive(Debug, FromRow)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub pix_keys: Option<Vec<String>>,
    pub photo_path: Option<String>,
    pub created_at: NaiveDateTime,
    pub hash_salt: Vec<u8>,
}
