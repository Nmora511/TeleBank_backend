pub mod connect_db;
pub mod routes;
use chrono::NaiveDateTime;
use serde::Deserialize;
use sqlx::{Error, FromRow, Pool, Postgres};
use uuid::Uuid;

pub async fn user_query_by_id(pool: &Pool<Postgres>, id: &Uuid) -> Result<User, Error> {
    let sql_query = include_str!("sql/select_user_by_id.sql");
    let select_user_result: Result<User, sqlx::Error> = sqlx::query_as::<_, User>(sql_query)
        .bind(id)
        .fetch_one(pool)
        .await;

    select_user_result
}

pub async fn user_query_by_username(
    pool: &Pool<Postgres>,
    username: &String,
) -> Result<User, Error> {
    let sql_query = include_str!("sql/select_user_by_username.sql");
    let select_user_result: Result<User, sqlx::Error> = sqlx::query_as::<_, User>(sql_query)
        .bind(username)
        .fetch_one(pool)
        .await;

    select_user_result
}

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

pub enum AuthenticationError {
    TokenNotFound,
    InvalidToken,
}

pub struct PartialUser {
    id: Uuid,
    username: String,
    name: String,
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
