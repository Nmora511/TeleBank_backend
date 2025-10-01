use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};

pub async fn connect_db(secrets: &shuttle_runtime::SecretStore) -> Pool<Postgres> {
    let database_url = secrets
        .get("DATABASE_URL")
        .expect("DATABASE_URL must be set in Secrets.toml");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create database pool");

    pool
}
