use sqlx::{Pool, Postgres};
use sqlx::postgres::PgPoolOptions;
use crate::config::Config;

pub async fn get_db_pool() -> Pool<Postgres> {
    let config = Config::from_env();
    PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to the database")
}
