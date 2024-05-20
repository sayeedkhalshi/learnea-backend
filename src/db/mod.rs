pub mod models;
use sqlx::SqlitePool;

pub async fn create_connection() -> sqlx::Result<SqlitePool> {
    // return pool
    let pool: SqlitePool = SqlitePool::connect("sqlite::memory:").await?;

    // Create from user
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}