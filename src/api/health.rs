use axum::{extract::State, routing::get, Json, Router};
use sqlx::PgPool;
use axum::http::StatusCode;
use serde_json::json;

/// Defines health check routes
pub fn health_routes() -> Router<PgPool> {
    Router::new()
        .route("/health/live", get(liveness_check))  // ✅ Liveness check
        .route("/health/ready", get(readiness_check)) // ✅ Readiness check
        .route("/products/health", get(product_health_check))
        .route("/contracts/health", get(contract_health_check))
}

/// **Liveness Check (Basic Check)**  
/// - ✅ Verifies that the API is running  
/// - ❌ Does NOT check the database  
async fn liveness_check() -> Json<serde_json::Value> {
    Json(json!({ "success": true, "message": "API is live" }))
}

/// **Readiness Check (Database Connectivity Check)**  
/// - ✅ Ensures database is connected  
/// - ❌ Returns `500` if the database is down  
async fn readiness_check(State(pool): State<PgPool>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    sqlx::query("SELECT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "success": false, "error": "Database unavailable", "details": e.to_string() }).to_string(),
            )
        })?;

    Ok(Json(json!({ "success": true, "message": "API is ready" })))
}

/// **Product API Health Check**
async fn product_health_check(State(pool): State<PgPool>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    sqlx::query("SELECT 1 FROM products LIMIT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "success": false, "error": "Products table unavailable", "details": e.to_string() }).to_string(),
            )
        })?;

    Ok(Json(json!({ "success": true, "message": "Product API is healthy" })))
}

/// **Contract API Health Check**
async fn contract_health_check(State(pool): State<PgPool>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    sqlx::query("SELECT 1 FROM contracts LIMIT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "success": false, "error": "Contracts table unavailable", "details": e.to_string() }).to_string(),
            )
        })?;

    Ok(Json(json!({ "success": true, "message": "Contract API is healthy" })))
}
