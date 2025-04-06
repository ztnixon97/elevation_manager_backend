use axum::{
    routing::{get, post, patch},
    Router,
};
use sqlx::PgPool;

use crate::db::queries::requests::*;

pub fn request_routes() -> Router<PgPool> {
    Router::new()
        .route("/requests", post(create_approval_request))
        .route("/requests", get(get_pending_requests))
        .route("/requests/{request_id}", get(get_approval_request_by_id_handler))
        .route("/requests/{request_id}", patch(update_approval_status))
}