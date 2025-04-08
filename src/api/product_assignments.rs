use crate::db::queries::product_assignments::{
    complete_assignment, create_user_assignment, delete_assignment, get_assignment,
    get_my_assignments, get_product_assignments, get_user_assignments,
};
use axum::{
    routing::{delete, get, patch, post},
    Router,
};

use sqlx::PgPool;


pub fn assignment_routes() -> Router<PgPool> {
    Router::new()
        .route("/product-assignments", post(create_user_assignment))
        .route("/product-assignments/{assignment_id}", get(get_assignment))
        .route("/product-assignments/{assignment_id}", delete(delete_assignment))
        .route("/product-assignments/{assignment_id}/complete", patch(complete_assignment))
        .route("/products/{product_id}/assignments", get(get_product_assignments))
        .route("/users/{user_id}/assignments", get(get_user_assignments))
        .route("/assignments/me", get(get_my_assignments))
}