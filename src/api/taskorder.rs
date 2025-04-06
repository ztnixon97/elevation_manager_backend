use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::PgPool;

// Assuming your TaskOrder query/handler functions are in `crate::db::queries::taskorder`
use crate::db::queries::taskorder::{
    create_task_order, delete_task_order, get_all_taskorders, get_task_order, update_task_order, get_task_id
};

/// Defines the TaskOrder routes to be used in the main router
pub fn taskorder_routes() -> Router<PgPool> {
    Router::new()
        // Create a new TaskOrder
        .route("/taskorders", post(create_task_order))
        // Get all TaskOrders
        .route("/taskorders", get(get_all_taskorders))
        // Get a single TaskOrder by ID
        .route("/taskorders/{taskorder_id}", get(get_task_order))
        // Update a TaskOrder by ID
        .route("/taskorders/{taskorder_id}", patch(update_task_order))
        // Delete a TaskOrder by ID
        .route("/taskorders/{taskorder_id}", delete(delete_task_order))
        .route("/taskorders/id/{task_name}",get(get_task_id))
}       
