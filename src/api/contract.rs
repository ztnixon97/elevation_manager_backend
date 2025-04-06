use crate::db::queries::contract::{
    create_contract, delete_contract, get_all_contracts, get_contract, update_contract,
};
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::PgPool;

/// Defines the contract routes to be used in the main router
pub fn contract_routes() -> Router<PgPool> {
    Router::new()
        .route("/contracts", post(create_contract)) // Create a contract
        .route("/contracts", get(get_all_contracts)) // Get all contracts
        .route("/contracts/{contract_id}", get(get_contract)) // Get a single contract by ID
        .route("/contracts/{contract_id}", patch(update_contract)) // Update a contract by ID
        .route("/contracts/{contract_id}", delete(delete_contract)) // Delete a contract by ID
}
