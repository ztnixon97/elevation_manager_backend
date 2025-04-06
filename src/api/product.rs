use crate::db::queries::product::{
    bulk_update_products, bulk_update_products_by_filter, create_product, create_product_type,
    delete_product, get_product, get_product_id, get_product_types, get_products, update_product,
};

use crate::db::models::*;
use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use sqlx::PgPool;

/// Defines the product routes to be used in the main router
pub fn product_routes() -> Router<PgPool> {
    Router::new()
        .route("/products", post(create_product)) // Create a product
        .route("/products", get(get_products)) // Get all products (with pagination & filters)
        .route("/products/{product_id}", get(get_product)) // Get a single product by ID
        .route("/products/{product_id}", patch(update_product)) // Update a product by ID
        .route("/products/{product_id}", delete(delete_product)) // Delete a product by ID
        .route("/products/id/{product_site}", get(get_product_id))
        .route("/products/bulk_update", put(bulk_update_products)) // Bulk update products by IDs
        .route(
            "/products/bulk_update_by_filter",
            put(bulk_update_products_by_filter),
        ) // Bulk update products by filters
        .route("/product_types", get(get_product_types)) // Get all product types
        .route("/product_types", post(create_product_type)) // Create a new product type
}
