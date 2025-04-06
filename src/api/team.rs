use crate::db::queries::team::{
    add_user_to_team, assign_product_to_team, assign_product_type_to_team, assign_task_order_to_team, create_team, delete_team, get_all_teams, get_team, get_team_members, get_team_product_types, get_team_products, get_team_task_orders, remove_product_from_team, remove_product_type_from_team, remove_task_order_from_team, remove_user_from_team, update_team, update_user_role
};
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::PgPool;

/// Register team management routes
pub fn team_routes() -> Router<PgPool> {
    Router::new()
        .route("/teams", post(create_team).get(get_all_teams)) // Create & List Teams
        .route(
            "/teams/{team_id}",
            get(get_team).put(update_team).delete(delete_team),
        ) // Manage Teams
        .route(
            "/teams/{team_id}/users",
            post(add_user_to_team).get(get_team_members),
        ) // Manage Team Members
        .route(
            "/teams/{team_id}/users/{user_id}",
            delete(remove_user_from_team).put(update_user_role),
        ) // Remove or Update User Role
        .route(
            "/teams/{team_id}/products",
            post(assign_product_to_team).get(get_team_products), // ✅ Combined into one route
        ) // Assign & Get Products for Team
        .route(
            "/teams/{team_id}/products/{product_id}",
            delete(remove_product_from_team),
        ) // Remove Product from Team
        .route(
            "/teams/{team_id}/product_types",
            post(assign_product_type_to_team).get(get_team_product_types), // ✅ Combined into one route
        ) // Assign & Get Product Types for Team
        .route(
            "/teams/{team_id}/product_types/{product_type_id}",
            delete(remove_product_type_from_team),
        )
        .route(
            "/teams/{team_id}/taskorders",
            post(assign_task_order_to_team).get(get_team_task_orders), // ✅ Combined into one route
        )
        .route(
            "/teams/{team_id}/taskorders/{task_id}",
            delete(remove_task_order_from_team),
        )

}
