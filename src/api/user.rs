use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::PgPool;
use crate::db::queries::user::*;
pub fn user_routes() -> Router<PgPool> {
    Router::new()
        .route("/users", get(get_all_users))
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", put(update_user))
        .route("/users/{id}/role", get(check_user_role))
        .route("/users/{id}", delete(delete_user))
        .route("/users/me", get(get_me))
        .route("/users/me/teams", get(get_user_teams))
}
