// src/api/notification.rs
use crate::db::queries::notification::*;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::PgPool;

pub fn notification_routes() -> Router<PgPool> {
    Router::new()
        .route(
            "/notifications",
            post(create_notification).get(get_notifications),
        )
        .route("/notifications/count", get(get_notification_count))
        .route(
            "/notifications/dismiss-all",
            post(dismiss_all_notifications),
        )
        .route(
            "/notifications/{notification_id}",
            get(get_notification)
                .patch(update_notification)
                .delete(delete_notification),
        )
        .route(
            "/notifications/{notification_id}/dismiss",
            post(dismiss_notification),
        )
        .route(
            "/teams/{team_id}/notifications",
            get(get_team_notifications),
        )
}
