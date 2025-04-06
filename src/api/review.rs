use crate::db::queries::review::{
    create_review, delete_review, delete_review_image, get_all_review_images, get_review,
    get_review_image, get_reviews_for_product, get_reviews_for_user, update_review,
    upload_review_image,
};
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::PgPool;

pub fn review_routes() -> Router<PgPool> {
    Router::new()
        .route("/reviews", post(create_review))
        .route(
            "/reviews/{id}",
            get(get_review).patch(update_review).delete(delete_review),
        )
        .route("/reviews/user/{user_id}", get(get_reviews_for_user))
        .route(
            "/reviews/product/{product_id}",
            get(get_reviews_for_product),
        )
        .route("/reviews/{review_id}/image", post(upload_review_image))
        .route(
            "/reviews/{review_id}/image/{filename}",
            get(get_review_image),
        )
        .route("/reviews/{review_id}/images", get(get_all_review_images))
        .route(
            "/reviews/{review_id}/image/{filename}",
            delete(delete_review_image),
        )
}
