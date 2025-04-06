use std::path::{Path, PathBuf};
use axum::{
    extract::{State, Path as AxumPath, Multipart, Extension},
    Json, http::StatusCode, response::IntoResponse, body::Bytes,
};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use sqlx::PgPool;
use serde_json::json;
use crate::db::models::review::{NewReview, Review, ReviewResponse, UpdateReview, ReviewImageUploadSchema};
use crate::utils::api_response::ApiResponse;
use crate::config::Config;
use crate::api::auth::Claims;

//
// Utility functions for human-readable folder structure:
// Reviews are stored under:
//   /reviews/{product_id}/{reviewer_id}_{username}/review_{review_id}.html
//
// Images are stored under:
//   /review_images/{product_id}/{reviewer_id}_{username}/{review_id}/{filename}
//

fn get_review_dir(product_id: i32, reviewer_id: i32, username: &str) -> PathBuf {
    Config::get()
        .review_storage_path
        .join(format!("{}/{}_{}", product_id, reviewer_id, username))
}

fn get_review_file_path(product_id: i32, reviewer_id: i32, username: &str, review_id: i32) -> PathBuf {
    get_review_dir(product_id, reviewer_id, username).join(format!("review_{}.html", review_id))
}

fn get_image_dir(product_id: i32, reviewer_id: i32, username: &str, review_id: i32) -> PathBuf {
    Config::get()
        .review_image_storage_path
        .join(format!("{}/{}/{}", product_id, format!("{}_{}", reviewer_id, username), review_id))
}

fn get_image_path(product_id: i32, reviewer_id: i32, username: &str, review_id: i32, filename: &str) -> PathBuf {
    get_image_dir(product_id, reviewer_id, username, review_id).join(filename)
}

//
// REVIEW CRUD FUNCTIONS
//

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/reviews",
    tag = "Reviews",
    request_body = NewReview,
    responses(
        (status = 201, description = "Sucucessfuly created review", body = i32),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_review(
    State(db_pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<NewReview>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(StatusCode::UNAUTHORIZED, "Invalid user ID in token", None)
    })?;
    let username = &claims.username;

    // Insert review record with a temporary empty review_path.
    let review = sqlx::query!(
        r#"
        INSERT INTO reviews (product_id, reviewer_id, review_status, product_status, review_path, created_at, updated_at)
        VALUES ($1, $2, $3, $4, '', NOW(), NOW())
        RETURNING id
        "#,
        payload.product_id,
        user_id,
        payload.review_status,
        payload.product_status,
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create review",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    // Compute final file path.
    let final_path = get_review_file_path(payload.product_id, user_id, username, review.id);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent).await.map_err(|e| {
            ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create review directory",
                Some(json!({ "message": e.to_string() })),
            )
        })?;
    }
    fs::write(&final_path, payload.content.clone()).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to write review file",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    // Update review record with the actual file path.
    sqlx::query!(
        "UPDATE reviews SET review_path = $1, updated_at = NOW() WHERE id = $2",
        &final_path.to_string_lossy(),
        review.id
    )
    .execute(&db_pool)
    .await
    .map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update review with file path",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    Ok(ApiResponse::success(
        StatusCode::CREATED,
        "Review created successfully",
        review.id,
    ))
}

#[utoipa::path(
    get,
    path = "/reviews/{review_id}",
    tag = "Reviews",
    params(
        ("review_id" = i32, Path, description = "Id of the review being retrieved"),
    ),
    responses(
        (status = 200, description = "Review retrived successfully", body = ReviewResponse),
        (status = 404, description = "Review not found"),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_review(
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
    AxumPath(review_id): AxumPath<i32>,
) -> Result<ApiResponse<ReviewResponse>, ApiResponse<()>> {
    let review = sqlx::query_as!(
        Review,
        r#"
        SELECT id, product_id, reviewer_id, review_status, product_status, review_path,
               created_at, updated_at
        FROM reviews
        WHERE id = $1
        "#,
        review_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Review not found", None))?;

    let content = fs::read_to_string(&review.review_path)
        .await
        .map_err(|e| {
            ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read review file",
                Some(json!({ "message": e.to_string() })),
            )
        })?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Review retrieved successfully",
        ReviewResponse { review, content },
    ))
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/reviews/user/{user_id}",
    params(
        ("user_id" = i32, Path, description = "ID of user for response"),
    ),
    responses(
        (status = 200, description= "Successfully retrived reviews for user", body = Vec<ReviewResponse>),
        (status = 404, description = "User ID not found"),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "Reviews",
    security(
        ("bearerAuth"= [])
    )
    
)]
pub async fn get_reviews_for_user(
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
    AxumPath(user_id): AxumPath<i32>,
) -> Result<ApiResponse<Vec<Review>>, ApiResponse<()>> {
    let reviews = sqlx::query_as!(
        Review,
        r#"
        SELECT id, product_id, reviewer_id, review_status, product_status, review_path,
               created_at, updated_at
        FROM reviews
        WHERE reviewer_id = $1
        "#,
        user_id
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "No reviews found for this user",
            None,
        )
    })?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Reviews retrieved successfully",
        reviews,
    ))
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/reviews/product/{product_id}",
    params(
        ("product_id" = i32, description = "Product ID of the reviews"),
    ),
    responses(
        (status = 200, description = "Successfully retrieved reviews for product", body = Vec<ReviewResponse>),
    ),
    tag = "Reviews",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_reviews_for_product(
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
    AxumPath(product_id): AxumPath<i32>,
) -> Result<ApiResponse<Vec<Review>>, ApiResponse<()>> {
    let reviews = sqlx::query_as!(
        Review,
        r#"
        SELECT id, product_id, reviewer_id, review_status, product_status, review_path,
               created_at, updated_at
        FROM reviews
        WHERE product_id = $1
        "#,
        product_id
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "No reviews found for this product",
            None,
        )
    })?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Reviews retrieved successfully",
        reviews,
    ))
}

#[axum::debug_handler]
#[utoipa::path(
    put,
    path = "/reviews/{review_id}",
    tag = "Reviews",
    params(
        ("review_id" = i32, Path, description= "ID of the review to be updated"),
    ),
    request_body = UpdateReview,
    responses(
        (status = 200, description ="Review updated successfully"),
        (status = 400, description = "No fields provided for update"),
        (status = 404, description = "Review not found"),
        (status = 500, description = "Internal Server Error"),
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_review(
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
    AxumPath(review_id): AxumPath<i32>,
    Json(payload): Json<UpdateReview>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let result = sqlx::query!(
        r#"
        UPDATE reviews
           SET review_status = COALESCE($1, review_status),
               product_status = COALESCE($2, product_status),
               updated_at = NOW()
         WHERE id = $3
        "#,
        payload.review_status,
        payload.product_status,
        review_id
    )
    .execute(&db_pool)
    .await
    .map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update review",
            None,
        )
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Review not found", None));
    }

    if let Some(new_content) = payload.content {
        let review_record = sqlx::query!("SELECT review_path FROM reviews WHERE id = $1", review_id)
            .fetch_one(&db_pool)
            .await
            .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Review not found", None))?;
        fs::write(&review_record.review_path, new_content)
            .await
            .map_err(|e| {
                ApiResponse::<()>::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to update review file",
                    Some(json!({ "message": e.to_string() })),
                )
            })?;
    }

    Ok(ApiResponse::success(StatusCode::OK, "Review updated successfully", ()))
}

#[axum::debug_handler]
#[utoipa::path(
    delete,
    path = "/reviews/{review_id}",
    tag = "Reviews",
    params(
        ("reivew_id" = i32, Path, description = "ID of the review to be deleted"),
    ),
    responses(
        (status = 200, description = "Review successfully deleted"),
        (status = 404, description = "Review not found"),
        (status = 500, description = "Internal Server Error"),
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_review(
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
    AxumPath(review_id): AxumPath<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let review_path: Option<String> = sqlx::query_scalar!("SELECT review_path FROM reviews WHERE id = $1", review_id)
        .fetch_optional(&db_pool)
        .await
        .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Review not found", None))?;

    if let Some(path) = review_path {
        if fs::metadata(&path).await.is_ok() {
            fs::remove_file(&path).await.ok();
        }
    }

    // Delete associated images folder (adjust as needed for your structure).
    let image_folder = Config::get()
        .review_image_storage_path
        .join(format!("review_{}", review_id));
    fs::remove_dir_all(&image_folder).await.ok();

    let deleted = sqlx::query!("DELETE FROM reviews WHERE id = $1 RETURNING id", review_id)
        .fetch_optional(&db_pool)
        .await
        .map_err(|_| ApiResponse::<()>::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete review", None))?;
    if deleted.is_none() {
        return Err(ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Review not found", None));
    }

    Ok(ApiResponse::success(StatusCode::OK, "Review deleted successfully", ()))
}

//
// IMAGE CRUD FUNCTIONS
//

#[axum::debug_handler]
#[utoipa::path(
    post,
    path = "/reviews/{review_id}/images",
    tag = "Reviews",
    params(
        ("review_id" = i32, Path, description = "ID of the review to upload images for"),
    ),
    request_body = ReviewImageUploadSchema,
    responses(
        (status = 200, description = "Images uploaded successfully", body = Vec<String>),
        (status = 400, description = "No image files uploaded"),
        (status = 404, description = "Review not found"),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn upload_review_image(
    State(db_pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    AxumPath(review_id): AxumPath<i32>,
    mut multipart: Multipart,
) -> Result<ApiResponse<Vec<String>>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(StatusCode::UNAUTHORIZED, "Invalid user ID in token", None)
    })?;
    let username = &claims.username;

    // Ensure the review belongs to this user and retrieve product_id.
    let rec = sqlx::query!("SELECT product_id, reviewer_id FROM reviews WHERE id = $1", review_id)
        .fetch_one(&db_pool)
        .await
        .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Review not found", None))?;
    if rec.reviewer_id != user_id {
        return Err(ApiResponse::<()>::error(StatusCode::FORBIDDEN, "Unauthorized", None));
    }

    let images_dir = Config::get()
        .review_image_storage_path
        .join(format!("{}/{}/{}", rec.product_id, format!("{}_{}", user_id, username), review_id));
    fs::create_dir_all(&images_dir).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create images directory",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    let mut uploaded_files = Vec::new();
    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "Failed to process multipart data",
            Some(json!({ "message": e.to_string() })),
        )
    })? {
        if let Some(filename) = field.file_name().map(|s| s.to_string()) {
            let file_path = images_dir.join(&filename);
            let mut file = fs::File::create(&file_path).await.map_err(|e| {
                ApiResponse::<()>::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create image file",
                    Some(json!({ "message": e.to_string() })),
                )
            })?;
            while let Some(chunk) = field.chunk().await.map_err(|e| {
                ApiResponse::<()>::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read image data",
                    Some(json!({ "message": e.to_string() })),
                )
            })? {
                file.write_all(&chunk).await.map_err(|e| {
                    ApiResponse::<()>::error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to write image file",
                        Some(json!({ "message": e.to_string() })),
                    )
                })?;
            }
            uploaded_files.push(filename);
        }
    }
    if uploaded_files.is_empty() {
        return Err(ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "No image files uploaded", None));
    }
    Ok(ApiResponse::success(StatusCode::OK, "Images uploaded successfully", uploaded_files))
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/reviews/{review_id}/images/{filename}",
    tag = "Reviews",
    params(
        ("review_id" = i32, Path, description = "ID of the review"),
        ("filename" = String, Path, description = "Name of the image file"),
    ),
    responses(
        (status = 200, description = "Image retrieved successfully"),
        (status = 404, description = "Image not found"),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_review_image(
    AxumPath((review_id, filename)): AxumPath<(i32, String)>,
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
) -> Result<impl IntoResponse, StatusCode> {
    let rec = sqlx::query!("SELECT product_id, review_path FROM reviews WHERE id = $1", review_id)
        .fetch_one(&db_pool)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let parts: Vec<&str> = rec.review_path.split('/').collect();
    if parts.len() < 2 {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let user_folder = parts[parts.len() - 2]; // e.g., "1_johndoe"
    let file_path = Config::get()
        .review_image_storage_path
        .join(format!("{}/{}/{}/{}", rec.product_id, user_folder, review_id, filename));
    if fs::metadata(&file_path).await.is_err() {
        return Err(StatusCode::NOT_FOUND);
    }
    let file = fs::File::open(&file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stream = ReaderStream::new(file);
    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "image/png")
        .body(axum::body::Body::from_stream(stream))
        .unwrap())
}

#[axum::debug_handler]
#[utoipa::path(
    get,
    path = "/reviews/{review_id}/images",
    tag = "Reviews",
    params(
        ("review_id" = i32, Path, description = "ID of the review"),
    ),
    responses(
        (status = 200, description = "Image filenames retrieved successfully", body = Vec<String>),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_all_review_images(
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
    AxumPath(review_id): AxumPath<i32>,
) -> Result<ApiResponse<Vec<String>>, ApiResponse<()>> {
    let storage_path = Config::get()
        .review_image_storage_path
        .join(format!("review_{}", review_id));
    let mut images = Vec::new();
    let mut entries = fs::read_dir(&storage_path).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read images directory",
            Some(json!({ "message": e.to_string() })),
        )
    })?;
    while let Some(entry) = entries.next_entry().await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read directory entry",
            Some(json!({ "message": e.to_string() })),
        )
    })? {
        if let Some(name) = entry.file_name().to_str() {
            images.push(name.to_string());
        }
    }
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Image filenames retrieved successfully",
        images,
    ))
}

#[axum::debug_handler]
#[utoipa::path(
    delete,
    path = "/reviews/{review_id}/images/{filename}",
    tag = "Reviews",
    params(
        ("review_id" = i32, Path, description = "ID of the review"),
        ("filename" = String, Path, description = "Name of the image file to be deleted"),
    ),
    responses(
        (status = 200, description = "Image deleted successfully"),
        (status = 404, description = "Image not found"),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_review_image(
    AxumPath((review_id, filename)): AxumPath<(i32, String)>,
    State(db_pool): State<PgPool>,
    Extension(_claims): Extension<Claims>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let file_path = Config::get()
        .review_image_storage_path
        .join(format!("review_{}/{}", review_id, filename));
    if fs::metadata(&file_path).await.is_err() {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Image not found",
            None,
        ));
    }
    fs::remove_file(&file_path).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to delete image",
            Some(json!({ "message": e.to_string() })),
        )
    })?;
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Image deleted successfully",
        (),
    ))
}

use utoipa::OpenApi;


#[derive(OpenApi)]
#[openapi(
    paths(
        create_review,
        get_review,
        get_reviews_for_user,
        get_reviews_for_product,
        update_review,
        delete_review,
        upload_review_image,
        get_review_image,
        get_all_review_images,
        delete_review_image
    ),
    components(
        schemas(ReviewResponse, NewReview, UpdateReview, Review, ReviewImageUploadSchema)
    ),
    tags(
        (name = "Reviews", description = "Review Management Endpoints")
    )
)]
pub struct ReviewDoc;
