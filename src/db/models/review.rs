use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

/// ✅ **Review Metadata Stored in PostgreSQL**
#[derive(Serialize, Deserialize, Debug, FromRow, ToSchema)]
pub struct Review {
    pub id: i32,
    pub product_id: i32,
    pub reviewer_id: i32,
    pub review_status: String,  // E.g. Pending, Approved, Rejected
    pub product_status: String, // Associated Product Status
    pub review_path: String,    // ✅ Path to stored HTML file (rich text)
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

/// ✅ **New Review Request (Frontend Sends This)**
#[derive(Deserialize, ToSchema)]
pub struct NewReview {
    pub product_id: i32,
    pub reviewer_id: i32,
    pub review_status: String,  // Pending / In-Review / Approved / Rejected
    pub product_status: String, // Status of the related product
    pub content: String,        // ✅ Rich text content (HTML/JSON from TipTap)
}

/// ✅ **Update Review Request**
#[derive(Deserialize, ToSchema)]
pub struct UpdateReview {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>, // ✅ If content exists, update it
}

/// ✅ **Review Response (Includes the HTML Content)**
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ReviewResponse {
    pub review: Review,  // ✅ Metadata from PostgreSQL
    pub content: String, // ✅ Loaded from `review_path`
}

#[derive(Serialize, ToSchema)]
pub struct ReviewImageUploadSchema {
    /// The image file to be uploaded (multipart/form-data)
    file: String,
}
