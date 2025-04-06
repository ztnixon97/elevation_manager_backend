use crate::db::models::review::Review;
use chrono::{NaiveDate, NaiveDateTime};
use s2::{cell::Cell, cellid::CellID, latlng::LatLng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, FromRow, Debug, ToSchema)]
pub struct Product {
    pub id: i32,
    pub taskorder_id: Option<i32>,
    pub item_id: String,
    pub site_id: String,
    pub product_type_id: i32,
    pub status: String,
    pub status_date: NaiveDate,
    pub acceptance_date: Option<NaiveDate>,
    pub publish_date: Option<NaiveDate>,
    pub file_path: Option<String>,
    pub s2_index: Option<String>,
    pub geom: Option<String>,
    pub classification: String,
    pub created_at: NaiveDateTime,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct NewProduct {
    pub taskorder_id: Option<i32>,
    pub item_id: String,
    pub site_id: String,
    pub product_type_id: i32,
    pub status: String,
    pub status_date: Option<NaiveDate>,
    pub acceptance_date: Option<NaiveDate>,
    pub publish_date: Option<NaiveDate>,
    pub file_path: Option<String>,
    pub s2_index: Option<String>,
    pub geom: Option<Value>,
    pub classification: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct UpdateProduct {
    pub taskorder_id: Option<i32>,
    pub site_id: Option<String>,
    pub status: Option<String>,
    pub status_date: Option<NaiveDate>,
    pub acceptance_date: Option<NaiveDate>,
    pub publish_date: Option<NaiveDate>,
    pub file_path: Option<String>,
    pub s2_index: Option<String>,
    pub geom: Option<Value>,
    pub classification: Option<String>,
}

impl UpdateProduct {
    /// Checks if all fields in `UpdateProduct` are `None`, indicating no updates were provided.
    pub fn is_empty(&self) -> bool {
        self.taskorder_id.is_none()
            && self.site_id.is_none()
            && self.status.is_none()
            && self.status_date.is_none()
            && self.acceptance_date.is_none()
            && self.publish_date.is_none()
            && self.file_path.is_none()
            && self.s2_index.is_none()
            && self.geom.is_none()
            && self.classification.is_none()
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct BulkUpdateProducts {
    pub product_ids: Vec<i32>,
    pub updates: UpdateProduct,
}

#[derive(Serialize, Deserialize, Debug, IntoParams)]
pub struct BulkUpdateByFilterParams {
    // Filters
    pub taskorder_id: Option<i32>,
    pub item_id: Option<String>,
    pub site_id: Option<String>,
    pub product_type_id: Option<i32>,
    pub status: Option<String>,
    pub status_date_min: Option<NaiveDate>,
    pub status_date_max: Option<NaiveDate>,
    pub acceptance_date_min: Option<NaiveDate>,
    pub acceptance_date_max: Option<NaiveDate>,
    pub publish_date_min: Option<NaiveDate>,
    pub publish_date_max: Option<NaiveDate>,
    pub file_path: Option<String>,
    pub s2_index: Option<String>,
    pub classification: Option<String>,

    // Fields to Update
    pub update_taskorder_id: Option<i32>,
    pub update_status: Option<String>,
    pub update_status_date: Option<NaiveDate>,
    pub update_acceptance_date: Option<NaiveDate>,
    pub update_publish_date: Option<NaiveDate>,
    pub update_file_path: Option<String>,
    pub update_classification: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ProductResponse {
    pub product: Product,
    pub reviews: Vec<Review>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamProductResponse {
    pub id: i32,
    pub item_id: String,
    pub site_id: String,
    pub status: String,
    pub status_date: Option<chrono::NaiveDate>,
    pub acceptance_date: Option<chrono::NaiveDate>,
    pub publish_date: Option<chrono::NaiveDate>,
    pub product_type_id: i32,
    pub s2_index: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, IntoParams, ToSchema)]
pub struct ProductFilterParams {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub taskorder_id: Option<i32>,
    pub item_id: Option<String>,
    pub site_id: Option<String>,
    pub product_type_id: Option<i32>,
    pub status: Option<String>,
    pub status_date_min: Option<NaiveDate>, // Filter for range queries
    pub status_date_max: Option<NaiveDate>,
    pub acceptance_date_min: Option<NaiveDate>,
    pub acceptance_date_max: Option<NaiveDate>,
    pub publish_date_min: Option<NaiveDate>,
    pub publish_date_max: Option<NaiveDate>,
    pub file_path: Option<String>,
    pub s2_index: Option<String>,
    pub classification: Option<String>,
}

impl ProductFilterParams {
    pub fn is_empty(&self) -> bool {
        self.taskorder_id.is_none()
            && self.item_id.is_none()
            && self.site_id.is_none()
            && self.product_type_id.is_none()
            && self.status.is_none()
            && self.status_date_min.is_none()
            && self.status_date_max.is_none()
            && self.acceptance_date_min.is_none()
            && self.acceptance_date_max.is_none()
            && self.publish_date_min.is_none()
            && self.publish_date_max.is_none()
            && self.file_path.is_none()
            && self.s2_index.is_none()
            && self.classification.is_none()
    }
}
#[derive(Serialize, Deserialize, Debug, IntoParams)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ProductType {
    pub id: i32,
    pub name: String,
    pub acronym: String,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct NewProductType {
    pub name: String,
    pub acronym: String,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct ProductIdResponse {
    pub id: i32,
}
