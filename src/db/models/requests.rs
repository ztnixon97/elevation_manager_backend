// src/db/models/requests.rs
use serde::{Deserialize, Serialize};
use chrono::{NaiveDateTime};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, sqlx::Type, ToSchema )]
#[sqlx(type_name = "approval_request_type", rename_all = "snake_case")]
pub enum ApprovalRequestType {
    TeamJoin,
    ProductAccess,
    ProductReviewApproval,
    ProductCheckout,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, sqlx::Type, ToSchema)]
#[sqlx(type_name = "approval_status", rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct ApprovalRequest {
    pub id: i32,
    pub request_type: ApprovalRequestType,
    pub requested_by: i32,
    pub target_id: Option<i32>,
    pub details: serde_json::Value,
    pub status: ApprovalStatus,
    pub reviewed_by: Option<i32>,
    pub requested_at: Option<NaiveDateTime>,
    pub reviewed_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NewApprovalRequest {
    pub request_type: ApprovalRequestType,
    pub target_id: Option<i32>,
    pub details: serde_json::Value,
}
