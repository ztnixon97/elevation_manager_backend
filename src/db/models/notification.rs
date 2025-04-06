// src/db/models/notification.rs
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, Clone, Debug, FromRow, ToSchema)]
pub struct Notification {
    pub id: i32,
    pub title: String,
    pub body: Option<String>,
    #[serde(rename = "type")]
    pub type_field: String, // Use type_field instead of r#type
    pub action_type: Option<String>,
    pub action_data: Option<Value>,
    pub global: bool,
    pub dismissible: bool,
    pub created_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub enum NotificationScope {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "team")]
    Team,
    #[serde(rename = "team_leads")]
    TeamLeads,
}

#[derive(Debug, Serialize, Deserialize, Clone, FromRow, ToSchema)]
pub struct NotificationTarget {
    pub id: i32,
    pub notification_id: i32,
    pub scope: String, // NotificationScope stored as string in DB
    pub target_id: i32,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct NotificationDismissal {
    pub id: i32,
    pub notification_id: i32,
    pub user_id: i32,
    pub dismissed_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NewNotification {
    pub title: String,
    pub body: Option<String>,
    #[serde(rename = "type")]
    pub type_field: Option<String>, // Use type_field instead of r#type
    pub action_type: Option<String>,
    pub action_data: Option<Value>,
    pub global: Option<bool>,
    pub dismissible: Option<bool>,
    pub expires_at: Option<NaiveDateTime>,
    pub targets: Vec<NotificationTargetInput>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NotificationTargetInput {
    pub scope: NotificationScope,
    pub target_id: i32,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateNotification {
    pub title: Option<String>,
    pub body: Option<String>,
    #[serde(rename = "type")]
    pub type_field: Option<String>, // Use type_field instead of r#type
    pub action_type: Option<String>,
    pub action_data: Option<Value>,
    pub global: Option<bool>,
    pub dismissible: Option<bool>,
    pub expires_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Deserialize, Default, IntoParams, ToSchema)]
pub struct NotificationFilter {
    pub include_dismissed: Option<bool>,
    pub include_expired: Option<bool>,
    #[serde(rename = "type")]
    pub type_field: Option<String>, // Use type_field instead of r#type
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct NotificationWithTargets {
    pub notification: Notification,
    pub targets: Vec<NotificationTarget>,
    pub dismissed: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NotificationCountResponse {
    pub total: i64,
    pub unread: i64,
}
