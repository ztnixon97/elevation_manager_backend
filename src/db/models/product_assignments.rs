use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use sqlx::FromRow;


#[derive(Serialize, Deserialize, ToSchema, FromRow, Debug)]
pub struct ProductAssignment {
    pub id: i32,
    pub product_id: i32,
    pub user_id: i32,
    pub team_id: Option<i32>,
    pub assignment_type: String,
    pub status: String,
    pub assigned_by: Option<i32>,
    pub assigned_at: Option<NaiveDateTime>,
    pub due_date: Option<NaiveDateTime>,
    pub reason: Option<String>,
    pub completed_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct NewProductAssignment {
    pub product_id: i32,
    pub user_id: i32,
    pub team_id: Option<i32>,
    pub assignment_type: String,
    pub status: Option<String>, // default is "active"
    pub assigned_by: Option<i32>,
    pub due_date: Option<NaiveDateTime>,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateProductAssignment {
    pub status: Option<String>,
    pub due_date: Option<NaiveDateTime>,
    pub completed_at: Option<NaiveDateTime>,
    pub reason: Option<String>,
}