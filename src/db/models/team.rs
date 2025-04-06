use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Team {
    pub id: i32,
    pub name: String,
    pub created_at: Option<NaiveDateTime>,
}


#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NewTeam {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateTeam {
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TeamResponse {
    pub id: i32,
    pub name: String,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddUserToTeam {
    pub user_id: i32,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct TeamMember {
    pub user_id: i32,
    pub username: String,
    pub team_id: i32,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamProductTypeResponse {
    pub id: i32,
    pub name: String,
    pub acronym: String,
}

#[derive(Debug, Serialize, Deserialize,)]
pub struct TeamTaskOrderReponse {
    pub id: i32,
    pub name: String,
    pub producer: Option<String>,
}