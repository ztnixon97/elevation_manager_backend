use chrono::{NaiveDateTime};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, FromRow, ToSchema)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub org: Option<String>,
    pub email: Option<String>,
    pub role: String,
    pub last_login: Option<NaiveDateTime>,
    pub account_locked: bool,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub deleted_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub password: Option<String>, // Raw password, will be hashed
    pub org: Option<String>,
    pub email: Option<String>,
    pub role: Option<String>,
    pub account_locked: Option<bool>,
}

impl UpdateUser {
    pub fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.password.is_none()
            && self.org.is_none()
            && self.email.is_none()
            && self.role.is_none()
            && self.account_locked.is_none()
            
    }
}

#[derive(Serialize, Deserialize, Debug, FromRow, ToSchema)]
pub struct UserLogin {
    pub id: i32,
    pub user_id: i32,
    pub login_time: Option<NaiveDateTime>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}


#[derive(Deserialize, Serialize, ToSchema)]
pub struct UserInfo {
    pub id: i32,
    pub username: String,
    pub role: String,
}