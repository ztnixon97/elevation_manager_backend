use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub status_code: u16,
    pub message: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<serde_json::Value>,
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        let status =
            StatusCode::from_u16(self.status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a success response
    pub fn success(status: StatusCode, message: impl Into<String>, data: T) -> Self {
        ApiResponse {
            success: true,
            status_code: status.as_u16(),
            message: message.into(),
            timestamp: Utc::now().to_rfc3339(),
            data: Some(data),
            errors: None,
        }
    }

    /// Create an error response
    pub fn error(
        status: StatusCode,
        message: impl Into<String>,
        errors: Option<serde_json::Value>,
    ) -> Self {
        ApiResponse {
            success: false,
            status_code: status.as_u16(),
            message: message.into(),
            timestamp: Utc::now().to_rfc3339(),
            data: None,
            errors,
        }
    }
}
