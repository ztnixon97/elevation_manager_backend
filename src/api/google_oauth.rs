use axum::{
    extract::{State, Query},
    routing::get,
    Router,
    http::StatusCode,
    response::Redirect,
    Json,
};
use serde_json::json;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use sqlx::PgPool;
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;
use std::env;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use utoipa::{path, IntoParams, ToSchema};
use crate::{api::auth::Claims, utils::api_response::ApiResponse};

#[derive(Deserialize, ToSchema, IntoParams)]
pub struct GoogleAuthCallback {
   pub  code: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GoogleTokenResponse {
    pub access_token: String,
    pub id_token: String,
}

#[derive(Deserialize, Serialize)]
pub struct GoogleUserInfo {
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AuthToken {
    pub token: String,
}

/// ✅ **Redirect User to Google OAuth**
#[utoipa::path(
    get,
    path = "/auth/google",
    tag="Google OAuth",
    responses(
        (status = 302, description = "redicrect to Google Oauth")
    )
)]
pub async fn google_auth_redirect() -> Redirect {
    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("Missing GOOGLE_REDIRECT_URI");

    let google_auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile&access_type=offline",
        client_id, redirect_uri
    );

    Redirect::to(&google_auth_url)
}

/// ✅ **Handle Google OAuth Callback**
#[utoipa::path(
    get,
    path = "/auth/google/callback",
    tag="Google OAuth",
    params(GoogleAuthCallback),
    responses(
        (status = 200, description = "Successfullly authenticated user via Google", body = AuthToken),
        (status = 500, description = "Internal Service Error")
    )
)]
pub async fn google_auth_callback(
    Query(params): Query<GoogleAuthCallback>,
    State(pool): State<PgPool>,
) -> Result<Json<AuthToken>, ApiResponse<()>> {
    let client = Client::new();

    let client_id = env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID");
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET");
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("Missing GOOGLE_REDIRECT_URI");

    let token_response: GoogleTokenResponse = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", &params.code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to exchange auth code",
            Some(json!({ "error": e.to_string() }))
        ))?
        .json()
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to parse token response",
            Some(json!({ "error": e.to_string() }))
        ))?;

    let id_token_parts: Vec<&str> = token_response.id_token.split('.').collect();
    if id_token_parts.len() != 3 {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "Invalid ID Token format",
            None
        ));
    }

    let decoded_json = URL_SAFE_NO_PAD.decode(id_token_parts[1])
        .map_err(|_| ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "Failed to decode ID Token",
            None
        ))?;

    let user_info: GoogleUserInfo = serde_json::from_slice(&decoded_json)
        .map_err(|_| ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "Failed to parse user info",
            None
        ))?;

    let (user_id, role) = find_or_create_user(&pool, &user_info)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error",
            Some(json!({ "error": e.to_string() }))
        ))?;

    let token = issue_jwt(user_id, user_info.email, role);

    Ok(Json(AuthToken { token }))
}

/// ✅ **Find or Create User in Database**
async fn find_or_create_user(
    pool: &PgPool,
    google_user: &GoogleUserInfo,
) -> Result<(i32, String), sqlx::Error> {
    let existing_user = sqlx::query!(
        "SELECT id, role FROM users WHERE email = $1",
        google_user.email
    )
    .fetch_optional(pool)
    .await?;

    if let Some(user) = existing_user {
        return Ok((user.id, user.role));
    }


    let new_user = sqlx::query!(
        "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, role",
        google_user.name,
        google_user.email,
        "", // Empty string as placeholder for password_hash
        "viewer"
    )
    .fetch_one(pool)
    .await?;
    Ok((new_user.id, new_user.role))
}

/// ✅ **Generate JWT Token**
fn issue_jwt(user_id: i32, email: String, role: String) -> String {
    let jwt_secret = env::var("JWT_SECRET").expect("Missing JWT_SECRET");
    let exp_duration = env::var("JWT_EXPIRATION")
        .unwrap_or_else(|_| "36000".to_string()) // 10 hours default
        .parse::<usize>()
        .unwrap_or(36000);

    let claims = Claims {
        sub: user_id.to_string(),
        username: email,
        role,
        exp: chrono::Utc::now().timestamp() as usize + exp_duration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .unwrap()
}

/// ✅ **Register Routes (Matches `auth_routes`)**
pub fn g_auth_routes() -> Router<PgPool> {
    Router::new()
        .route("/auth/google", get(google_auth_redirect))
        .route("/auth/google/callback", get(google_auth_callback))
}

/// ✅ **Secure Routes (If Needed)**
pub fn g_secure_auth_routes() -> Router<PgPool> {
    Router::new()
}

use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(
        google_auth_redirect,
        google_auth_callback
    ),
    components(schemas(
        GoogleAuthCallback, AuthToken
        // plus anything else you need
    )),
    tags(
        (name = "Google OAuth", description = "Google-based OAuth endpoints")
    )
)]
pub struct GoogleOAuthDoc;
