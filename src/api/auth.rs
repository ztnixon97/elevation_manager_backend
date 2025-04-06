use axum::{debug_handler, extract::{Path, State}, http::StatusCode, routing::post, Extension, Json, Router};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, Header, EncodingKey,};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use serde_json::json;
use utoipa::{ToSchema, path};
use crate::{config::Config, utils::api_response::ApiResponse};
use tracing::{warn, error, info};
/// Reperesnts a request to register a new user.
#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Desired username
    pub username: String,
    /// User Password
    pub password: String,
    /// Role assigned to the user
    pub role: String,
}

/// Represets a successful user registration response
#[derive(Serialize, ToSchema)]
pub struct RegisterResponse {
   pub  message: String,
}
/// JWT Claims used for authentication.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub  struct Claims {
    /// Subject - User ID as String
    pub sub: String,  // User ID as String
    /// The username of the authenticated user.
    pub username: String, // Username
    /// the role assigned to the user
    pub role: String,  // User Role
    /// Expriation timestamp (UNIX TIME)
    pub exp: usize,  // Expiration Time (UNIX TIME)
}

impl Claims {
    /// Converts `sub` (user ID) to `i32`, or returns a descriptive error.
    pub fn user_id(&self) -> Result<i32, ApiResponse<()>> {
        self.sub.parse::<i32>().map_err(|_| {
            ApiResponse::error(
                axum::http::StatusCode::BAD_REQUEST,
                "Invalid user ID format in token",
                None,
            )
        })
    }
}


/// Represetns a request to log in
#[derive(Serialize, Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// Username for authentication
    pub username: String,
    /// Password for authenticatin
    pub password: String,
}

/// Represents a successful loging response returing jwt token.
#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub role: String,
}

/// Handels user login
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `payload` - JSON request containing the username and password
///
/// # Returns
/// * `200 OK` - Returns a JWT token if authentication is successfull.
/// * `401 Unauthorized` - If credentails are incorrect.
/// * `500 internal Serever Error` - If a database or token generation error occurs.
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "Authentication",
    request_body(
        content = LoginRequest,
        description = "User login details",
    ),
    responses(
        (status = 200, description = "Successful login", body = LoginResponse),
        (status = 401, description = "Invalid username or password"),
        (status = 500, description = "Internal Server Error")
    )
)]
pub async fn login(
    State(pool): State<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let config = Config::get();

    let user = sqlx::query!(
        "SELECT id, username, password_hash, role, account_locked FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"success": false, "message": format!("Database error: {}", e)}).to_string(),
    ))?;

    if let Some(user) = user {
        // ✅ Deny login if the account is locked
        if user.account_locked {
            warn!("🔒 Login attempt for locked account: {}", payload.username);
            return Err((
                StatusCode::FORBIDDEN,
                json!({"success": false, "message": "Account is locked. Contact your administrator."}).to_string(),
            ));
        }

        match verify(&payload.password, &user.password_hash) {
            Ok(true) => {
                let claims = Claims {
                    sub: user.id.to_string(),
                    username: user.username.clone(),
                    role: user.role.clone(),
                    exp: chrono::Utc::now().timestamp() as usize + 36000, // 10 hour expiration
                };
                let role = user.role;
                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
                )
                .map_err(|e| (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"success": false, "message": format!("Token generation failed: {}", e)}).to_string(),
                ))?;

                info!("✅ Login successful for user: {}", payload.username);
                return Ok(Json(LoginResponse { token, role }));
            }
            Ok(false) => {
                warn!("❌ Invalid password attempt for user: {}", payload.username);
                return Err((
                    StatusCode::UNAUTHORIZED,
                    json!({"success": false, "message": "Invalid username or password."}).to_string(),
                ));
            }
            Err(e) => {
                error!("❌ Password verification error: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"success": false, "message": format!("Password verification error: {}", e)}).to_string(),
                ));
            }
        }
    }

    // ✅ If no user was found, return a proper 401 error
    warn!("❌ Login attempt for non-existent user: {}", payload.username);
    Err((
        StatusCode::UNAUTHORIZED,
        json!({"success": false, "message": "Invalid username or password."}).to_string(),
    ))
}



/// Handles user registration.
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `payload` - JSON request containing username, password, and role.
///
/// # Returns
/// * `201 Created` - If registration is successful.
/// * `409 Conflict` - If the username is already taken
/// * `500 Internal Server Error` - If a database error occurs.
#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    tag= "Authentication",
    responses(
        (status = 200, description = "Successful Register", body = RegisterResponse),
        (status = 409, description = "Username already taken"),
        (status = 500, description = "Internal Server Error")
    )
)]
pub async fn register(
    State(pool): State<PgPool>,  
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    let password_hash = hash(&payload.password, DEFAULT_COST)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"success": false, "message": format!("Password hashing failed: {}", e)}).to_string(),
        ))?;
    let role = "viewer";
    let result = sqlx::query!(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
        payload.username,
        password_hash,
        role
     )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok(Json(RegisterResponse { message: "User registered".into() })),
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                if db_err.code().map(|code| code == "23505").unwrap_or(false) {
                    return Err((
                        StatusCode::CONFLICT,
                        json!({"success": false, "message": "Username already taken"}).to_string(),
                    ));
                }
            }
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"success": false, "message": format!("Database error: {}", e)}).to_string(),
            ))
        }
    }
}

/// Represents a request to change a user's password.
#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest{
    pub old_password: String,
    pub new_password: String,
}

/// Handles a user password change request
///
/// Allows an **authenticated user** to change thier own password.
/// The user must provide their **current password** for verification.
/// 
/// # Arguments
/// * `pool` - Database connection pool
/// * `user_id` - The ID of the user changing thier password.
/// * `payload` = JSON request containing the  old and new passwords (ChangePasswordRequest)
///
/// # Returns
/// * `200 OK` - If the password was successfully updated.
/// * `401 Unauthorized` - If the old password is incorrect
/// * `404 Not Found` - If the user ID does not exist.
/// * `500 Internal Server Error` - If password hasing or database opeartions fail
#[utoipa::path(
    post,
    path = "/auth/change_password/{user_id}",
    tag= "Authentication",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Passowrd updated successfully"),
        (status = 401, description = "Old Password incorrect"),
        (status = 404, description = "User_id does not exist"),
        (status = 500, description = "Internal Server Error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn change_password(
    State(pool): State<PgPool>,
    Path(user_id): Path<i32>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database Query Failed",
            Some(json!( {"error": e.to_string() }))
    ))?;

    let user = match user {
        Some(user) => user,
        None => return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "User not found",
            None
        )),
    };

    let is_valid = verify(&payload.old_password, &user.password_hash).unwrap_or(false);
    if !is_valid {
        return Err(ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Incorrect old password",
            None,
        ));
    }

    let new_password_hash = hash(&payload.new_password, DEFAULT_COST).map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Password hashing failed",
            Some(json!({ "error": e.to_string() })),
        )
    })?;


    let result = sqlx::query!(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        new_password_hash,
        user_id
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok(ApiResponse::success(
            StatusCode::OK,
            "Password updated successfully",
            (),
        )),
        Err(e) => Err(ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed  to update password",
            Some(json!({ "db_error": e.to_string() }))
        )),
    }
}

/// Represnets a password reset request
#[derive(Deserialize, Debug, ToSchema)]
pub struct ResetPasswordRequest {
    /// ID of the user whos password is being resest
    pub user_id: i32,
    /// New password for the user
    pub new_password: String,
}

/// Handles admin-initiated password resets for users.
/// 
/// This allows **administrators** to reset a user's password **without needing the old password**.
/// Only users with the `admin` role can use this endpoint.
/// 
/// # Arguments
/// * `pool` - Database connection pool.
/// * `current_user` - The currently authenticated user (must be an admin).
/// * `payload` - JSON request containing the target user ID and the new password.
/// 
/// # Returns
/// * `200 OK` - If the password was successfully reset.
/// * `403 Forbidden` - If a non-admin user attempts to reset a password.
/// * `500 Internal Server Error` - If password hashing or database operations fail.
#[utoipa::path(
    post,
    path = "/auth/reset_password",
    tag = "Authentication",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Successfuly password reset"),
        (status = 403, description = "Non-admin user attempts to reset a password"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn reset_password(
    State(pool): State<PgPool>,
    Extension(current_user): Extension<Claims>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    // ensure that only admins can reset passwords
    if current_user.role != "admin" {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "Unauthorized: Only admins can reset passwords",
            None,
        ));
    }

    let new_password_hash = hash(&payload.new_password, DEFAULT_COST).map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Password Hashing Failed",
            Some(json!({ "error": e.to_string() })),
        )
    })?;

    let result = sqlx::query!(
        "UPDATE users SET password_hash = $1, updated_at = NOW() where id = $2",
        new_password_hash,
        payload.user_id
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok(ApiResponse::success(
            StatusCode::OK,
            "Password reset succesfully",
            (),
        )),
        Err(e) => Err(ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to reset password",
            Some(json!({ "db_error": e.to_string() }))
        )),
    }
}

/// Registers the public authentication routes for the API.
/// 
/// These routes **do not require authentication** and are publicly accessible.
/// They allow users to register and log in using **username/password authentication**.
/// 
/// # Routes
/// - `POST /auth/register` → Register a new user.
/// - `POST /auth/login` → Authenticate a user and return a JWT token.
///
/// # Example Usage
/// **Register a New User:**
/// ```sh
/// curl -X POST http://localhost:3000/auth/register -H "Content-Type: application/json" -d '{"username": "new_user", "password": "securepassword"}'
/// ```
/// 
/// **Log in and Get JWT Token:**
/// ```sh
/// curl -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d '{"username": "new_user", "password": "securepassword"}'
/// ```
///
/// # Returns
/// - `201 Created` → User successfully registered.
/// - `200 OK` → User authenticated, returns JWT token.
/// - `409 Conflict` → Username already exists.
/// - `401 Unauthorized` → Invalid login credentials.
/// - `500 Internal Server Error` → Unexpected server/database error.
pub fn auth_routes() -> Router<PgPool> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
}

/// Registers the **protected** authentication routes for the API.
/// 
/// These routes **require authentication** and are only accessible to users with a valid JWT token.
/// 
/// # Routes
/// - `POST /auth/change_password/{user_id}` → Allows a user to change their password (requires old password).
/// - `POST /auth/reset_password` → Allows an **admin** to reset another user's password.
/// 
/// # Authorization
/// - `change_password` → The user must provide their **current password** before setting a new one.
/// - `reset_password` → **Admins only** can reset any user's password.
/// 
/// # Example Usage
/// **Change Password:**
/// ```sh
/// curl -X POST http://localhost:3000/auth/change_password/1 -H "Authorization: Bearer <JWT_TOKEN>" -H "Content-Type: application/json" -d '{"old_password": "oldPass123", "new_password": "newPass456"}'
/// ```
/// 
/// **Admin Reset User Password:**
/// ```sh
/// curl -X POST http://localhost:3000/auth/reset_password -H "Authorization: Bearer <JWT_TOKEN>" -H "Content-Type: application/json" -d '{"user_id": 2, "new_password": "adminResetPass"}'
/// ```
///
/// # Returns
/// - `200 OK` → Password successfully changed or reset.
/// - `401 Unauthorized` → User not authenticated or wrong old password.
/// - `403 Forbidden` → Only admins can reset passwords.
/// - `500 Internal Server Error` → Password hashing or database failure.
pub fn secure_auth_routes() -> Router<PgPool> {
    Router::new()
        .route("/auth/change_password/{user_id}", post(change_password))
        .route("/auth/reset_password", post(reset_password))
}


use utoipa::OpenApi;
use utoipa::openapi::security::{SecurityScheme, HttpAuthScheme, Http};
use utoipa::Modify;
use utoipa::openapi::ComponentsBuilder;
use utoipa::openapi::Components;

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // ✅ Correctly clone existing components (if any)
        let mut components = openapi.components.clone().unwrap_or(Components::default());

        // ✅ Correctly use `add_security_scheme` instead of `security_scheme`
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );

        openapi.components = Some(components);
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(login, register, change_password, reset_password),
    components(
        schemas(
            LoginRequest, LoginResponse,
            RegisterRequest, RegisterResponse,
            ChangePasswordRequest, ResetPasswordRequest
        )
    ),
    tags(
        (name= "Authentication", description = "User Auth Endpoints")
    ),
    modifiers(&SecurityAddon)
)]
pub struct AuthDoc;
