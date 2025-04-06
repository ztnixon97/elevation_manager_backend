use axum::{
    extract::{Path, State}, http::StatusCode, Extension, Json
};

use bcrypt::{hash, DEFAULT_COST};
use sqlx::{PgPool, QueryBuilder};
use serde_json::json;

use crate::{api::auth::Claims, db::models::user::{
    UpdateUser, User, UserInfo
}, utils::api_response::ApiResponse};

use crate::db::models::team::Team;
// create user handeled by auth/registration


#[utoipa::path(
    get,
    path = "/users",
    responses(
        (status = 200, description = "List all users", body = [User]),
        (status = 500, description = "Failed to retrieve users")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_all_users(
    State(pool): State<PgPool>,
) -> Result<ApiResponse<Vec<User>>, ApiResponse<()>> {
    let users = sqlx::query_as!(
        User,
        r#"SELECT * FROM users ORDER BY id"#
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve Users",
            Some(json!({ "db_error" : e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Users retrieved successfully",
        users
    ))
}

#[utoipa::path(
    get,
    path = "/users/{id}",
    params(
        ("id" = i32, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Retrieve a single user", body = User),
        (status = 404, description = "User not found")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_user(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
) -> Result<ApiResponse<User>, ApiResponse<()>> {
    let user = sqlx::query_as!(
        User,
        r#"SELECT * FROM users WHERE id = $1"#,
        id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "User not found",
            None
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "User retrieved successfully",
        user,
    ))
}

#[utoipa::path(
    get,
    path = "/users/{username}/role",
    params(
        ("username" = String, Path, description = "Username")
    ),
    responses(
        (status = 200, description = "User role retrieved successfully"),
        (status = 404, description = "User not found")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn check_user_role(
    State(pool): State<PgPool>,
    Path(username): Path<String>,
) -> Result<ApiResponse<String>, ApiResponse<()>> {
    let user_role = sqlx::query_scalar!(
        r#"SELECT role FROM users WHERE username = $1"#,
        username
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "User not found",
            None
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "User role retrieved successfully",
        user_role,
    ))
}

#[utoipa::path(
    delete,
    path = "/users/{id}",
    params(
        ("id" = i32, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User deleted successfully"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Failed to delete user")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_user(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let result = sqlx::query!(
        r#"DELETE FROM users WHERE id = $1"#,
        id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to delete User",
            Some(json!({ "db_error" : e.to_string() }))
    ))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "User not found",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "User deleted successfully",
        ()
    ))
}
#[utoipa::path(
    put,
    path = "/users/{id}",
    request_body = UpdateUser,
    params(
        ("id" = i32, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User updated successfully"),
        (status = 400, description = "No fields provided for update"),
        (status = 500, description = "Failed to update user")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_user(
    State(pool): State<PgPool>,
    Extension(current_user): Extension<Claims>,
    Path(id): Path<i32>,
    Json(update): Json<UpdateUser>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if update.is_empty() {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No fields provided for update",
            None,
        ));
    }

    println!("Incoming UpdateUser: {:?}", update);

    let mut query_builder = QueryBuilder::new("UPDATE users SET ");
    let mut first = true; // Controls comma placement

    if let Some(username) = &update.username {
        if !first { query_builder.push(", "); }
        query_builder.push("username = ").push_bind(username);
        first = false;
    }
    if let Some(org) = &update.org {
        if !first { query_builder.push(", "); }
        query_builder.push("org = ").push_bind(org);
        first = false;
    }
    if let Some(email) = &update.email {
        if !first { query_builder.push(", "); }
        query_builder.push("email = ").push_bind(email);
        first = false;
    }
    if let Some(account_locked) = update.account_locked {
        if !first { query_builder.push(", "); }
        query_builder.push("account_locked = ").push_bind(account_locked); // ✅ No conversion needed
        first = false;
    }
    if let Some(role) = &update.role {
        if current_user.role == "admin" {
            if !first { query_builder.push(", "); }
            query_builder.push("role = ").push_bind(role);
            first = false;
        }
    }

    // Always update timestamp
    if !first { query_builder.push(", "); }
    query_builder.push("updated_at = NOW()");
    
    // WHERE clause
    query_builder.push(" WHERE id = ").push_bind(id);


    // Execute query
    let query = query_builder.build();
    let result = query.execute(&pool).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update User",
            Some(json!({ "db_error": e.to_string() }))
        )
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "User not found",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "User updated successfully",
        ()
    ))
}

#[utoipa::path(
    get,
    path = "/users/me/teams",
    responses(
        (status = 200, description = "User teams retrieved successfully", body = [Team]),
        (status = 500, description = "Failed to retrieve teams")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_user_teams(
    State(pool): State<PgPool>,
    Extension(current_user): Extension<Claims>,
) -> Result<ApiResponse<Vec<Team>>, ApiResponse<()>> {
    let user_id = current_user.user_id()?;
    let teams = sqlx::query_as!(
        Team,
        r#"
        SELECT t.id, t.name, t.created_at
        FROM team_members tm
        JOIN teams t ON t.id = tm.team_id
        WHERE tm.user_id = $1
        ORDER BY t.name
        "#,
        user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve teams",
            Some(json!({ "db_error" : e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Teams retrieved successfully",
        teams
    ))
}

#[utoipa::path(
    get,
    path = "/users/me",
    responses(
        (status = 200, description = "Current authenticated user info", body = UserInfo),
        (status = 401, description = "Unauthorized")
    ),
    tag = "Users",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_me(
    Extension(current_user): Extension<Claims>,
) -> Result<ApiResponse<UserInfo>, ApiResponse<()>> {
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Authenticated user info",
        UserInfo {
            id: current_user.user_id()?,
            username: current_user.username.clone(),
            role: current_user.role.clone(),
        },
    ))
}


use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_all_users,
        get_user,
        update_user,
        check_user_role,
        delete_user,
        get_user_teams,
        get_me,
    ),
    components(
        schemas(User, UpdateUser)
    ),
    tags(
        (name = "Users", description = "User Management API")
    )
)]
pub struct UserDoc;
