use axum::{extract::{Path, Query, State}, http::StatusCode, Extension, Json};
use sqlx::PgPool;
use serde_json::{json, Value};
use crate::{db::models::product::{PaginationParams, ProductResponse, TeamProductResponse}, middleware::auth::UserPermissions, utils::api_response::ApiResponse};
use crate::db::models::team::*;
use serde::Deserialize;

use utoipa::ToSchema;
/// Create a new team
#[utoipa::path(
    post,
    path = "/teams",
    request_body = NewTeam,
    responses(
        (status = 201, description = "Team created successfully", body = i32),
        (status = 403, description = "User lacks permission to create a team"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Json(payload): Json<NewTeam>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    if !user_permissions.is_admin() && !user_permissions.is_manager() {
        return Err(ApiResponse::error(StatusCode::FORBIDDEN, "You don't have sufficent permission to create a team", None));
    }
    let result = sqlx::query!(
        "INSERT INTO teams (name) VALUES ($1) RETURNING id",
        payload.name
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(record) => Ok(ApiResponse::success(
            StatusCode::CREATED,
            "Team created successfully",
            record.id,
        )),
        Err(e) => Err(ApiResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create team",
            Some(json!({ "error": e.to_string() })),
        )),
    }
}

/// Get a single team by ID
#[utoipa::path(
    get,
    path = "/teams/{team_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID to retrieve")
    ),
    responses(
        (status = 200, description = "Team found", body = TeamResponse),
        (status = 404, description = "Team not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
) -> Result<ApiResponse<TeamResponse>, ApiResponse<()>> {
    if !user_permissions.is_admin() && !user_permissions.is_manager() && !user_permissions.is_on_team(team_id) {
        return Err(ApiResponse::error(StatusCode::FORBIDDEN, "You don't have sufficent permission to access the team", None));
    }
    let result = sqlx::query_as!(
        TeamResponse,
        "SELECT id, name, created_at FROM teams WHERE id = $1",
        team_id
    )
    .fetch_one(&db_pool)
    .await;

    match result {
        Ok(team) => Ok(ApiResponse::success(StatusCode::OK, "Team found", team)),
        Err(_) => Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None)),
    }
}

/// Get all teams with pagination
#[utoipa::path(
    get,
    path = "/teams",
    params(
        PaginationParams
    ),
    responses(
        (status = 200, description = "List of teams retrieved successfully"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_all_teams(
    State(db_pool): State<PgPool>,
    Query(params): Query<PaginationParams>,
) -> Result<ApiResponse<Value>, ApiResponse<()>> {
    let page = params.page.unwrap_or(1).max(1); // Ensure page >= 1
    let limit = params.limit.unwrap_or(1000).max(1); // Ensure limit >= 1
    let offset = (page - 1) * limit;


    let total_count: i64 = sqlx::query_scalar!(
            "SELECT count(id) FROM teams"
        )
        .fetch_one(&db_pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve team count",
                Some(json!({ "message": e.to_string() }))
         ))?
         .ok_or_else(|| ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unexpected null result for team count",
                None
        ))?;
    let total_pages = (total_count as f64 / limit as f64).ceil() as i64;

    let teams: Vec<Team> = sqlx::query_as!(
        Team,
        "SELECT id, name, created_at FROM teams ORDER BY name LIMIT $1 OFFSET $2",
        limit as i64,
        offset as i64
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve teams",
        Some(json!({ "error": e.to_string() })),
    ))?;

    Ok(ApiResponse::success(StatusCode::OK, "Teams retrieved successfully", json!({
        "page": page,
        "limit": limit,
        "total_teams": total_count,
        "total_pages": total_pages,
        "teams": teams
    })))
}

/// Update a team
#[utoipa::path(
    put,
    path = "/teams/{team_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID to update")
    ),
    request_body = UpdateTeam,
    responses(
        (status = 200, description = "Team updated successfully"),
        (status = 403, description = "User lacks permission to update team"),
        (status = 404, description = "Team not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
    Json(payload): Json<UpdateTeam>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.is_manager() && !user_permissions.is_team_lead(team_id) && !user_permissions.is_admin() {
        return Err(ApiResponse::error(StatusCode::FORBIDDEN, "You do not have permission to udpate this team", None));
    }
    let result = sqlx::query!(
        "UPDATE teams SET name = COALESCE($1, name) WHERE id = $2",
        payload.name,
        team_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(query_result) => {
            if query_result.rows_affected() == 0 {
                return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
            }
            Ok(ApiResponse::success(StatusCode::OK, "Team updated successfully", ()))
        }
        Err(e) => Err(ApiResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update team",
            Some(json!({ "error": e.to_string() })),
        )),
    }
}

/// Delete a team
#[utoipa::path(
    delete,
    path = "/teams/{team_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID to delete")
    ),
    responses(
        (status = 204, description = "Team deleted successfully"),
        (status = 403, description = "User lacks permission to delete team"),
        (status = 404, description = "Team not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    
    if !user_permissions.is_manager() &&  !user_permissions.is_admin() {
        return Err(ApiResponse::error(StatusCode::FORBIDDEN, "You do not have permission to udpate this team", None));
    }
    let result = sqlx::query!("DELETE FROM teams WHERE id = $1", team_id)
        .execute(&db_pool)
        .await;

    match result {
        Ok(query_result) => {
            if query_result.rows_affected() == 0 {
                return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
            }
            Ok(ApiResponse::success(StatusCode::NO_CONTENT, "Team deleted successfully", ()))
        }
        Err(e) => Err(ApiResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to delete team",
            Some(json!({ "error": e.to_string() })),
        )),
    }
}

#[utoipa::path(
    post,
    path = "/teams/{team_id}/users",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    request_body = AddUserToTeam,
    responses(
        (status = 200, description = "User added to team"),
        (status = 403, description = "User lacks permission to add users"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn add_user_to_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
    Json(payload): Json<AddUserToTeam>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.can_add_user_to_team(team_id, &payload.role) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to add user to the team",
            None,
        ));
    }

    let result = sqlx::query!(
        "INSERT INTO team_members (user_id, team_id, role) VALUES ($1, $2, $3)
        ON CONFLICT (user_id, team_id) DO UPDATE SET role = EXCLUDED.role",
        payload.user_id,
        team_id,
        payload.role
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(_) => Ok(ApiResponse::success(StatusCode::OK, "User added to team", ())),
        Err(_) => Err(ApiResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to add user to team",
            None,
        )),
    }
}

#[utoipa::path(
    get,
    path = "/teams/{team_id}/users",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    responses(
        (status = 200, description = "List of team members retrieved successfully"),
        (status = 403, description = "User lacks permission to view team members"),
        (status = 404, description = "Team not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_team_members(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
) -> Result<ApiResponse<Value>, ApiResponse<()>> {

    // ✅ Ensure the team exists before fetching members
    let team_exists = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)",
        team_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Database error", None))?;

    if !team_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
    }

    // ✅ Ensure user has permission
    if !user_permissions.is_admin() && !user_permissions.is_manager() && !user_permissions.is_team_lead(team_id) {
        return Err(ApiResponse::error(StatusCode::FORBIDDEN, "You do not have permission to view team members", None));
    }

    // ✅ Fetch all team members
    let members = sqlx::query_as!(
        TeamMember,
        "SELECT tm.user_id as user_id, tm.team_id as team_id, tm.role as role, 
                u.username as username 
         FROM team_members tm 
         JOIN users u ON tm.user_id = u.id 
         WHERE tm.team_id = $1",
        team_id
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve team members", None))?;

    // ✅ Always return an array (even if empty)
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Team members retrieved successfully",
        json!({ "members": members }),
    ))
}

/// Remove a user from a team (Admins, Managers, and Team Leads)
#[utoipa::path(
    delete,
    path = "/teams/{team_id}/users/{user_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID"),
        ("user_id" = i32, Path, description = "User ID to remove")
    ),
    responses(
        (status = 204, description = "User removed from team successfully"),
        (status = 403, description = "User lacks permission to remove users"),
        (status = 404, description = "User not found in team"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn remove_user_from_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path((team_id, user_id)): Path<(i32, i32)>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.is_admin() && !user_permissions.is_manager() && !user_permissions.is_team_lead(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to remove users from this team",
            None,
        ));
    }

    let result = sqlx::query!(
        "DELETE FROM team_members WHERE user_id = $1 AND team_id = $2",
        user_id,
        team_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(query_result) => {
            if query_result.rows_affected() == 0 {
                return Err(ApiResponse::error(StatusCode::NOT_FOUND, "User not found in team", None));
            }
            Ok(ApiResponse::success(StatusCode::NO_CONTENT, "User removed from team successfully", ()))
        }
        Err(_) => Err(ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to remove user from team", None)),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateUserRole {
    pub role: String, // e.g., "team_lead", "editor", "viewer"
}

#[utoipa::path(
    put,
    path = "/teams/{team_id}/users/{user_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID"),
        ("user_id" = i32, Path, description = "User ID to update role for")
    ),
    request_body = UpdateUserRole,
    responses(
        (status = 200, description = "User role updated successfully"),
        (status = 403, description = "User lacks permission to update role"),
        (status = 404, description = "User not found in team"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_user_role(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path((team_id, user_id)): Path<(i32, i32)>,
    Json(payload): Json<UpdateUserRole>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.is_admin() && !user_permissions.is_manager() && !user_permissions.is_team_lead(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to modify user roles in this team",
            None,
        ));
    }

    let result = sqlx::query!(
        "UPDATE team_members SET role = $1 WHERE user_id = $2 AND team_id = $3",
        payload.role,
        user_id,
        team_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(query_result) => {
            if query_result.rows_affected() == 0 {
                return Err(ApiResponse::error(StatusCode::NOT_FOUND, "User not found in team", None));
            }
            Ok(ApiResponse::success(StatusCode::OK, "User role updated successfully", ()))
        }
        Err(_) => Err(ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update user role", None)),
    }
}

/// **Get all products assigned to a specific team**
#[utoipa::path(
    get,
    path = "/teams/{team_id}/products",
    params(
        ("team_id" = i32, Path, description = "Team ID to retrieve products for")
    ),
    responses(
        (status = 200, description = "Products retrieved successfully", body = Vec<ProductResponse>),
        (status = 403, description = "User lacks permission to view products"),
        (status = 404, description = "No products found for this team"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_team_products(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
) -> Result<ApiResponse<Value>, ApiResponse<()>> {
    
    // Ensure the user has permission to view products for this team
    if !user_permissions.is_admin() && !user_permissions.is_manager() && !user_permissions.is_on_team(team_id) {
        return Err(ApiResponse::error(StatusCode::FORBIDDEN, "You do not have permission to view products for this team", None));
    }

    // ✅ First, check if the team exists
    let team_exists = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)",
        team_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        ApiResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error checking team existence",
            Some(json!({ "error": e.to_string() })),
        )
    })?;

    if !team_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
    }

    // ✅ Fetch assigned products
    let result = sqlx::query_as!(
        TeamProductResponse,
        r#"
        SELECT p.id, p.item_id, p.site_id, p.status, p.status_date, 
               p.acceptance_date, p.publish_date, p.product_type_id, p.s2_index
        FROM products p
        JOIN product_teams pt ON p.id = pt.product_id
        WHERE pt.team_id = $1
        ORDER BY p.status_date DESC
        "#,
        team_id
    )
    .fetch_all(&db_pool)
    .await;

    match result {
        Ok(products) => Ok(ApiResponse::success(
            StatusCode::OK,
            "Products retrieved successfully",
            json!({ "products": products }), // ✅ Always return an array (even if empty)
        )),
        Err(e) => Err(ApiResponse::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve team products",
            Some(json!({ "error": e.to_string() })),
        )),
    }
}


#[derive(Deserialize, ToSchema)]
pub struct AssignProduct {
    pub product_id: i32,
}

#[utoipa::path(
    post,
    path = "/teams/{team_id}/products",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    request_body = AssignProduct,
    responses(
        (status = 200, description = "Product assigned to team"),
        (status = 403, description = "User lacks permission"),
        (status = 409, description = "Product already assigned to team"),
        (status = 404, description = "Team or Product not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn assign_product_to_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>, // ✅ Now only extracting
    Path(team_id): Path<i32>,
    Json(payload): Json<AssignProduct>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    
    // ✅ **Use permissions from RBAC middleware**
    if !user_permissions.is_admin() 
        && !user_permissions.is_manager() 
        && !user_permissions.is_team_lead(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to assign products to this team",
            None,
        ));
    }

    // 🔍 Validate Team and Product Existence
    let exists = sqlx::query!(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1) AS team_exists, 
                EXISTS (SELECT 1 FROM products WHERE id = $2) AS product_exists",
        team_id,
        payload.product_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Database error", None
    ))?;

    if !exists.team_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
    }
    if !exists.product_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Product not found", None));
    }

    // Check if Product is Already Assigned
    let assigned = sqlx::query!(
        "SELECT 1 AS exists_flag FROM product_teams WHERE team_id = $1 AND product_id = $2",
        team_id,
        payload.product_id
    )
    .fetch_optional(&db_pool)
    .await    
    .map_err(|_| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Database error", None
    ))?;

    if assigned.is_some() {
        return Err(ApiResponse::error(
            StatusCode::CONFLICT,
            "Product is already assigned to this team",
            None,
        ));
    }

    // Assign Product to Team
    let result = sqlx::query!(
        "INSERT INTO product_teams (team_id, product_id) VALUES ($1, $2)",
        team_id,
        payload.product_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(_) => Ok(ApiResponse::success(StatusCode::OK, "Product assigned to team", ())),

        Err(_) => Err(ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to assign product", None)),
    }
}



#[utoipa::path(
    delete,
    path = "/teams/{team_id}/products/{product_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID"),
        ("product_id" = i32, Path, description = "Product ID")
    ),
    responses(
        (status = 204, description = "Product removed from team successfully"),
        (status = 403, description = "User lacks permission"),
        (status = 404, description = "Product not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]

pub async fn remove_product_from_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path((team_id, product_id)): Path<(i32, i32)>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    // ✅ Check if user has the required permissions
    if !user_permissions.is_admin() 
        && !user_permissions.is_manager() 
        && !user_permissions.is_team_lead(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to remove products assigned to this team",
            None,
        ));
    }

    // ✅ First check if the product is assigned before deleting
    let assigned = sqlx::query!(
        "SELECT 1 AS exists_flag FROM product_teams WHERE team_id = $1 AND product_id = $2",
        team_id,
        product_id
    )
    .fetch_optional(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Database error", None
    ))?;

    if assigned.is_none() {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Product not assigned to team", None));
    }

    // ✅ Perform deletion
    let result = sqlx::query!(
        "DELETE FROM product_teams WHERE team_id = $1 AND product_id = $2",
        team_id,
        product_id
    )
    .execute(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Failed to remove product", None
    ))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Product not found in team", None));
    }

    Ok(ApiResponse::success(StatusCode::OK, "Product removed from team", ()))
}


#[derive(Deserialize, ToSchema)]
pub struct AssignProductType {
    pub product_type_id: i32,
}

#[utoipa::path(
    post,
    path = "/teams/{team_id}/product_types",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    request_body = AssignProductType,
    responses(
        (status = 200, description = "Product type assigned to team"),
        (status = 403, description = "User lacks permission"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn assign_product_type_to_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
    Json(payload): Json<AssignProductType>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.can_assign_product_to_team(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to assign product types to this team",
            None,
        ));
    }

    let result = sqlx::query!(
        "INSERT INTO product_type_teams (team_id, product_type_id) VALUES ($1, $2)
        ON CONFLICT DO NOTHING",
        team_id,
        payload.product_type_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(_) => Ok(ApiResponse::success(StatusCode::OK, "Product type assigned to team", ())),
        Err(_) => Err(ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to assign product type", None)),
    }
}

#[utoipa::path(
    delete,
    path = "/teams/{team_id}/product_types/{product_type_id}",
    params(
        ("team_id" = i32, Path, description = "Team ID"),
        ("product_type_id" = i32, Path, description = "Product Type ID")
    ),
    responses(
        (status = 204, description = "Product type removed from team successfully"),
        (status = 403, description = "User lacks permission"),
        (status = 404, description = "Product type not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn remove_product_type_from_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path((team_id, product_type_id)): Path<(i32, i32)>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.can_assign_product_to_team(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to remove product types from this team",
            None,
        ));
    }

    let result = sqlx::query!(
        "DELETE FROM product_type_teams WHERE team_id = $1 AND product_type_id = $2",
        team_id,
        product_type_id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(query_result) => {
            if query_result.rows_affected() == 0 {
                return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Product type not found in team", None));
            }
            Ok(ApiResponse::success(StatusCode::OK, "Product type removed from team", ()))
        }
        Err(_) => Err(ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to remove product type", None)),
    }
}

#[utoipa::path(
    get,
    path = "/teams/{team_id}/product_types",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    responses(
        (status = 200, description = "List of team product types retrieved successfully"),
        (status = 404, description = "Team not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_team_product_types(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
) -> Result<ApiResponse<Vec<TeamProductTypeResponse>>, ApiResponse<()>> {
    // ✅ Ensure the team exists
    let team_exists = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)",
        team_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Database error", None))?;

    if !team_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
    }

    // ✅ Retrieve product types
    let product_types = sqlx::query_as!(
        TeamProductTypeResponse,
        "SELECT pt.id, pt.name, pt.acronym
         FROM product_types pt
         JOIN product_type_teams ptt ON pt.id = ptt.product_type_id
         WHERE ptt.team_id = $1",
        team_id
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|e| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve team product types",
        Some(json!({ "error": e.to_string() })),
    ))?;

    // ✅ Always return an array (even if empty), no 404 for missing data
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Team product types retrieved successfully",
        product_types,
    ))
}


#[utoipa::path(
    get,
    path = "/teams/{team_id}/taskorders",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    responses(
        (status = 200, description = "Successfully retrieved Task Orders for the team"),
        (status = 404, description = "Team not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_team_task_orders(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>
) -> Result<ApiResponse<Value>, ApiResponse<()>> {
    
    // ✅ Ensure the team exists
    let team_exists = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)",
        team_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Database error", None))?;

    if !team_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
    }

    // ✅ Fetch task orders assigned to the team
    let task_orders = sqlx::query_as!(
        TeamTaskOrderReponse,
        "SELECT t.id, t.name, t.producer
         FROM task_order_teams tot 
         JOIN taskorders t ON tot.task_order_id = t.id
         WHERE tot.team_id = $1",
        team_id
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve task orders", None))?;

    // ✅ Always return an array (even if empty) instead of `404`
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Successfully retrieved Task Orders",
        json!({ "task_orders": task_orders }),
    ))
}


#[utoipa::path(
    post,
    path = "/teams/{team_id}/taskorders",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    request_body = AssignTaskOrder,
    responses(
        (status = 200, description = "Task Order assigned to team"),
        (status = 403, description = "User lacks permission"),
        (status = 409, description = "Task Order already assigned to team"),
        (status = 404, description = "Team or Task Order not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Teams",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn assign_task_order_to_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
    Json(payload): Json<AssignTaskOrder>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    
    if !user_permissions.can_assign_product_to_team(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to assign task orders to this team",
            None,
        ));
    }

    // Check if team exists
    let team_exists = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE id = $1)",
        team_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking team existence: {:?}", e);
        ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Database error", None)
    })?;

    if !team_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Team not found", None));
    }

    // Check if task order exists
    let task_exists = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM taskorders WHERE id = $1)",
        payload.id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking task order existence: {:?}", e);
        ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Database error", None)
    })?;

    if !task_exists.unwrap_or(false) {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Task Order not found", None));
    }

    // Check if task order is already assigned to team
    let already_assigned = sqlx::query_scalar!(
        "SELECT 1 FROM task_order_teams WHERE team_id = $1 AND task_order_id = $2",
        team_id,
        payload.id
    )
    .fetch_optional(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking task order assignment: {:?}", e);
        ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Database error", None)
    })?;

    if already_assigned.is_some() {
        return Err(ApiResponse::error(
            StatusCode::CONFLICT,
            "Task Order is already assigned to this team",
            None,
        ));
    }

    // Assign task order to team
    let result = sqlx::query!(
        "INSERT INTO task_order_teams (team_id, task_order_id) VALUES ($1, $2)",
        team_id,
        payload.id
    )
    .execute(&db_pool)
    .await;

    match result {
        Ok(_) => Ok(ApiResponse::success(StatusCode::OK, "Task Order assigned to team", ())),
        Err(e) => {
            tracing::error!("Database error inserting task order assignment: {:?}", e);
            Err(ApiResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to assign Task Order", None))
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct AssignTaskOrder {
    pub id: i32
}


pub async fn remove_task_order_from_team(
    State(db_pool): State<PgPool>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path((team_id, task_id)) : Path<(i32, i32)>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if !user_permissions.can_assign_product_to_team(team_id) {
        return Err(ApiResponse::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to remove task orders assigned to this team",
            None,
        ));
    }

    let assigned = sqlx::query!(
        "SELECT 1 as existing_flag from task_order_teams WHERE team_id = $1 and task_order_id = $2",
        team_id,
        task_id
    )
    .fetch_optional(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Database error", None
    ))?;

    if assigned.is_none() {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Task Order not assigned to team", None));
    }

    let result = sqlx::query!(
        "DELETE from task_order_teams WHERE team_id = $1 and task_order_id = $2",
        team_id,
        task_id
    )
    .execute(&db_pool)
    .await
    .map_err(|_| ApiResponse::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Failed to remove Task Order", None
    ))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::error(StatusCode::NOT_FOUND, "Task Order not found in team", None));
    }

    Ok(ApiResponse::success(StatusCode::OK, "Task ORder removed from team", ()))
}

use utoipa::OpenApi;

use super::user;

#[derive(OpenApi)]
#[openapi(
    paths(
        create_team,
        get_team,
        get_all_teams,
        update_team,
        delete_team,
        add_user_to_team,
        get_team_members,
        remove_user_from_team,
        get_team_products,
        get_team_product_types,
        update_user_role,
        assign_product_to_team,
        remove_product_from_team,
        assign_product_type_to_team,
        remove_product_type_from_team,
        assign_task_order_to_team,
        get_team_task_orders,
    ),
    components(
        schemas(
            TeamResponse,
            NewTeam,
            UpdateTeam,
            TeamMember,
            AddUserToTeam,
            UpdateUserRole,
            AssignProduct,
            AssignProductType,
            AssignTaskOrder,
        )
    ),
    tags(
        (name = "Teams", description = "Team Management Endpoints")
    )
)]
pub struct TeamDoc;
