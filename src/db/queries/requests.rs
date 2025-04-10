

use axum::{
    extract::{Extension, Path, State}, http::{request, StatusCode}, Json
};
use sqlx::{PgPool, QueryBuilder, Row};
use serde_json::{json, Value};
use chrono::Utc;
use utoipa::openapi;

use crate::utils::api_response::ApiResponse;
use crate::db::models::requests::{
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
    NewApprovalRequest
};
use crate::api::auth::Claims;
use crate::middleware::auth::UserPermissions;

use crate::utils::notification;
use super::{team::add_user_to_team, user};


#[utoipa::path(
    post,
    path = "/requests",
    request_body = NewApprovalRequest,
    responses(
        (status = 201, description = "Approval request created successfully", body = ApprovalRequest),
        (status = 409, description = "Duplicate request already pending"),
        (status = 500, description = "Failed to insert approval request")
    ),
    tag = "Requests",
    security(("bearerAuth" = []))
)]
pub async fn create_approval_request(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<NewApprovalRequest>,
) -> Result<ApiResponse<ApprovalRequest>, ApiResponse<()>> {
    // Parse user_id from claims
    let user_id = claims.sub.parse::<i32>().unwrap_or_default();
    
    // Check for duplicates
    let duplicate_exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM approval_requests
            WHERE request_type = $1 AND requested_by = $2 AND target_id IS NOT DISTINCT FROM $3 AND status = 'pending'
        )
        "#,
        payload.request_type as _,
        user_id,
        payload.target_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(Some(false))
    .unwrap_or(false);

    if duplicate_exists {
        return Err(ApiResponse::<()>::error(
            StatusCode::CONFLICT,
            "Duplicate request already pending",
            None,
        ));
    }

    // Start a transaction for atomic operations
    let mut tx = pool.begin().await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to start transaction",
        Some(json!({"error": e.to_string()}))
    ))?;

    // Insert the approval request
    let result = sqlx::query_as!(
        ApprovalRequest,
        r#"
        INSERT INTO approval_requests (request_type, requested_by, target_id, details)
        VALUES ($1, $2, $3, $4)
        RETURNING id, request_type as "request_type!: ApprovalRequestType", requested_by, target_id, details, status as "status!: ApprovalStatus", reviewed_by, requested_at, reviewed_at
        "#,
        payload.request_type as _,
        user_id,
        payload.target_id,
        payload.details
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, 
        "Failed to insert approval request", 
        Some(json!({"error": e.to_string()}))
    ))?;

    // Handle notifications for specific request types
    match result.request_type {
        ApprovalRequestType::TeamJoin => {
            // Check if this is a team join request
            if let Some(team_id) = result.target_id {
                // Get the role from details
                let role = result.details.get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("member")
                    .to_string();

                // Get user info for the notification
                let user = sqlx::query!(
                    "SELECT username FROM users WHERE id = $1",
                    user_id
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| ApiResponse::<()>::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to retrieve user details",
                    Some(json!({"error": e.to_string()}))
                ))?;

                // Get team name for the notification
                let team = sqlx::query!(
                    "SELECT name FROM teams WHERE id = $1",
                    team_id
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| ApiResponse::<()>::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to retrieve team details",
                    Some(json!({"error": e.to_string()}))
                ))?;

                // Create notification
                notification::notify_team_access_request(
                    &pool, // Use the pool directly, not the transaction
                    user_id,
                    &user.username,
                    team_id,
                    &team.name,
                    &role,
                    result.id,
                )
                .await
                .map_err(|e| ApiResponse::<()>::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create notification",
                    Some(json!({"error": e.to_string()}))
                ))?;
            }
        },
        // Add handlers for other request types as needed
        _ => {
            // No special notification handling for other request types
        }
    }

    // Commit the transaction
    tx.commit().await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to commit transaction",
        Some(json!({"error": e.to_string()}))
    ))?;

    Ok(ApiResponse::success(StatusCode::CREATED, "Approval request created", result))
}

pub async fn get_approval_request_by_id(
    pool: &PgPool,
    request_id: i32,
) -> Result<ApprovalRequest, ApiResponse<()>> {
    sqlx::query_as!(
        ApprovalRequest,
        r#"
        SELECT id, request_type as "request_type!: ApprovalRequestType", requested_by, target_id, details,
               status as "status!: ApprovalStatus", reviewed_by, requested_at, reviewed_at
        FROM approval_requests
        WHERE id = $1
        "#,
        request_id
    )
    .fetch_one(pool)
    .await
    .map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Approval request not found",
            None,
        )
    })
}

#[utoipa::path(
    get,
    path = "/requests/{request_id}",
    params(
        ("request_id" = i32, Path, description = "Approval request ID")
    ),
    responses(
        (status = 200, description = "Approval request retrieved", body = ApprovalRequest),
        (status = 404, description = "Approval request not found")
    ),
    tag = "Requests",
    security(("bearerAuth" = []))
)]
pub async fn get_approval_request_by_id_handler(
    State(pool): State<PgPool>,
    Path(request_id): Path<i32>,
) -> Result<ApiResponse<ApprovalRequest>, ApiResponse<()>> {
    let request = get_approval_request_by_id(&pool, request_id).await?;
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Approval request retrieved",
        request,
    ))
}

#[utoipa::path(
    get,
    path = "/requests",
    responses(
        (status = 200, description = "List of pending approval requests", body = Vec<ApprovalRequest>),
        (status = 500, description = "Failed to retrieve requests")
    ),
    tag = "Requests",
    security(("bearerAuth" = []))
)]
pub async fn get_pending_requests(
    State(pool): State<PgPool>
) -> Result<ApiResponse<Vec<ApprovalRequest>>, ApiResponse<()>> {
    let requests = sqlx::query_as!(
        ApprovalRequest,
        r#"
        SELECT id, request_type as "request_type!: ApprovalRequestType", requested_by, target_id, details, status as "status!: ApprovalStatus", reviewed_by, requested_at, reviewed_at
        FROM approval_requests
        WHERE status = 'pending'
        ORDER BY requested_at DESC
        "#
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve requests", Some(json!({"error": e.to_string()}))))?;

    Ok(ApiResponse::success(StatusCode::OK, "Pending approval requests", requests))
}


#[utoipa::path(
    get,
    path = "/teams/{team_id}/requests",
    params(
        ("team_id" = i32, Path, description = "Team ID")
    ),
    responses(
        (status = 200, description = "List of pending approval requests for team", body = Vec<ApprovalRequest>),
        (status = 403, description = "User is not authorized to view team requests"),
        (status = 500, description = "Failed to retrieve requests")
    ),
    tag = "Requests",
    security(("bearerAuth" = []))
)]
pub async fn get_team_pending_requests(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(team_id): Path<i32>,
) -> Result<ApiResponse<Vec<ApprovalRequest>>, ApiResponse<()>> {
    // Check if user has permission to view team requests
    if !user_permissions.is_team_lead(team_id) && !user_permissions.is_admin() && !user_permissions.is_manager() {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "You don't have permission to view team requests",
            None,
        ));
    }

    // Get all pending TeamJoin requests for this team
    let mut requests = sqlx::query_as!(
        ApprovalRequest,
        r#"
        SELECT id, 
               request_type as "request_type!: ApprovalRequestType", 
               requested_by, 
               target_id, 
               details, 
               status as "status!: ApprovalStatus", 
               reviewed_by, 
               requested_at, 
               reviewed_at
        FROM approval_requests
        WHERE status = 'pending' 
          AND request_type = 'team_join'
          AND target_id = $1
        ORDER BY requested_at DESC
        "#,
        team_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, 
        "Failed to retrieve team requests", 
        Some(json!({"error": e.to_string()}))
    ))?;

    // Enrich requests with usernames for better frontend display
    // Create a list of user IDs we need to fetch
    let user_ids: Vec<i32> = requests
        .iter()
        .map(|req| req.requested_by)
        .collect();

    if !user_ids.is_empty() {
        let usernames = sqlx::query!(
            r#"
            SELECT id, username 
            FROM users 
            WHERE id = ANY($1)
            "#,
            &user_ids
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch user details",
            Some(json!({"error": e.to_string()}))
        ))?;

        // Create a username lookup map
        let username_map: std::collections::HashMap<i32, String> = usernames
            .into_iter()
            .map(|row| (row.id, row.username))
            .collect();

        // Add username to each request's details as an extension field
        for request in &mut requests {
            if let Some(username) = username_map.get(&request.requested_by) {
                // Add username to the details JSON
                let mut details = request.details.clone();
                if let Some(obj) = details.as_object_mut() {
                    obj.insert("username".to_string(), json!(username));
                    request.details = details;
                }
            }
        }
    }

    Ok(ApiResponse::success(StatusCode::OK, "Team pending requests", requests))
}
#[utoipa::path(
    patch,
    path = "/requests/{request_id}",
    request_body = ApprovalStatus,
    responses(
        (status = 200, description = "Approval status updated successfully", body = ApprovalRequest),
        (status = 400, description = "Invalid request type or status"),
        (status = 404, description = "Approval request not found"),
        (status = 500, description = "Failed to update approval request")
    ),
    tag = "Requests",
    security(("bearerAuth" = []))
)]
pub async fn update_approval_status(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(request_id): Path<i32>,
    Json(status): Json<ApprovalStatus>,
) -> Result<ApiResponse<ApprovalRequest>, ApiResponse<()>> {
    use sqlx::Row;
    let reviewed_at = Utc::now().naive_utc();
    let reviewer_id = claims.sub.parse::<i32>().unwrap_or_default();

    let request = get_approval_request_by_id(&pool, request_id)
        .await
        .map_err(|_| ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Approval request not found",
            None,
        ))?;

    if request.status != ApprovalStatus::Pending {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "Approval request is not pending",
            None,
        ));
    }

    match request.request_type {
        ApprovalRequestType::TeamJoin => {
            handle_team_join_approval(&pool, &user_permissions, reviewer_id, &request, status.clone()).await?;
            // Notification builder for crating system notification
        }
        _ => {
            return Err(ApiResponse::<()>::error(
                StatusCode::BAD_REQUEST,
                "Invalid request type",
                None,
            ));
        }
    }

    let updated_request = sqlx::query_as!(
        ApprovalRequest,
        r#"
        UPDATE approval_requests
        SET status = $1, reviewed_by = $2, reviewed_at = $3
        WHERE id = $4
        RETURNING id, request_type as "request_type!: ApprovalRequestType", requested_by, target_id, details,
                  status as "status!: ApprovalStatus", reviewed_by, requested_at, reviewed_at
        "#,
        status as ApprovalStatus,
        reviewer_id,
        reviewed_at,
        request_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to update approval request",
        Some(json!({ "error": e.to_string() })),
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Approval status updated successfully",
        updated_request,
    ))
}


async fn handle_team_join_approval(
    pool: &PgPool,
    user_permissions: &UserPermissions,
    reviewer_id: i32,
    request: &ApprovalRequest,
    status: ApprovalStatus,
) -> Result<(), ApiResponse<()>> {
    let Some(team_id) = request.target_id else {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "Invalid target ID for team join request",
            None,
        ));
    };

    let requested_role = request
        .details
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("member");

    if !user_permissions.can_add_user_to_team(team_id, requested_role) {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to approve this request",
            None,
        ));
    }

    if status == ApprovalStatus::Approved {
        sqlx::query!(
            r#"
            INSERT INTO team_members (user_id, team_id, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, team_id) DO UPDATE SET role = EXCLUDED.role
            "#,
            request.requested_by,
            team_id,
            requested_role
        )
        .execute(pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to add user to team",
            Some(json!({"error": e.to_string()})),
        ))?;

    }

    Ok(())
}

/// Handle a team access request and create relevant notifications
async fn handle_team_access_request(
    pool: &PgPool,
    user_id: i32,
    team_id: i32,
    role: &str,
    request_id: i32,
) -> Result<(), ApiResponse<()>> {
    // Verify the user and team exist
    let user = sqlx::query!(
        "SELECT username FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, 
        "Database error", 
        Some(json!({"error": e.to_string()}))
    ))?
    .ok_or_else(|| ApiResponse::<()>::error(
        StatusCode::NOT_FOUND,
        "User not found",
        None
    ))?;

    let team = sqlx::query!(
        "SELECT name FROM teams WHERE id = $1",
        team_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, 
        "Database error", 
        Some(json!({"error": e.to_string()}))
    ))?
    .ok_or_else(|| ApiResponse::<()>::error(
        StatusCode::NOT_FOUND,
        "Team not found",
        None
    ))?;

    // Create notification for team leads
    notification::notify_team_access_request(
        pool,
        user_id,
        &user.username,
        team_id,
        &team.name,
        role,
        request_id,
    )
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to create notification",
        Some(json!({ "error": e.to_string() }))
    ))?;

    Ok(())
}

use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(
        create_approval_request,
        get_pending_requests,
        get_approval_request_by_id_handler,
        update_approval_status
    ),
    components(schemas(ApprovalRequest, NewApprovalRequest, ApprovalStatus, ApprovalRequestType)),
    tags(
        (name = "Requests", description = "Endpoints for managing approval requests")
    )
)]
pub struct RequestDoc;
