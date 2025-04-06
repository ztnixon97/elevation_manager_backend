

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
    let duplicate_exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM approval_requests
            WHERE request_type = $1 AND requested_by = $2 AND target_id IS NOT DISTINCT FROM $3 AND status = 'pending'
        )
        "#,
        payload.request_type as _,
        claims.sub.parse::<i32>().unwrap_or_default(),
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

    let result = sqlx::query_as!(
        ApprovalRequest,
        r#"
        INSERT INTO approval_requests (request_type, requested_by, target_id, details)
        VALUES ($1, $2, $3, $4)
        RETURNING id, request_type as "request_type!: ApprovalRequestType", requested_by, target_id, details, status as "status!: ApprovalStatus", reviewed_by, requested_at, reviewed_at
        "#,
        payload.request_type as _,
        claims.sub.parse::<i32>().unwrap_or_default(),
        payload.target_id,
        payload.details
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to insert approval request", Some(json!({"error": e.to_string()}))))?;

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