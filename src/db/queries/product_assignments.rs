use crate::db::models::product_assignments::{
    NewProductAssignment, ProductAssignment, UpdateProductAssignment,
};
use crate::api::auth::Claims;
use crate::middleware::auth::UserPermissions;
use crate::utils::api_response::ApiResponse;

use axum::{
    extract::{Extension, Path, State}, http::{request, StatusCode}, Json
};
use chrono::NaiveDateTime;
use sqlx::{pool, PgPool};
use utoipa::openapi;
use axum::debug_handler;

#[utoipa::path(
    post,
    path = "/product-assignments",
    request_body = NewProductAssignment,
    responses(
        (status = 201, description = "Product assignment created successfully", body = ProductAssignment),
        (status = 403, description = "Permission denied - user cannot edit product or assign to team"),
        (status = 500, description = "Failed to create product assignment")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_user_assignment(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Extension(user_permissions): Extension<UserPermissions>,
    Json(new_assignment): Json<NewProductAssignment>,
) -> Result<ApiResponse<ProductAssignment>, ApiResponse<()>> {

    let status = new_assignment.status.unwrap_or_else(|| "active".to_string());
    let assigned_by = new_assignment
        .assigned_by
        .unwrap_or_else(|| claims.user_id().unwrap_or(0));
    let now = chrono::Utc::now().naive_utc();

    // Permissions check
    if !user_permissions.can_edit_product(new_assignment.product_id) {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to edit this product",
            None,
        ));
    }

    let team_name = if let Some(team_id) = new_assignment.team_id {
        if !user_permissions.is_team_lead(team_id) {
            return Err(ApiResponse::<()>::error(
                StatusCode::FORBIDDEN,
                "You do not have permission to assign this product to this team",
                None,
            ));
        }

        // Safe to unwrap here because we already checked team_id is Some
        get_team_name(&pool, team_id)
            .await
            .unwrap_or_else(|_| format!("Team #{}", team_id))
    } else {
        "Unassigned".to_string()
    };

    // Insert the assignment into the database
    let result = sqlx::query_as!(
        ProductAssignment,
        r#"
        INSERT INTO product_assignments (
            product_id, 
            user_id, 
            team_id, 
            assignment_type,
            status, 
            assigned_by, 
            assigned_at, 
            due_date,
            reason
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING 
            id,
            product_id,
            user_id,
            team_id,
            assignment_type,
            status,
            assigned_by,
            assigned_at,
            due_date,
            reason,
            completed_at
        "#,
        new_assignment.product_id,
        new_assignment.user_id,
        new_assignment.team_id,
        new_assignment.assignment_type,
        status,
        assigned_by,
        now,
        new_assignment.due_date,
        new_assignment.reason
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to create product assignment",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    // Create a notification for the assigned user
    let product_name = get_product_name(&pool, new_assignment.product_id)
        .await
        .unwrap_or_else(|_| format!("Product #{}", new_assignment.product_id));

    let _ = create_assignment_notification(
        &pool,
        new_assignment.user_id,
        &product_name,
        &team_name,
        &claims.username,
        result.id,
        &new_assignment.assignment_type,
    )
    .await;

    Ok(ApiResponse::success(
        StatusCode::CREATED,
        "Product assignment created successfully",
        result,
    ))
}

async fn create_assignment_notification(
    pool : &PgPool,
    user_id: i32,
    product_name : &str,
    team_name: &str,
    assigned_by: &str,
    assignment_id: i32,
    assignment_type: &str,
) -> Result<(), sqlx::Error> {
    let notification_title = match assignment_type {
        "assigned" => format!("{team_name}: Product Assignment: {product_name}"),
        "checkout" => format!("{team_name}: Product Checkout: {product_name}"),
        _ => format!("Product Assignment: {product_name}"),
    };

    let notification_body = match assignment_type {
        "assigned" => format!("You have been assigned to the product: {product_name} by {assigned_by}"),
        "checkout" => format!("You have checked out the product: {product_name}"),
        _ => format!("You have been assigned to the product: {product_name}"),
    };

    let record = sqlx::query!(
        r#"
        INSERT INTO notifications (
            title, 
            body, 
            type, 
            action_type, 
            action_data,
            global, 
            dismissible
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7
        )
        RETURNING id
        "#,
        notification_title,
        notification_body,
        "task_assignment",
        "view_assignment",
        serde_json::json!({ "assignment_id": assignment_id }),
        false,
        true
    )
    .fetch_one(pool)
    .await?;
        
    // Create notification target
    let notification_id = record.id;
    sqlx::query!(
        r#"
        INSERT INTO notification_targets (notification_id, scope, target_id)
        VALUES ($1, 'user', $2)
        "#,
        notification_id,
        user_id
    )
    .execute(pool)
    .await?;

    // Add this return statement
    Ok(())
}

// Helper function to get product name
async fn get_product_name(pool: &PgPool, product_id: i32) -> Result<String, sqlx::Error> {
    let result = sqlx::query!(
        "SELECT site_id FROM products WHERE id = $1",
        product_id
    )
    .fetch_optional(pool)
    .await?;
    
    Ok(result.map(|r| r.site_id).unwrap_or_else(|| format!("Product #{}", product_id)))
}

// Helper function to get team name
async fn get_team_name(pool: &PgPool, team_id: i32) -> Result<String, sqlx::Error> {
    let result = sqlx::query!(
        "SELECT name FROM teams WHERE id = $1",
        team_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|r| r.name).unwrap_or_else(|| format!("Team #{}", team_id)))
}

#[utoipa::path(
    patch,
    path = "/product-assignments/{assignment_id}/complete",
    params(
        ("assignment_id" = i32, Path, description = "ID of the assignment to complete")
    ),
    request_body = Option<UpdateProductAssignment>,
    responses(
        (status = 200, description = "Product assignment completed successfully", body = ProductAssignment),
        (status = 403, description = "Permission denied - user cannot complete this assignment"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Failed to complete product assignment")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
#[debug_handler]
pub async fn complete_assignment(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(assignment_id): Path<i32>,
    Json(update_data): Json<UpdateProductAssignment>,
) -> Result<ApiResponse<ProductAssignment>, ApiResponse<()>> {
    // First, fetch the current assignment to verify permissions
    let assignment = sqlx::query_as!(
        ProductAssignment,
        r#"
        SELECT 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        FROM product_assignments
        WHERE id = $1
        "#,
        assignment_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to fetch assignment",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    let assignment = match assignment {
        Some(a) => a,
        None => {
            return Err(ApiResponse::<()>::error(
                StatusCode::NOT_FOUND,
                "Assignment not found",
                None,
            ));
        }
    };

    let user_id = claims.user_id().unwrap_or(0);
    let can_complete = assignment.user_id == user_id
        || user_permissions.can_edit_product(assignment.product_id);

    if !can_complete {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to complete this assignment",
            None,
        ));
    }

    let now = chrono::Utc::now().naive_utc();

    let status = update_data.status.clone().unwrap_or_else(|| "completed".to_string());
    let reason = update_data.reason.clone();
    let completed_at = update_data.completed_at.unwrap_or(now);

    let updated_assignment = sqlx::query_as!(
        ProductAssignment,
        r#"
        UPDATE product_assignments 
        SET 
            status = $1,
            completed_at = $2,
            reason = COALESCE($3, reason)
        WHERE id = $4
        RETURNING 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        "#,
        status,
        completed_at,
        reason,
        assignment_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to update assignment",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    let product_name = get_product_name(&pool, assignment.product_id).await
        .unwrap_or_else(|_| format!("Product #{}", assignment.product_id));

    if let Some(assigned_by) = assignment.assigned_by {
        if assigned_by != user_id {
            let completer_name = claims.username.clone();
            let _ = create_completion_notification(
                &pool,
                assigned_by,
                &product_name,
                &completer_name,
                assignment_id,
                &assignment.assignment_type,
            ).await;
        }
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product assignment completed successfully",
        updated_assignment
    ))
}

async fn create_completion_notification(
    pool: &PgPool,
    user_id: i32,
    product_name: &str,
    completer_name: &str,
    assignment_id: i32,
    assignment_type: &str,
) -> Result<(), sqlx::Error> {
    let notification_title = match assignment_type {
        "assigned" => format!("Assignment Completed: {product_name}"),
        "checkout" => format!("Product Checked In: {product_name}"),
        _ => format!("Assignment Completed: {product_name}"),
    };

    let notification_body = match assignment_type {
        "assigned" => format!("{completer_name} has completed the assignment for {product_name}"),
        "checkout" => format!("{completer_name} has checked in {product_name}"),
        _ => format!("The assignment for {product_name} has been completed"),
    };

    let record = sqlx::query!(
        r#"
        INSERT INTO notifications (
            title, 
            body, 
            type, 
            action_type, 
            action_data,
            global, 
            dismissible
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7
        )
        RETURNING id
        "#,
        notification_title,
        notification_body,
        "assignment_completion",
        "view_assignment",
        serde_json::json!({ "assignment_id": assignment_id }),
        false,
        true
    )
    .fetch_one(pool)
    .await?;

        // Create notification target
    let notification_id = record.id;
    sqlx::query!(
        r#"
        INSERT INTO notification_targets (notification_id, scope, target_id)
        VALUES ($1, 'user', $2)
        "#,
        notification_id,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[utoipa::path(
    delete,
    path = "/product-assignments/{assignment_id}",
    params(
        ("assignment_id" = i32, Path, description = "ID of the assignment to delete")
    ),
    responses(
        (status = 200, description = "Product assignment successfully deleted"),
        (status = 403, description = "Permission denied - user cannot delete this assignment"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Failed to delete product assignment")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_assignment(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Extension(user_permissions): Extension<UserPermissions>,
    Path(assignment_id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    // First, fetch the current assignment to verify permissions
    let assignment = sqlx::query_as!(
        ProductAssignment,
        r#"
        SELECT 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        FROM product_assignments
        WHERE id = $1
        "#,
        assignment_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to fetch assignment",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    let assignment = match assignment {
        Some(a) => a,
        None => return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Assignment not found",
            None,
        )),
    };

    // Check permissions - only team leads, admins, or the original assigner can delete assignments
    let user_id = claims.user_id().unwrap_or(0);
    let is_original_assigner = assignment.assigned_by.map_or(false, |id| id == user_id);
    let can_delete = 
        // Original assigner
        is_original_assigner || 
        // Admin or team lead with product editing rights
        user_permissions.can_edit_product(assignment.product_id);

    if !can_delete {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "You do not have permission to delete this assignment",
            None,
        ));
    }

    // Delete the assignment
    sqlx::query!(
        "DELETE FROM product_assignments WHERE id = $1",
        assignment_id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to delete assignment",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    // Get product name for notification
    let product_name = get_product_name(&pool, assignment.product_id).await
        .unwrap_or_else(|_| format!("Product #{}", assignment.product_id));
    
    // Notify the assigned user that their assignment has been removed
    let _ = create_assignment_removal_notification(
        &pool,
        assignment.user_id,
        &product_name,
        &claims.username,
        &assignment.assignment_type,
    ).await;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product assignment deleted successfully",
        ()
    ))
}

async fn create_assignment_removal_notification(
    pool: &PgPool,
    user_id: i32,
    product_name: &str,
    removed_by: &str,
    assignment_type: &str,
) -> Result<(), sqlx::Error> {
    let notification_title = match assignment_type {
        "assigned" => format!("Assignment Removed: {product_name}"),
        "checkout" => format!("Checkout Cancelled: {product_name}"),
        _ => format!("Assignment Removed: {product_name}"),
    };

    let notification_body = match assignment_type {
        "assigned" => format!("Your assignment for {product_name} has been removed by {removed_by}"),
        "checkout" => format!("Your checkout of {product_name} has been cancelled by {removed_by}"),
        _ => format!("Your assignment for {product_name} has been removed"),
    };

    let record = sqlx::query!(
        r#"
        INSERT INTO notifications (
            title, 
            body, 
            type, 
            action_type, 
            action_data,
            global, 
            dismissible
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7
        )
        RETURNING id
        "#,
        notification_title,
        notification_body,
        "assignment_removal",
        "view_product",
        serde_json::json!({ "product_id": product_name }),
        false,
        true
    )
    .fetch_one(pool)
    .await?;

    // Create notification target
    let notification_id = record.id;
    sqlx::query!(
        r#"
        INSERT INTO notification_targets (notification_id, scope, target_id)
        VALUES ($1, 'user', $2)
        "#,
        notification_id,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Get a product assignment by ID
#[utoipa::path(
    get,
    path = "/product-assignments/{assignment_id}",
    params(
        ("assignment_id" = i32, Path, description = "ID of the assignment to retrieve")
    ),
    responses(
        (status = 200, description = "Product assignment retrieved successfully", body = ProductAssignment),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Failed to fetch product assignment")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_assignment(
    State(pool): State<PgPool>,
    Path(assignment_id): Path<i32>,
) -> Result<ApiResponse<ProductAssignment>, ApiResponse<()>> {
    let assignment = sqlx::query_as!(
        ProductAssignment,
        r#"
        SELECT 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        FROM product_assignments
        WHERE id = $1
        "#,
        assignment_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to fetch assignment",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    match assignment {
        Some(a) => Ok(ApiResponse::success(
            StatusCode::OK,
            "Assignment retrieved successfully",
            a,
        )),
        None => Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Assignment not found",
            None,
        )),
    }
}
#[utoipa::path(
    get,
    path = "/products/{product_id}/assignments",
    params(
        ("product_id" = i32, Path, description = "ID of the product to get assignments for")
    ),
    responses(
        (status = 200, description = "Product assignments retrieved successfully", body = Vec<ProductAssignment>),
        (status = 500, description = "Failed to fetch product assignments")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_product_assignments(
    State(pool): State<PgPool>,
    Path(product_id): Path<i32>,
) -> Result<ApiResponse<Vec<ProductAssignment>>, ApiResponse<()>> {
    let assignments = sqlx::query_as!(
        ProductAssignment,
        r#"
        SELECT 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        FROM product_assignments
        WHERE product_id = $1
        "#,
        product_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to fetch product assignments",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product assignments retrieved successfully",
        assignments,
    ))
}

/// Get assignments for a user
#[utoipa::path(
    get,
    path = "/users/{user_id}/assignments",
    params(
        ("user_id" = i32, Path, description = "ID of the user to get assignments for")
    ),
    responses(
        (status = 200, description = "User assignments retrieved successfully", body = Vec<ProductAssignment>),
        (status = 500, description = "Failed to fetch user assignments")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_user_assignments(
    State(pool): State<PgPool>,
    Path(user_id): Path<i32>,
) -> Result<ApiResponse<Vec<ProductAssignment>>, ApiResponse<()>> {
    let assignments = sqlx::query_as!(
        ProductAssignment,
        r#"
        SELECT 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        FROM product_assignments
        WHERE user_id = $1
        "#,
        user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to fetch user assignments",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "User assignments retrieved successfully",
        assignments,
    ))
}

/// Get current user's assignments
#[utoipa::path(
    get,
    path = "/assignments/me",
    responses(
        (status = 200, description = "Current user's assignments retrieved successfully", body = Vec<ProductAssignment>),
        (status = 500, description = "Failed to fetch user assignments")
    ),
    tag = "Product Assignments",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_my_assignments(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
) -> Result<ApiResponse<Vec<ProductAssignment>>, ApiResponse<()>> {
    let user_id = claims.user_id().map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID in token",
            None,
        )
    })?;

    let assignments = sqlx::query_as!(
        ProductAssignment,
        r#"
        SELECT 
            id, product_id, user_id, team_id, assignment_type, 
            status, assigned_by, assigned_at, due_date, reason, completed_at
        FROM product_assignments
        WHERE user_id = $1
        "#,
        user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to fetch user assignments",
        Some(serde_json::json!({ "error": e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Your assignments retrieved successfully",
        assignments,
    ))
}

// OpenAPI documentation
use utoipa::OpenApi;
#[derive(OpenApi)]
#[openapi(
    paths(
        create_user_assignment,
        get_assignment,
        complete_assignment,
        delete_assignment,
        get_product_assignments,
        get_user_assignments,
        get_my_assignments
    ),
    components(
        schemas(
            ProductAssignment, 
            NewProductAssignment, 
            UpdateProductAssignment
        )
    ),
    tags(
        (name = "Product Assignments", description = "API for managing product assignments")
    )
)]
pub struct AssignmentApiDoc;
