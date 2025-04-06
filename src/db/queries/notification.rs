// src/db/queries/notification.rs
use axum::{
    extract::{Path, Query, State, Extension},
    http::StatusCode,
    Json,
};
use sqlx::{PgPool, QueryBuilder, Row}; // Add Row trait import
use serde_json::json;
use chrono::Utc;
use crate::api::auth::Claims;
use crate::db::models::notification::{
    Notification, NotificationTarget, NotificationDismissal, 
    NewNotification, UpdateNotification, NotificationFilter,
    NotificationWithTargets, NotificationCountResponse, NotificationScope
};
use crate::utils::api_response::ApiResponse;

/// Create a new notification with targets
#[utoipa::path(
    post,
    path = "/notifications",
    request_body = NewNotification,
    responses(
        (status = 201, description = "Notification created successfully", body = i32),
        (status = 500, description = "Failed to create notification")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_notification(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<NewNotification>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    // Check permissions - only admin and managers can create notifications
    if claims.role != "admin" && claims.role != "manager" {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions to create notifications",
            None
        ));
    }
    
    // Start a transaction
    let mut tx = pool.begin().await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to start transaction",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    // Insert notification
    let notification_id = sqlx::query!(
        r#"
        INSERT INTO notifications (
            title, body, type, action_type, action_data, 
            global, dismissible, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
        payload.title,
        payload.body,
        payload.type_field.unwrap_or("info".to_string()),
        payload.action_type,
        payload.action_data,
        payload.global.unwrap_or(false),
        payload.dismissible.unwrap_or(true),
        payload.expires_at,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to create notification",
        Some(json!({ "error": e.to_string() }))
    ))?
    .id;
    
    // Insert targets
    for target in &payload.targets {
        let scope_str = match target.scope {
            NotificationScope::User => "user",
            NotificationScope::Team => "team",
            NotificationScope::TeamLeads => "team_leads",
        };
        
        // Fixed query to convert string to enum type
        sqlx::query!(
            r#"
            INSERT INTO notification_targets (notification_id, scope, target_id)
            VALUES ($1, $2::notification_scope, $3)
            "#,
            notification_id,
            scope_str,
            target.target_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create notification target",
            Some(json!({ "error": e.to_string() }))
        ))?;
    }
    
    // Commit transaction
    tx.commit().await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to commit transaction",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    Ok(ApiResponse::success(
        StatusCode::CREATED,
        "Notification created successfully",
        notification_id
    ))
}

/// Get notifications relevant to the current user
#[utoipa::path(
    get,
    path = "/notifications",
    params(
        NotificationFilter
    ),
    responses(
        (status = 200, description = "Notifications retrieved successfully", body = Vec<NotificationWithTargets>),
        (status = 500, description = "Failed to retrieve notifications")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_notifications(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Query(filter): Query<NotificationFilter>,
) -> Result<ApiResponse<Vec<NotificationWithTargets>>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID format in token",
            None,
        )
    })?;
    
    // Build the base query for notifications
    let mut query = String::from(
        r#"
        WITH user_teams AS (
            SELECT team_id FROM team_members WHERE user_id = $1
        ),
        user_team_leads AS (
            SELECT team_id FROM team_members 
            WHERE user_id = $1 AND role = 'team_lead'
        ),
        relevant_notifications AS (
            SELECT DISTINCT n.id
            FROM notifications n
            LEFT JOIN notification_targets nt ON n.id = nt.notification_id
            WHERE 
                (n.global = true)
                OR (nt.scope = 'user' AND nt.target_id = $1)
                OR (nt.scope = 'team' AND nt.target_id IN (SELECT team_id FROM user_teams))
                OR (nt.scope = 'team_leads' AND nt.target_id IN (SELECT team_id FROM user_team_leads))
        "#
    );
    
    // Add filter for dismissed notifications
    if filter.include_dismissed.unwrap_or(false) == false {
        query.push_str(
            r#"
            AND n.id NOT IN (
                SELECT notification_id FROM notification_dismissals 
                WHERE user_id = $1
            )
            "#
        );
    }
    
    // Add filter for expired notifications
    if filter.include_expired.unwrap_or(false) == false {
        query.push_str(
            r#"
            AND (n.expires_at IS NULL OR n.expires_at > NOW())
            "#
        );
    }
    
    // Add filter for notification type
    if let Some(type_filter) = &filter.type_field {
        query.push_str(" AND n.type = $2");
    }
    
    // Close the CTE and select the actual notifications
    query.push_str(
        r#"
        )
        SELECT 
            n.id, n.title, n.body, n.type, n.action_type, n.action_data,
            n.global, n.dismissible, n.created_at, n.expires_at,
            CASE WHEN nd.id IS NOT NULL THEN true ELSE false END as dismissed
        FROM notifications n
        JOIN relevant_notifications rn ON n.id = rn.id
        LEFT JOIN notification_dismissals nd ON n.id = nd.notification_id AND nd.user_id = $1
        ORDER BY n.created_at DESC
        "#
    );
    
    // Add pagination
    if let Some(limit) = filter.limit {
        query.push_str(&format!(" LIMIT {}", limit));
    }
    
    if let Some(offset) = filter.offset {
        query.push_str(&format!(" OFFSET {}", offset));
    }
    
    // Execute the query
    let notification_rows = if let Some(type_filter) = &filter.type_field {
        sqlx::query(&query)
            .bind(user_id)
            .bind(type_filter)
            .fetch_all(&pool)
            .await
    } else {
        sqlx::query(&query)
            .bind(user_id)
            .fetch_all(&pool)
            .await
    }
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve notifications",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    // Collect notification IDs
    let notification_ids: Vec<i32> = notification_rows
        .iter()
        .map(|row| row.get::<i32, _>("id"))
        .collect();
    
    if notification_ids.is_empty() {
        return Ok(ApiResponse::success(
            StatusCode::OK,
            "No notifications found",
            vec![]
        ));
    }
    
    // Fetch all targets for these notifications
    let targets = sqlx::query!(
        r#"
        SELECT id, notification_id, scope::text as "scope!", target_id
        FROM notification_targets
        WHERE notification_id = ANY($1)
        "#,
        &notification_ids
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve notification targets",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    // Map the results to NotificationTarget structures
    let targets: Vec<NotificationTarget> = targets
        .into_iter()
        .map(|row| NotificationTarget {
            id: row.id,
            notification_id: row.notification_id,
            scope: row.scope,
            target_id: row.target_id,
        })
        .collect();
    
    // Group targets by notification ID
    let mut targets_map: std::collections::HashMap<i32, Vec<NotificationTarget>> = std::collections::HashMap::new();
    for target in targets {
        targets_map
            .entry(target.notification_id)
            .or_insert_with(Vec::new)
            .push(target);
    }
    
    // Build the final response
    let notifications = notification_rows
        .into_iter()
        .map(|row| {
            let id: i32 = row.get("id");
            let dismissed: bool = row.get("dismissed");
            
            NotificationWithTargets {
                notification: Notification {
                    id,
                    title: row.get("title"),
                    body: row.get("body"),
                    type_field: row.get("type"),
                    action_type: row.get("action_type"),
                    action_data: row.get("action_data"),
                    global: row.get("global"),
                    dismissible: row.get("dismissible"),
                    created_at: row.get("created_at"),
                    expires_at: row.get("expires_at"),
                },
                targets: targets_map.get(&id).cloned().unwrap_or_default(),
                dismissed,
            }
        })
        .collect();
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Notifications retrieved successfully",
        notifications
    ))
}

/// Get a single notification with its targets
#[utoipa::path(
    get,
    path = "/notifications/{notification_id}",
    params(
        ("notification_id" = i32, Path, description = "ID of the notification to retrieve")
    ),
    responses(
        (status = 200, description = "Notification retrieved successfully", body = NotificationWithTargets),
        (status = 403, description = "Unauthorized to access this notification"),
        (status = 404, description = "Notification not found"),
        (status = 500, description = "Failed to retrieve notification")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_notification(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Path(notification_id): Path<i32>,
) -> Result<ApiResponse<NotificationWithTargets>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID format in token",
            None,
        )
    })?;
    
    // Get the notification
    let notification = sqlx::query!(
        r#"
        SELECT id, title, body, type as "type_field", action_type, action_data, 
               global, dismissible, created_at, expires_at
        FROM notifications 
        WHERE id = $1
        "#,
        notification_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve notification",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    let notification = match notification {
        Some(n) => Notification {
            id: n.id,
            title: n.title,
            body: n.body,
            type_field: n.type_field,
            action_type: n.action_type,
            action_data: n.action_data,
            global: n.global,
            dismissible: n.dismissible,
            created_at: n.created_at,
            expires_at: n.expires_at,
        },
        None => return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Notification not found",
            None
        )),
    };
    
    // If not global, check if the user has access
    if !notification.global && claims.role != "admin" {
        // Get the targets
        let targets_records = sqlx::query!(
            r#"
            SELECT id, notification_id, scope::text as "scope!", target_id
            FROM notification_targets
            WHERE notification_id = $1
            "#,
            notification_id
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve notification targets",
            Some(json!({ "error": e.to_string() }))
        ))?;
        
        // Map the results to NotificationTarget structures
        let targets: Vec<NotificationTarget> = targets_records
            .into_iter()
            .map(|row| NotificationTarget {
                id: row.id,
                notification_id: row.notification_id,
                scope: row.scope,
                target_id: row.target_id,
            })
            .collect();
        
        // Check if the user is a target
        let user_teams = sqlx::query!(
            "SELECT team_id FROM team_members WHERE user_id = $1",
            user_id
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve user teams",
            Some(json!({ "error": e.to_string() }))
        ))?;
        
        let user_team_ids: Vec<i32> = user_teams.iter().map(|r| r.team_id).collect();
        
        let user_team_leads = sqlx::query!(
            "SELECT team_id FROM team_members WHERE user_id = $1 AND role = 'team_lead'",
            user_id
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve user team leads",
            Some(json!({ "error": e.to_string() }))
        ))?;
        
        let user_team_lead_ids: Vec<i32> = user_team_leads.iter().map(|r| r.team_id).collect();
        
        let has_access = targets.iter().any(|target| {
            match target.scope.as_str() {
                "user" => target.target_id == user_id,
                "team" => user_team_ids.contains(&target.target_id),
                "team_leads" => user_team_lead_ids.contains(&target.target_id),
                _ => false,
            }
        });
        
        if !has_access {
            return Err(ApiResponse::<()>::error(
                StatusCode::FORBIDDEN,
                "Unauthorized to access this notification",
                None
            ));
        }
    }
    
    // Get the targets
    let targets_records = sqlx::query!(
        r#"
        SELECT id, notification_id, scope::text as "scope!", target_id
        FROM notification_targets
        WHERE notification_id = $1
        "#,
        notification_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve notification targets",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    // Map the results to NotificationTarget structures
    let targets: Vec<NotificationTarget> = targets_records
        .into_iter()
        .map(|row| NotificationTarget {
            id: row.id,
            notification_id: row.notification_id,
            scope: row.scope,
            target_id: row.target_id,
        })
        .collect();
    
    // Check if this notification has been dismissed by the user
    let dismissed = sqlx::query!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM notification_dismissals
            WHERE notification_id = $1 AND user_id = $2
        ) as "dismissed!"
        "#,
        notification_id,
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to check notification dismissal",
        Some(json!({ "error": e.to_string() }))
    ))?
    .dismissed;
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Notification retrieved successfully",
        NotificationWithTargets {
            notification,
            targets,
            dismissed,
        }
    ))
}

/// Update a notification (admin/manager only)
#[utoipa::path(
    patch,
    path = "/notifications/{notification_id}",
    params(
        ("notification_id" = i32, Path, description = "ID of the notification to update")
    ),
    request_body = UpdateNotification,
    responses(
        (status = 200, description = "Notification updated successfully"),
        (status = 403, description = "Unauthorized to update this notification"),
        (status = 404, description = "Notification not found"),
        (status = 500, description = "Failed to update notification")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_notification(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Path(notification_id): Path<i32>,
    Json(payload): Json<UpdateNotification>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    // Check permissions - only admin and managers can update notifications
    if claims.role != "admin" && claims.role != "manager" {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions to update notifications",
            None
        ));
    }
    
    // Check if notification exists
    let notification_exists = sqlx::query!(
        "SELECT EXISTS(SELECT 1 FROM notifications WHERE id = $1) as exists",
        notification_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to check if notification exists",
        Some(json!({ "error": e.to_string() }))
    ))?
    .exists
    .unwrap_or(false);
    
    if !notification_exists {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Notification not found",
            None
        ));
    }
    
    let mut query_builder = QueryBuilder::new("UPDATE notifications SET ");
    let mut first = true;
    
    macro_rules! add_field {
        ($field:expr, $value:expr) => {
            if let Some(val) = $value {
                if !first {
                    query_builder.push(", ");
                }
                query_builder.push($field);
                query_builder.push(" = ");
                query_builder.push_bind(val);
                first = false;
            }
        };
    }
    
    add_field!("title", &payload.title);
    add_field!("body", &payload.body);
    add_field!("type", &payload.type_field);
    add_field!("action_type", &payload.action_type);
    add_field!("action_data", &payload.action_data);
    add_field!("global", &payload.global);
    add_field!("dismissible", &payload.dismissible);
    add_field!("expires_at", &payload.expires_at);
    
    if first {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No fields provided for update",
            None
        ));
    }
    
    query_builder.push(" WHERE id = ");
    query_builder.push_bind(notification_id);
    
    query_builder
        .build()
        .execute(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update notification",
            Some(json!({ "error": e.to_string() }))
        ))?;
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Notification updated successfully",
        ()
    ))
}

/// Dismiss a notification for the current user
#[utoipa::path(
    post,
    path = "/notifications/{notification_id}/dismiss",
    params(
        ("notification_id" = i32, Path, description = "ID of the notification to dismiss")
    ),
    responses(
        (status = 200, description = "Notification dismissed successfully"),
        (status = 403, description = "Notification is not dismissible"),
        (status = 404, description = "Notification not found"),
        (status = 500, description = "Failed to dismiss notification")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn dismiss_notification(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Path(notification_id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID format in token",
            None,
        )
    })?;
    
    // Check if notification exists and is dismissible
    let notification = sqlx::query!(
        "SELECT dismissible FROM notifications WHERE id = $1",
        notification_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve notification",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    let notification = match notification {
        Some(n) => n,
        None => return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Notification not found",
            None
        )),
    };
    
    // Fixed the dismissible check using unwrap_or and proper comparison
    if !notification.dismissible.unwrap_or(true) {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "This notification cannot be dismissed",
            None
        ));
    }
    
    // Add dismissal record
    sqlx::query!(
        r#"
        INSERT INTO notification_dismissals (notification_id, user_id)
        VALUES ($1, $2)
        ON CONFLICT (notification_id, user_id) DO NOTHING
        "#,
        notification_id,
        user_id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to dismiss notification",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Notification dismissed successfully",
        ()
    ))
}

/// Dismiss all notifications for the current user
#[utoipa::path(
    post,
    path = "/notifications/dismiss-all",
    responses(
        (status = 200, description = "All notifications dismissed successfully", body = u64),
        (status = 500, description = "Failed to dismiss notifications")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn dismiss_all_notifications(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
) -> Result<ApiResponse<u64>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID format in token",
            None,
        )
    })?;
    
    // Find all dismissible notifications for this user
    let dismissible_notifications = sqlx::query!(
        r#"
        WITH user_teams AS (
            SELECT team_id FROM team_members WHERE user_id = $1
        ),
        user_team_leads AS (
            SELECT team_id FROM team_members 
            WHERE user_id = $1 AND role = 'team_lead'
        ),
        relevant_notifications AS (
            SELECT DISTINCT n.id
            FROM notifications n
            LEFT JOIN notification_targets nt ON n.id = nt.notification_id
            WHERE 
                n.dismissible = true
                AND (
                    (n.global = true)
                    OR (nt.scope = 'user' AND nt.target_id = $1)
                    OR (nt.scope = 'team' AND nt.target_id IN (SELECT team_id FROM user_teams))
                    OR (nt.scope = 'team_leads' AND nt.target_id IN (SELECT team_id FROM user_team_leads))
                )
                AND (n.expires_at IS NULL OR n.expires_at > NOW())
                AND n.id NOT IN (
                    SELECT notification_id FROM notification_dismissals 
                    WHERE user_id = $1
                )
        )
        SELECT id FROM relevant_notifications
        "#,
        user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve dismissible notifications",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    if dismissible_notifications.is_empty() {
        return Ok(ApiResponse::success(
            StatusCode::OK,
            "No notifications to dismiss",
            0
        ));
    }
    
    // Insert dismissals for all relevant notifications
// Insert dismissals for all relevant notifications
    let notification_ids: Vec<i32> = dismissible_notifications.iter().map(|r| r.id).collect();
    
    let mut tx = pool.begin().await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to start transaction",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    for notification_id in &notification_ids {
        sqlx::query!(
            r#"
            INSERT INTO notification_dismissals (notification_id, user_id)
            VALUES ($1, $2)
            ON CONFLICT (notification_id, user_id) DO NOTHING
            "#,
            notification_id,
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to dismiss notifications",
            Some(json!({ "error": e.to_string() }))
        ))?;
    }
    
    tx.commit().await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to commit transaction",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "All notifications dismissed successfully",
        notification_ids.len() as u64
    ))
}

/// Delete a notification (admin/manager only)
#[utoipa::path(
    delete,
    path = "/notifications/{notification_id}",
    params(
        ("notification_id" = i32, Path, description = "ID of the notification to delete")
    ),
    responses(
        (status = 200, description = "Notification deleted successfully"),
        (status = 403, description = "Unauthorized to delete this notification"),
        (status = 404, description = "Notification not found"),
        (status = 500, description = "Failed to delete notification")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_notification(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
    Path(notification_id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    // Check permissions - only admin and managers can delete notifications
    if claims.role != "admin" && claims.role != "manager" {
        return Err(ApiResponse::<()>::error(
            StatusCode::FORBIDDEN,
            "Insufficient permissions to delete notifications",
            None
        ));
    }
    
    // Check if notification exists
    let notification_exists = sqlx::query!(
        "SELECT EXISTS(SELECT 1 FROM notifications WHERE id = $1) as exists",
        notification_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to check if notification exists",
        Some(json!({ "error": e.to_string() }))
    ))?
    .exists
    .unwrap_or(false);
    
    if !notification_exists {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Notification not found",
            None
        ));
    }
    
    // Delete notification (cascade will handle targets and dismissals)
    sqlx::query!(
        "DELETE FROM notifications WHERE id = $1",
        notification_id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to delete notification",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Notification deleted successfully",
        ()
    ))
}

/// Get notification counts for the current user
#[utoipa::path(
    get,
    path = "/notifications/count",
    responses(
        (status = 200, description = "Notification counts retrieved successfully", body = NotificationCountResponse),
        (status = 500, description = "Failed to retrieve notification counts")
    ),
    tag = "Notifications",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_notification_count(
    State(pool): State<PgPool>,
    Extension(claims): Extension<Claims>,
) -> Result<ApiResponse<NotificationCountResponse>, ApiResponse<()>> {
    let user_id = claims.sub.parse::<i32>().map_err(|_| {
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID format in token",
            None,
        )
    })?;
    
    let counts = sqlx::query!(
        r#"
        WITH user_teams AS (
            SELECT team_id FROM team_members WHERE user_id = $1
        ),
        user_team_leads AS (
            SELECT team_id FROM team_members 
            WHERE user_id = $1 AND role = 'team_lead'
        ),
        relevant_notifications AS (
            SELECT DISTINCT n.id
            FROM notifications n
            LEFT JOIN notification_targets nt ON n.id = nt.notification_id
            WHERE 
                (n.global = true)
                OR (nt.scope = 'user' AND nt.target_id = $1)
                OR (nt.scope = 'team' AND nt.target_id IN (SELECT team_id FROM user_teams))
                OR (nt.scope = 'team_leads' AND nt.target_id IN (SELECT team_id FROM user_team_leads))
        )
        SELECT 
            COUNT(*) as "total!: i64",
            COUNT(*) FILTER (
                WHERE n.id NOT IN (
                    SELECT notification_id FROM notification_dismissals WHERE user_id = $1
                )
                AND (n.expires_at IS NULL OR n.expires_at > NOW())
            ) as "unread!: i64"
        FROM notifications n
        JOIN relevant_notifications rn ON n.id = rn.id
        "#,
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve notification counts",
        Some(json!({ "error": e.to_string() }))
    ))?;
    
    Ok(ApiResponse::success(
        StatusCode::OK,
        "Notification counts retrieved successfully",
        NotificationCountResponse {
            total: counts.total,
            unread: counts.unread,
        }
    ))
}

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        create_notification,
        get_notifications,
        get_notification,
        update_notification,
        dismiss_notification,
        dismiss_all_notifications,
        delete_notification,
        get_notification_count
    ),
    components(
        schemas(
            Notification,
            NotificationTarget,
            NotificationDismissal,
            NewNotification,
            NotificationTargetInput,
            UpdateNotification,
            NotificationFilter,
            NotificationWithTargets,
            NotificationCountResponse,
            NotificationScope
        )
    ),
    tags(
        (name = "Notifications", description = "Notification Management Endpoints")
    )
)]
pub struct NotificationDoc;
