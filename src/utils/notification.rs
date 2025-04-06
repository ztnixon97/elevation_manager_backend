use chrono::Utc;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;
use std::time::Duration;

use crate::db::models::notification::{
    NotificationScope, 
    NotificationTargetInput,
};

/// Result type for notification operations
pub type NotificationResult<T> = Result<T, NotificationError>;

/// Errors that can occur in notification operations
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Invalid target provided: {0}")]
    InvalidTarget(String),
    
    #[error("Failed to serialize notification data: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Notification builder for creating system notifications
pub struct NotificationBuilder {
    title: String,
    body: Option<String>,
    notification_type: String,
    targets: Vec<NotificationTargetInput>,
    action_type: Option<String>,
    action_data: Option<Value>,
    dismissible: bool,
    expires_in_days: Option<i64>,
}

impl NotificationBuilder {
    /// Create a new notification builder with required fields
    pub fn new(title: impl Into<String>, notification_type: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: None,
            notification_type: notification_type.into(),
            targets: Vec::new(),
            action_type: None,
            action_data: None,
            dismissible: true,
            expires_in_days: Some(14), // Default to 14 days
        }
    }

    /// Set notification body
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Add a target user to the notification
    pub fn target_user(mut self, user_id: i32) -> Self {
        self.targets.push(NotificationTargetInput {
            scope: NotificationScope::User,
            target_id: user_id,
        });
        self
    }

    /// Add multiple target users to the notification
    pub fn target_users(mut self, user_ids: Vec<i32>) -> Self {
        for user_id in user_ids {
            self.targets.push(NotificationTargetInput {
                scope: NotificationScope::User,
                target_id: user_id,
            });
        }
        self
    }

    /// Add a target team to the notification
    pub fn target_team(mut self, team_id: i32) -> Self {
        self.targets.push(NotificationTargetInput {
            scope: NotificationScope::Team,
            target_id: team_id,
        });
        self
    }

    /// Add multiple target teams to the notification
    pub fn target_teams(mut self, team_ids: Vec<i32>) -> Self {
        for team_id in team_ids {
            self.targets.push(NotificationTargetInput {
                scope: NotificationScope::Team,
                target_id: team_id,
            });
        }
        self
    }

    /// Add a target team's leads to the notification
    pub fn target_team_leads(mut self, team_id: i32) -> Self {
        self.targets.push(NotificationTargetInput {
            scope: NotificationScope::TeamLeads,
            target_id: team_id,
        });
        self
    }

    /// Set the action type and data for when notification is clicked
    pub fn action(mut self, action_type: impl Into<String>, action_data: Value) -> Self {
        self.action_type = Some(action_type.into());
        self.action_data = Some(action_data);
        self
    }

    /// Set whether the notification can be dismissed
    pub fn dismissible(mut self, dismissible: bool) -> Self {
        self.dismissible = dismissible;
        self
    }

    /// Set expiration time in days (None means no expiration)
    pub fn expires_in_days(mut self, days: Option<i64>) -> Self {
        self.expires_in_days = days;
        self
    }

    /// Build and send the notification
    pub async fn send(self, pool: &PgPool) -> NotificationResult<i32> {
        // Validate required fields
        if self.targets.is_empty() {
            return Err(NotificationError::InvalidTarget(
                "At least one target is required".to_string(),
            ));
        }

        // Calculate expiration date if provided
        let expires_at = self.expires_in_days.map(|days| {
            (Utc::now() + chrono::Duration::days(days)).naive_utc()
        });
        
        // Start a transaction
        let mut tx = pool.begin().await?;
        
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
            self.title,
            self.body,
            self.notification_type,
            self.action_type,
            self.action_data,
            false, // Never global for system notifications
            self.dismissible,
            expires_at,
        )
        .fetch_one(&mut *tx)
        .await?
        .id;
        
        // Insert targets
        for target in &self.targets {
            let scope_str = match target.scope {
                NotificationScope::User => "user",
                NotificationScope::Team => "team", 
                NotificationScope::TeamLeads => "team_leads",
            };
            
            // Use raw query to avoid type casting issues
            sqlx::query(
                "INSERT INTO notification_targets (notification_id, scope, target_id) VALUES ($1, $2, $3)"
            )
            .bind(notification_id)
            .bind(scope_str)
            .bind(target.target_id)
            .execute(&mut *tx)
            .await?;
        }
        
        // Commit transaction
        tx.commit().await?;
        
        Ok(notification_id)
    }
}

/// Common notification types for system usage
pub mod notification_types {
    pub const TEAM_ACCESS_REQUEST: &str = "team_access_request";
    pub const TASK_ASSIGNMENT: &str = "task_assignment";
    pub const PRODUCT_STATUS_CHANGE: &str = "status_change";
    pub const REVIEW_REQUEST: &str = "review_request";
    pub const SYSTEM_ANNOUNCEMENT: &str = "system_announcement";
    pub const PRODUCT_ASSIGNMENT: &str = "product_assignment";
}

/// Helper functions for common notification scenarios
pub async fn notify_team_access_request(
    pool: &PgPool, 
    user_id: i32, 
    username: &str,
    team_id: i32,
    team_name: &str,
    role: &str,
    request_id: i32,
) -> NotificationResult<i32> {
    // Get team leads for notification
    let team_leads = sqlx::query!(
        "SELECT user_id FROM team_members WHERE team_id = $1 AND role = 'team_lead'",
        team_id
    )
    .fetch_all(pool)
    .await?;
    
    let team_lead_ids: Vec<i32> = team_leads.iter().map(|lead| lead.user_id).collect();
    
    if team_lead_ids.is_empty() {
        // Notify admins instead if no team leads
        let admins = sqlx::query!(
            "SELECT id FROM users WHERE role = 'admin'",
        )
        .fetch_all(pool)
        .await?;
        
        let admin_ids: Vec<i32> = admins.iter().map(|admin| admin.id).collect();
        
        NotificationBuilder::new(
            format!("Team Access Request: {}", username),
            notification_types::TEAM_ACCESS_REQUEST,
        )
        .body(format!("User {} has requested to join team '{}' with role '{}'", username, team_name, role))
        .target_users(admin_ids)
        .action("view_request", json!({
            "user_id": user_id,
            "team_id": team_id,
            "requested_role": role,
            "request_id": request_id
        }))
        .send(pool)
        .await
    } else {
        // Notify team leads
        NotificationBuilder::new(
            format!("Team Access Request: {}", username),
            notification_types::TEAM_ACCESS_REQUEST,
        )
        .body(format!("User {} has requested to join your team with role '{}'", username, role))
        .target_users(team_lead_ids)
        .action("view_request", json!({
            "user_id": user_id,
            "team_id": team_id,
            "requested_role": role,
            "request_id": request_id
        }))
        .send(pool)
        .await
    }
}

pub async fn notify_task_order_assignment(
    pool: &PgPool,
    team_id: i32,
    team_name: &str,
    task_order_id: i32,
    task_name: &str,
    assigned_by_id: i32,
    assigned_by_name: &str,
) -> NotificationResult<i32> {
    NotificationBuilder::new(
        format!("New Task Order: {}", task_name),
        notification_types::TASK_ASSIGNMENT,
    )
    .body(format!("Your team '{}' has been assigned a new task order by {}", team_name, assigned_by_name))
    .target_team(team_id)
    .action("view_task_order", json!({
        "task_order_id": task_order_id,
        "team_id": team_id
    }))
    .send(pool)
    .await
}

pub async fn notify_product_status_change(
    pool: &PgPool,
    product_id: i32,
    product_name: &str,
    old_status: &str,
    new_status: &str,
    changed_by_id: i32,
    changed_by_name: &str,
) -> NotificationResult<i32> {
    // Get teams with access to this product
    let teams = sqlx::query!(
        "SELECT team_id FROM product_teams WHERE product_id = $1",
        product_id
    )
    .fetch_all(pool)
    .await?;
    
    let team_ids: Vec<i32> = teams.iter().map(|team| team.team_id).collect();
    
    let mut builder = NotificationBuilder::new(
        format!("Status Update: {} → {}", old_status, new_status),
        notification_types::PRODUCT_STATUS_CHANGE,
    )
    .body(format!("Product '{}' status changed from '{}' to '{}' by {}", 
        product_name, old_status, new_status, changed_by_name))
    .action("view_product", json!({
        "product_id": product_id
    }));
    
    // Add each team as a target
    for team_id in team_ids {
        builder = builder.target_team(team_id);
    }
    
    builder.send(pool).await
}

pub async fn notify_review_request(
    pool: &PgPool,
    reviewer_id: i32,
    product_id: i32,
    product_name: &str,
    requested_by_id: i32,
    requested_by_name: &str,
    deadline_days: Option<i32>,
) -> NotificationResult<i32> {
    let deadline_msg = if let Some(days) = deadline_days {
        format!(" Deadline: {} days", days)
    } else {
        String::new()
    };
    
    NotificationBuilder::new(
        format!("Review Request: {}{}", product_name, deadline_msg),
        notification_types::REVIEW_REQUEST,
    )
    .body(format!("{} has requested your review for product '{}'", 
        requested_by_name, product_name))
    .target_user(reviewer_id)
    .action("review_product", json!({
        "product_id": product_id,
        "requested_by": requested_by_id
    }))
    .dismissible(false) // Can't dismiss review requests
    .expires_in_days(deadline_days.map(|d| d as i64).or(Some(7)))
    .send(pool)
    .await
}

pub async fn notify_system_announcement(
    pool: &PgPool,
    title: &str,
    message: &str,
    action_type: Option<&str>,
    action_data: Option<Value>,
    target_all_users: bool,
    expires_in_days: Option<i64>,
) -> NotificationResult<i32> {
    let mut builder = NotificationBuilder::new(
        title,
        notification_types::SYSTEM_ANNOUNCEMENT,
    )
    .body(message.to_string())
    .expires_in_days(expires_in_days);
    
    // Add action if provided
    if let (Some(action), Some(data)) = (action_type, action_data) {
        builder = builder.action(action, data);
    }
    
    // Target all users by getting them from the database if requested
    if target_all_users {
        let users = sqlx::query!(
            "SELECT id FROM users WHERE account_locked = false",
        )
        .fetch_all(pool)
        .await?;
        
        let user_ids: Vec<i32> = users.iter().map(|user| user.id).collect();
        builder = builder.target_users(user_ids);
    }
    
    builder.send(pool).await
}

/// Utility to find team leads for a given team
pub async fn get_team_leads(pool: &PgPool, team_id: i32) -> Result<Vec<i32>, sqlx::Error> {
    let leads = sqlx::query!(
        "SELECT user_id FROM team_members WHERE team_id = $1 AND role = 'team_lead'",
        team_id
    )
    .fetch_all(pool)
    .await?;
    
    Ok(leads.iter().map(|lead| lead.user_id).collect())
}

/// Utility to get admins
pub async fn get_admin_user_ids(pool: &PgPool) -> Result<Vec<i32>, sqlx::Error> {
    let admins = sqlx::query!(
        "SELECT id FROM users WHERE role = 'admin'",
    )
    .fetch_all(pool)
    .await?;
    
    Ok(admins.iter().map(|admin| admin.id).collect())
}
