use std::collections::{HashMap};
use std::sync::Arc;
use axum::{
    extract::{Request, State, Extension, Path},
    body::Body,
    http::StatusCode,
    middleware::Next,
    response::{Response, IntoResponse},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::error;
use moka::sync::Cache; // ✅ High-performance TTL Cache
use std::time::Duration;
use crate::config::Config;
use crate::utils::api_response::ApiResponse;
use serde_json::json;
use crate::api::auth::Claims;

/// ✅ **RBAC Permissions Cache Using `moka`**
pub type PermissionCache = Arc<Cache<i32, UserPermissions>>;

/// ✅ **Initialize the `moka` Cache**
pub fn create_permission_cache() -> PermissionCache {
    Arc::new(
        Cache::builder()
            .time_to_live(Duration::from_secs(600)) // ✅ TTL = 10 minutes
            .build(),
    )
}

/// ✅ **JWT Middleware** (Handles Token Authentication)
pub async fn jwt_middleware(
    mut req: Request<Body>, 
    next: Next,
) -> Result<Response, Response> {
    // Log the entire request for debugging
    //tracing::error!("Incoming request: {:?}", req);

    // Step 1: Extract Authorization header
    let auth_header = req.headers().get("Authorization").ok_or_else(|| {
        tracing::error!("Missing Authorization header");
        ApiResponse::<()>::error(StatusCode::UNAUTHORIZED, "Missing Authorization header", None).into_response()
    })?;

    // Step 2: Convert header to string
    let token_str = auth_header.to_str().map_err(|_| {
        tracing::error!("Invalid Authorization header format");
        ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "Invalid Authorization header format", None).into_response()
    })?;

    // Step 3: Strip "Bearer " prefix
    let token = token_str.strip_prefix("Bearer ").ok_or_else(|| {
        tracing::error!("Invalid token format (missing 'Bearer ' prefix)");
        ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "Invalid token format (missing 'Bearer ' prefix)", None).into_response()
    })?;

    // Step 4: Decode the JWT token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(Config::get().jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        tracing::error!("JWT decoding failed: {:?}", e);
        ApiResponse::<()>::error(StatusCode::UNAUTHORIZED, "Invalid token", Some(json!({ "error": e.to_string() }))).into_response()
    })?;

    // Step 5: Insert claims into request extensions
    tracing::info!("JWT decoded successfully: {:?}", token_data.claims);
    req.extensions_mut().insert(token_data.claims);

    // Step 6: Proceed to the next middleware
    Ok(next.run(req).await)
}

/// ✅ **User Permissions Structure**
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserPermissions {
    pub user_id: i32,
    pub global_role: String,
    pub teams: HashMap<i32, String>, // Team ID -> Role (team-lead, editor, viewer, etc.)
    pub task_order_permissions: HashMap<i32, String>, // Task Order ID -> Role
    pub product_type_permissions: HashMap<i32, String>, // Product Type ID -> Role
    pub explicit_product_permissions: HashMap<i32, String>, // Explicit Product ID -> Role
}

impl UserPermissions {
    /// ✅ **Check if user is a system-wide administrator**
    pub fn is_admin(&self) -> bool {
        self.global_role == "admin"
    }

    /// ✅ **Check if user is a system-wide manager**
    pub fn is_manager(&self) -> bool {
        self.global_role == "manager"
    }

    /// ✅ **Check if user is a team lead for a specific team**
    pub fn is_team_lead(&self, team_id: i32) -> bool {
        matches!(self.teams.get(&team_id), Some(role) if role == "team_lead")
    }

    /// ✅ **Check if user is on a specific team (any role)**
    pub fn is_on_team(&self, team_id: i32) -> bool {
        self.teams.contains_key(&team_id)
    }

    /// ✅ **Get user's role within a team**
    pub fn get_team_role(&self, team_id: i32) -> Option<&String> {
        self.teams.get(&team_id)
    }

    /// ✅ **Check if user has a role in any team**
    pub fn is_in_any_team(&self) -> bool {
        !self.teams.is_empty()
    }

    /// ✅ **Check if user has explicit permissions for a product**
    pub fn has_explicit_product_permission(&self, product_id: i32) -> Option<&String> {
        self.explicit_product_permissions.get(&product_id)
    }

    /// ✅ **Check if user can edit a product**
    pub fn can_edit_product(&self, product_id: i32) -> bool {
        if let Some(role) = self.has_explicit_product_permission(product_id) {
            return role == "editor" || role == "team_lead" || self.is_admin();
        }

        self.task_order_permissions.values().any(|role| role == "editor" || role == "team_lead")
            || self.product_type_permissions.values().any(|role| role == "editor" || role == "team_lead")
            || self.is_admin()
    }

    /// ✅ **Check if user can view a product**
    pub fn can_view_product(&self, product_id: i32) -> bool {
        self.is_admin()
            || self.explicit_product_permissions.contains_key(&product_id)
            || !self.task_order_permissions.is_empty()
            || !self.product_type_permissions.is_empty()
    }

    /// ✅ **Check if user can add a member to a team**
    pub fn can_add_user_to_team(&self, team_id: i32, role: &str) -> bool {
        if self.is_admin() || self.is_manager() || self.is_team_lead(team_id) {
            return true;
        }
        false
    }

    /// ✅ **Check if user can remove a member from a team**
    pub fn can_remove_user_from_team(&self, team_id: i32, target_role: &str) -> bool {
        if self.is_admin() || self.is_manager() || self.is_team_lead(team_id) {
            return true;
        }
        false
    }

    /// ✅ **Check if user can assign a product to a team**
    pub fn can_assign_product_to_team(&self, team_id: i32) -> bool {
        self.is_admin() || self.is_manager() || self.is_team_lead(team_id)
    }

    /// ✅ **Check if user can remove a product from a team**
    pub fn can_remove_product_from_team(&self, team_id: i32) -> bool {
        self.is_admin() || self.is_manager() || self.is_team_lead(team_id)
    }
}


/// ✅ **RBAC Middleware with `moka`**
pub async fn rbac_middleware(
    State(db_pool): State<PgPool>,
    Extension(permission_cache): Extension<PermissionCache>, // ✅ Uses Axum **Extension**
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let claims = req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| {
            error!("Missing JWT claims in request");
            ApiResponse::<()>::error(
                StatusCode::UNAUTHORIZED,
                "Missing JWT claims in request",
                None,
            ).into_response()
        })?;

    let user_id: i32 = claims.sub.parse().map_err(|_| {
        error!("Invalid user ID format in JWT claims");
        ApiResponse::<()>::error(
            StatusCode::UNAUTHORIZED,
            "Invalid user ID format in JWT claims",
            None,
        ).into_response()
    })?;

    // ✅ **Check cache first before querying DB**
    if let Some(cached_permissions) = permission_cache.get(&user_id) {
        req.extensions_mut().insert(cached_permissions.clone());
        return Ok(next.run(req).await);
    }

    // ❌ **If not cached, query database**
    let user_permissions = match fetch_rbac_from_db(user_id, &db_pool).await {
        Ok(permissions) => permissions,
        Err(err) => {
            error!("Database query failed: {:?}", err);
            return Err(ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load user permissions",
                Some(json!({ "error": err.to_string() })),
            ).into_response());
        }
    };

    // ✅ **Cache the retrieved permissions**
    permission_cache.insert(user_id, user_permissions.clone()); // ✅ FIXED: No TTL argument

    // ✅ **Attach to request & continue**
    req.extensions_mut().insert(user_permissions);
    Ok(next.run(req).await)
}

/// ✅ **Query Database for RBAC Data**
async fn fetch_rbac_from_db(user_id: i32, pool: &PgPool) -> Result<UserPermissions, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        WITH user_teams AS (
            SELECT tm.team_id, tm.role
            FROM team_members tm 
            WHERE tm.user_id = $1
        )
        SELECT 
            u.role AS global_role,
            ut.team_id AS "team_id?",
            ut.role AS "team_role?",
            pt.product_id AS "product_id?",
            ptt.product_type_id AS "product_type_id?",
            tot.task_order_id AS "task_order_id?",
            etp.product_id AS "explicit_product_id?",
            etp.role AS "explicit_product_role?"
        FROM users u
        LEFT JOIN user_teams ut ON TRUE
        LEFT JOIN product_teams pt ON ut.team_id = pt.team_id
        LEFT JOIN product_type_teams ptt ON ut.team_id = ptt.team_id
        LEFT JOIN task_order_teams tot ON ut.team_id = tot.team_id
        LEFT JOIN explicit_team_product etp ON etp.user_id = u.id
        WHERE u.id = $1
        "#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let global_role = rows.first().map_or("user".to_string(), |r| r.global_role.clone());

    Ok(UserPermissions { user_id, global_role, teams: HashMap::new(), task_order_permissions: HashMap::new(), product_type_permissions: HashMap::new(), explicit_product_permissions: HashMap::new() })
}
