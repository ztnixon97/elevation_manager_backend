use async_graphql::{Context, Object, SimpleObject, InputObject, Result, ErrorExtensions};
use chrono::{NaiveDate, NaiveDateTime};
use sqlx::PgPool;
use crate::middleware::auth::UserPermissions;
use axum::Extension;

#[derive(SimpleObject, Clone)]
#[graphql(rename_args = "camelCase")]
pub struct TeamGQL {
    pub id: i32,
    pub name: String,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(InputObject)]
pub struct PaginationInput {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(SimpleObject)]
#[graphql(rename_args = "camelCase")]
pub struct PaginatedTeams {
    pub page: u32,
    pub total_pages: u32,
    pub total_count: i64,
    pub items: Vec<TeamGQL>,
}

#[derive(SimpleObject, Clone)]
#[graphql(rename_args = "camelCase")]
pub struct TaskOrderGQL {
    pub id: i32,
    pub name: String,
    pub producer: Option<String>,
}


#[derive(SimpleObject, Clone)]
#[graphql(rename_args = "camelCase")]
pub struct ReviewGQL {
    pub id: i32,
    pub review_status: String,
    pub product_status: String,
    pub review_path: String,
}

#[derive(SimpleObject, Clone)]
#[graphql(rename_args = "camelCase")]
pub struct UserGQL {
    pub id: i32,
    pub username: String,
    pub role: String,
}

#[derive(SimpleObject, Clone)]
#[graphql(rename_args = "camelCase")]
pub struct ProductGQL {
    pub id: Option<i32>,
    pub taskorder_id: Option<i32>,
    pub item_id: Option<String>,
    pub site_id: Option<String>,
    pub product_type_id: Option<i32>,
    pub status: Option<String>,
    pub status_date: Option<NaiveDate>,
    pub acceptance_date: Option<NaiveDate>,
    pub publish_date: Option<NaiveDate>,
    pub file_path: Option<String>,
    pub s2_index: Option<String>,
    pub geom: Option<String>,
    pub classification: Option<String>,
    pub created_at: Option<NaiveDateTime>,
}


#[derive(SimpleObject)]
#[graphql(rename_args = "camelCase")]
pub struct PaginatedProducts {
    pub page: u32,
    pub total_pages: u32,
    pub total_count: i64,
    pub items: Vec<ProductGQL>,
}


#[derive(Default)]
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn team(
        &self,
        ctx: &Context<'_>,
        id: i32
    ) -> Result<Option<TeamGQL>> {
        let user_permissions = ctx.data::<UserPermissions>()?;

        if !user_permissions.is_admin()
            && !user_permissions.is_manager()
            && !user_permissions.is_on_team(id)
        {
            return Err("Forbidden".extend_with(|_, e| {
                e.set("code", "FORBIDDEN");
                e.set("message", "You do not have permission to view this team");
            }));
        }

        let db = ctx.data::<PgPool>()?;
        let team = sqlx::query_as!(
            TeamGQL,
            "SELECT id, name, created_at FROM teams WHERE id = $1",
            id
        )
        .fetch_optional(db)
        .await?;

        Ok(team)
    }

    async fn teams(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
        
    ) -> Result<PaginatedTeams> {
        let user_permissions = ctx.data::<UserPermissions>()?;

        if !user_permissions.is_admin() && !user_permissions.is_manager() {
            return Err("Forbidden".extend_with(|_, e| {
                e.set("code", "FORBIDDEN");
                e.set("message", "You do not have permission to list teams");
            }));
        }

        let db = ctx.data::<PgPool>()?;
        let page = pagination.as_ref().and_then(|p| p.page).unwrap_or(1).max(1);
        let limit = pagination.as_ref().and_then(|p| p.limit).unwrap_or(10).max(1);
        let offset = (page - 1) * limit;

        let total_count: i64 = sqlx::query_scalar!("SELECT count(*) FROM teams")
            .fetch_one(db)
            .await?
            .unwrap_or(0);

        let teams = sqlx::query_as!(
            TeamGQL,
            "SELECT id, name, created_at FROM teams ORDER BY name LIMIT $1 OFFSET $2",
            limit as i64,
            offset as i64
        )
        .fetch_all(db)
        .await?;

        let total_pages = ((total_count as f64) / (limit as f64)).ceil() as u32;

        Ok(PaginatedTeams {
            page,
            total_pages,
            total_count,
            items: teams,
        })
    }

    async fn product(
        &self,
        ctx: &Context<'_>,
        id: i32,
        
    ) -> Result<Option<ProductGQL>> {
        let db = ctx.data::<PgPool>()?;
        let user_permissions = ctx.data::<UserPermissions>()?;

        let has_access = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM product_teams pt
                JOIN team_members tm ON pt.team_id = tm.team_id
                WHERE pt.product_id = $1 AND tm.user_id = $2
                UNION
                SELECT 1 FROM explicit_team_product
                WHERE product_id = $1 AND user_id = $2
            )
            "#,
            id,
            user_permissions.user_id
        )
        .fetch_one(db)
        .await?
        .unwrap_or(false);
    
        if !has_access && !user_permissions.is_admin() {
            return Err("Forbidden".extend_with(|_, e| {
                e.set("code", "FORBIDDEN");
                e.set("message", "You do not have permission to access this product");
            }));
        }
    
        let product = sqlx::query_as!(
            ProductGQL,
            r#"
            SELECT id, taskorder_id, item_id, site_id, product_type_id, status, status_date, 
                acceptance_date, publish_date, file_path, s2_index, ST_AsEWKT(geom) AS "geom",classification, created_at
            FROM products
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(db)
        .await?;
    
        Ok(product)
    }
    
    async fn products(
        &self,
        ctx: &Context<'_>,
        pagination: Option<PaginationInput>,
    ) -> Result<PaginatedProducts> {
        let db = ctx.data::<PgPool>()?;
        let page = pagination.as_ref().and_then(|p| p.page).unwrap_or(1).max(1);
        let limit = pagination.as_ref().and_then(|p| p.limit).unwrap_or(10).max(1);
        let offset = (page - 1) * limit;
        let user_permissions = ctx.data::<UserPermissions>()?;
    
        let rows = sqlx::query_as!(
            ProductGQL,
            r#"
            SELECT 
                p.id, 
                p.taskorder_id, 
                p.item_id, 
                p.site_id, 
                p.product_type_id, 
                p.status, 
                p.status_date, 
                p.acceptance_date, 
                p.publish_date, 
                p.file_path, 
                p.s2_index, 
                ST_AsEWKT(p.geom) AS geom, 
                p.classification, 
                p.created_at
            FROM products p
            JOIN product_teams pt ON p.id = pt.product_id
            JOIN team_members tm ON pt.team_id = tm.team_id
            WHERE tm.user_id = $1

            UNION ALL

            SELECT 
                p.id, 
                p.taskorder_id, 
                p.item_id, 
                p.site_id, 
                p.product_type_id, 
                p.status, 
                p.status_date, 
                p.acceptance_date, 
                p.publish_date, 
                p.file_path, 
                p.s2_index, 
                ST_AsEWKT(p.geom) AS geom, 
                p.classification, 
                p.created_at
            FROM products p
            JOIN explicit_team_product etp ON p.id = etp.product_id
            WHERE etp.user_id = $1
            ORDER BY status DESC
            LIMIT $2 OFFSET $3;
            "#,
            user_permissions.user_id,
            limit as i64,
            offset as i64
        )
        .fetch_all(db)
        .await
        .map_err(|e| async_graphql::Error::new(e.to_string()))?;
    
        let total_count: i64 = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM products p
                JOIN product_teams pt ON p.id = pt.product_id
                JOIN team_members tm ON pt.team_id = tm.team_id
                WHERE tm.user_id = $1
                UNION ALL
                SELECT 1 FROM products p
                JOIN explicit_team_product etp ON p.id = etp.product_id
                WHERE etp.user_id = $1
            ) sub
            "#,
            user_permissions.user_id
        )
        .fetch_one(db)
        .await?
        .unwrap_or(0);
    
        let total_pages = ((total_count as f64) / (limit as f64)).ceil() as u32;
    
        Ok(PaginatedProducts {
            page,
            total_pages,
            total_count,
            items: rows,
        })
    }
    

    async fn task_orders(
        &self,
        ctx: &Context<'_>,
        
    ) -> Result<Vec<TaskOrderGQL>> {
        let db = ctx.data::<PgPool>()?;
        let user_permissions = ctx.data::<UserPermissions>()?;

        if user_permissions.is_admin() || user_permissions.is_manager() {
            return Ok(sqlx::query_as!(
                TaskOrderGQL,
                "SELECT id, name, producer FROM taskorders ORDER BY name"
            )
            .fetch_all(db)
            .await.map_err(|e| async_graphql::Error::new(e.to_string()))?);


        }

        let assigned = sqlx::query_as!(
            TaskOrderGQL,
            r#"
            SELECT t.id, t.name, t.producer
            FROM taskorders t
            JOIN task_order_teams tot ON t.id = tot.task_order_id
            JOIN team_members tm ON tm.team_id = tot.team_id
            WHERE tm.user_id = $1
            ORDER BY t.name
            "#,
            user_permissions.user_id
        )
        .fetch_all(db)
        .await?;

        Ok(assigned)
    }

    async fn task_order(
        &self,
        ctx: &Context<'_>,
        id: i32,
        
    ) -> Result<Option<TaskOrderGQL>> {
        let db = ctx.data::<PgPool>()?;
        let user_permissions = ctx.data::<UserPermissions>()?;

        if user_permissions.is_admin() || user_permissions.is_manager() {
            return Ok(sqlx::query_as!(
                TaskOrderGQL,
                "SELECT id, name, producer FROM taskorders WHERE id = $1",
                id
            )
            .fetch_optional(db)
            .await.map_err(|e| async_graphql::Error::new(e.to_string()))?);


        }

        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM task_order_teams tot
                JOIN team_members tm ON tot.team_id = tm.team_id
                WHERE tot.task_order_id = $1 AND tm.user_id = $2
            )
            "#,
            id,
            user_permissions.user_id
        )
        .fetch_one(db)
        .await?
        .unwrap_or(false);

        if !exists {
            return Err("Forbidden".extend_with(|_, e| {
                e.set("code", "FORBIDDEN");
                e.set("message", "You do not have access to this task order");
            }));
        }

        let task = sqlx::query_as!(
            TaskOrderGQL,
            "SELECT id, name, producer FROM taskorders WHERE id = $1",
            id
        )
        .fetch_optional(db)
        .await?;

        Ok(task)
    }
    async fn reviews(
        &self,
        ctx: &Context<'_>,
        
    ) -> Result<Vec<ReviewGQL>> {
        let db = ctx.data::<PgPool>()?;
        let user_permissions = ctx.data::<UserPermissions>()?;

        let reviews = if user_permissions.is_admin() {
            sqlx::query_as!(
                ReviewGQL,
                "SELECT id, review_status, product_status, review_path FROM reviews ORDER BY created_at DESC"
            )
            .fetch_all(db)
            .await?
        } else {
            sqlx::query_as!(
                ReviewGQL,
                r#"
                SELECT r.id, r.review_status, r.product_status, r.review_path
                FROM reviews r
                WHERE r.reviewer_id = $1
                OR EXISTS (
                    SELECT 1
                    FROM product_teams pt
                    JOIN team_members tm ON pt.team_id = tm.team_id
                    WHERE pt.product_id = r.product_id
                    AND tm.user_id = $1
                )
                OR EXISTS (
                    SELECT 1 FROM explicit_team_product etp
                    WHERE etp.product_id = r.product_id AND etp.user_id = $1
                )
                ORDER BY r.created_at DESC
                "#,
                user_permissions.user_id
            )
            .fetch_all(db)
            .await?
        };
    
        Ok(reviews)
    }
    async fn review(
        &self,
        ctx: &Context<'_>,
        id: i32,
        
    ) -> Result<Option<ReviewGQL>> {
        let db = ctx.data::<PgPool>()?;
        let user_permissions = ctx.data::<UserPermissions>()?;

        let review = sqlx::query!(
            "SELECT product_id, reviewer_id FROM reviews WHERE id = $1",
            id
        )
        .fetch_optional(db)
        .await?;
    
        let Some(r) = review else {
            return Ok(None);
        };
    
        if user_permissions.is_admin() || r.reviewer_id == user_permissions.user_id {
            return Ok(sqlx::query_as!(
                ReviewGQL,
                "SELECT id, review_status, product_status, review_path FROM reviews WHERE id = $1",
                id
            )
            .fetch_optional(db)
            .await.map_err(|e| async_graphql::Error::new(e.to_string()))?);


        }
    
        let has_access = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM product_teams pt
                JOIN team_members tm ON pt.team_id = tm.team_id
                WHERE pt.product_id = $1 AND tm.user_id = $2
                UNION
                SELECT 1 FROM explicit_team_product
                WHERE product_id = $1 AND user_id = $2
            )
            "#,
            r.product_id,
            user_permissions.user_id
        )
        .fetch_one(db)
        .await?
        .unwrap_or(false);
    
        if has_access {
            return Ok(sqlx::query_as!(
                ReviewGQL,
                "SELECT id, review_status, product_status, review_path FROM reviews WHERE id = $1",
                id
            )
            .fetch_optional(db)
            .await.map_err(|e| async_graphql::Error::new(e.to_string()))?);


        }
    
        Err("Forbidden".extend_with(|_, e| {
            e.set("code", "FORBIDDEN");
            e.set("message", "You do not have access to this review");
        }))
    }
    
    async fn users(
        &self,
        ctx: &Context<'_>,
        
    ) -> Result<Vec<UserGQL>> {
        let user_permissions = ctx.data::<UserPermissions>()?;

        if !user_permissions.is_admin() && !user_permissions.is_manager() {
            return Err("Forbidden".extend_with(|_, e| {
                e.set("code", "FORBIDDEN");
                e.set("message", "Only admins and managers can list users");
            }));
        }

        let db = ctx.data::<PgPool>()?;
        let users = sqlx::query_as!(
            UserGQL,
            "SELECT id, username, role FROM users ORDER BY username"
        )
        .fetch_all(db)
        .await?;

        Ok(users)
    }

    async fn user(
        &self,
        ctx: &Context<'_>,
        id: i32,
        
    ) -> Result<Option<UserGQL>> {
        let db = ctx.data::<PgPool>()?;
        let user_permissions = ctx.data::<UserPermissions>()?;

        if !user_permissions.is_admin()
            && !user_permissions.is_manager()
            && user_permissions.user_id != id
        {
            return Err("Forbidden".extend_with(|_, e| {
                e.set("code", "FORBIDDEN");
                e.set("message", "You can only access your own user record");
            }));
        }

        let user = sqlx::query_as!(
            UserGQL,
            "SELECT id, username, role FROM users WHERE id = $1",
            id
        )
        .fetch_optional(db)
        .await?;

        Ok(user)
    }
}
