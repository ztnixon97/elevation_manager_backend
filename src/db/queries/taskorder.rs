use axum::{
    extract::{State, Path},
    Json,
    http::StatusCode,
};
use sqlx::{PgPool, QueryBuilder};
use serde_json::json;

use crate::db::models::{product::ProductResponse, taskorder::{NewTaskOrder, TaskIdResponse, TaskOrder, UpdateTaskOrder}};
use crate::utils::api_response::ApiResponse;

/// Creates a new TaskOrder
#[utoipa::path(
    post,
    path = "/taskorders",
    request_body = NewTaskOrder,
    responses(
        (
            status = 201,
            description = "Successfully created Task Order",
            body = i32
        ),
        (
            status = 500,
            description = "Internal Server Error"
        )
    ),
    tag = "Task Orders",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_task_order(
    State(pool): State<PgPool>,
    Json(new_order): Json<NewTaskOrder>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    // Insert the new task_order into the DB
    let result = sqlx::query!(
        r#"
        INSERT INTO taskorders (
            contract_id,
            name,
            producer,
            cor,
            pop,
            price,
            status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
        new_order.contract_id,
        new_order.name,
        new_order.producer,
        new_order.cor,
        new_order.pop,    // bracket-range -> DATERANGE
        new_order.price,
        new_order.status
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to create TaskOrder",
        Some(json!({ "db_error": e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::CREATED,
        "TaskOrder created successfully",
        result.id,
    ))
}

/// Retrieves all TaskOrders
#[utoipa::path(
    get,
    path = "/taskorders",
    responses(
        (
            status = 200,
            description = "Successfully retreived task orders",
            body = Vec<TaskOrder>
        ),
        (
            status = 500,
            description = "Failed to retrieve task orders"
        )
    ),
    tag = "Task Orders",
    security(
        ("bearerAuth"= [])
    )
)]
pub async fn get_all_taskorders(
    State(pool): State<PgPool>,
) -> Result<ApiResponse<Vec<TaskOrder>>, ApiResponse<()>> {
    let taskorders = sqlx::query_as!(
        TaskOrder,
        // If your columns match exactly, SELECT * is fine
        r#"SELECT
             id,
             contract_id,
             name,
             producer,
             cor,
             pop as "pop: _",      -- important for range fields: "pop: PgRange<NaiveDate>"
             price,
             status,
             created_at
           FROM taskorders
           ORDER BY id
        "#
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve TaskOrders",
        Some(json!({ "db_error": e.to_string() }))
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "TaskOrders retrieved successfully",
        taskorders,
    ))
}

/// Retrieves a specific TaskOrder by ID
#[utoipa::path(
    get,
    path = "/taskorders/{task_id}",
    params(
        ("task_id" = i32, Path, description= "id of task order"),
    ),
    responses(
        (
            status = 200,
            description = "Task Order Retrived Successfully",
            body = TaskOrder
        ),
        (
            status = 404, description = "Task Order not found"
        ),
        (
            status = 500,
            description = "Failed to fetch task order"
        )
    ),
    tag = "Task Orders",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_task_order(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
) -> Result<ApiResponse<TaskOrder>, ApiResponse<()>> {
    let task_order = sqlx::query_as!(
        TaskOrder,
        r#"
        SELECT
            id,
            contract_id,
            name,
            producer,
            cor,
            pop as "pop: _",      -- parse into PgRange<NaiveDate>
            price,
            status,
            created_at
        FROM taskorders
        WHERE id = $1
        "#,
        id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(
        StatusCode::NOT_FOUND,
        "TaskOrder not found",
        None
    ))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "TaskOrder retrieved successfully",
        task_order,
    ))
}

/// Macro for partial updates in an UPDATE statement:
macro_rules! push_if_some {
    ($separated:ident, $update:ident, $field:ident) => {
        if let Some(value) = &$update.$field {
            $separated.push(concat!(stringify!($field), " = ")).push_bind(value);
        }
    };
}

/// Updates an existing TaskOrder
#[utoipa::path(
    put,
    path = "/taskorders/{task_id}",
    params(
        ("task_id" = i32, Path, description = "ID of the task order to be updated"),
    ),
    request_body = UpdateTaskOrder,
    responses(
        (status = 200, description = "Task order updated successfully"),
        (status = 400, description = "No fields provided for update"),
        (status = 404, description = "Task order not found"),
        (status = 500, description = "Failed to update task order"),
    ),
    tag = "Task Orders",
    security(
        ("bearerAuth"= [])
    )
)]
pub async fn update_task_order(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
    Json(update): Json<UpdateTaskOrder>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    // If no fields were provided, return BAD_REQUEST
    if update.is_empty() {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No fields provided for update",
            None,
        ));
    }

    let mut query_builder = QueryBuilder::new("UPDATE taskorders SET ");
    let mut separated = query_builder.separated(", ");

    // For each field in UpdateTaskOrder, if Some(...) => set that column
    push_if_some!(separated, update, contract_id);
    push_if_some!(separated, update, name);
    push_if_some!(separated, update, producer);
    push_if_some!(separated, update, cor);
    push_if_some!(separated, update, pop);      // bracket-range -> DATERANGE
    push_if_some!(separated, update, price);
    push_if_some!(separated, update, status);

    // Always update updated_at to now()
    separated.push("updated_at = NOW()");
    // Add WHERE clause
    query_builder.push(" WHERE id = ").push_bind(id);

    let query = query_builder.build();
    let result = query
        .execute(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update TaskOrder",
            Some(json!({ "db_error": e.to_string() }))
        ))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "TaskOrder not found",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "TaskOrder updated successfully",
        (),
    ))
}

/// Deletes a TaskOrder
#[utoipa::path(
    delete,
    path = "/taskorders/{task_id}",
    params(
        ("task_id"= i32, Path, description = "ID of the task order to be deleted")
    ),
    responses(
        (status = 200, description = "Task order deleted successfully"),
        (status = 404, description = "Task order not found"),
        (status = 500, description = "Failed to delete task order")
    ),
    tag = "Task Orders",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_task_order(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let result = sqlx::query!(
        "DELETE FROM taskorders WHERE id = $1",
        id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to delete TaskOrder",
        Some(json!({ "db_error": e.to_string() }))
    ))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "TaskOrder not found",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "TaskOrder deleted successfully",
        (),
    ))
}

#[utoipa::path(
    get,
    path = "/taskorders/id/{task_name}",
    params(
        ("task_name" = String, Path, description = "Name of the task order")
    ),
    responses(
        (status = 200, description = "Task Order ID retrived successfully"),
        (status = 404, description = "Task Order Not Found"),
        (status = 500, description = "Internal Server error")
    ),
    tag = "Task Orders",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_task_id(
    State(db_pool): State<PgPool>,
    Path(task_name): Path<String>,
) -> Result<ApiResponse<TaskIdResponse>, ApiResponse<()>> {
    let task = sqlx::query!(
        "SELECT id AS task_id FROM taskorders WHERE name = $1",
        task_name
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Task Order not found", None))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
         "Task Order ID retrived successfully",
          TaskIdResponse { id: task.task_id },
        ))
}


use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        create_task_order,
        get_all_taskorders,
        get_task_order,
        update_task_order,
        delete_task_order,
        get_task_id
    ),
    components(
        schemas(TaskOrder, UpdateTaskOrder, NewTaskOrder, TaskIdResponse)  // ✅ Fixed `components`
    ),
    tags(
        (name = "Task Orders", description = "Task Order API Endpoints")
    )
)]
pub struct TaskOrderDoc;
