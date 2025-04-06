use axum::{
    extract::{State, Path, Query},
    Json,
    http::StatusCode,
};
use sqlx::{PgPool, QueryBuilder};
use serde_json::json;
use utoipa::ToSchema;

use crate::db::models::contract::{Contract, NewContract, UpdateContract};
use crate::utils::api_response::ApiResponse;

/// Creates a new contract
#[utoipa::path(
    post,
    path = "/contracts",
    request_body = NewContract,
    responses(
        (status = 201, description = "Successfully created contract", body = i32),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "Contracts",
    security(("bearerAuth" = []))
)]
pub async fn create_contract(
    State(pool): State<PgPool>,
    Json(new_contract): Json<NewContract>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    let result = sqlx::query!(
        r#"
        INSERT INTO contracts (
            number, name, awarding_agency, award_date, start_date, end_date,
            modification_date, current_obligation, current_spend, spend_ceiling,
            base_value, funding_source, status, pop_start_date, pop_end_date, 
            option_years, reporting_frequency, last_report_date, prime_contractor, 
            contract_type, classification
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 
            $16, $17, $18, $19, $20, $21
        )
        RETURNING id
        "#,
        new_contract.number, new_contract.name, new_contract.awarding_agency,
        new_contract.award_date, new_contract.start_date, new_contract.end_date,
        new_contract.modification_date, new_contract.current_obligation,
        new_contract.current_spend, new_contract.spend_ceiling,
        new_contract.base_value, new_contract.funding_source, new_contract.status,
        new_contract.pop_start_date, new_contract.pop_end_date,
        new_contract.option_years, new_contract.reporting_frequency,
        new_contract.last_report_date, new_contract.prime_contractor,
        new_contract.contract_type, new_contract.classification
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Failed to create contract", 
        Some(json!({ "db_error": e.to_string() })))
    )?;

    Ok(ApiResponse::success(StatusCode::CREATED, "Contract created successfully", result.id))
}

/// Retrieves all contracts
#[utoipa::path(
    get,
    path = "/contracts",
    responses(
        (status = 200, description = "Successfully retrieved contracts", body = Vec<Contract>),
        (status = 500, description = "Failed to retrieve contracts")
    ),
    tag = "Contracts",
    security(("bearerAuth"= []))
)]
pub async fn get_all_contracts(
    State(pool): State<PgPool>,
) -> Result<ApiResponse<Vec<Contract>>, ApiResponse<()>> {
    let contracts = sqlx::query_as!(
        Contract,
        r#"SELECT * FROM contracts ORDER BY name"#
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve contracts", 
        Some(json!({ "db_error": e.to_string() })))
    )?;

    Ok(ApiResponse::success(StatusCode::OK, "Contracts retrieved successfully", contracts))
}

/// Retrieves a specific contract by ID
#[utoipa::path(
    get,
    path = "/contracts/{contract_id}",
    params(("contract_id" = i32, Path, description= "ID of the Contract")),
    responses(
        (status = 200, description = "Contract retrieved successfully", body = Contract),
        (status = 404, description = "Contract not found"),
        (status = 500, description = "Failed to fetch contract")
    ),
    tag = "Contracts",
    security(("bearerAuth" = []))
)]
pub async fn get_contract(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
) -> Result<ApiResponse<Contract>, ApiResponse<()>> {
    let contract = sqlx::query_as!(
        Contract,
        r#"SELECT * FROM contracts WHERE id = $1"#,
        id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(
        StatusCode::NOT_FOUND, "Contract not found", None
    ))?;

    Ok(ApiResponse::success(StatusCode::OK, "Contract retrieved successfully", contract))
}

/// Macro for dynamically updating fields in SQL query
macro_rules! push_if_some {
    ($separated:ident, $update:ident, $field:ident) => {
        if let Some(value) = &$update.$field {
            $separated.push(concat!(stringify!($field), " = ")).push_bind(value);
        }
    };
}

/// Updates an existing contract
#[utoipa::path(
    put,
    path = "/contracts/{contract_id}",
    params(("contract_id" = i32, Path, description = "ID of the Contract to be updated")),
    request_body = UpdateContract,
    responses(
        (status = 200, description = "Contract updated successfully"),
        (status = 400, description = "No fields provided for update"),
        (status = 404, description = "Contract not found"),
        (status = 500, description = "Failed to update contract")
    ),
    tag = "Contracts",
    security(("bearerAuth"= []))
)]
pub async fn update_contract(
    State(pool): State<PgPool>,
    Path(id): Path<i32>,
    Json(update): Json<UpdateContract>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if update.is_empty() {
        return Err(ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "No fields provided for update", None));
    }

    let mut query_builder = QueryBuilder::new("UPDATE contracts SET ");
    let mut separated = query_builder.separated(", ");

    push_if_some!(separated, update, name);
    push_if_some!(separated, update, status);
    push_if_some!(separated, update, awarding_agency);
    push_if_some!(separated, update, contract_type);
    push_if_some!(separated, update, classification);
    push_if_some!(separated, update, prime_contractor);
    push_if_some!(separated, update, pop_start_date);
    push_if_some!(separated, update, pop_end_date);
    push_if_some!(separated, update, reporting_frequency);
    push_if_some!(separated, update, current_obligation);
    push_if_some!(separated, update, current_spend);
    push_if_some!(separated, update, spend_ceiling);
    push_if_some!(separated, update, base_value);

    separated.push("updated_at = NOW()");
    query_builder.push(" WHERE id = ").push_bind(id);

    let query = query_builder.build();
    let result = query.execute(&pool).await.map_err(|e| ApiResponse::<()>::error(
        StatusCode::INTERNAL_SERVER_ERROR, "Failed to update contract",
        Some(json!({ "db_error": e.to_string() })))
    )?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Contract not found", None));
    }

    Ok(ApiResponse::success(StatusCode::OK, "Contract updated successfully", ()))
}

/// Deletes a contract
#[utoipa::path(
    delete,
    path = "/contracts/{contract_id}",
    params(("contract_id"= i32, Path, description = "ID of the Contract to be deleted")),
    responses(
        (status = 200, description = "Contract deleted successfully"),
        (status = 404, description = "Contract not found"),
        (status = 500, description = "Failed to delete contract")
    ),
    tag = "Contracts",
    security(("bearerAuth" = []))
)]
pub async fn delete_contract(
    State(pool): State<PgPool>,
    Path(id): Path<i32>
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let result = sqlx::query!("DELETE FROM contracts WHERE id = $1", id)
        .execute(&pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete contract", Some(json!({ "db_error": e.to_string() }))))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Contract not found", None));
    }

    Ok(ApiResponse::success(StatusCode::OK, "Contract deleted successfully", ()))
}
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        create_contract,
        get_all_contracts,
        get_contract,
        update_contract,
        delete_contract
    ),
    components(
        schemas(Contract, NewContract, UpdateContract)
    ),
    tags(
        (name = "Contracts", description = "Contract API Endpoints")
    )
)]
pub struct ContractDoc;


// #[utoipa::path(
//     post,
//     path = "/contracts/{contract_id}/modifications",
//     params(("contract_id" = i32, Path, description = "ID of the Contract")),
//     request_body = ContractModification,
//     responses(
//         (status = 201, description = "Successfully created contract modification and updated contract", body = i32),
//         (status = 500, description = "Internal Server Error")
//     ),
//     tag = "Contracts",
//     security(("bearerAuth" = []))
// )]
// pub async fn create_contract_modification(
//     State(pool): State<PgPool>,
//     Path(contract_id): Path<i32>,
//     Json(new_modification): Json<ContractModification>,
// ) -> Result<ApiResponse<i32>, ApiResponse<()>> {
//     let mut transaction = pool.begin().await.map_err(|e| ApiResponse::<()>::error(
//         StatusCode::INTERNAL_SERVER_ERROR, "Failed to start transaction",
//         Some(json!({ "db_error": e.to_string() })))
//     )?;

//     // **Get the current contract value**
//     let contract = sqlx::query!(
//         "SELECT spend_ceiling, end_date FROM contracts WHERE id = $1",
//         contract_id
//     )
//     .fetch_one(&mut *transaction)
//     .await
//     .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Contract not found", None))?;

//     // **Insert modification**
//     let result = sqlx::query!(
//         r#"
//         INSERT INTO contract_modifications (
//             contract_id, modification_number, modification_date, description, modification_type,
//             previous_value, modified_value, new_end_date, justification, modification_document, modified_by
//         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
//         RETURNING id
//         "#,
//         contract_id,
//         new_modification.modification_number,
//         new_modification.modification_date,
//         new_modification.description,
//         new_modification.modification_type,
//         contract.spend_ceiling, // Previous contract value
//         new_modification.modified_value,
//         new_modification.new_end_date,
//         new_modification.justification,
//         new_modification.modification_document,
//         new_modification.modified_by
//     )
//     .fetch_one(&mut *transaction)
//     .await
//     .map_err(|e| ApiResponse::<()>::error(
//         StatusCode::INTERNAL_SERVER_ERROR, "Failed to create contract modification",
//         Some(json!({ "db_error": e.to_string() })))
//     )?;

//     // **Update main contract with new value or end date**
//     let updated_rows = sqlx::query!(
//         r#"
//         UPDATE contracts
//         SET spend_ceiling = $1, end_date = COALESCE($2, end_date)
//         WHERE id = $3
//         "#,
//         new_modification.modified_value,
//         new_modification.new_end_date,
//         contract_id
//     )
//     .execute(&mut *transaction)
//     .await
//     .map_err(|e| ApiResponse::<()>::error(
//         StatusCode::INTERNAL_SERVER_ERROR, "Failed to update contract",
//         Some(json!({ "db_error": e.to_string() })))
//     )?;

//     if updated_rows.rows_affected() == 0 {
//         return Err(ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Contract not found", None));
//     }

//     // **Commit transaction**
//     transaction.commit().await.map_err(|e| ApiResponse::<()>::error(
//         StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit transaction",
//         Some(json!({ "db_error": e.to_string() })))
//     )?;

//     Ok(ApiResponse::success(
//         StatusCode::CREATED,
//         "Contract modification created and contract updated successfully",
//         result.id
//     ))
// }


// #[utoipa::path(
//     get,
//     path = "/contracts/{contract_id}/modifications",
//     params(("contract_id" = i32, Path, description = "ID of the Contract")),
//     responses(
//         (status = 200, description = "Successfully retrieved contract modifications", body = Vec<ContractModification>),
//         (status = 500, description = "Failed to retrieve contract modifications")
//     ),
//     tag = "Contracts",
//     security(("bearerAuth"= []))
// )]
// pub async fn get_contract_modifications(
//     State(pool): State<PgPool>,
//     Path(contract_id): Path<i32>,
// ) -> Result<ApiResponse<Vec<ContractModification>>, ApiResponse<()>> {
//     let modifications = sqlx::query_as!(
//         ContractModification,
//         r#"SELECT * FROM contract_modifications WHERE contract_id = $1 ORDER BY modification_date"#,
//         contract_id
//     )
//     .fetch_all(&pool)
//     .await
//     .map_err(|e| ApiResponse::<()>::error(
//         StatusCode::INTERNAL_SERVER_ERROR, "Failed to retrieve contract modifications",
//         Some(json!({ "db_error": e.to_string() })))
//     )?;

//     Ok(ApiResponse::success(StatusCode::OK, "Contract modifications retrieved successfully", modifications))
// }
