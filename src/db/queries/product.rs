use axum::{
    extract::{State, Path, Query},
    Json,
    http::StatusCode,
};
use serde::Deserialize;
use sqlx::{PgPool, QueryBuilder, Row};
use serde_json::{json, Value};
use s2::{cellid::CellID, cell::Cell, latlng::LatLng};
use crate::db::models::{
    product::{ProductIdResponse, BulkUpdateByFilterParams, BulkUpdateProducts, NewProduct, NewProductType, Product, ProductFilterParams, ProductResponse, ProductType, UpdateProduct},
    review::Review 
};
use crate::utils::api_response::ApiResponse;

// Utility Functions

fn s2_to_polygon(s2_token: &str) -> Result<Vec<(f64, f64)>, String> {
    let cell_id = CellID::from_token(s2_token);
    if !cell_id.is_valid() {
        return Err(format!("Invalid S2 token: {s2_token}"));
    }

    let cell = Cell::from(cell_id);
    let mut polygon_coords = Vec::new();
    for i in 0..4 {
        let vertex = LatLng::from(cell.vertex(i));
        polygon_coords.push((vertex.lng.deg(), vertex.lat.deg()));
    }
    polygon_coords.push(polygon_coords[0]);
    Ok(polygon_coords)
}

pub fn detect_geometry_format(geometry: &Value) -> Result<String, String> {
    if let Some(obj) = geometry.as_object() {
        let geojson_str = serde_json::to_string(obj)
            .map_err(|e| format!("Failed to serialize GeoJSON: {e}"))?;
        return Ok(format!("ST_GeomFromGeoJSON('{geojson_str}')"));
    }

    let Some(s) = geometry.as_str() else {
        return Err("Invalid geometry format. Must be GeoJSON, WKT, WKB, EWKT, or EWKB.".to_string());
    };

    let s_trim = s.trim();
    let upper = s_trim.to_uppercase();

    if upper.starts_with("SRID=") {
        return Ok(format!("ST_GeomFromEWKT('{s_trim}')"));
    }

    if upper.starts_with("POINT(")
        || upper.starts_with("LINESTRING(")
        || upper.starts_with("POLYGON(")
        || upper.starts_with("MULTI")
        || upper.starts_with("GEOMETRYCOLLECTION(")
    {
        return Ok(format!("ST_GeomFromText('{s_trim}', 4326)"));
    }

    let maybe_hex = s_trim.trim_start_matches("0x").trim_start_matches("0X");
    if !maybe_hex.is_empty() && maybe_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(format!("ST_GeomFromEWKB(E'\\\\x{maybe_hex}')"));
    }

    Err("Unrecognized geometry format.".to_string())
}

// API Handlers
#[utoipa::path(
    post,
    path = "/products",
    request_body = NewProduct,
    responses(
        (
            status = 201, 
            description = "Successfully created product", 
            body = i32
        ),
        (
            status = 400, 
            description = "No valid geometry or S2 index provided or invalid data"
        ),
        (
            status = 500,
            description = "Failed to insert product or other internal error"
        )
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_product(
    State(db_pool): State<PgPool>,
    Json(payload): Json<NewProduct>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    let geometry_expr = if let Some(geom) = &payload.geom {
        detect_geometry_format(geom).map_err(|msg| {
            ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "Invalid geometry format", Some(json!({ "error": msg })))
        })?
    } else if let Some(s2) = &payload.s2_index {
        let mut polygon_coords = s2_to_polygon(s2).map_err(|msg| {
            ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "Invalid S2 index", Some(json!({ "error": msg })))
        })?;

        if polygon_coords.first() != polygon_coords.last() {
            polygon_coords.push(polygon_coords[0]);
        }

        let geojson_polygon = json!({
            "type": "Polygon",
            "coordinates": [polygon_coords.iter().map(|(lon, lat)| vec![*lon, *lat]).collect::<Vec<_>>()],
        });

        detect_geometry_format(&geojson_polygon).map_err(|msg| {
            ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "Failed to generate geometry", Some(json!({ "error": msg })))
        })?
    } else {
        return Err(ApiResponse::<()>::error(StatusCode::BAD_REQUEST, "No valid geometry or S2 index provided", None));
    };

    let mut query_builder = QueryBuilder::new(
        "INSERT INTO products (taskorder_id, item_id, site_id, product_type_id, status, 
         status_date, acceptance_date, publish_date, file_path, s2_index, classification, geom, created_at) VALUES (",
    );

    query_builder
        .push_bind(payload.taskorder_id)
        .push(", ")
        .push_bind(payload.item_id.clone())
        .push(", ")
        .push_bind(payload.site_id.clone())
        .push(", ")
        .push_bind(payload.product_type_id)
        .push(", ")
        .push_bind(payload.status.clone())
        .push(", ")
        .push_bind(payload.status_date)
        .push(", ")
        .push_bind(payload.acceptance_date)
        .push(", ")
        .push_bind(payload.publish_date)
        .push(", ")
        .push_bind(payload.file_path.clone())
        .push(", ")
        .push_bind(payload.s2_index.clone())
        .push(", ")
        .push_bind(payload.classification)
        .push(", ")
        .push(format!("{geometry_expr}, NOW()) RETURNING id"));

    let query = query_builder.build();
    let row = query.fetch_one(&db_pool).await.map_err(|e| {
        ApiResponse::<()>::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to insert product", Some(json!({ "message": e.to_string() })))
    })?;

    let new_id: i32 = row.get("id");

    Ok(ApiResponse::success(StatusCode::CREATED, "Product created successfully", new_id))
}
/// Retrieves a single product by ID
#[utoipa::path(
    get,
    path = "/products/{product_id}",
    params(
        ("product_id" = i32, Path, description = "ID of the product to retrieve")
    ),
    responses(
        (status = 200, description = "Product retrieved successfully", body = ProductResponse),
        (status = 404, description = "Product not found"),
        (status = 500, description = "Failed to fetch reviews or other database error")
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_product(
    State(db_pool): State<PgPool>,
    Path(product_id): Path<i32>,
) -> Result<ApiResponse<ProductResponse>, ApiResponse<()>> {
    let product = sqlx::query_as!(
        Product,
        r#"
        SELECT id, taskorder_id, item_id, site_id, product_type_id, status, status_date, 
            acceptance_date, publish_date, file_path, s2_index, ST_AsEWKT(geom) AS "geom",classification, created_at
        FROM products
        WHERE id = $1
        "#,
        product_id
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Product not found", None))?;

    let reviews: Vec<Review> = sqlx::query_as!(
        Review,
        r#"
        SELECT id, product_id, reviewer_id, review_status, product_status, review_path, created_at, updated_at
        FROM reviews
        WHERE product_id = $1
        "#,
        product_id
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|e| ApiResponse::<()>::error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch reviews", Some(json!({ "message": e.to_string() }))))?;

    Ok(ApiResponse::success(StatusCode::OK, "Product retrieved successfully", ProductResponse { product, reviews }))
}


#[utoipa::path(
    get,
    path = "/products/id/{product_site}",
    params(
        ("product_site" = String, Path, description = "Site name to fetch the product ID")
    ),
    responses(
        (status = 200, description = "Product ID retrieved successfully", body = ProductIdResponse),
        (status = 404, description = "Product not found"),
        (status = 500, description = "Internal server error")
    ),
    tag="Products",
    security(
        ("bearerAuth" = [])
    )
    
)]
pub async fn get_product_id(
    State(db_pool): State<PgPool>,
    Path(product_site): Path<String>,
) -> Result<ApiResponse<ProductIdResponse>, ApiResponse<()>> {
    let product = sqlx::query!(
        r#"
        SELECT id AS product_id FROM products WHERE site_id = $1
        "#,
        product_site
    )
    .fetch_one(&db_pool)
    .await
    .map_err(|_| ApiResponse::<()>::error(StatusCode::NOT_FOUND, "Product not found", None))?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product ID retrieved successfully",
        ProductIdResponse { id: product.product_id },
    ))
}

/// Retrieves all products with pagination
#[utoipa::path(
    get,
    path = "/products",
    params(
        ProductFilterParams,
    ),
    responses(
        (
            status = 200,
            description = "Successfully retrieved a paginated list of products",
            body = Vec<ProductResponse>
        ),
        (
            status = 500,
            description = "Failed to retrive products"
        )
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]

pub async fn get_products(
    State(db_pool): State<PgPool>,
    Query(params): Query<ProductFilterParams>,
) -> Result<ApiResponse<Value>, ApiResponse<()>> {
    let mut query_builder = QueryBuilder::new(
        "SELECT id, taskorder_id, item_id, site_id, product_type_id, status, 
            status_date, acceptance_date, publish_date, file_path, s2_index, 
            ST_AsEWKT(geom) AS geom, classification, created_at FROM products"
    );

    let mut count_query_builder = QueryBuilder::new("SELECT COUNT(id) FROM products");

    let mut has_conditions = false; // Track if WHERE conditions exist

    macro_rules! push_if_some {
        ($field:ident) => {
            if let Some(value) = &params.$field {
                if has_conditions {
                    query_builder.push(" AND ");
                    count_query_builder.push(" AND ");
                } else {
                    query_builder.push(" WHERE ");
                    count_query_builder.push(" WHERE ");
                    has_conditions = true;
                }
                query_builder.push(stringify!($field)).push(" = ").push_bind(value);
                count_query_builder.push(stringify!($field)).push(" = ").push_bind(value);
            }
        };
    }

    push_if_some!(taskorder_id);
    push_if_some!(item_id);
    push_if_some!(site_id);
    push_if_some!(product_type_id);
    push_if_some!(status);
    push_if_some!(file_path);
    push_if_some!(s2_index);
    push_if_some!(classification);

    // Handle date range filters
    macro_rules! push_date_range {
        ($field:ident, $min:ident, $max:ident) => {
            if let Some(min_date) = &params.$min {
                if has_conditions {
                    query_builder.push(" AND ");
                    count_query_builder.push(" AND ");
                } else {
                    query_builder.push(" WHERE ");
                    count_query_builder.push(" WHERE ");
                    has_conditions = true;
                }
                query_builder.push(stringify!($field)).push(" >= ").push_bind(min_date);
                count_query_builder.push(stringify!($field)).push(" >= ").push_bind(min_date);
            }
            if let Some(max_date) = &params.$max {
                if has_conditions {
                    query_builder.push(" AND ");
                    count_query_builder.push(" AND ");
                } else {
                    query_builder.push(" WHERE ");
                    count_query_builder.push(" WHERE ");
                    has_conditions = true;
                }
                query_builder.push(stringify!($field)).push(" <= ").push_bind(max_date);
                count_query_builder.push(stringify!($field)).push(" <= ").push_bind(max_date);
            }
        };
    }

    push_date_range!(status_date, status_date_min, status_date_max);
    push_date_range!(acceptance_date, acceptance_date_min, acceptance_date_max);
    push_date_range!(publish_date, publish_date_min, publish_date_max);

    // Ensure ORDER BY is always included in the product query
    query_builder.push(" ORDER BY item_id");

    // Apply pagination if requested
    if params.page.is_some() || params.limit.is_some() || params.offset.is_some() {
        let page = params.page.unwrap_or(1).max(1);
        let limit = params.limit.unwrap_or(10).min(100);
        let offset = params.offset.unwrap_or((page - 1) * limit);

        query_builder.push(" LIMIT ").push_bind(limit as i64).push(" OFFSET ").push_bind(offset as i64);
    }

    // Fetch total count with filtering conditions applied
    let total_count: i64 = count_query_builder
        .build_query_scalar::<i64>()
        .fetch_one(&db_pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve product count",
            Some(json!({ "message": e.to_string() })))
        )?
        ;

    // Fetch products with dynamically built query
    let products: Vec<Product> = query_builder
        .build_query_as::<Product>()
        .fetch_all(&db_pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve products",
            Some(json!({ "message": e.to_string() })))
        )?;

    Ok(ApiResponse::success(
        StatusCode::OK, 
        "Products retrieved successfully", 
        json!({
            "page": params.page.unwrap_or(1),
            "limit": params.limit.unwrap_or(total_count as u32),
            "total_products": total_count,
            "total_pages": if params.limit.is_some() { (total_count as f64 / params.limit.unwrap_or(10) as f64).ceil() as u32 } else { 1 },
            "products": products
        })
    ))
}

/// Updates an existing product
#[utoipa::path(
    patch,
    path = "/products/{product_id}",
    params(
        ("product_id" = i32, Path, description = "ID of the product to update")
    ),
    request_body = UpdateProduct,
    responses(
        (status = 200, description = "Product updated successfully"),
        (status = 400, description = "No fields provided for update or invalid geometry"),
        (status = 404, description = "Product not found"),
        (status = 500, description = "Failed to update product due to a server error")
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn update_product(
    State(db_pool): State<PgPool>,
    Path(product_id): Path<i32>,
    Json(payload): Json<UpdateProduct>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    if payload.is_empty() {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No fields provided for update",
            None,
        ));
    }

    let mut query_builder = QueryBuilder::new("UPDATE products SET ");
    let mut first = true; // ✅ Controls comma placement

    // ✅ Macro to push fields while ensuring proper comma placement
    macro_rules! push_if_some {
        ($field:ident) => {
            if let Some(value) = &payload.$field {
                if !first { query_builder.push(", "); }
                query_builder.push(concat!(stringify!($field), " = ")).push_bind(value);
                first = false;
            }
        };
    }

    push_if_some!(taskorder_id);
    push_if_some!(site_id);
    push_if_some!(status);
    push_if_some!(status_date);
    push_if_some!(acceptance_date);
    push_if_some!(publish_date);
    push_if_some!(file_path);
    push_if_some!(s2_index);
    push_if_some!(classification);

    // ✅ Handle `geom` safely (raw SQL, no bind)
    if let Some(geom_val) = &payload.geom {
        let geometry_expr = detect_geometry_format(geom_val)
            .map_err(|msg| ApiResponse::<()>::error(
                StatusCode::BAD_REQUEST,
                "Invalid geometry format",
                Some(json!({ "error": msg })),
            ))?;
        if !first { query_builder.push(", "); }
        query_builder.push("geom = ").push(geometry_expr);
        first = false;
    }

    // ✅ Ensure at least one field is updated before executing
    if first {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No valid fields provided for update",
            None,
        ));
    }

    // ✅ WHERE clause
    query_builder.push(" WHERE id = ").push_bind(product_id);

    // Execute query
    let query = query_builder.build();
    let result = query.execute(&db_pool).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update product",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Product not found",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product updated successfully",
        (),
    ))
}



#[utoipa::path(
    patch,
    path = "/products/bulk_update",
    request_body = BulkUpdateProducts,
    responses(
        (status = 200, description = "Products updated successfully", body = u32),
        (status = 400, description = "No fields provided for update or invalid request"),
        (status = 404, description = "No matching products found for update"),
        (status = 500, description = "Failed to update products due to a server error")
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn bulk_update_products(
    State(db_pool): State<PgPool>,
    Json(payload): Json<BulkUpdateProducts>,
) -> Result<ApiResponse<u32>, ApiResponse<()>> {
    if payload.product_ids.is_empty() {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No product IDs provided",
            None,
        ));
    }

    if payload.updates.is_empty() {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No fields provided for update",
            None,
        ));
    }

    let mut query_builder = QueryBuilder::new("UPDATE products SET ");
    let mut first = true; // ✅ Controls comma placement

    // ✅ Macro to push fields while ensuring correct comma placement
    macro_rules! push_if_some {
        ($field:ident) => {
            if let Some(value) = &payload.updates.$field {
                if !first { query_builder.push(", "); }
                query_builder.push(concat!(stringify!($field), " = ")).push_bind(value);
                first = false;
            }
        };
    }

    push_if_some!(taskorder_id);
    push_if_some!(site_id);
    push_if_some!(status);
    push_if_some!(status_date);
    push_if_some!(acceptance_date);
    push_if_some!(publish_date);
    push_if_some!(file_path);
    push_if_some!(s2_index);
    push_if_some!(classification);

    // ✅ Handle `geom` safely (raw SQL, no bind)
    if let Some(geom_val) = &payload.updates.geom {
        let geometry_expr = detect_geometry_format(geom_val).map_err(|msg| {
            ApiResponse::<()>::error(
                StatusCode::BAD_REQUEST,
                "Invalid geometry format",
                Some(json!({ "error": msg })),
            )
        })?;
        if !first { query_builder.push(", "); }
        query_builder.push("geom = ").push(geometry_expr);
        first = false;
    }

    // ✅ Ensure at least one field is updated before executing
    if first {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No valid fields provided for update",
            None,
        ));
    }

    // ✅ WHERE clause for bulk updates
    query_builder.push(" WHERE id = ANY(").push_bind(&payload.product_ids).push(")");

    // Execute query
    let query = query_builder.build();
    let result = query.execute(&db_pool).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update products",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "No matching products found for update",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Products updated successfully",
        result.rows_affected() as u32,
    ))
}


#[utoipa::path(
    patch,
    path = "/products/bulk_update_by_filter",
    params(BulkUpdateByFilterParams),
    request_body =  UpdateProduct,
    responses(
        (status = 200, description = "Products updated successfully", body = u32),
        (status = 400, description = "No fields provided for update or invalid request"),
        (status = 404, description = "No matching products found for update"),
        (status = 500, description = "Failed to update products due to a server error")
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]

pub async fn bulk_update_products_by_filter(
    State(db_pool): State<PgPool>,
    Query(params): Query<BulkUpdateByFilterParams>, // Filters
    Json(payload): Json<UpdateProduct>, // New values
) -> Result<ApiResponse<u32>, ApiResponse<()>> {
    let mut query_builder = QueryBuilder::new("UPDATE products SET ");
    let mut first_update = true; // ✅ Tracks comma placement for updates

    // ✅ Macro to dynamically add update fields
    macro_rules! push_if_some {
        ($param:ident, $field:ident) => {
            if let Some(value) = &payload.$param {
                if !first_update { query_builder.push(", "); }
                query_builder.push(concat!(stringify!($field), " = ")).push_bind(value);
                first_update = false;
            }
        };
    }

    push_if_some!(taskorder_id, taskorder_id);
    push_if_some!(status, status);
    push_if_some!(status_date, status_date);
    push_if_some!(acceptance_date, acceptance_date);
    push_if_some!(publish_date, publish_date);
    push_if_some!(file_path, file_path);
    push_if_some!(classification, classification);

    // ✅ Ensure at least one update field exists before proceeding
    if first_update {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No fields provided for update",
            None,
        ));
    }

    let mut first_filter = true; // ✅ Ensures correct `WHERE` clause placement

    // ✅ Macro to dynamically add filter conditions
    macro_rules! push_filter_if_some {
        ($param:ident, $field:ident) => {
            if let Some(value) = &params.$param {
                if first_filter {
                    query_builder.push(" WHERE ");
                    first_filter = false;
                } else {
                    query_builder.push(" AND ");
                }
                query_builder.push(concat!(stringify!($field), " = ")).push_bind(value);
            }
        };
    }

    push_filter_if_some!(taskorder_id, taskorder_id);
    push_filter_if_some!(item_id, item_id);
    push_filter_if_some!(site_id, site_id);
    push_filter_if_some!(product_type_id, product_type_id);
    push_filter_if_some!(status, status);
    push_filter_if_some!(file_path, file_path);
    push_filter_if_some!(s2_index, s2_index);
    push_filter_if_some!(classification, classification);

    // ✅ Macro for date range conditions
    macro_rules! push_date_range {
        ($field:ident, $min:ident, $max:ident) => {
            if let Some(min_date) = &params.$min {
                if first_filter {
                    query_builder.push(" WHERE ");
                    first_filter = false;
                } else {
                    query_builder.push(" AND ");
                }
                query_builder.push(concat!(stringify!($field), " >= ")).push_bind(min_date);
            }
            if let Some(max_date) = &params.$max {
                if first_filter {
                    query_builder.push(" WHERE ");
                    first_filter = false;
                } else {
                    query_builder.push(" AND ");
                }
                query_builder.push(concat!(stringify!($field), " <= ")).push_bind(max_date);
            }
        };
    }

    push_date_range!(status_date, status_date_min, status_date_max);
    push_date_range!(acceptance_date, acceptance_date_min, acceptance_date_max);
    push_date_range!(publish_date, publish_date_min, publish_date_max);

    // ✅ Ensure there is at least one filter (WHERE condition)
    if first_filter {
        return Err(ApiResponse::<()>::error(
            StatusCode::BAD_REQUEST,
            "No filters provided for bulk update",
            None,
        ));
    }

    // Execute query
    let query = query_builder.build();
    let result = query.execute(&db_pool).await.map_err(|e| {
        ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update products",
            Some(json!({ "message": e.to_string() })),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "No matching products found for update",
            None,
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Products updated successfully",
        result.rows_affected() as u32,
    ))
}


#[utoipa::path(
    delete,
    path = "/products/{product_id}",
    params(
        ("product_id" = i32, Path, description = "ID of the product to delete")
    ),
    responses(
        (status = 200, description = "Product deleted successfully"),
        (status = 404, description = "Product not found"),
        (status = 500, description = "Failed to delete product due to a server error")
    ),
    tag = "Products",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_product(
    State(db_pool): State<PgPool>,
    Path(product_id): Path<i32>,
) -> Result<ApiResponse<()>, ApiResponse<()>> {
    let result = sqlx::query!("DELETE FROM products WHERE id = $1", product_id)
        .execute(&db_pool)
        .await
        .map_err(|e| ApiResponse::<()>::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to delete product",
            Some(json!({ "message": e.to_string() }))
        ))?;

    if result.rows_affected() == 0 {
        return Err(ApiResponse::<()>::error(
            StatusCode::NOT_FOUND,
            "Product not found",
            None
        ));
    }

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product deleted successfully",
        ()
    ))
}

#[utoipa::path(
    post,
    path = "/product_types",
    request_body = NewProductType,
    responses(
        (status = 201, description = "Successfully created product type", body = i32),
        (status = 500, description = "Failed to insert product type due to a server error")
    ),
    tag = "Product Types",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_product_type(
    State(db_pool): State<PgPool>,
    Json(payload): Json<NewProductType>,
) -> Result<ApiResponse<i32>, ApiResponse<()>> {
    // 1) Start building an INSERT statement
    let mut query_builder = QueryBuilder::new(
        "INSERT INTO product_types (name, acronym) VALUES ("
    );

    // 2) Bind the name
    query_builder.push_bind(&payload.name);
    query_builder.push(", ");
    query_builder.push_bind(&payload.acronym);

    // 3) We want the new id, so add RETURNING
    query_builder.push(") RETURNING id");

    // 4) Build the final query
    let query = query_builder.build();

    // 5) Execute and fetch a single row
    let row = query
        .fetch_one(&db_pool)
        .await
        .map_err(|e| {
            ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert product type",
                Some(json!({ "message": e.to_string() }))
            )
        })?;

    // 6) Extract the "id" column from the row
    let new_id: i32 = row.get("id");

    Ok(ApiResponse::success(
        StatusCode::CREATED,
        "Product Type inserted",
        new_id
    ))
}

#[utoipa::path(
    get,
    path = "/product_types",
    responses(
        (status = 200, description = "List of product types retrieved successfully", body = Vec<ProductType>),
        (status = 500, description = "Failed to fetch product types due to a server error")
    ),
    tag = "Product Types",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn get_product_types(
    State(db_pool): State<PgPool>,
) -> Result<ApiResponse<Vec<ProductType>>, ApiResponse<()>> {
    let product_types = sqlx::query_as!(
        ProductType,
        r#"
        SELECT id, name, acronym
        FROM product_types
        ORDER BY name  
        "#
    )
    .fetch_all(&db_pool)
    .await
    .map_err(|e| {
            ApiResponse::<()>::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetech product types",
                Some(json!({"error": e.to_string() }))
            )
        })?;

    Ok(ApiResponse::success(
        StatusCode::OK,
        "Product Types reterived successfully",
         product_types,
     ))
}

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_products,
        get_product,
        create_product,
        update_product,
        delete_product,
        bulk_update_products_by_filter,
        get_product_id,
    ),
    components(
        schemas(ProductIdResponse, ProductResponse, UpdateProduct, NewProduct, ProductFilterParams, BulkUpdateProducts)
    ),
    tags(
        (name = "Products", description = "Product Management Endpoints")
    )
)]
pub struct ProductDoc;

#[derive(OpenApi)]
#[openapi(
    paths(
        get_product_types,
        create_product_type
    ),
    components(
        schemas(
            ProductType, NewProductType
        )
    ),
    tags(
            (name= "Product Types", description = "Product Type managment Endpoints")
        )
)]
pub struct ProductTypeDoc;
