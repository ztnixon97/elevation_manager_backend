use axum::{
    extract::{Query, State, Json},
    response::{IntoResponse, Response},
    routing::{get, post},
    http::{StatusCode, header},
    Router,
};
use quick_xml::de::from_str;
use bytes::Bytes;
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use chrono::{NaiveDate,NaiveDateTime};
use std::collections::HashMap;
/// Registers WFS routes
pub fn wfs_routes() -> Router<PgPool> {
    Router::new()
        .route("/wfs", get(handle_wfs_request)) // Handles GetCapabilities, DescribeFeatureType, GetFeature
        .route("/wfs", post(handle_wfs_transaction)) // Handles Insert, Update, Delete transactions
}

/// Query parameters for WFS requests

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")] // Allows QGIS-style uppercase parameters
pub struct WfsQueryParams {
    pub service: Option<String>,
    pub request: Option<String>,
    pub type_name: Option<String>, // Matches "typeName" correctly
    pub bbox: Option<String>,
    pub status: Option<String>,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    pub count: Option<i32>,
    pub start_index: Option<i32>, // Matches "startIndex"
}
/// Handles WFS requests (Capabilities, Schema, Feature Retrieval)

pub async fn handle_wfs_request(
    State(db_pool): State<PgPool>,
    Query(query_map): Query<HashMap<String, String>>, // Capture all query params
) -> Response {
    println!("Received raw query params: {:?}", query_map);

    // Normalize keys to lowercase
    let query_params: HashMap<String, String> = query_map
        .into_iter()
        .map(|(key, value)| (key.to_lowercase(), value))
        .collect();

    match query_params.get("request").map(|s| s.trim().to_lowercase()) {
        Some(ref req) if req == "getcapabilities" => get_capabilities().into_response(),
        Some(ref req) if req == "describefeaturetype" => describe_feature_type(Query(query_params)).await.into_response(), // ✅ Correct way to call it
        Some(ref req) if req == "getfeature" => get_feature(&db_pool, &query_params).await.into_response(),
        _ => {
            println!("Invalid or missing WFS request: {:?}", query_params);
            (StatusCode::BAD_REQUEST, "Invalid or missing WFS request parameter").into_response()
        }
    }
}

/// Returns WFS Capabilities
fn get_capabilities() -> Response {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <wfs:WFS_Capabilities version="2.0.0"
        xmlns:wfs="http://www.opengis.net/wfs/2.0"
        xmlns:ows="http://www.opengis.net/ows/1.1"
        xmlns:gml="http://www.opengis.net/gml/3.2"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="
            http://www.opengis.net/wfs/2.0
            http://schemas.opengis.net/wfs/2.0/wfs.xsd">
        
        <ows:ServiceIdentification>
            <ows:Title>Elevation Manager WFS-T</ows:Title>
            <ows:Abstract>WFS-T Service for Digital Elevation Models</ows:Abstract>
            <ows:ServiceType>WFS</ows:ServiceType>
            <ows:ServiceTypeVersion>2.0.0</ows:ServiceTypeVersion>
            <ows:Fees>NONE</ows:Fees>
            <ows:AccessConstraints>NONE</ows:AccessConstraints>
        </ows:ServiceIdentification>

        <wfs:FeatureTypeList>
            <wfs:FeatureType>
                <wfs:Name>products</wfs:Name>
                <wfs:DefaultCRS>urn:ogc:def:crs:EPSG::4326</wfs:DefaultCRS>
                <wfs:Operations>
                    <wfs:Operation>Query</wfs:Operation>
                    <wfs:Operation>Insert</wfs:Operation>
                    <wfs:Operation>Update</wfs:Operation>
                    <wfs:Operation>Delete</wfs:Operation>
                    <wfs:Operation>Transaction</wfs:Operation> <!-- 🛠️ Required for WFS-T -->
                </wfs:Operations>
            </wfs:FeatureType>
        </wfs:FeatureTypeList>

        <wfs:OperationsMetadata>
            <ows:Operation name="Transaction">
                <ows:DCP>
                    <ows:HTTP>
                        <ows:Post xlink:href="http://127.0.0.1:3000/wfs"/>
                    </ows:HTTP>
                </ows:DCP>
            </ows:Operation>
        </wfs:OperationsMetadata>

        <wfs:Constraint name="ImplementsTransactionalWFS">
            <ows:DefaultValue>TRUE</ows:DefaultValue> <!-- ✅ Ensures WFS-T is advertised -->
        </wfs:Constraint>

    </wfs:WFS_Capabilities>"#;
    
    Response::builder()
        .header("Content-Type", "application/xml")
        .body(xml.into())
        .unwrap()
}


/// Returns Feature Type Schema

pub async fn describe_feature_type(
    Query(query_map): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    println!("DescribeFeatureType request received: {:?}", query_map);

    let query_params: HashMap<String, String> = query_map
        .into_iter()
        .map(|(key, value)| (key.to_lowercase(), value))
        .collect();

    if let Some(type_name) = query_params.get("typename") {
        if type_name != "products" {
            println!("Requested feature type not found: {:?}", type_name);
            return (StatusCode::BAD_REQUEST, "Invalid or unknown feature type").into_response();
        }
    } else {
        println!("Missing typename in DescribeFeatureType request");
        return (StatusCode::BAD_REQUEST, "Missing typename parameter").into_response();
    }

    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
    <xsd:schema
        targetNamespace="http://www.example.com/wfs"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:gml="http://www.opengis.net/gml"
        elementFormDefault="qualified">
      
      <xsd:import namespace="http://www.opengis.net/gml"
                  schemaLocation="http://schemas.opengis.net/gml/3.2.1/gml.xsd"/>

      <xsd:element name="products" substitutionGroup="gml:_Feature" type="wfs:ProductType"/>

      <xsd:complexType name="ProductType">
        <xsd:complexContent>
          <xsd:extension base="gml:AbstractFeatureType">
            <xsd:sequence>
              <xsd:element name="id" type="xsd:int"/>
              <xsd:element name="taskorder_id" type="xsd:int" minOccurs="0"/>
              <xsd:element name="item_id" type="xsd:string"/>
              <xsd:element name="site_id" type="xsd:string"/>
              <xsd:element name="product_type_id" type="xsd:int"/>
              <xsd:element name="status" type="xsd:string"/>
              <xsd:element name="status_date" type="xsd:date" minOccurs="0"/>
              <xsd:element name="acceptance_date" type="xsd:date" minOccurs="0"/>
              <xsd:element name="publish_date" type="xsd:date" minOccurs="0"/>
              <xsd:element name="file_path" type="xsd:string" minOccurs="0"/>
              <xsd:element name="s2_index" type="xsd:string" minOccurs="0"/>
              <xsd:element name="classification" type="xsd:string"/>
              <xsd:element name="created_at" type="xsd:dateTime"/>
              <xsd:element name="geom" type="gml:PointPropertyType"/>
            </xsd:sequence>
          </xsd:extension>
        </xsd:complexContent>
      </xsd:complexType>

    </xsd:schema>"#;

    Response::builder()
        .header("Content-Type", "application/xml")
        .body(xml.into())
        .unwrap()
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")] // Match WFS XML casing
struct WfsTransaction {
    transaction_type: String,
    taskorder_id: Option<i32>,
    item_id: Option<String>,
    site_id: Option<String>,
    product_type_id: Option<i32>,
    status: Option<String>,
    status_date: Option<String>,
    acceptance_date: Option<String>,
    publish_date: Option<String>,
    file_path: Option<String>,
    s2_index: Option<String>,
    classification: Option<String>,
    geom: Option<String>, // Assume WKT or GeoJSON inside XML
}

/// Handles WFS Transactions (Insert, Update, Delete)
pub async fn handle_wfs_transaction(
    State(db_pool): State<PgPool>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let xml_string = String::from_utf8(body.to_vec())
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    println!("Received WFS-T request: {}", xml_string);

    let transaction: WfsTransaction = from_str(&xml_string)
        .map_err(|e| {
            println!("XML Parsing Error: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;

    let response_xml = match transaction.transaction_type.as_str() {
        "Insert" => {
            match insert_product(&db_pool, &transaction).await {
                Ok(id) => generate_transaction_response("Insert", true, Some(id)),
                Err(_) => generate_transaction_response("Insert", false, None),
            }
        },
        "Update" => {
            let transaction_json = serde_json::to_value(&transaction)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let success = update_product(&db_pool, &transaction_json).await.is_ok();
            generate_transaction_response("Update", success, None)
        },
        "Delete" => {
            let transaction_json = serde_json::to_value(&transaction)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let success = delete_product(&db_pool, &transaction_json).await.is_ok();
            generate_transaction_response("Delete", success, None)
        },

        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let response = Response::builder()
        .header(header::CONTENT_TYPE, "application/xml")
        .body(response_xml.into())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(response)
}


/// Generates a WFS-T Transaction response
fn generate_transaction_response(operation: &str, success: bool, insert_id: Option<i32>) -> String {
    let status = if success { "1" } else { "0" };

    // Determine the correct element names based on the operation
    let (total_tag, results_tag, feature_id_tag, feature_id_value) = match operation {
        "Insert" => ("totalInserted", "InsertResults", "FeatureId", insert_id.map(|id| id.to_string()).unwrap_or_default()),
        "Update" => ("totalUpdated", "", "", String::new()),
        "Delete" => ("totalDeleted", "", "", String::new()),
        _ => ("", "", "", String::new()),
    };

    // Build the response accordingly; for update and delete you may not need InsertResults
    let insert_results = if operation == "Insert" {
        format!(
            r#"<wfs:InsertResults>
                    <wfs:Feature>
                        <wfs:FeatureId fid="{}"/>
                    </wfs:Feature>
                </wfs:InsertResults>"#,
            feature_id_value
        )
    } else {
        "".to_string()
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <wfs:TransactionResponse xmlns:wfs="http://www.opengis.net/wfs/2.0">
            <wfs:TransactionSummary>
                <wfs:{}>{}</wfs:{}>
            </wfs:TransactionSummary>
            {}
        </wfs:TransactionResponse>"#,
        total_tag, status, total_tag, insert_results
    )
}



/// Inserts a new product via WFS-T
async fn insert_product(db_pool: &PgPool, transaction: &WfsTransaction) -> Result<i32, StatusCode> {
    let query = "INSERT INTO products (taskorder_id, item_id, site_id, product_type_id, status, status_date, acceptance_date, publish_date, file_path, s2_index, geom, classification) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, ST_GeomFromText($11, 4326), $12) 
                 RETURNING id";

    let row = sqlx::query(query)
        .bind(transaction.taskorder_id)
        .bind(&transaction.item_id)
        .bind(&transaction.site_id)
        .bind(transaction.product_type_id)
        .bind(&transaction.status)
        .bind(&transaction.status_date)
        .bind(&transaction.acceptance_date)
        .bind(&transaction.publish_date)
        .bind(&transaction.file_path)
        .bind(&transaction.s2_index)
        .bind(&transaction.geom) // Assumes WKT format
        .bind(&transaction.classification)
        .fetch_one(db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.get("id"))
}




async fn get_feature(db_pool: &PgPool, params: &HashMap<String, String>) -> Response {
    println!("Received GetFeature request: {:?}", params);

    // Detect requested format
    let output_format = params
        .get("outputformat")
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "text/xml".to_string()); // Default to GML

    // Prepare the SQL query
    let query = String::from(r#"
        SELECT id, taskorder_id, item_id, site_id, product_type_id, status, 
               status_date, acceptance_date, publish_date, file_path, s2_index, 
               ST_AsGML(3, geom, 15, 0)::TEXT AS gml_geom, 
               classification, created_at
        FROM products
    "#);

    // Execute query
    let rows = match sqlx::query(&query).fetch_all(db_pool).await {
        Ok(rows) => rows,
        Err(e) => {
            println!("Database query error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error fetching features").into_response();
        }
    };

    if rows.is_empty() {
        println!("No products found for the requested query.");
        return (StatusCode::NOT_FOUND, "No features available").into_response();
    }

    // ✅ QGIS-compatible GML output
    let mut features = Vec::new();
    for row in rows {
        let geometry_gml = row.get::<String, _>("gml_geom");

        let created_at = row.get::<NaiveDateTime, _>("created_at").format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        // ✅ Use `wfs:` prefix for ALL attributes
        let feature = format!(
            r#"<gml:featureMember>
                <wfs:products xmlns:wfs="http://www.opengis.net/wfs/2.0">
                    <wfs:id>{}</wfs:id>
                    <wfs:taskorder_id>{}</wfs:taskorder_id>
                    <wfs:item_id>{}</wfs:item_id>
                    <wfs:site_id>{}</wfs:site_id>
                    <wfs:product_type_id>{}</wfs:product_type_id>
                    <wfs:status>{}</wfs:status>
                    <wfs:status_date>{}</wfs:status_date>
                    <wfs:acceptance_date>{}</wfs:acceptance_date>
                    <wfs:publish_date>{}</wfs:publish_date>
                    <wfs:file_path>{}</wfs:file_path>
                    <wfs:s2_index>{}</wfs:s2_index>
                    <wfs:classification>{}</wfs:classification>
                    <wfs:created_at>{}</wfs:created_at>
                    <wfs:geom>{}</wfs:geom>
                </wfs:products>
            </gml:featureMember>"#,
            row.get::<i32, _>("id"),
            row.get::<Option<i32>, _>("taskorder_id").map_or(String::new(), |v| v.to_string()),
            row.get::<String, _>("item_id"),
            row.get::<String, _>("site_id"),
            row.get::<i32, _>("product_type_id"),
            row.get::<String, _>("status"),
            row.get::<Option<NaiveDate>, _>("status_date").map_or("".to_string(), |d| d.to_string()),
            row.get::<Option<NaiveDate>, _>("acceptance_date").map_or("".to_string(), |d| d.to_string()),
            row.get::<Option<NaiveDate>, _>("publish_date").map_or("".to_string(), |d| d.to_string()),
            row.get::<Option<String>, _>("file_path").unwrap_or_default(),
            row.get::<Option<String>, _>("s2_index").unwrap_or_default(),
            row.get::<String, _>("classification"),
            created_at,
            geometry_gml
        );

        features.push(feature);
    }

    // ✅ Ensure `gml:boundedBy` is included
    let response = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <wfs:FeatureCollection
            xmlns:wfs="http://www.opengis.net/wfs/2.0"
            xmlns:gml="http://www.opengis.net/gml/3.2">
            <gml:boundedBy>
                <gml:Envelope srsName="EPSG:4326">
                    <gml:lowerCorner>-180 -90</gml:lowerCorner>
                    <gml:upperCorner>180 90</gml:upperCorner>
                </gml:Envelope>
            </gml:boundedBy>
            {}
        </wfs:FeatureCollection>"#,
        features.join("\n")
    );

    return Response::builder()
        .header("Content-Type", "application/xml")
        .body(response.into())
        .unwrap();
}



/// Updates all product fields
async fn update_product(db_pool: &PgPool, payload: &Value) -> Result<Json<Value>, StatusCode> {
    let id: i32 = payload["id"].as_i64().ok_or(StatusCode::BAD_REQUEST)? as i32;
    let query = "UPDATE products SET taskorder_id = $1, item_id = $2, site_id = $3, product_type_id = $4, status = $5, status_date = $6, acceptance_date = $7, publish_date = $8, file_path = $9, s2_index = $10, geom = ST_GeomFromGeoJSON($11), classification = $12 WHERE id = $13";
    
    sqlx::query(query)
        .bind(&payload["taskorder_id"])
        .bind(&payload["item_id"])
        .bind(&payload["site_id"])
        .bind(&payload["product_type_id"])
        .bind(&payload["status"])
        .bind(&payload["status_date"])
        .bind(&payload["acceptance_date"])
        .bind(&payload["publish_date"])
        .bind(&payload["file_path"])
        .bind(&payload["s2_index"])
        .bind(&payload["geom"])
        .bind(&payload["classification"])
        .bind(id)
        .execute(db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(json!({ "success": true })))
}

/// Deletes a product
async fn delete_product(db_pool: &PgPool, payload: &Value) -> Result<Json<Value>, StatusCode> {
    let id: i32 = payload["id"].as_i64().ok_or(StatusCode::BAD_REQUEST)? as i32;
    sqlx::query!("DELETE FROM products WHERE id = $1", id)
        .execute(db_pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "success": true })))
}
