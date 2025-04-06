use async_graphql::{Request, ErrorExtensions, Pos}; // 👈 import Pos
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{State, Extension},
    http::HeaderMap,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use sqlx::PgPool;

use crate::graphql::graph_schema::AppSchema;
use crate::middleware::auth::{UserPermissions};
pub fn graphql_routes(schema: AppSchema) -> Router<PgPool> {
    Router::new()
        .route("/graphql", get(graphql_handler).post(graphql_handler))
        .layer(Extension(schema))
}

#[axum::debug_handler]
pub async fn graphql_handler(
    Extension(schema): Extension<AppSchema>,
    Extension(user_permissions): Extension<UserPermissions>, // 👈 from middleware
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut gql_request: Request = req.into_inner();
    gql_request = gql_request.data(user_permissions); // ✅ inject permissions
    schema.execute(gql_request).await.into()
}
