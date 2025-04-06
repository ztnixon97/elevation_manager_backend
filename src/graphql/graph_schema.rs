use async_graphql::{Schema};
use crate::graphql::graph::QueryRoot;
use sqlx::PgPool;

pub type AppSchema = Schema<QueryRoot, async_graphql::EmptyMutation, async_graphql::EmptySubscription>;

pub fn create_schema(pool: PgPool) -> AppSchema {
    Schema::build(QueryRoot, async_graphql::EmptyMutation, async_graphql::EmptySubscription)
        .data(pool) // ✅ Add PgPool to the schema's context
        .finish()
}
