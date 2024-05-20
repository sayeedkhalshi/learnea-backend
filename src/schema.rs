use juniper::{EmptySubscription, FieldError, FieldResult, RootNode};
use juniper_compose::{composable_object, composite_object};
use sqlx::SqlitePool;

use crate::db::models::User;

pub struct Context {
    pub pool: SqlitePool,
    pub user_id: Option<i32>,
}

impl juniper::Context for Context {}

impl Context {
    /**
     * This will return a user if the token is valid, otherwise it will abort the request. Use
     * context.user to get the user and not abort the request, this will be None if the
     * token is invalid.
     */

    pub async fn require_user(&self) -> FieldResult<User> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users WHERE id = $1;
            "#,
        )
        .bind(self.user_id)
        .fetch_one(&self.pool)
        .await;

        match user {
            Ok(user) => Ok(user),
            Err(_) => Err(FieldError::from(
                "Invalid token. Is it expired or the wrong type?",
            )),
        }
    }
}

// Testing juniper compose
#[derive(Default)]
pub struct TestQueries;

#[composable_object]
#[juniper::graphql_object(Context = Context)]
impl TestQueries {
    fn api_version() -> &'static str {
        "1.0"
    }
}

composite_object!(pub RootQuery<Context = Context>(TestQueries, crate::objects::auth::AuthQueries));
composite_object!(pub RootMutation<Context = Context>(crate::objects::auth::AuthMutations));

pub type Schema = RootNode<'static, RootQuery, RootMutation, EmptySubscription<Context>>;

pub fn create_schema() -> Schema {
    Schema::new(RootQuery, RootMutation, EmptySubscription::new())
}