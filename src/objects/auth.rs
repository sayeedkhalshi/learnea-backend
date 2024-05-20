use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use juniper::{FieldError, FieldResult};
use juniper_compose::{composable_object, composite_object};
use serde::{Deserialize, Serialize};
use sqlx::{query, Executor, SqlitePool};

use crate::{db::models::User, schema::Context};
use chrono::{Duration, Utc};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    aud: String,
}

#[derive(GraphQLObject)]
#[graphql(description = "Response with token")]
struct RefreshResponse {
    access_token: String,
    access_expires_in: i32,
}

#[derive(GraphQLObject)]
#[graphql(description = "Response with both tokens")]
struct LoginResponse {
    access_token: String,
    access_expires_in: i32,
    refresh_token: String,
    refresh_expires_in: i32,
}

impl Default for LoginResponse {
    fn default() -> Self {
        Self {
            access_token: "".to_owned(),
            access_expires_in: get_validity(TokenTypes::Access).num_seconds() as i32,
            refresh_token: "".to_owned(),
            refresh_expires_in: get_validity(TokenTypes::Refresh).num_seconds() as i32,
        }
    }
}

#[derive(GraphQLObject)]
#[graphql(description = "Response with username")]
struct IdentityResponse {
    username: String,
}

#[derive(GraphQLInputObject)]
#[graphql(description = "Login details")]
struct LoginVariables {
    username: String,
    password: String,
}

#[derive(GraphQLInputObject)]
#[graphql(description = "Login details")]
struct AuthVariables {
    token: String,
}

#[derive(Default)]
pub struct AuthQueries;

#[composable_object]
#[juniper::graphql_object(Context = Context)]
impl AuthQueries {
    async fn who_am_i(ctx: &Context) -> FieldResult<IdentityResponse> {
        let user = ctx.require_user().await?;

        Ok(IdentityResponse {
            username: user.username.clone(),
        })
    }
}

#[derive(Default)]
pub struct AuthMutations;

#[composable_object]
#[juniper::graphql_object(Context = Context)]
impl AuthMutations {
    async fn login(ctx: &Context, cred: LoginVariables) -> FieldResult<LoginResponse> {
        // Get user from db and compare password
        let res = sqlx::query_as::<_, User>(
            r#"
                SELECT * FROM users WHERE username = $1;
                "#,
        )
        .bind(&cred.username)
        .fetch_one(&ctx.pool)
        .await?;

        let valid = verify(cred.password, &res.password)?;

        if !valid {
            return Err(FieldError::from("Invalid password"));
        }

        let refresh_token = create_token(res.id, TokenTypes::Refresh)?;
        let access_token = create_token(res.id, TokenTypes::Access)?;

        Ok(LoginResponse {
            refresh_token,
            access_token,
            ..Default::default()
        })
    }

    async fn register(ctx: &Context, cred: LoginVariables) -> FieldResult<LoginResponse> {
        let mut tx = ctx.pool.begin().await?;

        // insert values and return user
        let hashed = hash(cred.password, DEFAULT_COST)?;
        // TODO: encrypt password
        let res = sqlx::query_as::<_, User>(
            r#"
                INSERT INTO users (username, password)
                VALUES ($1, $2);
                SELECT * FROM users WHERE id = last_insert_rowid();
                "#,
        )
        .bind(&cred.username)
        .bind(&hashed)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let refresh_token = create_token(res.id, TokenTypes::Refresh)?;
        let access_token = create_token(res.id, TokenTypes::Access)?;

        Ok(LoginResponse {
            refresh_token,
            access_token,
            ..Default::default()
        })
    }

    async fn refresh(ctx: &Context, cred: AuthVariables) -> FieldResult<RefreshResponse> {
        let user_id = check_token(Some(&cred.token), TokenTypes::Refresh).await;

        if user_id.is_none() {
            return Err(FieldError::from("Invalid token"));
        }

        let token = create_token(user_id.unwrap(), TokenTypes::Access)?;

        Ok(RefreshResponse {
            access_token: token,
            access_expires_in: get_validity(TokenTypes::Access).num_seconds() as i32,
        })
    }
}

pub async fn check_token(token: Option<&str>, token_type: TokenTypes) -> Option<i32> {
    if token.is_none() || token.unwrap().is_empty() {
        return None;
    }

    let audience = match token_type {
        TokenTypes::Access => "access",
        TokenTypes::Refresh => "refresh",
    };

    let mut validation = Validation::default();
    validation.set_audience(&[audience.to_owned()]);

    let token = decode::<Claims>(
        &token.unwrap(),
        &DecodingKey::from_secret(
            std::env::var("SECRET")
                .expect("SECRET must be set")
                .as_ref(),
        ),
        &validation,
    );

    match token {
        Ok(token) => {
            let user_id = token.claims.sub.parse::<i32>().unwrap();

            Some(user_id)
        }
        Err(_) => None,
    }
}

pub enum TokenTypes {
    Access,
    Refresh,
}

pub fn create_token(user_id: i32, token_type: TokenTypes) -> Result<String, FieldError> {
    let audience = match token_type {
        TokenTypes::Access => "access",
        TokenTypes::Refresh => "refresh",
    };

    let claims = Claims {
        sub: user_id.to_string(),
        exp: (Utc::now() + get_validity(token_type)).timestamp() as usize,
        aud: audience.to_owned(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(
            std::env::var("SECRET")
                .expect("SECRET must be set")
                .as_ref(),
        ),
    );

    match token {
        Ok(token) => Ok(token),
        Err(_) => Err(FieldError::from("Error creating token")),
    }
}

pub fn get_validity(token_type: TokenTypes) -> Duration {
    match token_type {
        TokenTypes::Access => Duration::minutes(15),
        TokenTypes::Refresh => Duration::days(30),
    }
}