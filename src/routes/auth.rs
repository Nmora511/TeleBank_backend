use crate::{AppState, AuthenticationError, LoginPayload, PartialUser, SignUpPayload, User};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Json, extract::State, http::StatusCode, http::header};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use bcrypt::{Version::TwoB, hash_with_salt, verify};
use chrono::Utc;
use cookie::time::Duration;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use rand::{TryRngCore, rngs::OsRng};
use serde_json::json;
use sha2::Sha256;
use sqlx::{Error, Pool, Postgres, Result};
use std::collections::BTreeMap;

#[derive(PartialEq)]
pub enum TokenType {
    RefreshToken,
    RegularToken,
}

fn generate_token(
    token_type: TokenType,
    secrets: &shuttle_runtime::SecretStore,
    user: &PartialUser,
    exp_hours: i64,
) -> String {
    let secret_name = if token_type == TokenType::RegularToken {
        "JWT_SECRET"
    } else {
        "REFRESH_TOKEN_SECRET"
    };

    let token_secret: String = secrets
        .get(secret_name)
        .expect("jwt token key must be in secrets");

    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(exp_hours))
        .expect("valid timestamp")
        .timestamp() as usize;

    let mut claims = BTreeMap::new();
    claims.insert("username", user.username.clone());
    claims.insert("name", user.name.clone());
    claims.insert("exp", expiration.to_string());

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(token_secret.as_bytes()).expect("HMAC key should be valid");

    let token: String = claims.sign_with_key(&key).expect("Failed to sign token");

    return token;
}

pub async fn user_query(pool: &Pool<Postgres>, username: &String) -> Result<User, Error> {
    let sql_query = include_str!("../sql/select_user_by_username.sql");
    let select_user_result: Result<User, sqlx::Error> = sqlx::query_as::<_, User>(sql_query)
        .bind(username)
        .fetch_one(pool)
        .await;

    select_user_result
}

async fn authenticate_refresh(
    state: &AppState,
    token: &String,
) -> Result<PartialUser, AuthenticationError> {
    let token_secret = state
        .secrets
        .get("REFRESH_TOKEN_SECRET")
        .expect("secret must be set");

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(token_secret.as_bytes()).expect("HMAC key should be valid");

    let claims: BTreeMap<String, String> = token
        .verify_with_key(&key)
        .map_err(|_| AuthenticationError::InvalidToken)?;

    let username = claims
        .get("username")
        .ok_or(AuthenticationError::InvalidToken)?
        .clone();
    let name = claims
        .get("name")
        .ok_or(AuthenticationError::InvalidToken)?
        .clone();

    let user_exists = user_query(&state.pool, &username).await;

    match user_exists {
        Ok(_) => {
            return Ok(PartialUser { username, name });
        }
        Err(_) => {
            return Err(AuthenticationError::InvalidToken);
        }
    }
}

pub async fn authenticate_token(
    state: &AppState,
    headers: HeaderMap,
) -> Result<PartialUser, AuthenticationError> {
    let auth_header = if let Some(header) = headers.get(header::AUTHORIZATION) {
        header
            .to_str()
            .map_err(|_| AuthenticationError::InvalidToken)?
    } else {
        return Err(AuthenticationError::TokenNotFound);
    };

    let token_str = if let Some(token) = auth_header.strip_prefix("Bearer ") {
        token
    } else {
        return Err(AuthenticationError::InvalidToken);
    };

    let token_secret = state
        .secrets
        .get("JWT_SECRET")
        .expect("JWT_SECRET must be set");

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(token_secret.as_bytes()).expect("HMAC key should be valid");

    let claims: BTreeMap<String, String> = token_str
        .verify_with_key(&key)
        .map_err(|_| AuthenticationError::InvalidToken)?;

    let username = claims
        .get("username")
        .ok_or(AuthenticationError::InvalidToken)?
        .clone();
    let name = claims
        .get("name")
        .ok_or(AuthenticationError::InvalidToken)?
        .clone();

    let user_exists = user_query(&state.pool, &username).await;

    match user_exists {
        Ok(_) => {
            return Ok(PartialUser { username, name });
        }
        Err(_) => {
            return Err(AuthenticationError::InvalidToken);
        }
    }
}

fn create_refresh_cookie(refresh_token: &String) -> Cookie<'_> {
    let mut refresh_cookie = Cookie::new("refreshToken", refresh_token.to_string());
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_path("/"); // Match the path from the JS example
    refresh_cookie.set_max_age(Duration::days(30));
    // For production, also set:
    // refresh_cookie.set_secure(true);
    // refresh_cookie.set_same_site(cookie::SameSite::Lax);
    refresh_cookie
}

fn auth_response(
    secrets: &shuttle_runtime::SecretStore,
    user: &PartialUser,
    message: &str,
) -> Response {
    let token = generate_token(TokenType::RegularToken, &secrets, &user, 4);

    let refresh_token = generate_token(TokenType::RefreshToken, &secrets, &user, 720);

    let refresh_token_cookie = create_refresh_cookie(&refresh_token);

    let response_json = json!({
    "message": message,
    "token" : token,
    "user": { "username": user.username, "name": user.name }
    });

    (
        StatusCode::OK,
        [(header::SET_COOKIE, refresh_token_cookie.to_string())],
        Json(response_json),
    )
        .into_response()
}

pub async fn authentication_tester(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let partial_user = authenticate_token(&state, headers).await;

    match partial_user {
        Ok(user) => {
            let message = json!({ "message": "Token reconhecido com sucesso", "username" : user.username, "name" : user.name });
            return (StatusCode::OK, Json(message));
        }
        Err(AuthenticationError::InvalidToken) => {
            let error = json!({ "message": "Invalid Token" });
            return (StatusCode::UNAUTHORIZED, Json(error));
        }
        Err(AuthenticationError::TokenNotFound) => {
            let error = json!({ "message": "Token not found" });
            return (StatusCode::UNAUTHORIZED, Json(error));
        }
    }
}

pub async fn signup_handler(
    State(state): State<AppState>,
    Json(payload): Json<SignUpPayload>,
) -> Response {
    if payload.username.is_empty()
        || payload.name.is_empty()
        || payload.password.is_empty()
        || payload.email.is_empty()
    {
        let error = json!({ "message": "Usuário, senha, email e nome são obrigatórios" });
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    let select_user_result = user_query(&state.pool, &(payload.username)).await;

    match select_user_result {
        Ok(_) => {
            let error = json!({ "message": "Nome de usuário já existente" });
            return (StatusCode::UNAUTHORIZED, Json(error)).into_response();
        }
        Err(sqlx::Error::RowNotFound) => {}
        Err(_) => {
            // Error: Any other database error.
            let error = json!({ "message": "Erro interno do servidor" });
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    }

    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt).unwrap();

    let Ok(hashed_password) = hash_with_salt(payload.password, 10, salt) else {
        let error = json!({ "message": "Erro interno do Servidor" });
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
    };

    let sql_query = include_str!("../sql/insert_user.sql");
    let insert_user_result = sqlx::query(sql_query)
        .bind(&payload.name)
        .bind(&payload.email)
        .bind(&payload.username)
        .bind(&hashed_password.format_for_version(TwoB))
        .bind(&salt)
        .execute(&state.pool)
        .await;

    match insert_user_result {
        Ok(_) => {
            let user: PartialUser = PartialUser {
                username: (payload.username),
                name: (payload.name),
            };

            return auth_response(&state.secrets, &user, "Conta criada com sucesso");
        }
        Err(_) => {
            let error = json!({ "message": "Erro interno do servidor" });
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    }
}

pub async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    if payload.username.is_empty() || payload.password.is_empty() {
        let error = json!({ "message": "Usuário e senha são obrigatórios" });
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    let user_result = user_query(&state.pool, &payload.username).await;

    match user_result {
        Ok(user) => {
            let password_verification = verify(payload.password, &user.password);

            match password_verification {
                Err(_) => {
                    let error = json!({ "message": "Erro interno do Servidor" });
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
                }
                Ok(verification_result) => {
                    if !verification_result {
                        let error = json!({ "message": "Usuário ou senha inválidos" });
                        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
                    }

                    let partial_user: PartialUser = PartialUser {
                        username: (user.username),
                        name: (user.name),
                    };

                    return auth_response(&state.secrets, &partial_user, "Login bem-sucedido");
                }
            }
        }
        Err(sqlx::Error::RowNotFound) => {
            // Error: No user was found with the given credentials.
            let error = json!({ "message": "Usuário ou senha inválidos" });
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
        Err(_) => {
            // Error: Any other database error.
            let error = json!({ "message": "Erro interno do servidor" });
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    }
}

pub async fn refresh_handler(jar: CookieJar, State(state): State<AppState>) -> impl IntoResponse {
    let refresh_token: String = match jar.get("refreshToken") {
        Some(cookie) => cookie.value().to_string(),

        None => {
            let error = json!({ "message": "Refresh token not found" });
            return (StatusCode::UNAUTHORIZED, Json(error));
        }
    };

    let partial_user: PartialUser = match authenticate_refresh(&state, &refresh_token).await {
        Ok(user) => user,
        Err(AuthenticationError::InvalidToken) => {
            let error = json!({ "message": "Invalid Token" });
            return (StatusCode::UNAUTHORIZED, Json(error));
        }
        Err(AuthenticationError::TokenNotFound) => {
            let error = json!({ "message": "Token not found" });
            return (StatusCode::UNAUTHORIZED, Json(error));
        }
    };

    let new_token = generate_token(TokenType::RegularToken, &state.secrets, &partial_user, 4);

    let response_json = json!({
    "message": "Token gerado com sucesso",
    "token" : new_token,
    });

    return (StatusCode::OK, Json(response_json));
}
