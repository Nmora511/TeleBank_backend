use crate::{AppState, LoginPayload, SignUpPayload, User};
use axum::response::{IntoResponse, Response};
use axum::{Json, extract::State, http::StatusCode, http::header};
use bcrypt::{Version::TwoB, hash_with_salt, verify};
use chrono::Utc;
use cookie::Cookie;
use cookie::time::Duration;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use rand::{TryRngCore, rngs::OsRng};
use serde_json::json;
use sha2::Sha256;
use sqlx::Result;
use std::collections::BTreeMap;

#[derive(PartialEq)]
enum TokenType {
    RefreshToken,
    RegularToken,
}

fn generate_token(
    token_type: TokenType,
    secrets: &shuttle_runtime::SecretStore,
    username: &String,
    name: &String,
    exp_hours: i64,
) -> String {
    let secret_name = if token_type == TokenType::RegularToken {
        "JWT_SECRET"
    } else {
        "REFRESH_TOKEN_SECRET"
    };

    let token_secret = secrets
        .get(secret_name)
        .expect("jwt token key must be in secrets");

    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(exp_hours))
        .expect("valid timestamp")
        .timestamp() as usize;

    let mut claims = BTreeMap::new();
    claims.insert("username", username.clone());
    claims.insert("name", name.clone());
    claims.insert("exp", expiration.to_string());

    let key: Hmac<Sha256> =
        Hmac::new_from_slice(token_secret.as_bytes()).expect("HMAC key should be valid");

    let token: String = claims.sign_with_key(&key).expect("Failed to sign token");

    return token;
}

// pub fn authenticate_token(secrets: shuttle_runtime::SecretStore, token: String) {}

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
    username: &String,
    name: &String,
    message: &str,
) -> Response {
    let token = generate_token(TokenType::RegularToken, &secrets, &username, &name, 4);

    let refresh_token = generate_token(TokenType::RefreshToken, &secrets, &username, &name, 720);

    let refresh_token_cookie = create_refresh_cookie(&refresh_token);

    let response_json = json!({
    "message": message,
    "token" : token,
    "user": { "username": username, "name": name }
    });

    (
        StatusCode::OK,
        [(header::SET_COOKIE, refresh_token_cookie.to_string())],
        Json(response_json),
    )
        .into_response()
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

    let sql_query = include_str!("../sql/select_user_by_username.sql");
    let select_user_result: Result<User, sqlx::Error> = sqlx::query_as::<_, User>(sql_query)
        .bind(&payload.username)
        .fetch_one(&state.pool)
        .await;

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
            return auth_response(
                &state.secrets,
                &payload.username,
                &payload.name,
                "Conta criada com sucesso",
            );
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

    let sql_query = include_str!("../sql/select_user_by_username.sql");
    let user_result: Result<User, sqlx::Error> = sqlx::query_as::<_, User>(sql_query)
        .bind(payload.username)
        .fetch_one(&state.pool)
        .await;

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

                    return auth_response(
                        &state.secrets,
                        &user.username,
                        &user.name,
                        "Login bem-sucedido",
                    );
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
