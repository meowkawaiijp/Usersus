use axum::{
    routing::post,
    Router,
    extract::State,
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashSet;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use client_lib::LicenseClaims;

#[derive(Clone)]
struct AppState {
    // A real server would use a database.
    // Here we use an in-memory set to keep track of revoked hardware IDs or token signatures
    // For simplicity, we assume we revoke by hardware ID (`sub`)
    revoked_hw_ids: Arc<Mutex<HashSet<String>>>,
    public_key_pem: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // In a real application, the path to the public key and revoked list would be loaded from config
    let public_key_path = std::env::var("PUBLIC_KEY_PATH").unwrap_or_else(|_| "public_key.pem".to_string());

    let public_key_pem = match std::fs::read(&public_key_path) {
        Ok(pem) => pem,
        Err(_) => {
            println!("Warning: Could not read public key from {}. Server will reject all verifications until you generate keys.", public_key_path);
            vec![]
        }
    };

    let state = AppState {
        revoked_hw_ids: Arc::new(Mutex::new(HashSet::new())),
        public_key_pem,
    };

    let app = Router::new()
        .route("/api/v1/verify", post(verify_license))
        .route("/api/v1/revoke", post(revoke_license))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    println!("License server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn verify_license(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if state.public_key_pem.is_empty() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Server misconfigured: missing public key").into_response();
    }

    let auth_header = headers.get("Authorization");
    let jwt = match auth_header {
        Some(header) => {
            let s = header.to_str().unwrap_or("");
            if s.starts_with("Bearer ") {
                s.trim_start_matches("Bearer ")
            } else {
                return (StatusCode::UNAUTHORIZED, "Invalid Authorization header format").into_response();
            }
        }
        None => return (StatusCode::UNAUTHORIZED, "Missing Authorization header").into_response(),
    };

    let key = match DecodingKey::from_ed_pem(&state.public_key_pem) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid server public key").into_response(),
    };

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 60;

    let token_data = match decode::<LicenseClaims>(jwt, &key, &validation) {
        Ok(data) => data,
        Err(err) => {
            // Log the error in a real app
            println!("Token decode error: {:?}", err);
            return (StatusCode::FORBIDDEN, "Invalid or expired license").into_response();
        }
    };

    let claims = token_data.claims;

    // Check if revoked
    let revoked = state.revoked_hw_ids.lock().await;
    if revoked.contains(&claims.sub) {
        return (StatusCode::FORBIDDEN, "License has been revoked").into_response();
    }

    (StatusCode::OK, "License is valid").into_response()
}

// Endpoint to simulate revoking a hardware ID
async fn revoke_license(
    State(state): State<AppState>,
    body: axum::extract::Json<String>, // Just accepting the hw_id as JSON string
) -> impl IntoResponse {
    let hw_id = body.0;
    let mut revoked = state.revoked_hw_ids.lock().await;
    revoked.insert(hw_id.clone());
    println!("Revoked hardware ID: {}", hw_id);
    (StatusCode::OK, format!("Revoked {}", hw_id)).into_response()
}
