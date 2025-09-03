// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use fastcrypto::ed25519::Ed25519KeyPair;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod app;
pub mod common;
pub mod dns;
pub mod proxy;

/// App state, at minimum needs to maintain the ephemeral keypair.  
pub struct AppState {
    /// Keypair - initially ephemeral, can be replaced with master key
    pub kp: Arc<RwLock<Ed25519KeyPair>>,
    /// Flag to track if master key has been set
    pub master_key_set: Arc<RwLock<bool>>,
}

/// Implement IntoResponse for EnclaveError.
impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            EnclaveError::GenericError(e) => (StatusCode::BAD_REQUEST, e),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

/// Enclave errors enum.
#[derive(Debug)]
pub enum EnclaveError {
    GenericError(String),
}
