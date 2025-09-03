// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::AppState;
use crate::EnclaveError;
use axum::Json;
use axum::extract::State;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::Signer;
use serde::{Deserialize, Serialize};
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use vsock::VsockStream;

/// Inner type T for IntentMessage<T>
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SealRequest {
    pub timestamp_ms: u64,
    pub id: Vec<u8>,
    pub requester: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignIntentRequest {
    pub payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignIntentResponse {
    pub signature: String,
}

pub async fn sign_intent(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignIntentRequest>,
) -> Result<Json<SignIntentResponse>, EnclaveError> {
    let signing_payload = Hex::decode(&request.payload)
        .map_err(|e| EnclaveError::GenericError(format!("Decode intent from hex error: {}", e)))?;
    let kp = state.kp.read().await;
    let sig = kp.sign(&signing_payload);
    Ok(Json(SignIntentResponse {
        signature: Hex::encode(sig),
    }))
}

pub async fn load_config() -> Result<Json<serde_json::Value>, EnclaveError> {
    let vsock_stream = VsockStream::connect_with_cid_port(2, 30999)
        .map_err(|e| EnclaveError::GenericError(format!("Connect to vsock error: {}", e)))?;
    let raw_fd = nix::unistd::dup(vsock_stream)
        .map_err(|e| EnclaveError::GenericError(format!("Dup vsock error: {}", e)))?;
    let vsock_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
    vsock_stream
        .set_nonblocking(true)
        .map_err(|e| EnclaveError::GenericError(format!("Set nonblocking error: {}", e)))?;

    let mut vsock_stream = TcpStream::from_std(vsock_stream).unwrap();
    let mut buf = Vec::new();
    vsock_stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| EnclaveError::GenericError(format!("Read to end error: {}", e)))?;
    let config: serde_json::Value = serde_json::from_slice(&buf)
        .map_err(|e| EnclaveError::GenericError(format!("Deserialize error: {}", e)))?;
    Ok(Json(config))
}
