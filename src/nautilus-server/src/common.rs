// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::AppState;
use crate::EnclaveError;
use axum::{Json, extract::State};
use fastcrypto::traits::Signer;
use fastcrypto::{encoding::Encoding, traits::ToFromBytes};
use fastcrypto::{encoding::Hex, traits::KeyPair as FcKeyPair};
use nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use nsm_api::driver;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::info;

use fastcrypto::ed25519::Ed25519KeyPair;
// ==== COMMON TYPES ====

/// Intent message wrapper struct containing the intent scope and timestamp.
/// This standardizes the serialized payload for signing.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntentMessage<T: Serialize> {
    pub intent: IntentScope,
    pub timestamp_ms: u64,
    pub data: T,
}

/// Intent scope enum. Add new scope here if needed, each corresponds to a
/// scope for signing. Replace in with your own intent per message type being signed by the enclave.
#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum IntentScope {
    Seal = 0,
}

impl<T: Serialize + Debug> IntentMessage<T> {
    pub fn new(data: T, timestamp_ms: u64, intent: IntentScope) -> Self {
        Self {
            data,
            timestamp_ms,
            intent,
        }
    }
}

/// Wrapper struct containing the response (the intent message) and signature.
#[derive(Serialize, Deserialize)]
pub struct ProcessedDataResponse<T> {
    pub response: T,
    pub signature: String,
}

/// Wrapper struct containing the request payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessDataRequest<T> {
    pub payload: T,
}

/// Sign the bcs bytes of the the payload with keypair.
pub fn to_signed_response<T: Serialize + Clone>(
    kp: &Ed25519KeyPair,
    payload: T,
    timestamp_ms: u64,
    intent: IntentScope,
) -> ProcessedDataResponse<IntentMessage<T>> {
    let intent_msg = IntentMessage {
        intent,
        timestamp_ms,
        data: payload.clone(),
    };

    let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
    let sig = kp.sign(&signing_payload);
    ProcessedDataResponse {
        response: intent_msg,
        signature: Hex::encode(sig),
    }
}

// ==== HEALTHCHECK, GET ATTESTATION ENDPOINT IMPL ====

/// Response for get attestation.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAttestationResponse {
    /// Attestation document serialized in Hex.
    pub attestation: String,
}

/// Endpoint that returns an attestation committed
/// to the enclave's public key.
pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GetAttestationResponse>, EnclaveError> {
    info!("get attestation called");

    let kp = state.kp.read().await;
    let pk = kp.public();
    let fd = driver::nsm_init();

    // Send attestation request to NSM driver with public key set.
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(ByteBuf::from(pk.as_bytes().to_vec())),
    };

    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            Ok(Json(GetAttestationResponse {
                attestation: Hex::encode(document),
            }))
        }
        _ => {
            driver::nsm_exit(fd);
            Err(EnclaveError::GenericError(
                "unexpected response".to_string(),
            ))
        }
    }
}

/// Health check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Hex encoded public key booted on enclave.
    pub pk: String,
}

/// Health check endpoint.
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthCheckResponse>, EnclaveError> {
    let kp = state.kp.read().await;
    let pk = kp.public();
    Ok(Json(HealthCheckResponse {
        pk: Hex::encode(pk.as_bytes()),
    }))
}
