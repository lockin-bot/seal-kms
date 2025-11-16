// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use axum::{
    Router,
    routing::{get, post},
};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use hickory_server::server::ServerFuture;
use nautilus_server::app::{public_key, sign_intent};
use nautilus_server::common::{get_attestation, health_check};
use nautilus_server::dns::LocalhostHandler;
use nautilus_server::{AppState, app::load_config};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Start DNS server
    let handler = LocalhostHandler {};
    let mut dns_server = ServerFuture::new(handler);
    let socket = UdpSocket::bind("127.0.0.1:53").await?;
    dns_server.register_socket(socket);
    println!("DNS server listening on port 53");

    // Allow accessing app server via vsock
    nautilus_server::proxy::spawn_proxy_vsock(8000, 8000);
    // Transparent proxy for outbound TLS traffic
    nautilus_server::proxy::spawn_proxy_tcp(443, 30443);

    let eph_kp = Ed25519KeyPair::generate(&mut rand::rngs::ThreadRng::default());

    let state = Arc::new(AppState {
        kp: Arc::new(RwLock::new(eph_kp)),
    });

    // Define your own restricted CORS policy here if needed.
    let cors = CorsLayer::new().allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(hello))
        .route("/sign_intent", post(sign_intent))
        .route("/public_key", get(public_key))
        .route("/load_config", get(load_config))
        .route("/get_attestation", get(get_attestation))
        .route("/health_check", get(health_check))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to port 3000: {e}"))?;
    info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;

    dns_server.block_until_done().await?;
    Ok(())
}

async fn hello() -> &'static str {
    "Hello from seal-kms!"
}
