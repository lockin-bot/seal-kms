use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader};

#[derive(Debug, Deserialize, Serialize)]
pub struct StreamProxy {
    pub host_port: u16,
    pub vsock_port: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SealConfig {
    pub enclave_package_id: String,
    pub module_name: String,
    pub otw_name: String,
    pub kms_package_id: String,
    pub enclave_endpoint: String,
    pub enclave_config_object_id: String,
    pub encrypted_master_key_object_id: String,
    pub sui_secret_key: String,
    pub sui_network: String,
    pub server_object_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EnclaveConfig {
    pub seal: SealConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub tcp_proxies: Vec<StreamProxy>,
    pub vsock_proxies: Vec<StreamProxy>,
    pub transparent_proxy_port: u32,
    pub enclave_cid: u32,
    pub enclave_config: EnclaveConfig,
}

pub fn load_config(path: &str) -> Result<ServerConfig> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let config: ServerConfig = serde_yaml::from_reader(reader)?;
    Ok(config)
}
