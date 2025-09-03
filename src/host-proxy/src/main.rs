mod config;
mod proxy;
mod transparent_proxy;

use anyhow::Result;
use std::{
    os::fd::{FromRawFd, IntoRawFd},
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, unix::AsyncFd},
    net::TcpStream,
    sync::broadcast,
    time::sleep,
};
use vsock::VsockListener;

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::load_config(std::option_env!("CONFIG_PATH").unwrap_or("config.yaml"))?;
    let (aborter, _) =
        broadcast::channel(config.tcp_proxies.len() + config.vsock_proxies.len() + 2);
    transparent_proxy::spawn_transparent_proxy(config.transparent_proxy_port, aborter.subscribe());
    for proxy in config.tcp_proxies {
        proxy::spawn_proxy_tcp(
            proxy.host_port,
            config.enclave_cid,
            proxy.vsock_port,
            aborter.subscribe(),
        );
    }
    for proxy in config.vsock_proxies {
        proxy::spawn_proxy_vsock(proxy.vsock_port, proxy.host_port, aborter.subscribe());
    }

    let raw_listener =
        VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, config.enclave_config_port)?;
    raw_listener.set_nonblocking(true)?;

    let config_listener = AsyncFd::new(raw_listener)?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl-C received, shutting down");
                break;
            }
            guard = config_listener.readable() => {
                let mut guard = guard?;
                match guard.try_io(|inner| inner.get_ref().accept()) {
                    Ok(Ok((stream, addr))) => {
                        if addr.cid() != config.enclave_cid {
                            eprintln!("Received connection from unexpected CID: {}", addr.cid());
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                        let raw_fd = nix::unistd::dup(stream)?;
                        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
                        std_stream.set_nonblocking(true)?;
                        let mut stream = TcpStream::from_std(std_stream)?;
                        let buf = serde_json::to_vec(&config.enclave_config)?;
                        stream.write_all(&buf).await?;
                        stream.shutdown().await?;
                    }
                    Ok(Err(e)) => {
                        eprintln!("Accept error: {:?}", e);
                    }
                    Err(_would_block) => {
                        continue;
                    }
                }
            }
        }
    }
    aborter.send(())?;
    sleep(Duration::from_millis(50)).await;
    Ok(())
}
