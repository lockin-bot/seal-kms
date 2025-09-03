use std::os::fd::{FromRawFd, IntoRawFd};

use tokio::{
    io::{copy_bidirectional, unix::AsyncFd},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};
use vsock::{VsockListener, VsockStream};

pub fn spawn_proxy_vsock(vsock_port: u32, host_port: u16, aborter: broadcast::Receiver<()>) {
    tokio::spawn(async move { proxy_vsock(vsock_port, host_port, aborter).await });
}

pub async fn proxy_vsock(
    vsock_port: u32,
    host_port: u16,
    mut aborter: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let raw_listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, vsock_port)?;
    raw_listener.set_nonblocking(true)?;

    let listener = AsyncFd::new(raw_listener)?;
    println!("Proxying vsock:{} to tcp:{}", vsock_port, host_port);

    loop {
        tokio::select! {
            _ = aborter.recv() => {
                println!("Shutting down proxy vsock:{} to tcp:{}", vsock_port, host_port);
                return Ok(());
            }
            guard = listener.readable() => {
                let mut guard = guard?;
                match guard.try_io(|inner| inner.get_ref().accept()) {
                    Ok(Ok((stream, _addr))) => {
                        tokio::spawn(async move {
                            // SAFETY: We know this is a valid FD for a stream
                            let raw_fd = nix::unistd::dup(stream)?;
                            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
                            std_stream.set_nonblocking(true)?;
                            let mut stream = TcpStream::from_std(std_stream)?;
                            let mut remote_stream = TcpStream::connect(("127.0.0.1", host_port)).await?;
                            copy_bidirectional(&mut stream, &mut remote_stream).await?;
                            anyhow::Ok(())
                        });
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
}

pub fn spawn_proxy_tcp(
    host_port: u16,
    vsock_cid: u32,
    vsock_port: u32,
    aborter: broadcast::Receiver<()>,
) {
    tokio::spawn(async move { proxy_tcp(host_port, vsock_cid, vsock_port, aborter).await });
}

pub async fn proxy_tcp(
    host_port: u16,
    vsock_cid: u32,
    vsock_port: u32,
    mut aborter: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", host_port)).await?;
    println!(
        "Proxying tcp:{} to vsock:{}:{}",
        host_port, vsock_cid, vsock_port
    );
    loop {
        tokio::select! {
            _ = aborter.recv() => {
                println!(
                    "Shutting down proxy tcp:{} to vsock:{}:{}",
                    host_port, vsock_cid, vsock_port
                );
                return Ok(());
            }
            rs = listener.accept() => {
                match rs {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let vsock_stream = VsockStream::connect_with_cid_port(vsock_cid, vsock_port)?;
                            // SAFETY: We know this is a valid FD for a stream
                            let raw_fd = nix::unistd::dup(vsock_stream)?;
                            let remote_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
                            remote_stream.set_nonblocking(true)?;
                            let mut remote_stream = TcpStream::from_std(remote_stream)?;
                            copy_bidirectional(&mut stream, &mut remote_stream).await?;
                            anyhow::Ok(())
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error: {:?}", e);
                        return Err(e.into());
                    }
                }
            }
        }
    }
}
