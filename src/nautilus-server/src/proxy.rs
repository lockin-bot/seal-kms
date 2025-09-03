use std::os::fd::{FromRawFd, IntoRawFd};

use tokio::{
    io::{copy_bidirectional, unix::AsyncFd},
    net::{TcpListener, TcpStream},
};
use vsock::{VsockListener, VsockStream};

pub fn spawn_proxy_vsock(vsock_port: u32, host_port: u16) {
    tokio::spawn(async move { proxy_vsock(vsock_port, host_port).await });
}

pub async fn proxy_vsock(vsock_port: u32, host_port: u16) -> anyhow::Result<()> {
    let raw_listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, vsock_port)?;
    raw_listener.set_nonblocking(true)?;

    let listener = AsyncFd::new(raw_listener)?;
    println!("Proxying vsock:{} to tcp:{}", vsock_port, host_port);

    loop {
        let mut guard = listener.readable().await?;

        match guard.try_io(|inner| inner.get_ref().accept()) {
            Ok(Ok((stream, _addr))) => {
                tokio::spawn(async move {
                    // SAFETY: We know this is a valid FD for a stream
                    let raw_fd = nix::unistd::dup(stream)?;
                    let std_stream =
                        unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
                    std_stream.set_nonblocking(true)?;
                    let mut stream = TcpStream::from_std(std_stream).unwrap();
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

pub fn spawn_proxy_tcp(host_port: u16, vsock_port: u32) {
    tokio::spawn(async move { proxy_tcp(host_port, vsock_port).await });
}

pub async fn proxy_tcp(host_port: u16, vsock_port: u32) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", host_port)).await?;
    println!("Proxying tcp:{} to vsock:{}", host_port, vsock_port);
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let vsock_stream = VsockStream::connect_with_cid_port(2, vsock_port)?;
            // SAFETY: We know this is a valid FD for a stream
            let raw_fd = nix::unistd::dup(vsock_stream)?;
            let vsock_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
            vsock_stream.set_nonblocking(true)?;

            let mut vsock_stream = TcpStream::from_std(vsock_stream).unwrap();
            copy_bidirectional(&mut stream, &mut vsock_stream).await?;
            anyhow::Ok(())
        });
    }
}
