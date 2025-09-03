use hickory_resolver::Resolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use std::os::fd::{FromRawFd, IntoRawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::{Duration, timeout};
use vsock::VsockListener;

const MAX_CLIENT_HELLO: usize = 64 * 1024; // upper bound to protect memory
const READ_TIMEOUT: Duration = Duration::from_secs(2);

pub fn spawn_transparent_proxy(port: u32, mut aborter: broadcast::Receiver<()>) {
    tokio::spawn(async move {
        let raw_listener = VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, port)?;
        raw_listener.set_nonblocking(true)?;

        let listener = AsyncFd::new(raw_listener)?;

        let resolver = Resolver::builder_tokio()?.build();

        println!(
            "Listening for transparent proxy connections on port {}",
            port
        );

        loop {
            tokio::select! {
                _ = aborter.recv() => {
                    println!("Shutting down transparent proxy");
                    break;
                }
                guard = listener.readable() => {
                    let mut guard = guard?;
                    match guard.try_io(|inner| inner.get_ref().accept()) {
                        Ok(Ok((stream, _addr))) => {
                            let raw_fd = nix::unistd::dup(stream)?;
                            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd.into_raw_fd()) };
                            std_stream.set_nonblocking(true)?;
                            let stream = TcpStream::from_std(std_stream)?;
                            let resolver = resolver.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_conn(stream, resolver).await {
                                    println!("Failed to handle transparent proxy connection: {:?}", e);
                                }
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
        anyhow::Ok(())
    });
}

async fn handle_conn(
    mut client: TcpStream,
    resolver: Resolver<TokioConnectionProvider>,
) -> anyhow::Result<()> {
    // Read some bytes with timeout into a buffer
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = match timeout(READ_TIMEOUT, client.read(&mut buf)).await {
        Ok(Ok(0)) => {
            // client closed immediately
            return Ok(());
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return Err(e.into());
        }
        Err(_) => {
            // timed out waiting for initial bytes
            return Err(anyhow::anyhow!("timeout reading ClientHello"));
        }
    };

    // try to extract SNI from the buffered bytes
    let sni = extract_sni_from_client_hello(&buf[..n]).unwrap_or_default();

    // Perform DNS lookup for the SNI hostname
    let socket_addr = if !sni.is_empty() {
        let results = resolver.lookup_ip(&sni).await?;
        results.iter().next()
    } else {
        None
    };

    let backend = socket_addr.ok_or(anyhow::anyhow!("No IP address found for {}", sni))?;

    println!("Transparent https proxy: {} -> {}", sni, backend);

    // connect to backend
    let mut backend_conn = TcpStream::connect((backend, 443)).await?;

    // first send the bytes we already read
    backend_conn.write_all(&buf[..n]).await?;

    tokio::io::copy_bidirectional(&mut client, &mut backend_conn).await?;

    Ok(())
}

/// Parse a TLS ClientHello (best-effort) and return the SNI hostname if present.
///
/// This is a defensive manual parser that extracts SNI from the first TLS record(s) present
/// in `data`. It checks bounds and returns None on malformed or incomplete data.
fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // Need at least 5 bytes for TLS record header
    if data.len() < 5 {
        return None;
    }
    let mut idx = 0usize;

    // TLS record header: type(1)=22 handshake, version(2), length(2)
    let record_type = data[0];
    if record_type != 22 {
        return None;
    } // not a handshake record
    let rec_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    idx += 5;
    if data.len() < idx + rec_len {
        return None;
    } // not enough bytes yet

    // Handshake header: msg_type(1)=1 ClientHello, length(3)
    if idx + 4 > data.len() {
        return None;
    }
    let hs_type = data[idx];
    if hs_type != 1 {
        return None;
    } // not ClientHello
    let hs_len = ((data[idx + 1] as usize) << 16)
        | ((data[idx + 2] as usize) << 8)
        | (data[idx + 3] as usize);
    idx += 4;
    if data.len() < idx + hs_len {
        return None;
    }

    // ClientHello fields:
    // client_version (2) + random (32)
    if idx + 2 + 32 > data.len() {
        return None;
    }
    idx += 2 + 32;

    // Session ID
    if idx + 1 > data.len() {
        return None;
    }
    let session_id_len = data[idx] as usize;
    idx += 1;
    if idx + session_id_len > data.len() {
        return None;
    }
    idx += session_id_len;

    // Cipher suites
    if idx + 2 > data.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
    idx += 2;
    if idx + cs_len > data.len() {
        return None;
    }
    idx += cs_len;

    // Compression methods
    if idx + 1 > data.len() {
        return None;
    }
    let comp_len = data[idx] as usize;
    idx += 1;
    if idx + comp_len > data.len() {
        return None;
    }
    idx += comp_len;

    // Extensions (optional)
    if idx + 2 > data.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
    idx += 2;
    if idx + ext_total > data.len() {
        return None;
    }
    let mut ext_idx = idx;
    let ext_end = idx + ext_total;

    while ext_idx + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[ext_idx], data[ext_idx + 1]]);
        let ext_len = u16::from_be_bytes([data[ext_idx + 2], data[ext_idx + 3]]) as usize;
        ext_idx += 4;
        if ext_idx + ext_len > ext_end {
            return None;
        }

        if ext_type == 0 {
            // server_name extension
            // structure: list_length(2), then list of (name_type(1), name_len(2), name)
            if ext_len < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([data[ext_idx], data[ext_idx + 1]]) as usize;
            let mut list_idx = ext_idx + 2;
            let list_end = ext_idx + ext_len;
            if list_idx + list_len > list_end {
                return None;
            }
            while list_idx + 3 <= list_end {
                let name_type = data[list_idx];
                let name_len =
                    u16::from_be_bytes([data[list_idx + 1], data[list_idx + 2]]) as usize;
                list_idx += 3;
                if list_idx + name_len > list_end {
                    return None;
                }
                if name_type == 0 {
                    // host_name
                    let name = &data[list_idx..list_idx + name_len];
                    if let Ok(s) = std::str::from_utf8(name) {
                        return Some(s.to_string());
                    } else {
                        return None;
                    }
                } else {
                    list_idx += name_len;
                }
            }
            return None;
        } else {
            ext_idx += ext_len;
        }
    }

    None
}
