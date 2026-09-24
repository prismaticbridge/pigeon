use arrayvec::ArrayString;
use async_compression::tokio::bufread::ZstdDecoder;
use iroh::{
    Endpoint, TransportAddr,
    endpoint::{Connection, RecvStream, RemoteInfo, SendStream},
};
use n0_error::{Result, StdResultExt, anyerr};
use pigeon::{
    DirectoryEntry, FileHeader, FsTreeHeader,
    constants::{CHUNK_SIZE, HTTP_CLIENT},
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
};

use crate::{
    api_wrapper::get_public_key,
    debug_print_above,
    mdns::exchange_usernames,
    utils::{get_endpoint_info, safe_input, safe_wait_connection_closed},
};

///Asks the user for confirmation to write to a file
async fn confirm_write(filename: &str, num_files: u32, total_size_bytes: u64, sender_name: &str) -> bool {
    //first, ask for initial confirmation
    let mut input = String::new();
    safe_input(
        &format!("Receive {filename} ({num_files} file(s), {total_size_bytes} bytes total) from {sender_name}? (y/N) "),
        &mut input,
    );
    let trimmed = input.trim();
    if !(trimmed.starts_with('y') || trimmed.starts_with('Y')) {
        return false;
    }
    //if confirmed and the file doesn't exist already, go
    if !PathBuf::from(filename).exists() {
        return true;
    };
    println!("{filename} exists already");
    input.clear();
    safe_input(&format!("Overwrite {filename}? (y/N) "), &mut input);
    let trimmed = input.trim();
    trimmed.starts_with('y') || trimmed.starts_with('Y')
}

///Deprecated because it crashes on deeply nested paths, due to future expansion using the whole stack
#[deprecated(note = "Replaced by `recv_fstree_serialized`")]
#[allow(dead_code)]
async fn recv_fstree_recursive(
    recv_stream: &mut ZstdDecoder<BufReader<RecvStream>>,
    current_dir_path: &Path,
) -> Result<()> {
    let header_size = recv_stream.read_u32().await? as usize;
    let mut buf = vec![0u8; header_size];
    recv_stream.read_exact(&mut buf).await.anyerr()?;

    let header: FsTreeHeader = postcard::from_bytes(&buf).anyerr()?;
    let dir_name = header.dir_name;
    let new_dir_path = current_dir_path.join(Path::new(dir_name.as_str()));
    std::fs::create_dir(&new_dir_path)?;

    for subtree in header.entries {
        match subtree {
            DirectoryEntry::Directory => {
                Box::pin(recv_fstree_serialized(recv_stream, &new_dir_path)).await?;
            }
            DirectoryEntry::File => {
                recv_file_wrapper(recv_stream, &new_dir_path).await?;
            }
        }
    }

    Ok(())
}

enum DeserializeFsTask {
    Directory(Arc<PathBuf>),
    File(Arc<PathBuf>),
}

///Receive a filesystem tree serialized with send_fstree_serialized and deserialize it, and write it
async fn recv_fstree_serialized(recv_stream: &mut ZstdDecoder<BufReader<RecvStream>>, base_dir: &Path) -> Result<()> {
    let mut tasks = vec![DeserializeFsTask::Directory(Arc::new(base_dir.to_path_buf()))];
    while let Some(fstask) = tasks.pop() {
        match fstask {
            DeserializeFsTask::Directory(parent_path) => {
                let header_size = recv_stream.read_u32().await? as usize;
                let mut buf = vec![0u8; header_size];
                recv_stream.read_exact(&mut buf).await.anyerr()?;

                let header: FsTreeHeader = postcard::from_bytes(&buf).anyerr()?;
                let dir_name = header.dir_name;
                let new_dir_path = Arc::new(parent_path.join(Path::new(dir_name.as_str())));
                std::fs::create_dir(new_dir_path.as_path())?;

                for subtree in header.entries {
                    match subtree {
                        DirectoryEntry::Directory => {
                            tasks.push(DeserializeFsTask::Directory(Arc::clone(&new_dir_path)));
                        }
                        DirectoryEntry::File => {
                            tasks.push(DeserializeFsTask::File(Arc::clone(&new_dir_path)));
                        }
                    }
                }
            }
            DeserializeFsTask::File(parent_path) => {
                recv_file_wrapper(recv_stream, &parent_path).await?;
            }
        }
    }

    Ok(())
}

///Wrapper to receive information about a file, and use it to receive the file
async fn recv_file_wrapper(
    recv_stream: &mut ZstdDecoder<BufReader<RecvStream>>,
    current_dir_path: &Path,
) -> Result<()> {
    let header_size = recv_stream.read_u32().await.anyerr()? as usize;
    debug_print_above!("prefix size: {}", header_size);
    let mut buf = vec![0u8; header_size];
    recv_stream.read_exact(&mut buf).await.anyerr()?;

    let header: FileHeader = postcard::from_bytes(&buf).anyerr()?;
    debug_print_above!("header: name: {}, size: {}", header.filename, header.size);
    recv_file_chunks(recv_stream, &current_dir_path.join(header.filename), header.size).await
}

///Receives a file by receiving compressed chunks, decompressing them, and writing them to a file
async fn recv_file_chunks(
    recv_stream: &mut ZstdDecoder<BufReader<RecvStream>>,
    file_path: &Path,
    expected_size: u64,
) -> Result<()> {
    let mut file = File::create(file_path).await.expect("Failed to create file");

    let mut buf = [0u8; CHUNK_SIZE];
    let mut progress_bar = tqdm::pbar(Some(expected_size as usize));
    let mut total_transferred: usize = 0;
    let bytes_copied = loop {
        let remaining = expected_size as usize - total_transferred;
        if remaining == 0 {
            break total_transferred;
        }
        let amt_read = if remaining < CHUNK_SIZE {
            recv_stream.read_exact(&mut buf[..remaining]).await?;
            file.write_all(&buf[..remaining]).await?;
            remaining
        } else {
            recv_stream.read_exact(&mut buf).await?;
            file.write_all(&buf).await?;
            CHUNK_SIZE
        };
        total_transferred += amt_read;
        let _ = progress_bar
            .update(amt_read)
            .map_err(|e| eprintln!("progress bar error: {e}"));
    } as u64;
    file.flush().await?;
    progress_bar.clear(false);

    // let bytes_copied = tokio::io::copy(recv_stream, &mut file).await;
    if bytes_copied > expected_size {
        eprintln!(
            "Warning: more data written ({bytes_copied}) than expected ({expected_size}), potentially corrupt file"
        );
    } else if bytes_copied < expected_size {
        eprintln!(
            "Warning: less data written ({bytes_copied}) than expected ({expected_size}), potentially corrupt file"
        );
    } else {
        println!("File transferred successfully");
    }
    Ok(())
}

///Listens for incoming connections and hands them to the appropriate function
pub async fn listen(endpoint: Endpoint) -> Result<()> {
    loop {
        let conn = loop {
            match endpoint.accept().await {
                Some(incoming) => {
                    match incoming.accept() {
                        Ok(accepting) => break accepting.await?,
                        Err(err) => {
                            eprintln!("incoming connection failed: {err:#}"); // this happens randomly, ignore it
                            continue;
                        }
                    };
                }
                None => continue,
            }
        };

        let Ok((mut send, mut recv)) = conn.accept_bi().await.anyerr() else {
            continue;
        };
        let remote_id = conn.remote_id();
        let connection_info = endpoint.remote_info(remote_id).await;

        let stream_type = recv.read_u8().await?;
        debug_print_above!("accepted connection with stream type {stream_type}");
        match stream_type {
            0 => return receive_file_connection(&mut send, recv, &conn, &connection_info).await,
            1 => {
                exchange_usernames(&mut send, &mut recv, get_endpoint_info(&conn, &endpoint).await?).await?;
                safe_wait_connection_closed(&conn).await;
            }
            _ => return Err(anyerr!("unknown stream type: {}", stream_type)),
        }
    }
}

///Receives a file or directory
///This is safe if the server is accessible, it may be unsafe on local LAN-only networks (see docs/security_issues.md)
pub async fn receive_file_connection(
    send: &mut SendStream,
    recv: RecvStream,
    conn: &Connection,
    remote_info: &Option<RemoteInfo>,
) -> Result<()> {
    let mut recv_decompressed = ZstdDecoder::new(BufReader::new(recv));
    let username_size = recv_decompressed.read_u8().await?;
    let mut buf = vec![0u8; username_size as usize];
    recv_decompressed.read_exact(&mut buf).await.anyerr()?;
    let claimed_sender_name = ArrayString::<32>::from_str(str::from_utf8(&buf).anyerr()?).anyerr()?;
    //first check if its a local connection, if so its trustworthy enough
    let mut trusted = false;
    if let Some(info) = remote_info {
        for addr in info.addrs() {
            if let TransportAddr::Ip(socket_addr) = addr.addr() {
                match socket_addr {
                    SocketAddr::V4(ipv4) => {
                        if ipv4.ip().is_private() || ipv4.ip().is_loopback() {
                            trusted = true;
                        }
                    }
                    SocketAddr::V6(ipv6) => {
                        if ipv6.ip().is_unique_local() || ipv6.ip().is_loopback() {
                            trusted = true;
                        }
                    }
                }
            }
        }
    }
    //if its not local, verify the public key with the server
    if !trusted {
        let real_publickey = get_public_key(&claimed_sender_name, &HTTP_CLIENT)
            .await
            .map_err(|e| anyerr!("Cannot verify peer's remote identity because the server returned error code {e}"))?;
        let peer_publickey = conn.remote_id();
        if real_publickey != peer_publickey {
            return Err(
            "Error: The peer's remote identity does not match the one on the server, they might be impersonating the real sender. Terminating the connection".into(),
        );
        }
    }
    //otherwise its the real sender, continue
    let sender_name = claimed_sender_name;

    let filename_size = recv_decompressed.read_u32().await?;
    let mut buf = vec![0u8; filename_size as usize];
    recv_decompressed.read_exact(&mut buf).await.anyerr()?;
    let filename_unsanitized = String::from_utf8(buf).anyerr()?;
    let filename_path = Path::new(&filename_unsanitized)
        .file_name()
        .expect("Received path ends in . or .. which is not supported, exiting");
    let filename = filename_path.to_str().unwrap();

    let total_size_bytes = recv_decompressed.read_u64().await?;
    let num_files = recv_decompressed.read_u32().await?;

    if confirm_write(filename, num_files, total_size_bytes, &sender_name).await {
        send.write_all(&[1]).await.expect("failed to send confirmation");
        send.flush().await?;

        if num_files == 1 {
            recv_file_chunks(
                &mut recv_decompressed,
                &PathBuf::from_str(&filename).anyerr()?,
                total_size_bytes,
            )
            .await?;
        } else {
            recv_fstree_serialized(&mut recv_decompressed, Path::new(".")).await?;
        }
        send.write_all(&[2]).await.expect("failed to send ACK");
        println!("Finished receiving file");
    } else {
        send.write_all(&[0]).await.expect("failed to send confirmation");
        println!("Not receiving file");
    }

    send.finish().anyerr()?;
    send.flush().await?;
    match send.stopped().await {
        Ok(None) => {}
        Ok(Some(val)) => eprintln!("Error (stopped returned Ok(Some(val))): {val}"),
        Err(e) => eprintln!("Error (stopped returned Err(e)): {e}"),
    }

    safe_wait_connection_closed(conn).await;

    Ok::<(), n0_error::AnyError>(())
}
