use std::path::{Path, PathBuf};

use arrayvec::ArrayString;
use async_compression::tokio::write::ZstdEncoder;
use iroh::{
    Endpoint,
    endpoint::{SendStream, VarInt},
    endpoint_info::EndpointInfo,
};
use n0_error::{Result, StdResultExt, anyerr};
use pigeon::{DirectoryEntry, FileHeader, FsTreeHeader, constants::CHUNK_SIZE};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use pigeon::common::PIGEON_ALPN;

use crate::{debug_print_above, utils::safe_print};

///Generates a header that can be parsed from bytes and describes how to receive a file
async fn generate_file_header(file: &File, filename: &str) -> FileHeader {
    let length = file.metadata().await.expect("Failed to get file metadata").len();
    FileHeader {
        size: length,
        filename: ArrayString::from(filename).unwrap(),
    }
}

///Sends file name, total size, and whether a file or directory is being sent
async fn send_request_information(
    path: &Path,
    send_stream: &mut ZstdEncoder<SendStream>,
    sender_username: &ArrayString<32>,
) -> Result<u64> {
    let name_message = sender_username.as_bytes();
    send_stream.write_u8(name_message.len() as u8).await?;
    send_stream.write_all(name_message).await.anyerr()?; // send username string

    let file_name = path
        .file_name()
        .expect("Error: paths ending in . or .. are not supported yet")
        .to_str()
        .expect(&format!(
            "Error: non-UTF-8 is platform dependent and cannot reliably be sent over the network (offending file path: {})",
            path.display()
        ));
    {
        let dir_name_message = file_name.as_bytes();
        let message_size = dir_name_message.len() as u32;
        send_stream.write_u32(message_size).await?;
        send_stream.write_all(&dir_name_message).await.anyerr()?;
    }

    if path.is_dir() {
        let (total_size_bytes, num_files) = get_fstree_size(path).await?;
        send_stream.write_u64(total_size_bytes).await?;
        send_stream.write_u32(num_files).await?;
        Ok(total_size_bytes)
    } else {
        let total_size_bytes = File::open(path).await?.metadata().await?.len();
        send_stream.write_u64(total_size_bytes).await?;
        send_stream.write_u32(1u32).await?; // 1 file
        Ok(total_size_bytes)
    }
}

///Returns the size in bytes of all files inside a folder, recursively
async fn get_fstree_size(dir_path: &Path) -> Result<(u64, u32)> {
    let mut dir_size: u64 = 0;
    let mut num_files: u32 = 1; //+1 for this directory
    for entry in std::fs::read_dir(dir_path)? {
        let path = entry?.path();
        if path.is_dir() {
            let (inner_dir_size, inner_num_files) = Box::pin(get_fstree_size(&path)).await?;
            dir_size += inner_dir_size;
            num_files += inner_num_files;
        } else {
            let file = File::open(path).await?;
            let metadata = file.metadata().await?;
            dir_size += metadata.len();
            num_files += 1;
        }
    }
    Ok((dir_size, num_files))
}

///Deprecated because it crashes on deeply nested paths, due to future expansion using the whole stack
#[deprecated(note = "Replaced by `send_fstree_serialized`")]
#[allow(dead_code)]
async fn send_fstree_recursive(send_stream: &mut ZstdEncoder<SendStream>, dir_path: &Path) -> Result<()> {
    let os_dir_name = dir_path
        .file_name()
        .expect("paths ending with . or .. are not supported yet");
    let lossy_dir_name = os_dir_name.to_string_lossy();
    let dir_name = ArrayString::<256>::from(&lossy_dir_name).map_err(|_| "directory name exceeds 256 bytes")?;
    let mut header = FsTreeHeader {
        dir_name,
        entries: Vec::new(),
    };

    let mut children = Vec::new();

    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        let is_dir = path.is_dir();
        if is_dir {
            header.entries.push(DirectoryEntry::Directory);
        } else {
            header.entries.push(DirectoryEntry::File);
        }

        children.push((is_dir, path));
    }

    let header_message = postcard::to_allocvec(&header).unwrap();
    send_stream.write_u32(header_message.len() as u32).await?;
    send_stream.write_all(&header_message).await.anyerr()?;

    for (is_dir, subtree) in children {
        if is_dir {
            Box::pin(send_fstree_serialized(send_stream, &subtree)).await?;
        } else {
            send_file_wrapper(send_stream, &subtree).await?;
        }
    }

    Ok(())
}

enum SerializeFsTask {
    Directory(PathBuf),
    File(PathBuf),
}

///Iterative function that serialized a filesystem tree into bytes and sends it
async fn send_fstree_serialized(send_stream: &mut ZstdEncoder<SendStream>, root_dir_path: &Path) -> Result<()> {
    let mut tasks = vec![SerializeFsTask::Directory(root_dir_path.to_path_buf())];

    while let Some(fstask) = tasks.pop() {
        match fstask {
            SerializeFsTask::Directory(dir_path) => {
                let os_dir_name = dir_path
                    .file_name()
                    .expect("paths ending in . or .. are not supported yet");
                let lossy_dir_name = os_dir_name.to_string_lossy();
                let dir_name =
                    ArrayString::<256>::from(&lossy_dir_name).map_err(|_| "directory name exceeds 256 bytes")?;
                let mut header = FsTreeHeader {
                    dir_name,
                    entries: Vec::new(),
                };
                for entry in std::fs::read_dir(dir_path)? {
                    let path = entry?.path();
                    if path.is_dir() {
                        header.entries.push(DirectoryEntry::Directory);
                        tasks.push(SerializeFsTask::Directory(path));
                    } else {
                        header.entries.push(DirectoryEntry::File);
                        tasks.push(SerializeFsTask::File(path));
                    }
                }

                let header_message = postcard::to_allocvec(&header).unwrap();
                send_stream.write_u32(header_message.len() as u32).await?;
                send_stream.write_all(&header_message).await.anyerr()?;
            }
            SerializeFsTask::File(file_path) => {
                send_file_wrapper(send_stream, &file_path).await?;
            }
        }
    }

    Ok(())
}

///Wrapper to send a single file, including its name and size
async fn send_file_wrapper(send_stream: &mut ZstdEncoder<SendStream>, file_path: &Path) -> Result<()> {
    let mut file = tokio::fs::File::open(file_path).await?;
    let header = generate_file_header(
        &file,
        &file_path
            .file_name()
            .expect("paths ending in . or .. are not supported yet")
            .to_string_lossy(),
    )
    .await;
    let header_message = postcard::to_allocvec(&header).anyerr()?;
    debug_print_above!("prefix size: {}", header_message.len());
    debug_print_above!("header: name: {}, size: {}", header.filename, header.size);
    send_stream.write_u32(header_message.len() as u32).await?;
    send_stream.write_all(&header_message).await.anyerr()?;
    let expected_size = header.size;
    send_file_chunks(send_stream, &mut file, expected_size).await
}

///Sends the compressed raw data of a file by splitting it into chunks, compressing each chunk, and sending the chunks
async fn send_file_chunks(
    send_stream: &mut ZstdEncoder<SendStream>,
    file: &mut File,
    expected_size: u64,
) -> Result<()> {
    let mut buf = [0u8; CHUNK_SIZE];
    let mut progress_bar = tqdm::pbar(Some(expected_size as usize));
    loop {
        let amt_read = file.read(&mut buf).await?;
        if amt_read == 0 {
            break;
        }
        send_stream.write_all(&buf[..amt_read]).await?;
        let _ = progress_bar
            .update(amt_read)
            .map_err(|e| eprintln!("progress bar error: {e}"));
    }
    progress_bar.clear(false);
    send_stream.flush().await?;
    Ok(())
}

///Attempts to connect to the requested peer and send the requested file
pub async fn connect_and_send(
    endpoint: &Endpoint,
    target: &EndpointInfo,
    path: &Path,
    sender_username: &ArrayString<32>,
) -> Result<()> {
    let mut attempts = 0;
    let conn = loop {
        let conn_result = endpoint.connect(target.clone(), PIGEON_ALPN).await;
        match conn_result {
            Ok(conn) => break conn,
            Err(e) => {
                if attempts < 5 {
                    attempts += 1;
                    safe_print(&format!(
                        "Error: Connection failed: {e}, retrying {} more times",
                        5 - attempts
                    ));
                } else {
                    return Err(anyerr!("Connection failed 5 times, exiting"));
                }
            }
        }
    };
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;

    //connection init information
    send.write_u8(0u8).await.anyerr()?; // stream type 0

    let mut send_compressed = ZstdEncoder::new(send);

    let expected_size = send_request_information(path, &mut send_compressed, sender_username).await?;
    send_compressed.flush().await?; //since we have to wait for response anyways

    let response = recv.read_u8().await?;
    if response == 0 {
        return Err(anyerr!("File send denied from other end, exiting"));
    } else if response == 1 {
        if path.is_dir() {
            send_fstree_serialized(&mut send_compressed, path).await?;
        } else {
            let mut file = File::open(path).await?; //lack of abstraction maybe
            send_file_chunks(&mut send_compressed, &mut file, expected_size).await?;
        }

        send_compressed.shutdown().await?;

        let ack = recv.read_u8().await?;
        if ack == 2 {
            safe_print("File sent successfully")
        } else {
            eprintln!("Error: Invalid acknowledgement received. Something almost certainly went wrong.")
        }
    }

    conn.close(VarInt::from(0u32), b"");

    Ok(())
}

#[derive(Clone)]
pub struct ConnectTargetInfo {
    pub endpoint: Endpoint,
    pub target: EndpointInfo,
    pub path: PathBuf,
    pub sender_name: ArrayString<32>,
}

pub async fn connect_async_wrapper(data: ConnectTargetInfo) -> Result<()> {
    connect_and_send(&data.endpoint, &data.target, &data.path, &data.sender_name).await
}
