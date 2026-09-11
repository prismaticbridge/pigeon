use std::path::PathBuf;
use std::sync::OnceLock;
use n0_error::{Result, StdResultExt};
use clap::Parser;

mod connect;
mod listen;
mod mdns;
mod utils;
mod api_wrapper;

use pigeon::common::{SECRET_KEY, MDNS_USERNAME, ONLINE_USERNAME, load_or_create_identity};
use pigeon::constants;

use crate::api_wrapper::{change_name_interactive, create_name_and_register, download_db, get_public_key, inject_db, register_http};
use crate::utils::{DiscoveryType, create_endpoint, get_endpoint_info_interactive, safe_print, try_load_name};
use crate::mdns::exchange_info_mdns;
use crate::connect::connect_and_send;
use listen::listen;

pub static USE_SERVER: OnceLock<bool> = OnceLock::new();

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    send_file: Option<PathBuf>,
    #[arg(short, long)]
    change_name: bool,
    #[arg(short, long)]
    download_db: bool,
    #[arg(short, long)]
    inject_db: bool,
}

async fn online_thread() -> Result<()> {
    USE_SERVER.set(true).expect("Can't set USE_SERVER for some reason");
    let current_username = MDNS_USERNAME.get().unwrap();
    let key = SECRET_KEY.get().unwrap();
    let result = get_public_key(&current_username).await;
    match result {
        Err(_) => {
            debug_print_above!("Failed to get public key or not registered yet, trying to register");
            register_http(&current_username, &key.public()).await.anyerr().inspect_err(|e| safe_print(&format!("Failed to register: {e}")))?;
            ONLINE_USERNAME.set(current_username.clone()).unwrap();
        }
        Ok(server_key) => {
            if server_key == key.public() {
                ONLINE_USERNAME.set(current_username.clone()).unwrap();
            } else {
                safe_print("Server and local public keys do not match, creating a new identity");
                ONLINE_USERNAME.set(create_name_and_register(&constants::DATA_DIR, &key.public(), true).await.anyerr()?).unwrap();
            }
        }
    }

    safe_print("Successfully connected to server, cross-network transfers are available");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key = load_or_create_identity(&constants::DATA_DIR.join(constants::CLIENT_KEY_FILE)).expect("Error: cannot load key");
    SECRET_KEY.set(key.clone()).expect("SECRET_KEY already set");
    let result = try_load_name(&constants::DATA_DIR.join(constants::NAME_FILE));
    let username = match result {
        Ok(username) => {
            username
        },
        Err(_) => {
            create_name_and_register(&constants::DATA_DIR, &key.public(), false).await?
        }
    };
    safe_print(&format!("Loaded previous identity {}. public key signature is {}", username, key.public()));
    pigeon::common::MDNS_USERNAME.set(username).expect("USERNAME already set");

    let online_thread = tokio::spawn(online_thread());

    if args.change_name {
        //could technically use "key" but SECRET_KEY should be the single source of truth
        return change_name_interactive(SECRET_KEY.get().unwrap()).await
    }
    else if args.download_db {
        tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(|| ONLINE_USERNAME.wait()),
        )
        .await.anyerr()?.anyerr()?;
        return download_db(SECRET_KEY.get().unwrap()).await
    }
    else if args.inject_db {
        tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(|| ONLINE_USERNAME.wait()),
        )
        .await.anyerr()?.anyerr()?;
        return inject_db(SECRET_KEY.get().unwrap()).await
    }

    let endpoint = create_endpoint().await?;

    let mdns_lookup_thread = tokio::spawn(exchange_info_mdns(endpoint.clone()));
    let listen_thread = tokio::spawn(listen(endpoint.clone()));

    if let Some(send_path) = args.send_file {
        let (target_info, discovery_type) = get_endpoint_info_interactive().await;
        let connect_name = match discovery_type {
            DiscoveryType::MDNS => MDNS_USERNAME.get().unwrap(),
            DiscoveryType::SERVER => ONLINE_USERNAME.get().unwrap(),
        };
        connect_and_send(&endpoint, &target_info, &send_path, connect_name).await?;

        //don't need to listen anymore once done sending
        if !listen_thread.is_finished() {
            listen_thread.abort();
            let _ = listen_thread.await;
        }
    }
    else {
        //if not sending, wait for listen thread to properly finish
        listen_thread.await.anyerr()??;
    }

    if !mdns_lookup_thread.is_finished() {
        mdns_lookup_thread.abort();
        let _ = mdns_lookup_thread.await;
    }
    if !online_thread.is_finished() {
        online_thread.abort();
        let _ = online_thread.await;
    }

    endpoint.close().await;

    println!("everything is done running, should exit now");

    return Ok(())
}
