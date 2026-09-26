use clap::Parser;
use n0_error::{Result, StdResultExt};
use std::path::PathBuf;
use std::sync::OnceLock;

mod api_wrapper;
mod connect;
mod listen;
mod mdns;
mod utils;

use pigeon::common::{MDNS_USERNAME, ONLINE_USERNAME, SECRET_KEY, load_or_create_identity};
use pigeon::constants::{self, HTTP_CLIENT};

use crate::api_wrapper::{
    change_name_interactive, create_name_and_register, delete_account, download_db, get_public_key, inject_db,
    register_http,
};
use crate::connect::{ConnectTargetInfo, connect_async_wrapper};
use crate::mdns::exchange_info_mdns;
use crate::utils::{
    CACHED_KEYS, DiscoveryType, create_endpoint, get_endpoint_info_interactive, safe_print, save_key_cache,
    try_load_key_cache, try_load_name, wait_online,
};
use listen::listen;

pub static USE_SERVER: OnceLock<bool> = OnceLock::new();

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    send_file: Option<PathBuf>,
    #[arg(short, long)]
    change_name: bool,
    #[arg(short, long)]
    delete_account: bool,
    #[arg(long)]
    disable_mdns: bool,
    #[arg(long)]
    download_db: bool,
    #[arg(long)]
    inject_db: bool,
}

///Thread that manages connection with the server
///Verifies that the public key is up-to-date with the server and prompts to register again if needed
async fn online_thread() -> Result<()> {
    let client = &HTTP_CLIENT;
    let current_username = MDNS_USERNAME.get().unwrap();
    let key = SECRET_KEY.get().unwrap();
    let result = get_public_key(&current_username, &client).await;
    match result {
        Err(_) => {
            debug_print_above!("Failed to get public key or not registered yet, trying to register");
            register_http(&current_username, &key.public(), &client)
                .await
                .anyerr()
                .inspect_err(|e| safe_print(&format!("Failed to register: {e}")))?;
            ONLINE_USERNAME.set(current_username.clone()).unwrap();
            USE_SERVER.set(true).expect("Can't set USE_SERVER for some reason");
        }
        Ok(server_key) => {
            USE_SERVER.set(true).expect("Can't set USE_SERVER for some reason");
            if server_key == key.public() {
                ONLINE_USERNAME.set(current_username.clone()).unwrap();
            } else {
                safe_print("Server and local public keys do not match, creating a new identity");
                ONLINE_USERNAME
                    .set(
                        create_name_and_register(&constants::DATA_DIR, &key.public(), true, &client)
                            .await
                            .anyerr()?,
                    )
                    .unwrap();
            }
        }
    }

    safe_print("Successfully connected to server, cross-network transfers are available");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key =
        load_or_create_identity(&constants::DATA_DIR.join(constants::CLIENT_KEY_FILE)).expect("Error: cannot load key");
    SECRET_KEY.set(key.clone()).expect("SECRET_KEY already set");
    let result = try_load_name(&constants::DATA_DIR.join(constants::NAME_FILE));
    let username = match result {
        Ok(username) => username,
        Err(_) => create_name_and_register(&constants::DATA_DIR, &key.public(), false, &HTTP_CLIENT).await?,
    };
    safe_print(&format!(
        "Loaded previous identity {}. public key signature is {}",
        username,
        key.public()
    ));
    pigeon::common::MDNS_USERNAME
        .set(username)
        .expect("USERNAME already set");

    let key_path = constants::DATA_DIR.join(constants::KEY_CACHE_FILE);
    match try_load_key_cache(&key_path) {
        Ok(cache) => {
            if let Ok(mut mutex) = CACHED_KEYS.lock() {
                mutex.extend(cache);
            }
        }
        Err(e) => {
            debug_print_above!("{}", e);
        }
    };

    let online_thread = tokio::spawn(online_thread());

    //Code duplication, but cleaning this up would make it harder to read
    if args.change_name {
        let _ = wait_online().await;
        let secret_key = SECRET_KEY.get().expect("Failed to read private key");
        return change_name_interactive(secret_key, &HTTP_CLIENT).await;
    } else if args.delete_account {
        let _ = wait_online().await;
        let secret_key = SECRET_KEY.get().expect("Failed to read private key");
        return delete_account(secret_key, &HTTP_CLIENT).await;
    } else if args.download_db {
        let _ = wait_online().await;
        let secret_key = SECRET_KEY.get().expect("Failed to read private key");
        return download_db(secret_key, &HTTP_CLIENT).await;
    } else if args.inject_db {
        let _ = wait_online().await;
        let secret_key = SECRET_KEY.get().expect("Failed to read private key");
        return inject_db(secret_key, &HTTP_CLIENT).await;
    }

    let endpoint = create_endpoint().await?;

    let mdns_lookup_thread = if args.disable_mdns {
        None
    } else {
        Some(tokio::spawn(exchange_info_mdns(endpoint.clone())))
    };
    let listen_thread = tokio::spawn(listen(endpoint.clone()));

    if let Some(send_path) = args.send_file {
        let (target_name, target_info, discovery_type) = get_endpoint_info_interactive(false).await;
        let mut try_server_concurrently = false;
        let connect_name = match discovery_type {
            DiscoveryType::MDNS => MDNS_USERNAME.get().unwrap(),
            DiscoveryType::CACHE => {
                debug_print_above!("using cache");
                try_server_concurrently = true;
                if *USE_SERVER.get().unwrap_or(&false) {
                    ONLINE_USERNAME.get().unwrap()
                } else {
                    MDNS_USERNAME.get().unwrap()
                }
            }
            DiscoveryType::SERVER => ONLINE_USERNAME.get().unwrap(),
        };

        //this is needed for spawning connect_and_send on a separate thread
        let mut connect_data = ConnectTargetInfo {
            endpoint,
            target: target_info,
            path: send_path,
            sender_name: *connect_name,
        };

        //simple case: we already queried the server, or don't need to because the peer was discovered with mdns
        if !try_server_concurrently {
            //async wrapper isn't actually needed here, but its cleaner to use it anyways
            debug_print_above!("Not using concurrency");
            connect_async_wrapper(connect_data.clone()).await?;
        } else {
            //spawn connect task on a different thread
            debug_print_above!("Spawning async wrapper");
            let mut join_handle = tokio::spawn(connect_async_wrapper(connect_data.clone()));
            //cache might be wrong, so concurrently retrieve the correct publickey
            let real_key_result = get_public_key(&target_name, &HTTP_CLIENT).await;
            if let Ok(real_key) = real_key_result {
                if real_key != connect_data.target.endpoint_id {
                    //guaranteed that the connection will fail since it's using the wrong public key, abort
                    debug_print_above!("killing async wrapper");
                    join_handle.abort();
                    //while waiting for abort to run, remove the bad cache entry
                    let old_bad_key = connect_data.target.endpoint_id;
                    connect_data.target.endpoint_id = real_key;

                    //find the bad cache entry
                    if let Ok(mut map) = CACHED_KEYS.lock() {
                        //remove all instances (you never know these days, there might be multiple)
                        map.retain(|(_name, key)| *key != old_bad_key);
                    }

                    //we don't care about errors, it was aborted so probably failed
                    let _ = join_handle.await;
                    debug_print_above!("spawning new async wrapper");
                    join_handle = tokio::spawn(connect_async_wrapper(connect_data.clone()));
                }
            }

            debug_print_above!("waiting for async wrapper to finish");
            join_handle.await.anyerr()??;
        }

        //don't need to listen anymore once done sending
        if !listen_thread.is_finished() {
            listen_thread.abort();
            let _ = listen_thread.await;
        }
        connect_data.endpoint.close().await;
    } else {
        //if not sending, wait for listen thread to properly finish
        listen_thread.await.anyerr()??;
    }

    if let Some(mdns_thread) = mdns_lookup_thread
        && !mdns_thread.is_finished()
    {
        mdns_thread.abort();
        let _ = mdns_thread.await;
    }
    if !online_thread.is_finished() {
        online_thread.abort();
        let _ = online_thread.await;
    }

    save_key_cache(&key_path);

    return Ok(());
}
