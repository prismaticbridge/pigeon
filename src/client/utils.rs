use crate::USE_SERVER;
use crate::api_wrapper::get_public_key;
use crate::mdns::get_endpoint_info_mdns;
use arrayvec::{ArrayString, CapacityError};
use iroh::endpoint::{Connection, ConnectionError};
use iroh::endpoint_info::{EndpointData, EndpointInfo};
use iroh::{Endpoint, PublicKey};
use n0_error::StdResultExt;
use n0_error::{Result, anyerr};
use pigeon::common::{ONLINE_USERNAME, SECRET_KEY, bind_endpoint};
use pigeon::constants::{HTTP_CLIENT, MAX_DISPLAYED_ENTRIES};
use std::cmp::min;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, atomic};
use std::time::Duration;

pub static CACHED_KEYS: Mutex<Vec<(ArrayString<32>, PublicKey)>> = Mutex::new(Vec::new());
pub static PRINT_QUEUE: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub static PRINT_BLOCKED: atomic::AtomicBool = AtomicBool::new(false);

///Flushes the output queue and gets one line as a string from stdin
pub fn safe_input(msg: &str, buf: &mut String) {
    PRINT_BLOCKED.store(true, atomic::Ordering::Relaxed);
    print!("{msg}");
    let _ = std::io::stdout().flush();
    let _ = std::io::stdin().read_line(buf);
    flush_print_queue();
    PRINT_BLOCKED.store(false, atomic::Ordering::Relaxed);
}

///Prints the string if nothing is blocking stdout, or queue it to be printed later
pub fn safe_print(msg: &str) {
    if !(PRINT_BLOCKED.load(atomic::Ordering::Relaxed)) {
        println!("{msg}");
    } else {
        PRINT_QUEUE.lock().unwrap().push(msg.to_string());
    }
}

///Flushes the output queue to stdout
pub fn flush_print_queue() {
    let mut queue = PRINT_QUEUE.lock().unwrap();
    for msg in queue.drain(..) {
        println!("{}", msg);
    }
}

///In debug mode, call safe_print
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_print_above {
    ($($arg:tt)*) => {
        crate::utils::safe_print(&format!($($arg)*))
    };
}

///In release mode, do nothing
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_print_above {
    ($($arg:tt)*) => {};
}

pub enum DiscoveryType {
    CACHE,
    MDNS,
    SERVER,
}

///Interactively prompt the user for names until they enter a name that can be resolved to a public key
pub async fn get_endpoint_info_interactive(ignore_cache: bool) -> (EndpointInfo, DiscoveryType) {
    let mut buf = String::new();
    if let Ok(keys) = CACHED_KEYS.lock() {
        for i in 0..min(keys.len(), MAX_DISPLAYED_ENTRIES) {
            safe_print(&format!(" {i} {}", keys[i].0));
        }
    }
    loop {
        safe_input("Target username, or number to use one of the above entries: ", &mut buf);
        let user_input_name: ArrayString<32> = ArrayString::from(buf.trim()).unwrap();
        let name = if user_input_name.chars().all(|c| c.is_ascii_digit()) {
            let index: usize = user_input_name
                .parse()
                .expect("Number entered has something wrong with it");
            if let Ok(keys) = CACHED_KEYS.lock() {
                keys[index].0
            } else {
                safe_print("Error: failed to aquire lock on cached keys");
                continue;
            }
        } else {
            user_input_name
        };
        let cached_key_entry = if ignore_cache {
            None
        } else {
            CACHED_KEYS
                .lock()
                .map(|map| {
                    map.iter()
                        .enumerate()
                        .find(|(_, (cached_name, _))| name == *cached_name)
                        .map(|(idx, item)| (idx, item.clone()))
                })
                .unwrap_or(None)
        };
        let info_option_mdns = get_endpoint_info_mdns(&name).await;
        if let Some(info) = info_option_mdns {
            //check against cached key
            if let Ok(mut map) = CACHED_KEYS.lock() {
                if let Some((idx, (_, key))) = cached_key_entry {
                    map.remove(idx);
                    if key != info.endpoint_id {
                        safe_print(
                            "Warning: Peer sent a key that does not match the one in cache, they either changed their name or are being impersonated",
                        );
                    } else {
                        //put back at the beginning cause it was correct
                        map.insert(0, (name, info.endpoint_id));
                    }
                } else {
                    //not in cache so add it
                    map.insert(0, (name, info.endpoint_id));
                }
            }
            return (info, DiscoveryType::MDNS);
        }
        //if its not in mdns, try using the cache
        if let Some((_, (_, key))) = cached_key_entry {
            return (
                EndpointInfo::from_parts(key, EndpointData::default()),
                DiscoveryType::CACHE,
            );
        }
        //if mdns doesn't find it yet, then use the server
        if USE_SERVER.get().unwrap_or(&false).clone() {
            let result = get_public_key(&name, &HTTP_CLIENT).await;
            match result {
                Ok(key) => {
                    if let Ok(mut map) = CACHED_KEYS.lock() {
                        map.insert(0, (name, key));
                    }
                    return (
                        EndpointInfo::from_parts(key, EndpointData::default()),
                        DiscoveryType::SERVER,
                    );
                }
                Err(e) => {
                    eprintln!("Error getting public key for target: {e}");
                }
            }
        }
        buf.clear();
    }
}

///Get the endpoint info necessary for exchanging names over mdns
pub async fn get_endpoint_info(connection: &Connection, endpoint: &Endpoint) -> Result<EndpointInfo> {
    let remote_id = connection.remote_id();
    if let Some(info) = endpoint.remote_info(remote_id).await {
        Ok(EndpointInfo::from_parts(
            remote_id,
            EndpointData::new(info.into_addrs().map(|a| a.addr().clone()).collect()),
        ))
    } else {
        Err(anyerr!("Cannot get remote endpoint info"))
    }
}

///Creates an endpoint without waiting for it to come online
pub async fn create_endpoint() -> Result<Endpoint> {
    let secret_key = SECRET_KEY.get().expect("Failed to load secret key");
    let endpoint = bind_endpoint(secret_key.clone()).await?;

    Ok(endpoint)
}

///Safely close the connection and check that it was closed intentionally
pub async fn safe_wait_connection_closed(connection: &Connection) {
    let remote_id = connection.remote_id();
    let res = tokio::time::timeout(Duration::from_secs(3), async move {
        let closed = connection.closed().await;
        if !matches!(closed, ConnectionError::ApplicationClosed(_)) {
            debug_print_above!("{remote_id} disconnected with an error: {closed:#}");
        }
    })
    .await;
    if res.is_err() {
        println!("{remote_id} did not disconnect within 3 seconds");
    }
}

///Attempt to load previous name from file
pub fn try_load_name(name_path: &Path) -> Result<ArrayString<32>> {
    if name_path.exists() {
        let name_bytes = std::fs::read(name_path).std_context("read name file")?;
        let name_arraystring: ArrayString<32> =
            ArrayString::from(&String::from_utf8(name_bytes).expect("Name file is not UTF-8").trim())
                .expect("Cannot convert name to arraystring");
        Ok(name_arraystring)
    } else {
        Err("No name file".into())
    }
}

///Read names from the user until they enter a valid one
pub async fn read_name() -> ArrayString<32> {
    let mut name_string = String::new();

    loop {
        safe_input("Choose a new name: ", &mut name_string);
        let result: Result<ArrayString<32>, CapacityError<&str>> = ArrayString::from(&name_string.trim());
        if let Ok(name_arraystring) = result {
            return name_arraystring;
        } else {
            println!("Something's wrong with that name, its probably too long");
        }
    }
}

///Attempts to load key cache from file
pub fn try_load_key_cache(key_path: &Path) -> Result<Vec<(ArrayString<32>, PublicKey)>> {
    let result = std::fs::read_to_string(key_path)
        .std_context("read key cache")
        .map(|s| serde_json::from_str(&s).unwrap_or_default())
        .map_err(|e| e.into());
    result
}

///Saves key cache to file
pub fn save_key_cache(key_path: &Path) {
    println!("saving key cache to {}", key_path.display());
    let cache = CACHED_KEYS.lock().unwrap().clone();
    std::fs::write(key_path, serde_json::to_string(&cache).unwrap())
        .std_context("save key cache")
        .ok();
}

pub async fn wait_online() -> Result<()> {
    tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            ONLINE_USERNAME.wait();
        }),
    )
    .await
    .anyerr()?
    .anyerr()
}
