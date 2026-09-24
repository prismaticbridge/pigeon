use arrayvec::ArrayString;
use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::routing::post;
use axum_server::tls_rustls::RustlsConfig;
use iroh::Signature;
use pigeon::AuthRequest;
use pigeon::ChangeNameRequest;
use pigeon::ClientMap;
use pigeon::DownloadDbRequest;
use pigeon::GetKeyRequest;
use pigeon::InjectDbRequest;
use pigeon::RegisterRequest;
use pigeon::constants;
use pigeon::constants::ADMIN_KEYS;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::utils::ping_thread;

mod utils;

#[derive(Clone)]
struct SharedState {
    clients: Arc<Mutex<ClientMap>>,
}

#[tokio::main]
async fn main() {
    let state = SharedState {
        clients: Arc::new(Mutex::new(HashMap::new())),
    };
    let app: Router = Router::new()
        .route("/register", post(handle_registration))
        .route("/getkey", get(handle_key_request))
        .route("/start_auth", post(start_auth))
        .route("/change_name", post(change_name))
        .route("/download_db", get(download_database))
        .route("/inject_db", post(inject_database))
        .with_state(state);

    if *constants::USE_CUSTOM_HTTPS {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("failed to set default rustls crypto provider");
        let config = RustlsConfig::from_pem_file("cert.pem", "key.pem")
            .await
            .expect("Failed to load cert.pem or key.pem");
        let addr = SocketAddr::from(([0, 0, 0, 0], 8000));

        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap()
    } else {
        let join_handle = tokio::spawn(ping_thread());
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
        axum::serve(listener, app).await.unwrap();
        join_handle
            .await
            .inspect_err(|e| eprintln!("something went wrong: {e}"))
            .unwrap();
    }
}

///Endpoint for registering with a name and public key, this fails on duplicate name
async fn handle_registration(
    axum::extract::State(state): axum::extract::State<SharedState>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, &'static str), (StatusCode, &'static str)> {
    let payload: RegisterRequest =
        postcard::from_bytes(&body).map_err(|_| (StatusCode::BAD_REQUEST, "invalid postcard binary payload"))?;
    if payload.name.chars().all(|c| c.is_ascii_digit()) {
        return Err((StatusCode::BAD_REQUEST, "name cannot be a number"));
    }
    let mut db = state.clients.lock().await;
    if db.contains_key(&payload.name) {
        debug_print!("Failed to create user: {}", payload.name);
        Err((StatusCode::BAD_REQUEST, "that name is already registered"))
    } else {
        db.insert(payload.name, (payload.publickey, None));
        debug_print!("Created new user: {}", payload.name);
        Ok((StatusCode::CREATED, "success"))
    }
}

///Unauthenticated, retrieve a given user's public key
async fn handle_key_request(
    axum::extract::State(state): axum::extract::State<SharedState>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let payload: GetKeyRequest = postcard::from_bytes(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, String::from("invalid postcard binary payload")))?;
    let db = state.clients.lock().await;
    match db.get(&payload.target) {
        None => Err((
            StatusCode::BAD_REQUEST,
            format!("{} is not registered", &payload.target),
        )),
        Some(key) => {
            let reply_payload = postcard::to_allocvec(&key.0).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("failed to serialize public key"),
                )
            })?;
            debug_print!("Get key called for username {}", payload.target);
            Ok(reply_payload)
        }
    }
}

///Assign random bytes as a challenge for authentication later
async fn start_auth(
    axum::extract::State(state): axum::extract::State<SharedState>,
    body: axum::body::Bytes,
) -> (StatusCode, String) {
    let Ok(payload) = postcard::from_bytes::<AuthRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, String::from("invalid postcard binary payload"));
    };
    let mut db = state.clients.lock().await;
    let result = db.get_mut(&payload.name);
    let entry = match result {
        None => {
            return (
                StatusCode::BAD_REQUEST,
                String::from("cannot change a name that is not registered"),
            );
        }
        Some(val) => val,
    };
    let mut challenge_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge_bytes);
    entry.1 = Some(challenge_bytes);
    //hex encoding is simpler since it allows response to always be a string
    let challenge = hex::encode(&challenge_bytes);
    println!("{}", challenge);

    (StatusCode::OK, challenge)
}

///Check that a client's key signature matches the public key registered in the server. possibly checks if they have admin rights
fn verify_auth(db: &mut ClientMap, name: &ArrayString<32>, signature: &Signature, check_admin: bool) -> bool {
    let (key, challenge) = match db.get_mut(name) {
        None => return false,
        Some(pair) => match pair.1.take() {
            None => return false,
            Some(challenge) => (&pair.0, challenge),
        },
    };

    let result = key.verify(&challenge, signature);

    if result.is_err() {
        return false;
    }
    if check_admin { ADMIN_KEYS.contains(key) } else { true }
}

///Authenticated, change a name in the server's database
async fn change_name(
    axum::extract::State(state): axum::extract::State<SharedState>,
    body: axum::body::Bytes,
) -> StatusCode {
    let Ok(payload) = postcard::from_bytes::<ChangeNameRequest>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let mut db = state.clients.lock().await;
    if !verify_auth(&mut db, &payload.old_name, &payload.signature, false) {
        debug_print!(
            "Auth denied for user claiming to be {} trying to change name",
            payload.old_name
        );
        return StatusCode::FORBIDDEN;
    }

    let collision = db.contains_key(&payload.new_name);
    if collision {
        return StatusCode::BAD_REQUEST;
    }
    debug_print!("Changing name {} to {}", payload.old_name, payload.new_name);
    let old_entry = db.remove(&payload.old_name);
    match old_entry {
        None => StatusCode::EXPECTATION_FAILED,
        Some(mut entry) => {
            entry.1 = None; // reset auth
            db.insert(payload.new_name, entry);
            StatusCode::OK
        }
    }
}

///Downlaod the entire registry of names and private keys, this is used for downloading state before server upgrades
///authenticated and requires admin
async fn download_database(
    axum::extract::State(state): axum::extract::State<SharedState>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let Ok(payload) = postcard::from_bytes::<DownloadDbRequest>(&body) else {
        return Err::<Vec<u8>, StatusCode>(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut db = state.clients.lock().await;
    if !verify_auth(&mut db, &payload.name, &payload.signature, true) {
        debug_print!("Auth denied for user {} trying to download database", payload.name);
        return Err::<Vec<u8>, StatusCode>(StatusCode::FORBIDDEN);
    }

    let response_bytes = postcard::to_allocvec(&*db).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    debug_print!("admin user {} downloaded db", payload.name);
    Ok(response_bytes)
}

///Replaces the entire registry of names and private keys with the supplied one, this is used for restoring state after server upgrades
///authenticated and requires admin
async fn inject_database(
    axum::extract::State(state): axum::extract::State<SharedState>,
    body: axum::body::Bytes,
) -> StatusCode {
    let Ok(payload) = postcard::from_bytes::<InjectDbRequest>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let mut db = state.clients.lock().await;

    if !verify_auth(&mut db, &payload.name, &payload.signature, true) {
        debug_print!("Auth denied for user {} trying to inject database", payload.name);
        return StatusCode::FORBIDDEN;
    }

    let Ok(inject_db) = postcard::from_bytes::<ClientMap>(&payload.db_bytes) else {
        return StatusCode::BAD_REQUEST;
    };

    debug_print!(
        "admin user {} injected db, {} entries added/replaced",
        payload.name,
        inject_db.len()
    );

    db.extend(inject_db);

    StatusCode::OK
}
