use directories::ProjectDirs;
use iroh::PublicKey;
use reqwest::{Certificate, Client};
use std::{path::PathBuf, sync::LazyLock}; // Standard library in modern Rust

static SERVER_URL: LazyLock<String> =
    LazyLock::new(|| std::env::var("SERVER_URL").unwrap_or(String::from("https://pigeon-87r8.onrender.com")));
pub static REGISTER_URL: LazyLock<String> = LazyLock::new(|| format!("{}/register", *SERVER_URL));
pub static GETKEY_URL: LazyLock<String> = LazyLock::new(|| format!("{}/getkey", *SERVER_URL));
pub static AUTH_URL: LazyLock<String> = LazyLock::new(|| format!("{}/auth", *SERVER_URL));
pub static START_AUTH_URL: LazyLock<String> = LazyLock::new(|| format!("{}/start_auth", *SERVER_URL));
pub static CHANGE_NAME_URL: LazyLock<String> = LazyLock::new(|| format!("{}/change_name", *SERVER_URL));
pub static DOWNLOAD_DB_URL: LazyLock<String> = LazyLock::new(|| format!("{}/download_db", *SERVER_URL));
pub static INJECT_DB_URL: LazyLock<String> = LazyLock::new(|| format!("{}/inject_db", *SERVER_URL));

pub static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    if *USE_CUSTOM_HTTPS {
        let cert_bytes = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/rootCA.pem"))
            .expect("custom https requested but cannot read certificate file rootCA.pem");
        let ca_cert =
            Certificate::from_pem(&cert_bytes).expect("Failed to load certificate, but USE_CUSTOM_HTTPS was requested");
        reqwest::Client::builder()
            .tls_certs_merge([ca_cert])
            .build()
            .expect("Failed to create client")
    } else {
        reqwest::Client::new()
    }
});

pub static DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    ProjectDirs::from("", "", "pigeon")
        .map(|proj_dirs| proj_dirs.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("~/.local/share/pigeon"))
});
pub const NAME_FILE: &str = "username.txt";
pub const CLIENT_KEY_FILE: &str = "ed25519_key";
pub const KEY_CACHE_FILE: &str = "key_cache.json";

pub const CHUNK_SIZE: usize = 64 * 1024;

pub const USE_CUSTOM_HTTPS: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("USE_CUSTOM_HTTPS")
        .map(|s| {
            s.parse::<bool>()
                .expect(&format!("USE_CUSTOM_HTTPS should only be true or false, not {}", s))
        })
        .unwrap_or(false)
});

pub const ADMIN_KEYS: LazyLock<[PublicKey; 1]> = LazyLock::new(|| {
    ["895bf370303e81cbb840494bbd0befa95e2c36114ffcb6b24504727e89990abd"]
        .map(|str| hex::decode(str).expect("failed to decode key"))
        .map(|bytes| PublicKey::from_bytes(&bytes.try_into().expect("invalid length")).expect("invalid public key"))
});

pub const SERVER_DB_FILE: &str = "server.db";
