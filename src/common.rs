use std::path::Path;
use std::sync::OnceLock;

use arrayvec::ArrayString;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use n0_error::{Result, StackResultExt, StdResultExt};

pub const PIGEON_ALPN: &[u8] = b"pigeon/0";
pub static MDNS_USERNAME: OnceLock<ArrayString<32>> = OnceLock::new();
pub static ONLINE_USERNAME: OnceLock<ArrayString<32>> = OnceLock::new();
pub static SECRET_KEY: OnceLock<SecretKey> = OnceLock::new();

pub fn load_or_create_identity(key_path: &Path) -> Result<SecretKey> {
    if key_path.exists() {
        let key = std::fs::read(key_path).std_context("read identity file")?;
        let key_bytes = hex::decode(key).expect("key file is not hex");
        Ok(SecretKey::from_bytes(&key_bytes.try_into().unwrap()))
    } else {
        if let Some(parent) = key_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).std_context("create config dir")?;
        }
        let key = SecretKey::generate();

        println!("Generated new key pair. public key signature: ");
        println!("{}", hex::encode(key.public()));

        std::fs::write(key_path, hex::encode(key.to_bytes())).std_context("write identity file")?;
        Ok(key)
    }
}

/// Binds an endpoint with given preset
pub async fn bind_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![PIGEON_ALPN.to_vec()])
        .bind()
        .await
        .context("bind endpoint")
}
