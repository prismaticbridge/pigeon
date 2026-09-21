use crate::constants::{CHANGE_NAME_URL, GETKEY_URL, NAME_FILE, REGISTER_URL, START_AUTH_URL};
use crate::debug_print_above;
use crate::utils::{read_name, safe_print};
use arrayvec::ArrayString;
use iroh::{PublicKey, SecretKey, Signature};
use n0_error::{AnyError, Result, StdResultExt, anyerr};
use pigeon::common::ONLINE_USERNAME;
use pigeon::constants::{DATA_DIR, DOWNLOAD_DB_URL, INJECT_DB_URL, SERVER_DB_FILE};
use pigeon::{AuthRequest, ChangeNameRequest, DownloadDbRequest, GetKeyRequest, InjectDbRequest, RegisterRequest};
use reqwest::{Client, StatusCode};
use std::path::Path;
use std::time::Duration;

const NETWORK_ERROR_SLEEP: Duration = Duration::from_secs(1);

fn handle_network_error(e: &reqwest::Error) {
    // for network errors, wait a bit and try again
    safe_print(&format!("network error: {}", e));
    if let Some(source) = std::error::Error::source(&e) {
        debug_print_above!("Caused by: {:?}", source);
    }
}

/// ONLY CALL if status is an ERROR
fn handle_status_errors(status: reqwest::StatusCode) -> AnyError {
    match status {
        StatusCode::BAD_REQUEST => return "Error: Bad request: name already exists or invalid byte string".into(),
        StatusCode::INTERNAL_SERVER_ERROR => return "Error: Internal server error".into(),
        StatusCode::FORBIDDEN => return "Error: Authentication failed".into(),
        StatusCode::EXPECTATION_FAILED => return "Error: Expectation failed".into(),
        status_code => {
            return format!(
                "Error: unexpected status code {}, something went very wrong",
                status_code
            )
            .into();
        }
    }
}

pub async fn create_name_and_register(
    path_prefix: &Path,
    publickey: &PublicKey,
    is_online: bool,
    client: &Client,
) -> Result<ArrayString<32>> {
    let name_path = path_prefix.join(NAME_FILE);
    let name_arraystring = loop {
        let potential_name = read_name().await;
        if is_online {
            let result = register_http(&potential_name, publickey, client).await;
            if result.is_ok() {
                break potential_name;
            } else {
                println!("That name is taken");
            }
        } else {
            break potential_name;
        }
    };

    if let Some(parent) = name_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).std_context("create config dir")?;
    }
    std::fs::write(name_path, name_arraystring.to_string()).std_context("write name file")?;
    return Ok(name_arraystring);
}

pub async fn get_public_key(target: &ArrayString<32>, client: &Client) -> Result<PublicKey, reqwest::Error> {
    let request = GetKeyRequest { target: *target };
    let payload = postcard::to_allocvec(&request).expect("failed to serialize request");

    loop {
        //send post
        let response = client.get(&(*GETKEY_URL)).body(payload.clone()).send().await;

        match response {
            Ok(res) => {
                let status = res.status();
                if let Err(reqwest_err) = res.error_for_status_ref() {
                    let error_text = res.text().await?;
                    debug_print_above!("error response: {}: {}", status, error_text);

                    return Err(reqwest_err);
                }
                if status.is_success() {
                    let response_bytes = res.bytes().await?;
                    let publickey: PublicKey =
                        postcard::from_bytes(&response_bytes).expect("failed to deserialize response bytes");
                    return Ok(publickey);
                }
                // other responses are unexpected, something went wrong
            }
            Err(e) => {
                handle_network_error(&e);
                tokio::time::sleep(NETWORK_ERROR_SLEEP).await;
            }
        }
    }
}

pub async fn register_http(
    name: &ArrayString<32>,
    publickey: &PublicKey,
    client: &Client,
) -> Result<(), reqwest::Error> {
    let request = RegisterRequest {
        name: *name,
        publickey: *publickey,
    };
    let payload = postcard::to_allocvec(&request).expect("failed to serialize request");

    loop {
        let response = client.post(&(*REGISTER_URL)).body(payload.clone()).send().await;

        match response {
            Ok(res) => {
                println!("FIRST");
                let status = res.status();
                if let Err(reqwest_err) = res.error_for_status_ref() {
                    let error_text = res.text().await?;
                    debug_print_above!("error response: {}: {}", status, error_text);

                    return Err(reqwest_err);
                }
                if status.is_success() {
                    return Ok(());
                }
                // other responses are unexpected, something went wrong
            }
            Err(e) => {
                println!("SECOND");
                handle_network_error(&e);
                tokio::time::sleep(NETWORK_ERROR_SLEEP).await;
            }
        }
    }
}

async fn start_auth(client: &reqwest::Client, secret_key: &SecretKey) -> Result<Signature> {
    let name = ONLINE_USERNAME
        .get()
        .expect("Cannot do this unless you are connected to the internet");
    let auth_request = AuthRequest { name: name.clone() };
    let payload = postcard::to_allocvec(&auth_request).anyerr()?;
    let response = client.post(&*START_AUTH_URL).body(payload).send().await.anyerr()?;

    let status = response.status();
    let text = response.text().await.anyerr()?;
    if !status.is_success() {
        eprintln!("Received error response: {}, {}", status, text);
        return Err("start_auth failed".into());
    }

    let challenge_bytes = hex::decode(&text).anyerr()?;
    let signature = secret_key.sign(&challenge_bytes);
    Ok(signature)
}

pub async fn change_name(new_name: &ArrayString<32>, secret_key: &SecretKey, client: &Client) -> Result<()> {
    let signature = start_auth(&client, secret_key).await?;
    let old_name = *ONLINE_USERNAME.get().unwrap();
    let change_name_request = ChangeNameRequest {
        old_name,
        new_name: *new_name,
        signature: signature,
    };

    let payload = postcard::to_allocvec(&change_name_request).anyerr()?;
    let response = client.post(&*CHANGE_NAME_URL).body(payload).send().await.anyerr()?;
    let status = response.status();
    if !status.is_success() {
        return Err(handle_status_errors(status));
    }

    std::fs::write(DATA_DIR.join(NAME_FILE), new_name.to_string())?;

    safe_print(&format!("Successfully changed name to {}", new_name));

    Ok(())
}

pub async fn change_name_interactive(secret_key: &SecretKey, client: &Client) -> Result<()> {
    let new_name = loop {
        let potential_name = read_name().await;
        let result = get_public_key(&potential_name, &client).await; // use get_public_key cause we actually know why it fails when it does
        if let Err(err) = result
            && let Some(status) = err.status()
            && status == StatusCode::BAD_REQUEST
        {
            break potential_name;
        }
        println!("That name is already taken, or a different error occured");
    };

    change_name(&new_name, secret_key, client).await
}

pub async fn download_db(secret_key: &SecretKey, client: &Client) -> Result<()> {
    let signature = start_auth(&client, secret_key).await?;
    let name = *ONLINE_USERNAME.get().unwrap();

    let download_db_request = DownloadDbRequest { name, signature };
    let payload = postcard::to_allocvec(&download_db_request).anyerr()?;

    let result = client.get(&*DOWNLOAD_DB_URL).body(payload).send().await;
    match result {
        Ok(response) => {
            let status = response.status();
            if !status.is_success() {
                return Err(handle_status_errors(status));
            }
            let db_bytes = response.bytes().await.anyerr()?;
            std::fs::write(SERVER_DB_FILE, db_bytes)?;
        }
        Err(e) => {
            handle_network_error(&e);
        }
    }

    Ok(())
}

pub async fn inject_db(secret_key: &SecretKey, client: &Client) -> Result<()> {
    let signature = start_auth(&client, secret_key).await?;
    let name = *ONLINE_USERNAME.get().unwrap();

    let db_bytes = std::fs::read(SERVER_DB_FILE)?;
    let inject_db_request = InjectDbRequest {
        name,
        signature,
        db_bytes,
    };
    let payload = postcard::to_allocvec(&inject_db_request).anyerr()?;

    let result = client.post(&*INJECT_DB_URL).body(payload).send().await;
    match result {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                Ok(())
            } else {
                Err(handle_status_errors(status))
            }
        }
        Err(e) => {
            handle_network_error(&e);
            Err(anyerr!(e))
        }
    }
}
