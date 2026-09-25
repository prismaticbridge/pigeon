pub mod common;
pub mod constants;
use arrayvec::ArrayString;
use iroh::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub name: ArrayString<32>,
    pub publickey: PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct GetKeyRequest {
    pub target: ArrayString<32>,
}

#[derive(Serialize, Deserialize)]
#[repr(C)]
pub struct FileHeader {
    pub size: u64,
    pub filename: ArrayString<256>,
}

#[derive(Serialize, Deserialize)]
pub struct FsTreeHeader {
    pub dir_name: ArrayString<256>,
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Serialize, Deserialize)]
pub enum DirectoryEntry {
    Directory,
    File,
}

#[derive(Serialize, Deserialize)]
pub struct ChangeNameRequest {
    pub old_name: ArrayString<32>,
    pub new_name: ArrayString<32>,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub name: ArrayString<32>,
}

#[derive(Serialize, Deserialize)]
pub struct DownloadDbRequest {
    pub name: ArrayString<32>,
    pub signature: Signature,
}

pub type ClientMap = HashMap<ArrayString<32>, (PublicKey, Option<[u8; 32]>)>;

#[derive(Serialize, Deserialize)]
pub struct InjectDbRequest {
    pub name: ArrayString<32>,
    pub signature: Signature,
    pub db_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteRequest {
    pub name: ArrayString<32>,
    pub signature: Signature,
}
