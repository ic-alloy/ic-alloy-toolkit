use ic_cdk::export::candid::CandidType;
use ic_cdk::export::serde::Deserialize;
use ic_cdk::export::Principal;

pub type CanisterId = Principal;

#[derive(CandidType, Deserialize, Eq, PartialEq)]
pub enum VetKDCurve {
    #[serde(rename = "bls12_381")]
    Bls12_381,
}

#[derive(CandidType, Deserialize, Eq, PartialEq)]
pub struct VetKDKeyId {
    pub curve: VetKDCurve,
    pub name: String,
}

#[derive(CandidType, Deserialize)]
pub struct VetKDPublicKeyRequest {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: VetKDKeyId,
}

#[derive(CandidType)]
pub struct VetKDPublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct VetKDEncryptedKeyRequest {
    pub public_key_derivation_path: Vec<Vec<u8>>,
    pub derivation_id: Vec<u8>,
    pub key_id: VetKDKeyId,
    pub encryption_public_key: Vec<u8>,
}

#[derive(CandidType)]
pub struct VetKDEncryptedKeyReply {
    pub encrypted_key: Vec<u8>,
}

use candid::{Deserialize, CandidType};
use ic_cdk::{update, query};
use std::cell::RefCell;
use std::collections::HashMap;
use alloy::primitives::Address;
use ic_crypto_internal_bls12_381_vetkd::{
    DerivationPath, DerivedPublicKey, EncryptedKey, VetKDEncryptedKeyReply, VetKDPublicKeyReply
};

// Types for storing DAO and secret data
#[derive(Clone, Debug, CandidType, Deserialize)]
struct SecretMetadata {
    dao_address: String,
    derivation_path: Vec<Vec<u8>>,
}

#[derive(Debug, CandidType, Deserialize)]
enum DaoError {
    SecretNotFound(String),
    InvalidData(String),
    EncryptionError(String),
    NotMember(String),
}

// Thread-local storage
thread_local! {
    static SECRETS: RefCell<HashMap<String, SecretMetadata>> = RefCell::new(HashMap::new());
}

/// Sets up a new secret for a DAO
/// 
/// # Arguments
/// * `dao_address` - Ethereum address of the DAO
/// * `secret_id` - Unique identifier for the secret
/// * `derivation_path` - Custom derivation path for the secret
#[update]
async fn set_secret(
    dao_address: String,
    secret_id: String,
    derivation_path: Vec<Vec<u8>>,
) -> Result<(), String> {
    // Validate inputs
    if secret_id.is_empty() {
        return Err("Secret ID cannot be empty".to_string());
    }
    
    // Store metadata
    SECRETS.with_borrow_mut(|secrets| {
        secrets.insert(
            secret_id.clone(),
            SecretMetadata {
                dao_address,
                derivation_path,
            },
        );
    });

    Ok(())
}

/// Gets the public key for encrypting data for a specific secret
#[update]
async fn get_public_key(secret_id: String) -> Result<VetKDPublicKeyReply, String> {
    let metadata = SECRETS.with_borrow(|secrets| {
        secrets.get(&secret_id).cloned()
    }).ok_or_else(|| "Secret not found".to_string())?;

    // Create request for vetkd system
    let request = VetKDPublicKeyRequest {
        canister_id: None, // Uses caller's canister ID
        derivation_path: metadata.derivation_path,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381,
            name: "test_key_1".to_string(),
        },
    };

    // Get public key from vetkd system
    vetkd_public_key(request).await
}

/// Gets the encrypted key for a specific secret
#[update]
async fn get_encrypted_key(
    secret_id: String,
    encryption_public_key: Vec<u8>,
    derivation_id: Vec<u8>,
) -> Result<VetKDEncryptedKeyReply, String> {
    let metadata = SECRETS.with_borrow(|secrets| {
        secrets.get(&secret_id).cloned()
    }).ok_or_else(|| "Secret not found".to_string())?;

    // Create request for vetkd system
    let request = VetKDEncryptedKeyRequest {
        encryption_public_key,
        public_key_derivation_path: metadata.derivation_path,
        derivation_id,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381,
            name: "test_key_1".to_string(),
        },
    };

    // Get encrypted key from vetkd system
    vetkd_encrypted_key(request).await
}

/// Lists all secret IDs for a given DAO address
#[query]
fn list_dao_secrets(dao_address: String) -> Vec<String> {
    SECRETS.with_borrow(|secrets| {
        secrets
            .iter()
            .filter(|(_, metadata)| metadata.dao_address == dao_address)
            .map(|(id, _)| id.clone())
            .collect()
    })
}

/// Removes a secret
#[update]
fn remove_secret(secret_id: String) -> Result<(), String> {
    SECRETS.with_borrow_mut(|secrets| {
        if secrets.remove(&secret_id).is_some() {
            Ok(())
        } else {
            Err("Secret not found".to_string())
        }
    })
}