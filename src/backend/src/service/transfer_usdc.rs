use candid::{Deserialize, CandidType};
use ic_cdk::{update, query};
use std::cell::RefCell;
use std::collections::HashMap;
use alloy::{
    network::EthereumWallet,
    primitives::{address, U256},
    providers::{Provider, ProviderBuilder},
    signers::Signer,
    sol,
    transports::icp::IcpConfig,
};
use ic_crypto_internal_bls12_381_vetkd::{
    DerivationPath, DerivedPublicKey, EncryptedKey, VetKDEncryptedKeyReply, VetKDPublicKeyReply
};

// Codegen from ABI file for DAO contract
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    DAO,
    r#"[
        {
            "inputs": [],
            "name": "getMembers",
            "outputs": [{"type": "address[]", "name": ""}],
            "stateMutability": "view",
            "type": "function"
        }
    ]"#
}

// Types for our storage
#[derive(Clone, Debug, CandidType, Deserialize)]
struct SecretMetadata {
    dao_address: String,
    derivation_path: Vec<Vec<u8>>,
}

#[derive(Debug, CandidType, Deserialize)]
enum DaoError {
    ContractError(String),
    SecretNotFound(String),
    InvalidData(String),
    NotMember(String),
}

// Thread-local storage
thread_local! {
    static SECRETS: RefCell<HashMap<String, SecretMetadata>> = RefCell::new(HashMap::new());
    static DAO_MEMBERS_CACHE: RefCell<HashMap<String, (Vec<String>, u64)>> = RefCell::new(HashMap::new());
    static NONCE: RefCell<Option<u64>> = const { RefCell::new(None) };
}

const CACHE_DURATION: u64 = 3600; // 1 hour in seconds

/// Sets up a new secret for a DAO
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
    
    // Verify DAO exists by checking if we can read members
    match read_dao_members(&dao_address).await {
        Ok(_) => (),
        Err(e) => return Err(format!("Invalid DAO address: {}", e)),
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
async fn get_public_key(
    secret_id: String,
    requester_address: String
) -> Result<VetKDPublicKeyReply, String> {
    // Verify requester is DAO member
    let metadata = SECRETS.with_borrow(|secrets| {
        secrets.get(&secret_id).cloned()
    }).ok_or_else(|| "Secret not found".to_string())?;

    let is_member = is_dao_member(&metadata.dao_address, &requester_address).await?;
    if !is_member {
        return Err("Requester is not a DAO member".to_string());
    }

    // Create request for vetkd system
    let request = VetKDPublicKeyRequest {
        canister_id: None,
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
    requester_address: String,
    encryption_public_key: Vec<u8>,
    derivation_id: Vec<u8>,
) -> Result<VetKDEncryptedKeyReply, String> {
    // Verify requester is DAO member
    let metadata = SECRETS.with_borrow(|secrets| {
        secrets.get(&secret_id).cloned()
    }).ok_or_else(|| "Secret not found".to_string())?;

    let is_member = is_dao_member(&metadata.dao_address, &requester_address).await?;
    if !is_member {
        return Err("Requester is not a DAO member".to_string());
    }

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

/// Read members from DAO contract with caching
async fn read_dao_members(dao_address: &str) -> Result<Vec<String>, String> {
    // Check cache first
    let current_time = ic_cdk::api::time();
    let cached_data = DAO_MEMBERS_CACHE.with_borrow(|cache| {
        cache.get(dao_address).and_then(|(members, timestamp)| {
            if current_time - timestamp < CACHE_DURATION {
                Some(members.clone())
            } else {
                None
            }
        })
    });

    if let Some(members) = cached_data {
        return Ok(members);
    }

    // Setup provider
    let signer = create_icp_signer().await?;
    let provider = setup_provider(signer).await?;

    // Create contract instance
    let contract = DAO::new(
        dao_address.parse().map_err(|e| format!("Invalid address: {}", e))?,
        provider,
    );

    // Call getMembers
    match contract.get_members().call().await {
        Ok(members) => {
            // Update cache
            let members_str: Vec<String> = members.iter()
                .map(|addr| format!("{:?}", addr))
                .collect();
            
            DAO_MEMBERS_CACHE.with_borrow_mut(|cache| {
                cache.insert(dao_address.to_string(), (members_str.clone(), current_time));
            });
            
            Ok(members_str)
        }
        Err(e) => Err(format!("Failed to read DAO members: {:?}", e)),
    }
}

/// Check if an address is a DAO member
async fn is_dao_member(dao_address: &str, member_address: &str) -> Result<bool, String> {
    let members = read_dao_members(dao_address).await?;
    Ok(members.contains(&member_address.to_string()))
}

/// Setup provider with signer
async fn setup_provider(signer: impl Signer) -> Result<Provider, String> {
    let wallet = EthereumWallet::from(signer);
    let rpc_service = get_rpc_service_sepolia();
    let config = IcpConfig::new(rpc_service);
    
    Ok(ProviderBuilder::new()
        .with_gas_estimation()
        .wallet(wallet)
        .on_icp(config)
        .build())
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

/// Clear DAO members cache for a specific DAO
#[update]
fn clear_dao_cache(dao_address: String) {
    DAO_MEMBERS_CACHE.with_borrow_mut(|cache| {
        cache.remove(&dao_address);
    });
}