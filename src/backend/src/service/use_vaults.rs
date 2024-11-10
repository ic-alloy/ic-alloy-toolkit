use std::cell::RefCell;
use alloy::{
    network::EthereumWallet,
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::request::TransactionRequest,
    signers::{LocalWallet, Signer, recover},
    transports::icp::IcpConfig,
    contract::{Contract, ContractInstance, AbiParser},
};
use ic_cdk::export::candid::{Deserialize, CandidType};
use sha3::{Keccak256, Digest};
use std::collections::HashMap;

// Constants for Ethereum and security
const DAO_ABI: &str = r#"[
    {
        "inputs": [],
        "name": "getMembers",
        "outputs": [{"type": "address[]", "name": ""}],
        "stateMutability": "view",
        "type": "function"
    }
]"#;

// Error types
#[derive(Debug)]
enum DaoError {
    ContractError(String),
    SignatureError(String),
    NotMember(String),
    SecretNotFound(String),
    InvalidData(String),
}

impl std::fmt::Display for DaoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaoError::ContractError(msg) => write!(f, "Contract error: {}", msg),
            DaoError::SignatureError(msg) => write!(f, "Signature verification failed: {}", msg),
            DaoError::NotMember(msg) => write!(f, "Not a DAO member: {}", msg),
            DaoError::SecretNotFound(msg) => write!(f, "Secret not found: {}", msg),
            DaoError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
        }
    }
}

// Types for our storage
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct SecretData {
    data: Vec<u8>,
    dao_address: Address,
}

// Thread-local storage
thread_local! {
    static SECRETS: RefCell<HashMap<String, SecretData>> = RefCell::new(HashMap::new());
    static DAO_MEMBERS_CACHE: RefCell<HashMap<Address, Vec<Address>>> = RefCell::new(HashMap::new());
}

/// Creates a message hash for signature verification
fn create_message_hash(secret_id: &str, user_address: Address) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(secret_id.as_bytes());
    hasher.update(user_address.as_bytes());
    hasher.finalize().to_vec()
}

/// Verifies if an address is a member of the DAO
async fn verify_dao_member(
    provider: &Provider<EthereumWallet>,
    dao_address: Address,
    member_address: Address,
) -> Result<bool, DaoError> {
    // Check cache first
    let cached_members = DAO_MEMBERS_CACHE.with_borrow(|cache| {
        cache.get(&dao_address).cloned()
    });

    let members = if let Some(members) = cached_members {
        members
    } else {
        // Create contract instance
        let contract = Contract::new(
            dao_address,
            AbiParser::default().parse(DAO_ABI).map_err(|e| DaoError::ContractError(e.to_string()))?,
            provider.clone(),
        );

        // Call getMembers function
        let members: Vec<Address> = contract
            .method("getMembers", ())
            .map_err(|e| DaoError::ContractError(e.to_string()))?
            .call()
            .await
            .map_err(|e| DaoError::ContractError(e.to_string()))?;

        // Cache the result
        DAO_MEMBERS_CACHE.with_borrow_mut(|cache| {
            cache.insert(dao_address, members.clone());
        });

        members
    };

    Ok(members.contains(&member_address))
}

/// Verify signature and return the signer's address
fn verify_signature(message: &[u8], signature: &[u8]) -> Result<Address, DaoError> {
    recover(message, signature)
        .map_err(|e| DaoError::SignatureError(format!("Failed to recover signer: {}", e)))
}

/// Sets a secret for a specific DAO
/// 
/// # Arguments
/// * `secret_data` - The secret data to store
/// * `dao_address` - The address of the DAO contract
/// * `secret_id` - Unique identifier for the secret
///
/// # Returns
/// * `Ok(())` if successful
/// * `Err(DaoError)` if the operation fails
#[ic_cdk::update]
async fn set(
    secret_data: Vec<u8>,
    dao_address: Address,
    secret_id: String,
) -> Result<(), String> {
    let result = set_internal(secret_data, dao_address, secret_id).await;
    result.map_err(|e| e.to_string())
}

async fn set_internal(
    secret_data: Vec<u8>,
    dao_address: Address,
    secret_id: String,
) -> Result<(), DaoError> {
    if secret_data.is_empty() {
        return Err(DaoError::InvalidData("Secret data cannot be empty".to_string()));
    }

    // Store the secret
    SECRETS.with_borrow_mut(|secrets| {
        secrets.insert(
            secret_id,
            SecretData {
                data: secret_data,
                dao_address,
            },
        );
    });

    Ok(())
}

/// Gets a secret if the requester is a member of the DAO
/// 
/// # Arguments
/// * `secret_id` - The ID of the secret to retrieve
/// * `signature` - The signature proving the requester is a DAO member
///
/// # Returns
/// * `Ok(Vec<u8>)` containing the secret data if successful
/// * `Err(DaoError)` if the operation fails
#[ic_cdk::update]
async fn get(secret_id: String, signature: Vec<u8>) -> Result<Vec<u8>, String> {
    let result = get_internal(secret_id, signature).await;
    result.map_err(|e| e.to_string())
}

async fn get_internal(secret_id: String, signature: Vec<u8>) -> Result<Vec<u8>, DaoError> {
    // Get the secret data
    let secret_data = SECRETS.with_borrow(|secrets| {
        secrets.get(&secret_id).cloned()
    }).ok_or_else(|| DaoError::SecretNotFound(format!("Secret {} not found", secret_id)))?;

    // Setup provider
    let provider = setup_provider().await?;

    // Create message hash
    let message = create_message_hash(&secret_id, secret_data.dao_address);

    // Verify signature and get signer
    let signer_address = verify_signature(&message, &signature)?;

    // Verify signer is a DAO member
    let is_member = verify_dao_member(&provider, secret_data.dao_address, signer_address).await?;
    if !is_member {
        return Err(DaoError::NotMember(format!("Address {} is not a DAO member", signer_address)));
    }

    Ok(secret_data.data)
}

/// Clears the DAO members cache for a specific DAO address
#[ic_cdk::update]
async fn clear_dao_cache(dao_address: Address) {
    DAO_MEMBERS_CACHE.with_borrow_mut(|cache| {
        cache.remove(&dao_address);
    });
}

// Helper function to setup provider
async fn setup_provider() -> Result<Provider<EthereumWallet>, DaoError> {
    let signer = create_icp_signer()
        .await
        .map_err(|e| DaoError::ContractError(e.to_string()))?;
    
    let wallet = EthereumWallet::from(signer);
    let rpc_service = get_rpc_service_sepolia();
    let config = IcpConfig::new(rpc_service);
    
    Ok(ProviderBuilder::new()
        .wallet(wallet)
        .on_icp(config))
}