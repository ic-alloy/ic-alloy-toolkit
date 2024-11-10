use alloy::{
    network::EthereumWallet,
    primitives::{address, U256},
    providers::{Provider, ProviderBuilder},
    signers::Signer,
    sol,
    transports::icp::IcpConfig,
};
use std::cell::RefCell;
use crate::{create_icp_signer, get_rpc_service_sepolia};
use candid::{CandidType, Deserialize};
use ic_cdk_macros::*;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};

use candid::{CandidType, Deserialize};
use ic_cdk_macros::*;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use tiny_keccak::{Keccak, Hasher};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hex;
use libsecp256k1::{recover, Message, RecoveryId, Signature};

// SIWE payload structure
#[derive(CandidType, Deserialize, Clone)]
struct SIWEPayload {
    message: String,      // The message that was signed
    signature: String,    // The Ethereum signature
}

// Encrypted storage item
#[derive(CandidType, Deserialize, Clone)]
struct EncryptedItem {
    encrypted_data: Vec<u8>,  // AES encrypted data
    nonce: Vec<u8>,          // AES nonce
    acls: Vec<String>,       // Authorized Ethereum addresses
}


thread_local! {
    static NONCE: RefCell<Option<u64>> = const { RefCell::new(None) };
    static MEMORY_MANAGER: std::cell::RefCell<MemoryManager<DefaultMemoryImpl>> = 
        std::cell::RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    
    static STORAGE: std::cell::RefCell<StableBTreeMap<String, EncryptedItem, Memory>> = 
        std::cell::RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
    ));

    // AES key derived from canister id (in production, use proper key management)
    static ENCRYPTION_KEY: std::cell::RefCell<[u8; 32]> = std::cell::RefCell::new({
        let canister_id = ic_cdk::id();
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(canister_id.as_slice());
        hasher.finalize(&mut hash);
        hash
    });
}

sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    DAO,
    "abi/DAO.json"
);

type Memory = ic_stable_structures::memory_manager::VirtualMemory<DefaultMemoryImpl>;

// Helper function to recover Ethereum address from signature
fn recover_eth_address(message: &str, signature: &str) -> Result<String, String> {
    // Remove '0x' prefix if present
    let sig_bytes = hex::decode(signature.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid signature format: {}", e))?;
    
    // The signature should be 65 bytes (r[32] + s[32] + v[1])
    if sig_bytes.len() != 65 {
        return Err("Invalid signature length".to_string());
    }

    // Extract r, s, and v
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];
    let v = sig_bytes[64];

    // Create recovery ID from v
    let recovery_id = RecoveryId::parse(v - 27)
        .map_err(|_| "Invalid recovery ID".to_string())?;

    // Hash the message
    let mut hasher = Keccak::v256();
    let mut message_hash = [0u8; 32];
    // In production, use proper SIWE message formatting
    hasher.update(format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message).as_bytes());
    hasher.finalize(&mut message_hash);

    // Recover the public key
    let message = Message::parse(&message_hash);
    let signature = Signature::parse_standard_slice(&[r, s].concat())
        .map_err(|_| "Invalid signature".to_string())?;

    let public_key = recover(&message, &signature, &recovery_id)
        .map_err(|_| "Could not recover public key".to_string())?;

    // Hash the public key to get the address
    let mut hasher = Keccak::v256();
    let mut address = [0u8; 32];
    hasher.update(&public_key.serialize()[1..]);
    hasher.finalize(&mut address);

    // Take last 20 bytes as Ethereum address
    Ok(format!("0x{}", hex::encode(&address[12..])))
}

#[ic_cdk::update]
fn set(key: String, value: String, acls: Vec<String>) -> Result<(), String> {
    // Validate Ethereum addresses
    for address in &acls {
        if !address.starts_with("0x") || address.len() != 42 {
            return Err("Invalid Ethereum address format".to_string());
        }
    }

    // Generate a random nonce
    let nonce_bytes = ic_cdk::api::time().to_be_bytes();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the value
    let cipher = ENCRYPTION_KEY.with(|key| {
        Aes256Gcm::new_from_slice(&key.borrow())
            .map_err(|e| format!("Encryption error: {}", e))
    })?;

    let encrypted_data = cipher
        .encrypt(nonce, value.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let item = EncryptedItem {
        encrypted_data,
        nonce: nonce_bytes.to_vec(),
        acls,
    };

    STORAGE.with(|storage| {
        storage.borrow_mut().insert(key, item);
    });

    Ok(())
}

#[ic_cdk::update]
fn get(key: String, siwe: SIWEPayload) -> Result<Option<String>, String> {
    // Recover the Ethereum address from the signature
    let recovered_address = recover_eth_address(&siwe.message, &siwe.signature)?;

    STORAGE.with(|storage| {
        match storage.borrow().get(&key) {
            Some(item) => {
                // Check if the recovered address is in the ACL
                if !item.acls.contains(&recovered_address) {
                    return Err("Access denied: address not in ACL".to_string());
                }

                // Decrypt the data
                let cipher = ENCRYPTION_KEY.with(|key| {
                    Aes256Gcm::new_from_slice(&key.borrow())
                        .map_err(|e| format!("Decryption error: {}", e))
                })?;

                let nonce = Nonce::from_slice(&item.nonce);
                let decrypted = cipher
                    .decrypt(nonce, item.encrypted_data.as_slice())
                    .map_err(|e| format!("Decryption failed: {}", e))?;

                String::from_utf8(decrypted)
                    .map(Some)
                    .map_err(|e| format!("Invalid UTF-8: {}", e))
            }
            None => Ok(None)
        }
    })
}


#[ic_cdk::update]
async fn set_for_dao(key: String, value: String, daoAddress: String) -> Result<(), String>  {

    let signer = create_icp_signer().await;
    let address = signer.address();
    let wallet = EthereumWallet::from(signer);
    let rpc_service = get_rpc_service_sepolia();
    let config = IcpConfig::new(rpc_service);
    let provider = ProviderBuilder::new()
        .with_gas_estimation()
        .wallet(wallet)
        .on_icp(config);

    let maybe_nonce = NONCE.with_borrow(|maybe_nonce| {
        // If a nonce exists, the next nonce to use is latest nonce + 1
        maybe_nonce.map(|nonce| nonce + 1)
    });

    // If no nonce exists, get it from the provider
    let nonce = if let Some(nonce) = maybe_nonce {
        nonce
    } else {
        provider.get_transaction_count(address).await.unwrap_or(0)
    };

    let contract = DAO::new(
        address!(daoAddress),
        provider.clone(),
    );

    match contract.getNodes().nonce(nonce).chain_id(11155111).from(address).send()
        .await
    {
        Ok(builder) => {
            let node_hash = *builder.tx_hash();
            let tx_response = provider.get_transaction_by_hash(node_hash).await.unwrap();

            match tx_response {
                Some(tx) => {
                    // The transaction has been mined and included in a block, the nonce
                    // has been consumed. Save it to thread-local storage. Next transaction
                    // for this address will use a nonce that is = this nonce + 1
                    NONCE.with_borrow_mut(|nonce| {
                        *nonce = Some(tx.nonce);
                    });
                    set(key, value, tx_response[0])
                }
                None => Err("Could not get transaction.".to_string()),
            }
        }
        Err(e) => Err(format!("{:?}", e)),
    }
}