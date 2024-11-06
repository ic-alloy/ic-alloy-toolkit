use std::cell::RefCell;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::types::request::TransactionRequest,
    signers::Signer,
    transports::icp::IcpConfig,
};

use crate::{create_icp_signer, get_rpc_service_sepolia};

thread_local! {
    static NONCE: RefCell<Option<u64>> = const { RefCell::new(None) };
}

/// This function will attempt to send 100 wei to the ethereum address of the canister.
///
/// Transfer some SepoliaEth to the canister address before calling this function.
///
/// Nonce handling is implemented manually instead of relying on the Alloy built in
/// `with_recommended_fillers` method. This minimizes the number of requests sent to the
/// EVM RPC.
///
/// The following RPC calls are made to complete a transaction:
/// - `eth_getTransactionCount`: To determine the next nonce. This call is only made once after
/// canister deployment, then the nonces are cached.
/// - `eth_estimateGas`: To determine the gas limit
/// - `eth_sendRawTransaction`: The transaction
/// - `eth_getTransactionByHash`: To determine if transaction was successful. Increment nonce only
/// if transaction was successful.
///
/// Even though this function makes half as many RPC calls as `send_eth_with_fillers` it is still
/// recommended to use a deduplication proxy between the EVM RPC canister and the RPC provider
/// (Alchemy, etc). For a fully decentralised deployment, one option is also to deploy a copy of
/// the EVM RPC canister yourself on an app subnet with only 13 nodes and your own RPC API key.
/// Perhaps 3 calls * 13 = 39 fits within the RPC call limits.
#[ic_cdk::update]
async fn send_eth() -> Result<String, String> {
    // Setup signer
    let signer = create_icp_signer().await;
    let address = signer.address();

    // Setup provider
    let wallet = EthereumWallet::from(signer);
    let rpc_service = get_rpc_service_sepolia();
    let config = IcpConfig::new(rpc_service);
    let provider = ProviderBuilder::new()
        .with_gas_estimation()
        .wallet(wallet)
        .on_icp(config);

    // Attempt to get nonce from thread-local storage
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

    let tx = TransactionRequest::default()
        .with_to(address)
        .with_value(U256::from(100))
        .with_nonce(nonce)
        .with_chain_id(11155111);

    let transport_result = provider.send_transaction(tx.clone()).await;
    match transport_result {
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
                    Ok(format!("{:?}", tx))
                }
                None => Err("Could not get transaction.".to_string()),
            }
        }
        Err(e) => Err(format!("{:?}", e)),
    }
}
