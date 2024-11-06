use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::types::request::TransactionRequest,
    signers::Signer,
    transports::icp::IcpConfig,
};

use crate::{create_icp_signer, get_rpc_service_sepolia};

/// This function will attempt to send 100 wei to the ethereum address of the canister.
///
/// Transfer some SepoliaEth to the canister address before calling this function.
///
/// Using `with_recommended_fillers` with the provider means the following RPC functions
/// will be called before transaction is made:
/// - `eth_getTransactionCount`: To determine the nonce of the Transction
/// - `eth_chainId`: To determine the chain id
/// - `eth_feeHistory`: To determine historic gas price
/// - `eth_estimateGas`: To determine the gas limit
/// - `eth_sendRawTransaction`: The transaction
/// - `eth_getTransactionByHash`: To determine if transaction was successful. Increment nonce only
/// if transaction was successful.
///
/// Using `with_recommended_fillers` is only recommended if you use a deduplication proxy between
/// the EVM RPC canister and the RPC service (Alchemy, etc). When making an EVM RPC call on IC,
/// that call is executed by all the nodes in the subnet, currently 34 on the subnet where the
/// EVM RPC canister resides. Usinf this example without a deduplication proxy would result in
/// 6 x 34 = 204 calls being made during the span of a few seconds. That most likely leads to the
/// ceiling of number of requests per second being hit and the RPC provider responding with an
/// error.
#[ic_cdk::update]
async fn send_eth_with_fillers() -> Result<String, String> {
    // Setup signer
    let signer = create_icp_signer().await;
    let address = signer.address();

    // Setup provider
    let wallet = EthereumWallet::from(signer);
    let rpc_service = get_rpc_service_sepolia();
    let config = IcpConfig::new(rpc_service);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_icp(config);

    let tx = TransactionRequest::default()
        .with_to(address)
        .with_value(U256::from(100));

    let transport_result = provider.send_transaction(tx.clone()).await;
    match transport_result {
        Ok(builder) => {
            let node_hash = *builder.tx_hash();
            let tx_response = provider.get_transaction_by_hash(node_hash).await.unwrap();
            match tx_response {
                Some(tx) => Ok(format!("{:?}", tx)),
                None => Err("Could not get transaction.".to_string()),
            }
        }
        Err(e) => Err(format!("{:?}", e)),
    }
}
