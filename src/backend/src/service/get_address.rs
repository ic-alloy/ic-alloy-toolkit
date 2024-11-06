use crate::create_icp_signer;
use alloy::signers::Signer;

/// Get the Ethereum address of the backend canister.
#[ic_cdk::update]
async fn get_address() -> Result<String, String> {
    let signer = create_icp_signer().await;
    let address = signer.address();
    Ok(address.to_string())
}
