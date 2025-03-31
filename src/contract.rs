use ethers::prelude::{Address, BaseContract, Http, Provider, H256};
use std::str::FromStr;
use zksync_types::U256;

pub const FFLONK_VERIFICATION_TYPE: U256 = U256::zero();
pub const PLONK_VERIFICATION_TYPE: U256 = U256::one();

/// Holds various values/parameters needed to interact with on chain data
pub struct ContractConfig {
    pub provider: Provider<Http>,
    pub diamond_proxy_contract: BaseContract,
    pub verifier_contract: BaseContract,
    pub diamond_proxy_address: Address,
}

impl ContractConfig {
    pub fn new(l1_rpc_url: String, network: String) -> Self {
        use ethers::abi::Abi;

        let provider =
            Provider::<Http>::try_from(l1_rpc_url).expect("Failed to connect to provider");

        let diamond_proxy_abi: Abi =
            Abi::load(&include_bytes!("../abis/IZKChain.json")[..]).unwrap();
        let verifier_abi: Abi = Abi::load(&include_bytes!("../abis/IVerifier.json")[..]).unwrap();

        let diamond_proxy_address = get_diamond_proxy_address(network);

        let diamond_proxy_contract = diamond_proxy_abi.into();
        let verifier_contract = verifier_abi.into();

        Self {
            provider,
            diamond_proxy_contract,
            verifier_contract,
            diamond_proxy_address,
        }
    }

    /// Pull the current verification key hash from on chain. Need to query the diamond proxy for the current used
    /// verifier contract address.
    pub async fn get_verification_key_hash(
        &self,
        block_number: u64,
        protocol_version_id: u16,
        verifier_type: Option<U256>,
    ) -> H256 {
        let diamond_contract_instance = self
            .diamond_proxy_contract
            .clone()
            .into_contract::<Provider<Http>>(self.diamond_proxy_address, self.provider.clone());

        let verifier_address = diamond_contract_instance
            .method::<_, Address>("getVerifier", ())
            .unwrap()
            .block(block_number)
            .call()
            .await
            .unwrap();

        let verifier_contract_instance = self
            .verifier_contract
            .clone()
            .into_contract::<Provider<Http>>(verifier_address, self.provider.clone());

        if protocol_version_id < 27 {
            verifier_contract_instance
                .method::<_, H256>("verificationKeyHash", ())
                .unwrap()
                .block(block_number)
                .call()
                .await
                .unwrap()
        } else {
            if verifier_type.unwrap() == FFLONK_VERIFICATION_TYPE {
                let flonk_verifier_address = verifier_contract_instance
                    .method::<_, Address>("FFLONK_VERIFIER", ())
                    .unwrap()
                    .block(block_number)
                    .call()
                    .await
                    .unwrap();
                let fflonk_verifier_contract_instance = self
                    .verifier_contract
                    .clone()
                    .into_contract::<Provider<Http>>(flonk_verifier_address, self.provider.clone());

                fflonk_verifier_contract_instance
                    .method::<_, H256>("verificationKeyHash", ())
                    .unwrap()
                    .block(block_number)
                    .call()
                    .await
                    .unwrap()
            } else {
                let plonk_verifier_address = verifier_contract_instance
                    .method::<_, Address>("PLONK_VERIFIER", ())
                    .unwrap()
                    .block(block_number)
                    .call()
                    .await
                    .unwrap();
                let fflonk_verifier_contract_instance = self
                    .verifier_contract
                    .clone()
                    .into_contract::<Provider<Http>>(plonk_verifier_address, self.provider.clone());

                fflonk_verifier_contract_instance
                    .method::<_, H256>("verificationKeyHash", ())
                    .unwrap()
                    .block(block_number)
                    .call()
                    .await
                    .unwrap()
            }
        }
    }
}

/// Returns the diamond proxy address for a given network.
pub fn get_diamond_proxy_address(network: String) -> Address {
    if network == "mainnet" {
        Address::from_str("32400084c286cf3e17e7b677ea9583e60a000324").unwrap()
    } else if network == "sepolia" {
        Address::from_str("9a6de0f62aa270a8bcb1e2610078650d539b1ef9").unwrap()
    } else if network == "stage-proofs" {
        Address::from_str("35360f304599cd6479978e2734f37b57ad6f1696").unwrap()
    } else {
        Address::default()
    }
}
