use colored::Colorize;
use ethers::prelude::{Provider, Http, BaseContract, Address, H256};
use std::str::FromStr;

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

        if network != "mainnet" && network != "sepolia" && network != "testnet" {
            panic!(
                "Please use network name `{}`, `{}`, or `{}`",
                "mainnet".yellow(),
                "sepolia".yellow(),
                "testnet".yellow()
            );
        }

        let provider =
            Provider::<Http>::try_from(l1_rpc_url).expect("Failed to connect to provider");

        let diamond_proxy_abi: Abi =
            Abi::load(&include_bytes!("../abis/IZkSync.json")[..]).unwrap();
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
    pub async fn get_verification_key_hash(&self, block_number: u64) -> H256 {
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
        verifier_contract_instance
            .method::<_, H256>("verificationKeyHash", ())
            .unwrap()
            .block(block_number)
            .call()
            .await
            .unwrap()
    }
}

/// Returns the diamond proxy address for a given network.
pub fn get_diamond_proxy_address(network: String) -> Address {
    if network == "mainnet" {
        Address::from_str("32400084c286cf3e17e7b677ea9583e60a000324").unwrap()
    } else if network == "sepolia" {
        Address::from_str("74fba6cca06eed111e03719d6bfa26ae7680b3ea").unwrap()
    } else if network == "testnet" {
        Address::from_str("1908e2bf4a88f91e4ef0dc72f02b8ea36bea2319").unwrap()
    } else {
        panic!(
            "Please use network name `{}`, `{}`, or `{}`",
            "mainnet".yellow(),
            "sepolia".yellow(),
            "testnet".yellow()
        );
    }
}
