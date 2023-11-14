use colored::Colorize;
use ethers::prelude::*;
use std::{str::FromStr, env};

pub struct ContractConfig {
    pub provider: Provider<Http>,
    pub diamond_proxy_contract: BaseContract,
    pub verifier_contract: BaseContract,
    pub diamond_proxy_address: Address,
}

impl ContractConfig {
    pub fn new(l1_rpc_url: String, network: String) -> Self {
        use ethers::abi::Abi;
        
        if network != "mainnet" && network != "sepolia" {
            panic!(
                "Please use network name `{}` or `{}`",
                "mainnet".yellow(),
                "testnet".yellow()
            );
        }

        println!("{:?}", env::current_dir().unwrap());

        let provider =
            Provider::<Http>::try_from(l1_rpc_url).expect("Failed to connect to provider");

        let diamond_proxy_abi: Abi =
            Abi::load(&include_bytes!("../abis/IZKSync.json")[..]).unwrap();
        let verifier_abi: Abi = Abi::load(&include_bytes!("../abis/IVerifier.json")[..]).unwrap();

        let diamond_proxy_address = if network.to_string() == "mainnet" {
            Address::from_str("32400084c286cf3e17e7b677ea9583e60a000324").unwrap()
        } else {
            Address::from_str("74fba6cca06eed111e03719d6bfa26ae7680b3ea").unwrap()
        };

        let diamond_proxy_contract = diamond_proxy_abi.into();
        let verifier_contract = verifier_abi.into();

        Self {
            provider,
            diamond_proxy_contract,
            verifier_contract,
            diamond_proxy_address,
        }
    }

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

pub fn get_diamond_proxy_address(network: String) -> Address {
    if network == "mainnet" {
        Address::from_str("32400084c286cf3e17e7b677ea9583e60a000324").unwrap()
    } else if network == "sepolia" {
        Address::from_str("74fba6cca06eed111e03719d6bfa26ae7680b3ea").unwrap()
    } else {
        panic!(
            "Please use network name `{}` or `{}`",
            "mainnet".yellow(),
            "testnet".yellow()
        );
    }
}
