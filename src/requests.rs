
use std::fs;
use std::io::Cursor;
use ethers::{
    contract::abigen,
    core::{abi::AbiDecode, types::Bytes},
    providers::{Http, Provider},
    types::Address,
};
use std::sync::Arc;
use ethers::types::U256;
use core::fmt::Write;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct L1BatchJson {
    commitTxHash: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct L1Tx {
    input: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct JSONL2RPCResponse {
    result: L1BatchJson,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct JSONRPCResponse {
    result: L1Tx,
}

abigen!(
    Executor,
    "abis/executor.json"
);


/// Download the proof file if it exists and saves locally
pub async fn fetch_proof_from_storage(batch_number: usize, network: String) -> Result<String, Box<dyn std::error::Error>> {

    println!("Downloading proof for batch {} on network {}", batch_number, network);

    let client = reqwest::Client::new();
    let url = format!("https://storage.googleapis.com/zksync-era-{}-proofs/proofs_fri/proof_{}.bin", network, batch_number);
    let proof = client.get(url).send()
        .await?;

    if proof.status().is_success() {
        fs::create_dir_all("./downloaded_proofs")?;
        let file_path = format!("./downloaded_proofs/proof_{}_{}.bin", network, batch_number);

        let mut file = std::fs::File::create(file_path.clone())?;
        let mut content =  Cursor::new(proof.bytes().await?);
        std::io::copy(&mut content, &mut file)?;

        return Ok(file_path);
    } else {
        return Err(format!("Proof for batch {} on network {} not found", batch_number, network).into());
    }
}

// Fetches given batch information from Era RPC
pub async fn fetch_batch_info(batch_number: usize, network: String) -> Result<String, Box<dyn std::error::Error>> {

    println!("Fetching batch {} information from zkSync Era on network {}", batch_number, network);

    let domain;
    if network.to_string() == "testnet" {
        domain = "https://testnet.era.zksync.dev"
    } else  {
        domain = "https://mainnet.era.zksync.io"
    }
    let client = reqwest::Client::new();

    let response = client.post(domain)
    .header("Content-Type", "application/json")
    .body(format!(r#"{{
            "jsonrpc": "2.0",
            "method": "zks_getL1BatchDetails",
            "params": [{}, false],
            "id": "1"
        }}"#, batch_number)).send()
        .await?;

    if response.status().is_success() {
        let json = response.json::<JSONL2RPCResponse>().await?;
        return Ok(json.result.commitTxHash);
    } else {
        return Err(format!("Failed to fetch information from zkSync Era RPC for batch {} on network {}", batch_number, network).into());
    }
}

// Fetches given batch information from Era RPC
pub async fn fetch_l1_info(tx_hash: String, rpc_url: String, batch_number: usize, network: String) -> Result<CommitBlockInfo, Box<dyn std::error::Error>> {

    let mut url = rpc_url.clone();
    println!("Fetching batch information from Ethereum on transaction {} using rpc {}", tx_hash, rpc_url);

    let client = reqwest::Client::new();

    let response = client.post(rpc_url)
    .header("Content-Type", "application/json")
    .body(format!(r#"{{
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": ["{}"],
            "id": "1"
        }}"#, tx_hash)).send()
        .await?;

        
    if response.status().is_success() {
        let json = response.json::<JSONRPCResponse>().await?;
        
        let calldata: Bytes = json.result.input.parse().unwrap();
        let decoded: Vec<CommitBlockInfo> = CommitBlocksCall::decode(&calldata)?.new_blocks_data;
        
        for val in decoded.iter() {
            // In case more than one batch  was commited
            if val.block_number == batch_number as u64 {

                let DIAMOND_PROXY = if network.to_string() == "mainnet" { "0x32400084c286cf3e17e7b677ea9583e60a000324" } else { "0x1908e2BF4a88F91E4eF0DC72f02b8Ea36BEa2319" };
        
                let provider = Provider::<Http>::try_from(url)?;
                let client = Arc::new(provider);
                let address: Address = DIAMOND_PROXY.parse()?;
                let contract = Executor::new(address, client);
            
                let contract_response = contract.stored_block_hash(U256::from(batch_number)).call().await.unwrap();
              
                let mut s = String::with_capacity(2 * contract_response.len());
                for byte in contract_response {
                    write!(s, "{:#04x?}", byte)?;
                }

                println!("{:?}", s);

                return Ok(val.clone());
            }
        }

        
        return Err(format!("Couldn't find batch information in transaction {}.", tx_hash).into());
    } else {
        return Err(format!("Failed to fetch information for transaction {} from Ethereum", tx_hash).into());
    }
}