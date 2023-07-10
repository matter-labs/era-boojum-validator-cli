
use std::fs;
use std::io::Cursor;

#[derive(serde::Serialize, serde::Deserialize)]
struct L1BatchJson {
    commitTxHash: String,
    proveTxHash: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JSONRPCResponse {
    result: L1BatchJson,
}

// Fetches given batch information from Era RPC
pub async fn fetch_batch_info(batch_number: usize, network: String) -> Result<L1BatchJson, Box<dyn std::error::Error>> {

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
        let json = response.json::<JSONRPCResponse>().await?;
        return Ok(json.result);
    } else {
        return Err(format!("Failed to fetch information from zkSync Era RPC for batch {} on network {}", batch_number, network).into());
    }
}

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
pub async fn fetch_l1_info(tx_hash: String, rpc_url: String) -> Result<String, Box<dyn std::error::Error>> {

    println!("Fetching batch information from Ethereum on transaction {} using rpc {}", tx_hash, rpc_url);

    let client = reqwest::Client::new();

    let response = client.post(rpc_url)
    .header("Content-Type", "application/json")
    .body(format!(r#"{{
            "jsonrpc": "2.0",
            "method": "zks_getL1BatchDetails",
            "params": [{}, false],
            "id": "1"
        }}"#, batch_number)).send()
        .await?;

    if response.status().is_success() {
        //println!("{:?}", response.text().await?);
        let json = response.json::<JSONRPCResponse>().await?;
        return Ok(format!("{}", json.result.proveTxHash));
    } else {
        return Err(format!("Failed to fetch information from zkSync Era RPC for batch {} on network {}", batch_number, network).into());
    }
}