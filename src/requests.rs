
use std::fs;
use std::io::Cursor;
use ethers::abi::Function;
use boojum::field::goldilocks::GoldilocksField;

/// Download the proof file if it exists and saves locally
pub async fn fetch_proof_from_storage(batch_number: u64, network: &str) -> Result<String, Box<dyn std::error::Error>> {

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

/// Download the proof file if it exists and saves locally
pub async fn fetch_aux_data_from_storage(batch_number: u64, network: &str) -> Result<AuxOutputWitnessWrapper, Box<dyn std::error::Error>> {

    println!("Downloading aux data for batch {} on network {}", batch_number, network);

    let client = reqwest::Client::new();
    let url = format!("https://storage.googleapis.com/zksync-era-{}-proofs/scheduler_witness_jobs_fri/aux_output_witness_{}.bin", network, batch_number);

    // let data = include_bytes!("keys/scheduler_witness_jobs_fri_aux_output_witness_74249.bin");
    
    // let result: AuxOutputWitnessWrapper = bincode::deserialize(&data[..]).unwrap();
        // return Ok(result);

    let aux_data = client.get(url).send()
        .await?;

    if aux_data.status().is_success() {
        let result: AuxOutputWitnessWrapper = bincode::deserialize(&aux_data.bytes().await?[..]).unwrap();
        return Ok(result);
    } else {
        return Err(format!("Proof for batch {} on network {} not found", batch_number, network).into());
    }
}

pub struct BatchL1Data {
    pub previous_enumeration_counter: u64,
    pub previous_root: Vec<u8>,
    pub new_enumeration_counter: u64,
    pub new_root: Vec<u8>,
    pub default_aa_hash: [u8; 32],
    pub bootloader_hash: [u8; 32],
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxOutputWitnessWrapper(
    pub zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness<GoldilocksField>,
);

pub async fn fetch_l1_data(batch_number: u64, network: &str, rpc_url: &str) -> Result<BatchL1Data, String> {
    use ethers::types::*;
    use ethers::prelude::*;
    use ethers::abi::Abi;
    use std::str::FromStr;
    use colored::Colorize;

    let DIAMOND_PROXY = if network.to_string() == "mainnet" { "32400084c286cf3e17e7b677ea9583e60a000324" } else { "1908e2BF4a88F91E4eF0DC72f02b8Ea36BEa2319" };

    let client = Provider::<Http>::try_from(rpc_url).expect("Failed to connect to provider");
    
    let contract_abi: Abi = Abi::load(&include_bytes!("../abis/IZkSync.json")[..]).unwrap();
    let function = contract_abi.functions_by_name("commitBlocks").unwrap()[0].clone();
    let previous_batch_number = batch_number - 1;
    let address = Address::from_str(DIAMOND_PROXY).unwrap();
    // let get_block_hash_function = contract.functions_by_name("storedBlockHash").unwrap()[0].clone();
    // let get_bootloader_code_hash_function = contract.functions_by_name("getL2BootloaderBytecodeHash").unwrap()[0].clone();
    // let get_default_aa_code_hash_function = contract.functions_by_name("getL2DefaultAccountBytecodeHash").unwrap()[0].clone();

    

    let event = contract_abi.events_by_name("BlockCommit").unwrap()[0].clone();
    let mut roots = vec![];
    let mut l1_block_number = 0;
    for b_number in [previous_batch_number, batch_number] {
        // let filter = Filter::new().from_block(16621828).to_block(BlockNumber::Latest).address(address).topic0(event.signature()).topic1(U256::from(b_number as u64));
        // let mut events = client.get_logs(&filter).await.map_err(|_| format!("failed to find commit transaction for block {}", b_number))?;
        // if events.len() != 1 {
        //     return Err(format!("failed to find commit transaction for block {}", b_number));
        // }
        // let event = events.pop().unwrap();
        // let tx_hash = event.transaction_hash.unwrap();

        let commit_tx = fetch_batch_commit_tx(b_number, network).await.map_err(|_| format!("failed to find commit transaction for block {}", b_number)).unwrap();
        
        let tx = client.get_transaction(TxHash::from_str(&commit_tx).unwrap()).await.map_err(|_| format!("failed to find commit transaction for block {}", b_number))?.unwrap();
        l1_block_number = tx.block_number.unwrap().as_u64();
        let calldata = tx.input.to_vec();

        let found_data = find_state_data_from_log(b_number, &function, &calldata);
        if found_data.is_none() {
            panic!("invalid log from L1 for block {}", b_number);
        }

        roots.push(found_data.unwrap());
    }

    assert_eq!(roots.len(), 2);

    let (previous_enumeration_counter, previous_root) = roots[0].clone();
    let (new_enumeration_counter, new_root) = roots[1].clone();

    println!("Will be verifying a proof for state transition from root {} to root {}", format!("0x{}",hex::encode(&previous_root)).yellow(), format!("0x{}",hex::encode(&new_root)).yellow());

    let base_contract: BaseContract = contract_abi.into();
    let contract_instance = base_contract.into_contract::<Provider<Http>>(address, client);
    let bootloader_code_hash = contract_instance.method::<_, H256>("getL2BootloaderBytecodeHash", ()).unwrap().block(l1_block_number).call().await.unwrap();
    let default_aa_code_hash = contract_instance.method::<_, H256>("getL2DefaultAccountBytecodeHash", ()).unwrap().block(l1_block_number).call().await.unwrap();

    println!("Will be using bootloader code hash {} and default AA code hash {}", format!("0x{}",hex::encode(bootloader_code_hash.as_bytes())).yellow(), format!("0x{}", hex::encode(default_aa_code_hash.as_bytes())).yellow());
    println!("\n");
    let result = BatchL1Data {
        previous_enumeration_counter,
        previous_root,
        new_enumeration_counter,
        new_root,
        bootloader_hash: *bootloader_code_hash.as_fixed_bytes(),
        default_aa_hash: *default_aa_code_hash.as_fixed_bytes(),
    };

    Ok(result)
}


#[derive(serde::Serialize, serde::Deserialize)]
pub struct JSONL2RPCResponse {
    result: L1BatchJson,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct L1BatchJson {
    commitTxHash: String,
}

// Fetches given batch information from Era RPC
pub async fn fetch_batch_commit_tx(batch_number: u64, network: &str) -> Result<String, Box<dyn std::error::Error>> {

    println!("Fetching batch {} information from zkSync Era on network {}", batch_number, network);

    let domain;
    if network== "testnet" {
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


fn find_state_data_from_log(batch_number: u64, function: &Function, calldata: &[u8]) -> Option<(u64, Vec<u8>)> {
    use ethers::abi;

    let mut parsed_input = function.decode_input(&calldata[4..]).unwrap();
    assert_eq!(parsed_input.len(), 2);
    let second_param = parsed_input.pop().unwrap();
    let first_param = parsed_input.pop().unwrap();

    let abi::Token::Tuple(first_param) = first_param else {
        panic!();
    };

    let abi::Token::Uint(previous_l2_block_number) = first_param[0].clone() else  {
        panic!()
    };
    if previous_l2_block_number.as_u64() >= batch_number {
        panic!("invalid log from L1");
    }
    let abi::Token::Uint(previous_enumeration_index) = first_param[2].clone() else  {
        panic!()
    };
    let _previous_enumeration_index = previous_enumeration_index.0[0];

    let abi::Token::Array(inner) = second_param else {
        panic!()
    };

    let mut found_params = None;

    for inner in inner.into_iter() {
        let abi::Token::Tuple(inner) = inner else {
            panic!()
        };
        let abi::Token::Uint(new_l2_block_number) = inner[0].clone() else  {
            panic!()
        };
        let new_l2_block_number = new_l2_block_number.0[0];
        if new_l2_block_number == batch_number {
            let abi::Token::Uint(new_enumeration_index) = inner[2].clone() else  {
                panic!()
            };
            let new_enumeration_index = new_enumeration_index.0[0];
    
            let abi::Token::FixedBytes(state_root) = inner[3].clone() else  {
                panic!()
            };

            assert_eq!(state_root.len(), 32);

            found_params = Some((new_enumeration_index, state_root));
        } else {
            continue;
        }
    }

    found_params
}