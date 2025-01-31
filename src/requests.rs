use std::str::FromStr;

use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::bn256::Bn256;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use colored::Colorize;
use ethers::abi::{Abi, Function};
use ethers::contract::BaseContract;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::TxHash;
use once_cell::sync::Lazy;
use zksync_types::{ethabi, H256};

use crate::batch::{parse_batch_proof, parse_commit_batch_info, CommitBatchInfo};
use crate::block_header::{self, BlockAuxilaryOutput, VerifierParams};
use crate::contract::get_diamond_proxy_address;
use crate::outputs::StatusCode;
use crate::snark_wrapper_verifier::L1BatchProofForL1;
use crate::utils::{
    get_abi_for_protocol_version, get_commit_function_for_protocol_version,
    get_prove_function_for_protocol_version,
};

pub static BLOCK_COMMIT_EVENT_SIGNATURE: Lazy<H256> = Lazy::new(|| {
    ethabi::long_signature(
        "BlockCommit",
        &[
            ethabi::ParamType::Uint(256),
            ethabi::ParamType::FixedBytes(32),
            ethabi::ParamType::FixedBytes(32),
        ],
    )
});

#[derive(Debug, Default, Clone)]
pub struct BatchL1Data {
    pub previous_enumeration_counter: u64,
    pub previous_root: Vec<u8>,
    // Enumeration counter (used for L2 -> L1 communication).
    pub new_enumeration_counter: u64,
    // Storage root.
    pub new_root: Vec<u8>,
    // Hash of the account abstraction code.
    pub default_aa_hash: [u8; 32],
    // Hash of the bootloader.yul code.
    pub bootloader_hash: [u8; 32],
    pub prev_batch_commitment: H256,
    pub curr_batch_commitment: H256,
}

#[derive(Debug, Clone)]
pub struct L1BatchAndProofData {
    pub batch_l1_data: BatchL1Data,
    pub aux_output: BlockAuxilaryOutput,
    pub scheduler_proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit>,
    pub verifier_params: VerifierParams,
    pub block_number: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxOutputWitnessWrapper(
    pub  circuit_definitions::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness<
        GoldilocksField,
    >,
);

pub async fn fetch_l1_data(
    batch_number: u64,
    current_protocol_version: u16,
    previous_protocol_version: u16,
    network: &str,
    rpc_url: &str,
) -> Result<L1BatchAndProofData, StatusCode> {
    let commit_data = fetch_l1_commit_data(
        batch_number,
        current_protocol_version,
        previous_protocol_version,
        network,
        rpc_url,
    )
    .await;
    if commit_data.is_err() {
        return Err(commit_data.err().unwrap());
    }

    let (batch_l1_data, aux_output) = commit_data.unwrap();

    let proof_info =
        fetch_proof_from_l1(batch_number, network, rpc_url, current_protocol_version).await;

    if proof_info.is_err() {
        return Err(proof_info.err().unwrap());
    }

    let (proof_data, block_number) = proof_info.unwrap();

    let verifier_params = fetch_verifier_param_from_l1(block_number, network, rpc_url).await;

    Ok(L1BatchAndProofData {
        batch_l1_data,
        aux_output,
        scheduler_proof: proof_data.scheduler_proof,
        verifier_params,
        block_number,
    })
}

pub async fn fetch_l1_commit_data(
    batch_number: u64,
    current_protocol_version: u16,
    previous_protocol_version: u16,
    network: &str,
    rpc_url: &str,
) -> Result<(BatchL1Data, BlockAuxilaryOutput), StatusCode> {
    let client = Provider::<Http>::try_from(rpc_url).expect("Failed to connect to provider");

    let previous_batch_number = batch_number - 1;
    let address = get_diamond_proxy_address(network.to_string());

    let mut roots = vec![];
    let mut l1_block_number = 0;
    let mut calldata = vec![];
    let mut prev_batch_commitment = H256::default();
    let mut curr_batch_commitment = H256::default();
    for (b_number, protocol_version) in [
        (previous_batch_number, previous_protocol_version),
        (batch_number, current_protocol_version),
    ] {
        let (function, _) = get_commit_function_for_protocol_version(protocol_version);

        let commit_tx = fetch_batch_commit_tx(b_number, network).await;

        if commit_tx.is_err() {
            return Err(commit_tx.err().unwrap());
        }

        let (commit_tx, _) = commit_tx.unwrap();

        let tx = client
            .get_transaction(TxHash::from_str(&commit_tx).unwrap())
            .await
            .map_err(|_| StatusCode::FailedToFindCommitTxn);

        if tx.is_err() {
            return Err(StatusCode::FailedToFindCommitTxn);
        }

        let tx = tx.unwrap().unwrap();
        l1_block_number = tx.block_number.unwrap().as_u64();
        calldata = tx.input.to_vec();

        let found_data = find_state_data_from_log(protocol_version, &function, &calldata);

        if found_data.is_err() || found_data.clone().unwrap().is_none() {
            return Err(StatusCode::InvalidLog);
        }

        let found_data = found_data.unwrap();

        let batch_commitment = client
            .get_transaction_receipt(tx.hash)
            .await
            .map_err(|_| StatusCode::FailedToGetTransactionReceipt)?
            .unwrap()
            .logs
            .iter()
            .find(|log| {
                log.address == address
                    && log.topics.len() == 4
                    && log.topics[0] == *BLOCK_COMMIT_EVENT_SIGNATURE
                    && log.topics[1] == H256::from_low_u64_be(b_number)
            })
            .map(|log| log.topics[3]);

        if batch_commitment.is_none() {
            return Err(StatusCode::FailedToGetBatchCommitment);
        }

        if b_number == previous_batch_number {
            prev_batch_commitment = batch_commitment.unwrap();
        } else {
            curr_batch_commitment = batch_commitment.unwrap();
        }

        roots.push(found_data.unwrap());
    }

    let (function, _) = get_commit_function_for_protocol_version(current_protocol_version);
    let aux_output =
        block_header::parse_aux_data(&function, &calldata, current_protocol_version).await;

    if aux_output.is_err() {
        return Err(aux_output.err().unwrap());
    }

    assert_eq!(roots.len(), 2);

    let (previous_enumeration_counter, previous_root) = roots[0].clone();
    let (new_enumeration_counter, new_root) = roots[1].clone();

    println!(
        "Will be verifying a proof for state transition from root {} to root {}",
        format!("0x{}", hex::encode(&previous_root)).yellow(),
        format!("0x{}", hex::encode(&new_root)).yellow()
    );

    let contract_abi = get_abi_for_protocol_version(current_protocol_version);
    let base_contract: BaseContract = contract_abi.into();
    let contract_instance = base_contract.into_contract::<Provider<Http>>(address, client);
    let bootloader_code_hash = contract_instance
        .method::<_, H256>("getL2BootloaderBytecodeHash", ())
        .unwrap()
        .block(l1_block_number)
        .call()
        .await
        .unwrap();
    let default_aa_code_hash = contract_instance
        .method::<_, H256>("getL2DefaultAccountBytecodeHash", ())
        .unwrap()
        .block(l1_block_number)
        .call()
        .await
        .unwrap();

    println!(
        "Will be using bootloader code hash {} and default AA code hash {}",
        format!("0x{}", hex::encode(bootloader_code_hash.as_bytes())).yellow(),
        format!("0x{}", hex::encode(default_aa_code_hash.as_bytes())).yellow()
    );
    println!("\n");
    let result = BatchL1Data {
        previous_enumeration_counter,
        previous_root,
        new_enumeration_counter,
        new_root,
        bootloader_hash: *bootloader_code_hash.as_fixed_bytes(),
        default_aa_hash: *default_aa_code_hash.as_fixed_bytes(),
        prev_batch_commitment,
        curr_batch_commitment,
    };

    Ok((result, aux_output.unwrap()))
}

pub async fn fetch_proof_from_l1(
    batch_number: u64,
    network: &str,
    rpc_url: &str,
    protocol_version: u16,
) -> Result<(L1BatchProofForL1, u64), StatusCode> {
    let client = Provider::<Http>::try_from(rpc_url).expect("Failed to connect to provider");

    let (function, _) = get_prove_function_for_protocol_version(protocol_version);

    let (_, prove_tx) = fetch_batch_commit_tx(batch_number, network)
        .await
        .map_err(|_| StatusCode::FailedToFindCommitTxn)
        .unwrap();

    if prove_tx.is_none() {
        let msg = format!(
            "Proof doesn't exist for batch {} on network {} yet, please try again soon. Exiting...",
            batch_number.to_string().red(),
            network.red()
        );
        println!("{}", msg);
        return Err(StatusCode::ProofDoesntExist);
    };

    let tx = client
        .get_transaction(TxHash::from_str(&prove_tx.unwrap()).unwrap())
        .await
        .map_err(|_| StatusCode::FailedToFindProveTxn)
        .unwrap()
        .unwrap();

    let l1_block_number = tx.block_number.unwrap().as_u64();
    let calldata = tx.input.to_vec();

    let proof = parse_batch_proof(&function, &calldata, protocol_version, network);

    match proof {
        None => Err(StatusCode::FailedToParseProof),
        Some(proof) => Ok((
            L1BatchProofForL1 {
                aggregation_result_coords: [[0u8; 32]; 4],
                scheduler_proof: proof,
            },
            l1_block_number,
        )),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct JSONL2RPCResponse {
    result: L1BatchJson,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct L1BatchJson {
    commitTxHash: String,
    proveTxHash: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct L1BatchRangeJson {
    result: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct JSONL2SyncRPCResponse {
    result: L2SyncDetails,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct L2SyncDetails {
    protocolVersion: String,
}

// Fetches given batch information from Era RPC
pub async fn fetch_batch_commit_tx(
    batch_number: u64,
    network: &str,
) -> Result<(String, Option<String>), StatusCode> {
    println!(
        "Fetching batch {} information from zkSync Era on network {}",
        batch_number, network
    );

    let domain;
    if network == "sepolia" {
        domain = "https://sepolia.era.zksync.dev";
    } else {
        domain = "https://mainnet.era.zksync.io";
    }
    let client = reqwest::Client::new();

    let response = client
        .post(domain)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{
            "jsonrpc": "2.0",
            "method": "zks_getL1BatchDetails",
            "params": [{}, false],
            "id": "1"
        }}"#,
            batch_number
        ))
        .send()
        .await;

    if response.is_err() {
        return Err(StatusCode::FailedToCallRPC);
    }

    let response = response.unwrap();

    if response.status().is_success() {
        let json = response.json::<JSONL2RPCResponse>().await;

        if json.is_err() {
            return Err(StatusCode::FailedToCallRPCJsonError);
        }

        let json = json.unwrap();

        return Ok((json.result.commitTxHash, json.result.proveTxHash));
    } else {
        return Err(StatusCode::FailedToCallRPCResponseError);
    }
}

// Fetches given batch information from Era RPC
pub async fn fetch_batch_protocol_version(
    batch_number: u64,
    network: &str,
) -> Result<String, StatusCode> {
    println!(
        "Fetching batch {} protocol version from zkSync Era on network {}",
        batch_number, network
    );

    let domain;
    if network == "sepolia" {
        domain = "https://sepolia.era.zksync.dev";
    } else {
        domain = "https://mainnet.era.zksync.io";
    }
    let client = reqwest::Client::new();

    let response = client
        .post(domain)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{
            "jsonrpc": "2.0",
            "method": "zks_getL1BatchBlockRange",
            "params": [{}],
            "id": "1"
        }}"#,
            batch_number
        ))
        .send()
        .await;

    if response.is_err() {
        return Err(StatusCode::FailedToCallRPC);
    }

    let response = response.unwrap();

    if response.status().is_success() {
        let json = response.json::<L1BatchRangeJson>().await;

        if json.is_err() {
            return Err(StatusCode::FailedToCallRPC);
        }

        let batch_range = json.unwrap();

        let l2_block_hex = batch_range.result[0].clone();

        let without_prefix = l2_block_hex.trim_start_matches("0x");
        let l2_block = i64::from_str_radix(without_prefix, 16);

        let response_2 = client
            .post(domain)
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{
                "jsonrpc": "2.0",
                "method": "en_syncL2Block",
                "params": [{}, false],
                "id": "1"
            }}"#,
                l2_block.unwrap()
            ))
            .send()
            .await;

        if response_2.is_err() {
            return Err(StatusCode::FailedToCallRPC);
        }

        let response_2 = response_2.unwrap();

        if response_2.status().is_success() {
            let json_2 = response_2.json::<JSONL2SyncRPCResponse>().await;

            if json_2.is_err() {
                return Err(StatusCode::FailedToCallRPC);
            }

            let sync_result = json_2.unwrap();

            let version = sync_result
                .result
                .protocolVersion
                .strip_prefix("Version")
                .unwrap();

            println!("Batch {} has protocol version {}", batch_number, version);

            return Ok(version.to_string());
        } else {
            return Err(StatusCode::FailedToCallRPC);
        }
    } else {
        return Err(StatusCode::FailedToCallRPC);
    }
}

fn find_state_data_from_log(
    protocol_version: u16,
    function: &Function,
    calldata: &[u8],
) -> Result<Option<(u64, Vec<u8>)>, StatusCode> {
    let batch = parse_commit_batch_info(function, calldata, protocol_version);

    match batch {
        None => Err(StatusCode::FailedToDeconstruct),
        Some(batch_commit) => {
            let CommitBatchInfo {
                batch_number: _,
                timestamp: _,
                index_repeated_storage_changes,
                new_state_root,
                number_l1_txns: _,
                priority_operations_hash: _,
                bootloader_contents_hash: _,
                event_queue_state_hash: _,
                sys_logs: _,
                total_pubdata: _,
            } = batch_commit;

            Ok(Some((
                index_repeated_storage_changes.as_u64(),
                new_state_root,
            )))
        }
    }
}

async fn fetch_verifier_param_from_l1(
    block_number: u64,
    network: &str,
    rpc_url: &str,
) -> VerifierParams {
    let client = Provider::<Http>::try_from(rpc_url).expect("Failed to connect to provider");
    let contract_abi: Abi = Abi::load(&include_bytes!("../abis/IZkSync.json")[..]).unwrap();

    let base_contract: BaseContract = contract_abi.into();
    let address = get_diamond_proxy_address(network.to_string());
    let contract_instance = base_contract.into_contract::<Provider<Http>>(address, client);
    let (
        recursion_node_level_vk_hash,
        recursion_leaf_level_vk_hash,
        recursion_circuits_set_vk_hash,
    ) = contract_instance
        .method::<_, (H256, H256, H256)>("getVerifierParams", ())
        .unwrap()
        .block(block_number)
        .call()
        .await
        .unwrap();

    VerifierParams {
        recursion_node_level_vk_hash: recursion_node_level_vk_hash.to_fixed_bytes(),
        recursion_leaf_level_vk_hash: recursion_leaf_level_vk_hash.to_fixed_bytes(),
        recursion_circuits_set_vk_hash: recursion_circuits_set_vk_hash.to_fixed_bytes(),
    }
}
