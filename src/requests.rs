use std::str::FromStr;

use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::bn256::Bn256;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use colored::Colorize;
use crypto::deserialize_proof;
use ethers::abi::{Abi, Function, Token};
use ethers::contract::BaseContract;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::TxHash;
use once_cell::sync::Lazy;
use primitive_types::U256;
use zksync_types::{ethabi, H256};

use crate::block_header::{self, BlockAuxilaryOutput, VerifierParams};
use crate::contract::get_diamond_proxy_address;
use crate::outputs::StatusCode;
use crate::snark_wrapper_verifier::L1BatchProofForL1;

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
    network: &str,
    rpc_url: &str,
) -> Result<L1BatchAndProofData, StatusCode> {
    let commit_data = fetch_l1_commit_data(batch_number, network, rpc_url).await;
    if commit_data.is_err() {
        return Err(commit_data.err().unwrap());
    }

    let (batch_l1_data, aux_output) = commit_data.unwrap();

    let proof_info = fetch_proof_from_l1(batch_number, network, rpc_url).await;

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
    network: &str,
    rpc_url: &str,
) -> Result<(BatchL1Data, BlockAuxilaryOutput), StatusCode> {
    let client = Provider::<Http>::try_from(rpc_url).expect("Failed to connect to provider");

    let contract_abi: Abi = Abi::load(&include_bytes!("../abis/IZkSync.json")[..]).unwrap();
    let function: Function = contract_abi.functions_by_name("commitBatches").unwrap()[0].clone();
    let previous_batch_number = batch_number - 1;
    let address = get_diamond_proxy_address(network.to_string());

    let mut roots = vec![];
    let mut l1_block_number = 0;
    let mut calldata = vec![];
    let mut prev_batch_commitment = H256::default();
    let mut curr_batch_commitment = H256::default();
    for b_number in [previous_batch_number, batch_number] {
        let commit_tx = fetch_batch_commit_tx(b_number, network)
            .await
            .map_err(|e| e);

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

        let found_data = find_state_data_from_log(b_number, &function, &calldata);

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

    let aux_output = block_header::parse_aux_data(&function, &calldata);

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
) -> Result<(L1BatchProofForL1, u64), StatusCode> {
    let client = Provider::<Http>::try_from(rpc_url).expect("Failed to connect to provider");

    let contract_abi: Abi = Abi::load(&include_bytes!("../abis/IZkSync.json")[..]).unwrap();
    let function = contract_abi.functions_by_name("proveBatches").unwrap()[0].clone();

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

    let parsed_input = function.decode_input(&calldata[4..]).unwrap();

    assert_eq!(parsed_input.len(), 3);
    let [_, _, Token::Tuple(proof)] = parsed_input.as_slice() else {
        return Err(StatusCode::InvalidTupleTypes);
    };

    assert_eq!(proof.len(), 2);

    let Token::Array(serialized_proof) = proof[1].clone() else {
        return Err(StatusCode::InvalidTupleTypes);
    };

    let proof = serialized_proof
        .iter()
        .filter_map(|e| {
            if let Token::Uint(x) = e {
                Some(x.clone())
            } else {
                None
            }
        })
        .collect::<Vec<U256>>();

    if network != "mainnet" && serialized_proof.len() == 0 {
        let msg = format!(
            "Proof doesn't exist for batch {} on network {}, exiting...",
            batch_number.to_string().red(),
            network.red()
        );
        println!("{}", msg);
        return Err(StatusCode::ProofDoesntExist);
    }

    let x: Proof<Bn256, ZkSyncSnarkWrapperCircuit> = deserialize_proof(proof);
    Ok((
        L1BatchProofForL1 {
            aggregation_result_coords: [[0u8; 32]; 4],
            scheduler_proof: x,
        },
        l1_block_number,
    ))
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
        domain = "https://sepolia.era.zksync.dev"
    } else if network == "mainnet" {
        domain = "https://mainnet.era.zksync.io"
    } else {
        domain = "https://testnet.era.zksync.dev"
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

fn find_state_data_from_log(
    batch_number: u64,
    function: &Function,
    calldata: &[u8],
) -> Result<Option<(u64, Vec<u8>)>, StatusCode> {
    use ethers::abi;

    let mut parsed_input = function.decode_input(&calldata[4..]).unwrap();
    assert_eq!(parsed_input.len(), 2);
    let second_param = parsed_input.pop().unwrap();
    let first_param = parsed_input.pop().unwrap();

    let abi::Token::Tuple(first_param) = first_param else {
        return Err(StatusCode::FailedToDeconstruct);
    };

    let abi::Token::Uint(previous_l2_block_number) = first_param[0].clone() else {
        return Err(StatusCode::FailedToDeconstruct);
    };
    if previous_l2_block_number.as_u64() >= batch_number {
        return Err(StatusCode::InvalidLog);
    }
    let abi::Token::Uint(previous_enumeration_index) = first_param[2].clone() else {
        return Err(StatusCode::FailedToDeconstruct);
    };
    let _previous_enumeration_index = previous_enumeration_index.0[0];

    let abi::Token::Array(inner) = second_param else {
        return Err(StatusCode::FailedToDeconstruct);
    };

    let mut found_params = None;

    for inner in inner.into_iter() {
        let abi::Token::Tuple(inner) = inner else {
            return Err(StatusCode::FailedToDeconstruct);
        };
        let abi::Token::Uint(new_l2_block_number) = inner[0].clone() else {
            return Err(StatusCode::FailedToDeconstruct);
        };
        let new_l2_block_number = new_l2_block_number.0[0];
        if new_l2_block_number == batch_number {
            let abi::Token::Uint(new_enumeration_index) = inner[2].clone() else {
                return Err(StatusCode::FailedToDeconstruct);
            };
            let new_enumeration_index = new_enumeration_index.0[0];

            let abi::Token::FixedBytes(state_root) = inner[3].clone() else {
                return Err(StatusCode::FailedToDeconstruct);
            };

            assert_eq!(state_root.len(), 32);

            found_params = Some((new_enumeration_index, state_root));
        } else {
            continue;
        }
    }

    Ok(found_params)
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
