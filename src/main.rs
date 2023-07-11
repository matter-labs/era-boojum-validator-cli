#![feature(generic_const_exprs)]
#![feature(array_chunks)]

use boojum::field::U64Representable;
use circuit_definitions::circuit_definitions::recursion_layer::scheduler::ConcreteSchedulerCircuitBuilder;
use clap::Parser;
use colored::Colorize;
use ethers::abi::Function;
use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Cursor;

pub mod block_header;

use boojum::{
    cs::implementations::{
        pow::NoPow, transcript::GoldilocksPoisedon2Transcript, verifier::VerificationKey,
    },
    field::goldilocks::{GoldilocksExt2, GoldilocksField},
};
use circuit_definitions::circuit_definitions::{
    base_layer::{BaseProofsTreeHasher, ZkSyncBaseLayerProof},
    recursion_layer::{ZkSyncRecursionLayerProof, ZkSyncRecursionLayerStorage},
};

#[derive(serde::Serialize, serde::Deserialize)]
pub enum FriProofWrapper {
    Base(ZkSyncBaseLayerProof),
    Recursive(ZkSyncRecursionLayerProof),
}

#[derive(Debug, Parser)]
#[command(author = "Matter Labs", version, about = "Boojum CLI verifier", long_about = None)]
struct Cli {
    #[arg(long, default_value = "74249")]
    /// Batch number to check proof for
    batch: u64,
    #[arg(long, default_value = "mainnet")]
    /// Batch number to check proof for
    network: String,
}

/// Reads proof (in FriProofWrapper format) from a given bin file.
pub fn proof_from_file<T: for<'a> Deserialize<'a>>(proof_path: &str) -> T {
    let mut file = File::open(proof_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let proof: T = bincode::deserialize(buffer.as_slice()).unwrap();
    proof
}

/// Verifies a given proof from "Scheduler" circuit.
pub fn verify_scheduler_proof(proof_path: &str) -> anyhow::Result<Vec<GoldilocksField>> {
    let scheduler_key: ZkSyncRecursionLayerStorage<
        VerificationKey<GoldilocksField, BaseProofsTreeHasher>,
    > = serde_json::from_slice(include_bytes!("keys/verification_scheduler_key.json")).unwrap();

    let proof = proof_from_file(proof_path);
    if let FriProofWrapper::Recursive(proof) = proof {
        println!("Proof type: {}", proof.short_description().bold());
        let verifier_builder =
            ConcreteSchedulerCircuitBuilder::dyn_verifier_builder::<GoldilocksExt2>();

        let verifier = verifier_builder.create_verifier();
        let proof = proof.into_inner();
        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &scheduler_key.into_inner(),
            &proof,
        );
        if result {
            Ok(proof.public_inputs)
        } else {
            anyhow::bail!("Invalid proof")
        }
    } else {
        anyhow::bail!("Invalid proof type")
    }
}

/// Download the proof file if it exists and saves locally
async fn fetch_proof_from_storage(batch_number: u64, network: String) -> Result<String, Box<dyn std::error::Error>> {

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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuxOutputWitnessWrapper(
    pub zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness<GoldilocksField>,
);

/// Download the proof file if it exists and saves locally
async fn fetch_aux_data_from_storage(batch_number: u64, network: String) -> Result<AuxOutputWitnessWrapper, Box<dyn std::error::Error>> {

    println!("Downloading aux data for batch {} on network {}", batch_number, network);

    let client = reqwest::Client::new();
    let url = format!("https://storage.googleapis.com/matterlabs-zksync-v2-{}-blob-store/scheduler_witness_jobs_fri/scheduler_witness_jobs_fri_aux_output_witness_{}.bin", network, batch_number);

    let data = include_bytes!("keys/scheduler_witness_jobs_fri_aux_output_witness_74249.bin");
    let result: AuxOutputWitnessWrapper = bincode::deserialize(&data[..]).unwrap();

    return Ok(result);

    // let proof = client.get(url).send()
    //     .await?;

    // if proof.status().is_success() {
    //     fs::create_dir_all("./downloaded_proofs")?;
    //     let file_path = format!("./downloaded_proofs/proof_{}_{}.bin", network, batch_number);

    //     let mut file = std::fs::File::create(file_path.clone())?;
    //     let mut content =  Cursor::new(proof.bytes().await?);
    //     std::io::copy(&mut content, &mut file)?;

    //     return Ok(file_path);
    // } else {
    //     return Err(format!("Proof for batch {} on network {} not found", batch_number, network).into());
    // }
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

struct BatchL1Data {
    previous_enumeration_counter: u64,
    previous_root: Vec<u8>,
    new_enumeration_counter: u64,
    new_root: Vec<u8>,
    default_aa_hash: [u8; 32],
    bootloader_hash: [u8; 32],
}

async fn fetch_l1_data(batch_number: u64) -> Result<BatchL1Data, String> {
    use ethers::types::*;
    use ethers::prelude::*;
    use ethers::abi::Abi;
    use std::str::FromStr;

    let client: Provider<Ws> =
        ***REMOVED***
            .await.map_err(|_| "Failed to connect to Infura proveider".to_string())?;
    // let client = std::sync::Arc::new(client);
    let contract_abi: Abi = Abi::load(&include_bytes!("IZkSync.json")[..]).unwrap();
    let function = contract_abi.functions_by_name("commitBlocks").unwrap()[0].clone();
    let previous_batch_number = batch_number - 1;
    let address = Address::from_str("32400084c286cf3e17e7b677ea9583e60a000324").unwrap();
    // let get_block_hash_function = contract.functions_by_name("storedBlockHash").unwrap()[0].clone();
    // let get_bootloader_code_hash_function = contract.functions_by_name("getL2BootloaderBytecodeHash").unwrap()[0].clone();
    // let get_default_aa_code_hash_function = contract.functions_by_name("getL2DefaultAccountBytecodeHash").unwrap()[0].clone();

    let event = contract_abi.events_by_name("BlockCommit").unwrap()[0].clone();
    let mut roots = vec![];
    let mut l1_block_number = 0;
    for b_number in [previous_batch_number, batch_number] {
        let filter = Filter::new().from_block(16621828).to_block(BlockNumber::Latest).address(address).topic0(event.signature()).topic1(U256::from(b_number as u64));
        let mut events = client.get_logs(&filter).await.map_err(|_| format!("failed to find commit transcation for block {}", b_number))?;
        if events.len() != 1 {
            return Err(format!("failed to find commit transcation for block {}", b_number));
        }
        let event = events.pop().unwrap();
        let tx_hash = event.transaction_hash.unwrap();
        let tx = client.get_transaction(tx_hash).await.map_err(|_| format!("failed to find commit transcation for block {}", b_number))?.unwrap();
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

    println!("Will be verifying a proof for state transition from root 0x{} to root 0x{}", hex::encode(&previous_root).yellow(), hex::encode(&new_root).yellow());

    let base_contract: BaseContract = contract_abi.into();
    let contract_instance = base_contract.into_contract::<Provider<Ws>>(address, client);
    let bootloader_code_hash = contract_instance.method::<_, H256>("getL2BootloaderBytecodeHash", ()).unwrap().block(l1_block_number).call().await.unwrap();
    let default_aa_code_hash = contract_instance.method::<_, H256>("getL2DefaultAccountBytecodeHash", ()).unwrap().block(l1_block_number).call().await.unwrap();

    println!("Will be using bootloader code hash 0x{} and default AA code hash 0x{}", hex::encode(bootloader_code_hash.as_bytes()).yellow(), hex::encode(default_aa_code_hash.as_bytes()).yellow());

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

#[tokio::main]
async fn main() {
    let opt = Cli::parse();

    let batch_number = opt.batch;
    let network = opt.network.clone();

    let batch_number = 74249u64;
    let network = "mainnet".to_string();

    if network.to_string() != "mainnet" {
        println!("Invalid network name. Please use 'mainnet' only for now");
        return
    }

    println!("Fetching data from Ethereum L1 for state roots, bootloader and default Account Abstraction parameters");

    let l1_data = fetch_l1_data(batch_number).await;
    if l1_data.is_err() {
        println!("Failed to get data from L1");
        return;
    }

    let l1_data = l1_data.unwrap();

    println!("Fetching auxilary block data");
    let aux_data = fetch_aux_data_from_storage(batch_number, network.to_string()).await;
    if aux_data.is_err() {
        println!("Failed to get auxilary data");
        return;
    }
    let aux_data = aux_data.unwrap();

    println!("Fetching and validating the proof itself");

    // while we do not prove all the blocks we use placeholders for non-state related parts
    // of the previous block
    let previous_block_meta_hash = [0u8; 32];
    let previous_block_aux_hash = [0u8; 32];

    use self::block_header::*;
    use sha3::{Digest, Keccak256};

    let previous_passthrough_data = BlockPassthroughData {
        per_shard_states: [
            PerShardState {
                enumeration_counter: l1_data.previous_enumeration_counter,
                state_root: l1_data.previous_root.try_into().unwrap(),
            },
            // porter shard is not used
            PerShardState {
                enumeration_counter: 0,
                state_root: [0u8; 32],
            },
        ]
    };
    let previous_passthrough_data_hash = to_fixed_bytes(Keccak256::digest(&previous_passthrough_data.into_flattened_bytes()).as_slice());

    let previous_block_content_hash = BlockContentHeader::formal_block_hash_from_partial_hashes(
        previous_passthrough_data_hash,
        previous_block_meta_hash,
        previous_block_aux_hash,
    );

    let new_passthrough_data = BlockPassthroughData {
        per_shard_states: [
            PerShardState {
                enumeration_counter: l1_data.new_enumeration_counter,
                state_root: l1_data.new_root.try_into().unwrap(),
            },
            // porter shard is not used
            PerShardState {
                enumeration_counter: 0,
                state_root: [0u8; 32],
            },
        ]
    };

    let new_meta_params = BlockMetaParameters {
        zkporter_is_available: false,
        bootloader_code_hash: l1_data.bootloader_hash,
        default_aa_code_hash: l1_data.default_aa_hash,
    };

    let aux_data = aux_data.0;

    let new_aux_params = BlockAuxilaryOutput {
        l1_messages_linear_hash: aux_data.l1_messages_linear_hash,
        rollup_state_diff_for_compression: aux_data.rollup_state_diff_for_compression,
        bootloader_heap_initial_content: aux_data.bootloader_heap_initial_content,
        events_queue_state: aux_data.events_queue_state,
    };

    let new_header = BlockContentHeader {
        block_data: new_passthrough_data,
        block_meta: new_meta_params,
        auxilary_output: new_aux_params,
    };
    let this_block_content_hash = new_header.into_formal_block_hash().0;

    let mut flattened_public_input = vec![];
    flattened_public_input.extend(previous_block_content_hash);
    flattened_public_input.extend(this_block_content_hash);
    // recursion parameters, for now hardcoded

    let node_layer_vk_commitment = [
        GoldilocksField::from_u64_unchecked(0),
        GoldilocksField::from_u64_unchecked(0),
        GoldilocksField::from_u64_unchecked(0),
        GoldilocksField::from_u64_unchecked(0),
    ];

    let mut recursion_node_verification_key_hash = [0u8; 32];
    for (dst, src) in recursion_node_verification_key_hash
        .array_chunks_mut::<8>()
        .zip(node_layer_vk_commitment.iter())
    {
        let le_bytes = src.to_reduced_u64().to_le_bytes();
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    let leaf_layer_parameters_commitment = [
        GoldilocksField::from_u64_unchecked(0),
        GoldilocksField::from_u64_unchecked(0),
        GoldilocksField::from_u64_unchecked(0),
        GoldilocksField::from_u64_unchecked(0),
    ];

    let mut leaf_layer_parameters_hash = [0u8; 32];
    for (dst, src) in leaf_layer_parameters_hash
        .array_chunks_mut::<8>()
        .zip(leaf_layer_parameters_commitment.iter())
    {
        let le_bytes = src.to_reduced_u64().to_le_bytes();
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    flattened_public_input.extend(recursion_node_verification_key_hash);
    flattened_public_input.extend(leaf_layer_parameters_hash);

    let input_keccak_hash = to_fixed_bytes(Keccak256::digest(&flattened_public_input).as_slice());
    let mut public_inputs = vec![];
    use boojum::field::PrimeField;
    use zkevm_circuits::scheduler::NUM_SCHEDULER_PUBLIC_INPUTS;
    let take_by = GoldilocksField::CAPACITY_BITS / 8;

    for chunk in input_keccak_hash
        .chunks_exact(take_by)
        .take(NUM_SCHEDULER_PUBLIC_INPUTS)
    {
        let mut buffer = [0u8; 8];
        buffer[1..].copy_from_slice(chunk);
        let as_field_element = GoldilocksField::from_u64_unchecked(u64::from_be_bytes(buffer));
        public_inputs.push(as_field_element);
    }
    
    let proof_response = fetch_proof_from_storage(batch_number, network.to_string()).await;

    if let Err(_err) = proof_response {
        println!("{}", _err);
        return
    }
    let proof_path = proof_response.unwrap();
    
    let valid_public_inputs = verify_scheduler_proof(&proof_path);
    if valid_public_inputs.is_err() {
        println!("Proof is {}", "INVALID".red());
    }
    let valid_public_inputs = valid_public_inputs.unwrap();

    println!("Comparing public input for new proof");
    println!("Recomputed public input is {}", format!("{:?}", public_inputs).blue());
    println!("Proof's public input is {}", format!("{:?}", valid_public_inputs).green());

    if public_inputs == valid_public_inputs {
        println!("Proof is {}", "VALID".green());
    } else {
        println!("Proof is {}", "INVALID".red());
    }
}

#[cfg(test)]

mod test {
    use circuit_definitions::{
        circuit_definitions::{
            base_layer::ZkSyncBaseLayerStorage,
            recursion_layer::node_layer::ConcreteNodeLayerCircuitBuilder,
            verifier_builder::StorageApplicationVerifierBuilder,
        },
        ZkSyncDefaultRoundFunction,
    };

    use super::*;
    #[test]
    fn test_scheduler_proof() {
        verify_scheduler_proof("scheduler_proof/proof_52272951.bin").expect("FAILED");
    }
    #[test]

    fn test_basic_proof() {
        // '10' is the id of the 'Storage Application' circuit (which is the one for which we have the basic_proof.bin)
        let key_10: ZkSyncBaseLayerStorage<VerificationKey<GoldilocksField, BaseProofsTreeHasher>> =
            serde_json::from_slice(include_bytes!("keys/verification_basic_10_key.json")).unwrap();

        let proof: ZkSyncBaseLayerProof = proof_from_file("example_proofs/basic_proof.bin");

        println!("Proof type: {}", proof.short_description().bold());

        let verifier_builder = StorageApplicationVerifierBuilder::<
            GoldilocksField,
            ZkSyncDefaultRoundFunction,
        >::dyn_verifier_builder::<GoldilocksExt2>();
        let verifier = verifier_builder.create_verifier();

        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &key_10.into_inner(),
            &proof.into_inner(),
        );

        assert!(result, "Proof failed");
    }
    #[test]

    fn test_leaf_proof() {
        // '13' is the id of the Leaf for Events sorter.
        let leaf_13: ZkSyncRecursionLayerStorage<
            VerificationKey<GoldilocksField, BaseProofsTreeHasher>,
        > = serde_json::from_slice(include_bytes!("keys/verification_leaf_13_key.json")).unwrap();

        let proof: ZkSyncRecursionLayerProof = proof_from_file("example_proofs/leaf_proof.bin");
        println!("Proof type: {}", proof.short_description().bold());

        let verifier_builder =
            ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<GoldilocksExt2>();

        let verifier = verifier_builder.create_verifier();
        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &leaf_13.into_inner(),
            &proof.into_inner(),
        );

        assert!(result, "Proof failed");
    }
    #[test]

    fn test_node_proof() {
        let node: ZkSyncRecursionLayerStorage<
            VerificationKey<GoldilocksField, BaseProofsTreeHasher>,
        > = serde_json::from_slice(include_bytes!("keys/verification_node_key.json")).unwrap();

        let proof: ZkSyncRecursionLayerProof = proof_from_file("example_proofs/node_proof.bin");
        println!("Proof type: {}", proof.short_description().bold());
        let verifier_builder =
            ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<GoldilocksExt2>();

        let verifier = verifier_builder.create_verifier();
        let result = verifier.verify::<BaseProofsTreeHasher, GoldilocksPoisedon2Transcript, NoPow>(
            (),
            &node.into_inner(),
            &proof.into_inner(),
        );
        assert!(result, "Proof failed");
    }
}
