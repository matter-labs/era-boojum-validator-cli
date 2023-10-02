#![feature(array_chunks)]

use circuit_definitions::circuit_definitions::recursion_layer::scheduler::ConcreteSchedulerCircuitBuilder;

use clap::{Parser, Subcommand};
use colored::Colorize;
use requests::{AuxOutputWitnessWrapper, BatchL1Data};
use serde::Deserialize;
use std::io::Read;
use std::{fs::File, process};
mod params;
mod requests;
mod snark_wrapper_verifier;

use crate::snark_wrapper_verifier::{generate_solidity_test, verify_snark};
pub mod block_header;

use circuit_definitions::boojum::{
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
    #[arg(long, default_value = "106971")]
    /// Batch number to check proof for
    batch: u64,
    #[arg(long, default_value = "mainnet")]
    /// Batch number to check proof for
    network: String,
    #[arg(long)]
    // RPC endpoint to use to fetch L1 information
    l1_rpc: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify the proof of the Snark wrapper (which is a wrapped FRI proof).
    VerifySnarkWrapper(VerifySnarkWrapperArgs),
    GenerateSolidityTest(GenerateSolidityTestArgs),
}

#[derive(Parser, Debug)]
pub struct VerifySnarkWrapperArgs {
    /// Path to the proof file (like l1_batch_proof_17.bin)
    l1_batch_proof_file: String,
    /// Snark verification scheduler key (like snark_verification_scheduler_key.json)
    snark_vk_scheduler_key_file: String,
}

#[derive(Parser, Debug)]
pub struct GenerateSolidityTestArgs {
    /// Path to the proof file (like l1_batch_proof_17.bin)
    l1_batch_proof_file: String,
}

/// Reads proof (in FriProofWrapper format) from a given bin file.
pub fn proof_from_file<T: for<'a> Deserialize<'a>>(proof_path: &str) -> T {
    let mut file = File::open(proof_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let proof: T = bincode::deserialize(buffer.as_slice()).unwrap();
    proof
}
fn get_scheduler_key_for_batch(batch_number: u64) -> &'static [u8] {
    match batch_number {
        1..=174710 => include_bytes!("keys/verification_scheduler_key.json"),
        _ => include_bytes!("keys/verification_scheduler_key_v5.json"),
    }
}

/// Verifies a given proof from "Scheduler" circuit.
pub fn verify_scheduler_proof(
    proof_path: &str,
    batch_number: u64,
) -> anyhow::Result<Vec<GoldilocksField>> {
    let scheduler_key: ZkSyncRecursionLayerStorage<
        VerificationKey<GoldilocksField, BaseProofsTreeHasher>,
    > = serde_json::from_slice(get_scheduler_key_for_batch(batch_number)).unwrap();

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

/// Computes the public inputs for a given batch in a given network.
/// Public inputs require us to fetch multiple data from the l1 (like state hash etc).
pub async fn compute_public_inputs(
    network: String,
    batch_number: u64,
    l1_rpc: Option<String>,
) -> anyhow::Result<Vec<GoldilocksField>> {
    // Loads verification keys.
    // As our circuits change, the verification keys also change - so depending on the batch number, they might have different values.
    let params = if network == "mainnet" {
        self::params::get_mainnet_params_holder().get_for_index(batch_number as usize)
    } else if network == "testnet" {
        self::params::get_testnet_params_holder().get_for_index(batch_number as usize)
    } else {
        unreachable!();
    };

    let Some([leaf_layer_parameters_commitment, node_layer_vk_commitment]) = params else {
        anyhow::bail!(format!("Can not get verification keys commitments for batch {}. Either it's too far in the past, or update the CLI", batch_number.to_string().yellow()));
    };

    println!("{}", "Fetching data from Ethereum L1 for state roots, bootloader and default Account Abstraction parameters".on_blue());

    let l1_data = requests::fetch_l1_data(batch_number, &network, &l1_rpc.unwrap()).await;
    if l1_data.is_err() {
        if let Err(_err) = l1_data {
            anyhow::bail!(format!("Failed to get data from L1: {}", _err));
        }
        anyhow::bail!("Failed to get data from L1");
    }

    let l1_data = l1_data.unwrap();

    println!("{}", "Fetching auxilary block data".on_blue());
    let aux_data = requests::fetch_aux_data_from_storage(batch_number, &network).await;
    if aux_data.is_err() {
        anyhow::bail!("Failed to get auxiliary data");
    }
    println!("\n");

    // After fetching the data, we recreate the public input hash (for which we need information from current and previous block).

    let aux_data = aux_data.unwrap();
    create_input_internal(
        l1_data,
        aux_data,
        leaf_layer_parameters_commitment,
        node_layer_vk_commitment,
    )
    .await
}

pub async fn create_input_internal(
    l1_data: BatchL1Data,
    aux_data: AuxOutputWitnessWrapper,
    leaf_layer_parameters_commitment: [GoldilocksField; 4],
    node_layer_vk_commitment: [GoldilocksField; 4],
) -> anyhow::Result<Vec<GoldilocksField>> {
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
        ],
    };
    let previous_passthrough_data_hash = to_fixed_bytes(
        Keccak256::digest(&previous_passthrough_data.into_flattened_bytes()).as_slice(),
    );

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
        ],
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

    let mut recursion_node_verification_key_hash = [0u8; 32];
    for (dst, src) in recursion_node_verification_key_hash
        .array_chunks_mut::<8>()
        .zip(node_layer_vk_commitment.iter())
    {
        let le_bytes = src.to_reduced_u64().to_le_bytes();
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

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
    use circuit_definitions::boojum::field::PrimeField;
    use circuit_definitions::boojum::field::U64Representable;
    use circuit_definitions::zkevm_circuits::scheduler::NUM_SCHEDULER_PUBLIC_INPUTS;
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
    Ok(public_inputs)
}

#[tokio::main]
async fn main() {
    let opt = Cli::parse();
    if let Some(command) = opt.command {
        // Expert commands
        let result = match command {
            Commands::VerifySnarkWrapper(args) => verify_snark(&args).await.err(),
            Commands::GenerateSolidityTest(args) => generate_solidity_test(&args).await.err(),
        };
        if let Some(error) = result {
            println!("Command failed: {}", error);
            process::exit(1);
        }
        return;
    }

    let batch_number = opt.batch;
    let network = opt.network.clone().to_string();
    let l1_rpc = opt.l1_rpc;

    if network != "mainnet" && network != "testnet" {
        println!(
            "Please use network name `{}` or `{}`",
            "mainnet".yellow(),
            "testnet".yellow()
        );
        return;
    }

    println!("{}", "Fetching and validating the proof itself".on_blue());

    let proof_response = requests::fetch_proof_from_storage(batch_number, &network).await;

    if let Err(_err) = proof_response {
        println!("{}", _err);
        return;
    }
    let proof_path = proof_response.unwrap();

    // First, we verify that the proof itself is valid.
    let valid_public_inputs = verify_scheduler_proof(&proof_path, batch_number);
    if valid_public_inputs.is_err() {
        println!("Proof is {}", "INVALID".red());
        return;
    } else {
        println!("Proof is {}", "VALID".green());
    }
    println!("\n");

    if l1_rpc.is_none() {
        println!(
            "{}",
            "Skipping building batch information from Ethereum as no RPC url was provided."
                .yellow()
        );
    } else {
        // Then we verify the public inputs (that contain the circuit code, prev and next root hash etc)
        // To make sure that the proof is matching a correct computation.

        let public_inputs = compute_public_inputs(network, batch_number, l1_rpc)
            .await
            .unwrap();

        let valid_public_inputs = valid_public_inputs.unwrap();

        println!(
            "{} ",
            "Comparing public input from Ethereum with input for boojum".on_blue()
        );
        println!(
            "Recomputed public input from current prover using L1 data is {}",
            format!("{:?}", public_inputs).bright_blue()
        );
        println!(
            "Boojum proof's public input is {}",
            format!("{:?}", valid_public_inputs).green()
        );

        if public_inputs == valid_public_inputs {
            println!("Boojum's proof is {}", "VALID".green());
        } else {
            println!("Boojum's proof is {}", "INVALID".red());
        }
        return;
    }

    println!("\n");
}

#[cfg(test)]

mod test {
    use crate::params::{to_goldilocks, CIRCUIT_V5};
    use crate::proof_from_file;
    use circuit_definitions::franklin_crypto::bellman::pairing::bn256::Fr;
    use circuit_definitions::franklin_crypto::bellman::{Field, PrimeField};

    use super::*;
    use circuit_definitions::{
        circuit_definitions::{
            base_layer::ZkSyncBaseLayerStorage,
            recursion_layer::node_layer::ConcreteNodeLayerCircuitBuilder,
            verifier_builder::StorageApplicationVerifierBuilder,
        },
        ZkSyncDefaultRoundFunction,
    };
    use colored::Colorize;
    #[test]
    fn test_scheduler_proof() {
        verify_scheduler_proof("example_proofs/proof_52272951.bin", 52272951).expect("FAILED");
    }

    #[tokio::test]
    async fn test_local_proof() {
        let (public_input, aux_witness) = verify_snark(&VerifySnarkWrapperArgs {
            l1_batch_proof_file: "example_proofs/snark_wrapper/l1_batch_proof_1.bin".to_string(),
            snark_vk_scheduler_key_file:
                "example_proofs/snark_wrapper/snark_verification_scheduler_key.json".to_string(),
        })
        .await
        .unwrap();

        let bootloader_code =
            hex::decode("01000923e7c6e9e116c813f5e9b45eda88e3892d9150839bd6004c2df1846d46")
                .unwrap();
        let mut bootloader_code_array = [0u8; 32];
        bootloader_code_array.copy_from_slice(&bootloader_code);

        let default_aa_code =
            hex::decode("0100067d70019d4919b5c8423df00fa89a5c53e734bccc1ad4a92e99df7474ab")
                .unwrap();
        let mut default_aa_array = [0u8; 32];
        default_aa_array.copy_from_slice(&default_aa_code);

        let prev_enum_counter = 23;
        let prev_root =
            hex::decode("38a3e641bf44aca21abf4cdfa2cac66cd1f222149e24105f6bfac98e0fc87503")
                .unwrap();

        let enum_counter = 83;
        let root = hex::decode("0557c172fdfa63645c318a741c7c53b38a8fcf12421d8d4ce311e4e633dbcafb")
            .unwrap();

        let [leaf_layer_parameters_commitment, node_layer_vk_commitment] =
            to_goldilocks(CIRCUIT_V5);
        let l1_data = BatchL1Data {
            previous_enumeration_counter: prev_enum_counter,
            previous_root: prev_root,
            new_enumeration_counter: enum_counter,
            new_root: root,
            default_aa_hash: default_aa_array,
            bootloader_hash: bootloader_code_array,
        };

        println!("proof input: {:?}", public_input);

        let result = create_input_internal(
            l1_data,
            aux_witness,
            leaf_layer_parameters_commitment,
            node_layer_vk_commitment,
        )
        .await;
        println!("computed proof input: {:?}", result);

        let r = result.unwrap();
        let mut recomputed_input = Fr::zero();
        // Right now we go in reverse order, but it might be changed soon.
        for i in (0..4).rev() {
            // 56 - as we only push 7 bytes.
            for _ in 0..56 {
                recomputed_input.double();
            }
            recomputed_input.add_assign(&Fr::from_str(&format!("{}", r[i].0)).unwrap());
        }

        assert_eq!(recomputed_input, public_input, "Public input doesn't match");
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
