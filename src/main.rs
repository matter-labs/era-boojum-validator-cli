#![feature(generic_const_exprs)]
#![feature(array_chunks)]

use circuit_definitions::circuit_definitions::recursion_layer::scheduler::ConcreteSchedulerCircuitBuilder;
use clap::Parser;
use colored::Colorize;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
mod params;
mod requests;

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

#[tokio::main]
async fn main() {
    let opt = Cli::parse();

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

    let valid_public_inputs = verify_scheduler_proof(&proof_path);
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
        let params = if network == "mainnet" {
            self::params::get_mainnet_params_holder().get_for_index(batch_number as usize)
        } else if network == "testnet" {
            self::params::get_testnet_params_holder().get_for_index(batch_number as usize)
        } else {
            unreachable!();
        };

        let Some([leaf_layer_parameters_commitment, node_layer_vk_commitment]) = params else {
            println!("Can not get verification keys commitments for batch {}. Either it's too far in the past, or update the CLI", batch_number.to_string().yellow());
            return;
        };

        println!("{}", "Fetching data from Ethereum L1 for state roots, bootloader and default Account Abstraction parameters".on_blue());

        let l1_data = requests::fetch_l1_data(batch_number, &network, &l1_rpc.unwrap()).await;
        if l1_data.is_err() {
            if let Err(_err) = l1_data {
                println!("{}", _err);
                return;
            }
            println!("Failed to get data from L1");
            return;
        }

        let l1_data = l1_data.unwrap();

        println!("{}", "Fetching auxilary block data".on_blue());
        let aux_data = requests::fetch_aux_data_from_storage(batch_number, &network).await;
        if aux_data.is_err() {
            println!("Failed to get auxiliary data");
            return;
        }
        println!("\n");

        let aux_data = aux_data.unwrap();

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

        let input_keccak_hash =
            to_fixed_bytes(Keccak256::digest(&flattened_public_input).as_slice());
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
        verify_scheduler_proof("example_proofs/proof_52272951.bin").expect("FAILED");
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
