#![feature(array_chunks)]
#![feature(slice_flatten)]

use circuit_definitions::circuit_definitions::recursion_layer::scheduler::ConcreteSchedulerCircuitBuilder;
use circuit_definitions::franklin_crypto::bellman::pairing::bn256::Fr;
use circuit_definitions::franklin_crypto::bellman::{Field, PrimeField};

use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::Deserialize;
use std::env;
use std::io::{self, Read};
use std::{fs::File, process};

mod crypto;
mod inputs;
mod params;
mod requests;
mod snark_wrapper_verifier;

use crate::inputs::{compute_public_inputs, generate_inputs};
use crate::requests::L1BatchAndProofData;
use crate::snark_wrapper_verifier::{
    generate_solidity_test, verify_snark, verify_snark_from_l1, L1BatchProofForL1,
};
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

const VERIFICATION_KEY_FILE_GITHUB: &str = "https://raw.githubusercontent.com/matter-labs/era-contracts/main/tools/data/scheduler_key.json";

#[derive(serde::Serialize, serde::Deserialize, Debug)]
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
    // Bool to request updating verification key
    #[arg(long)]
    update_verification_key: Option<bool>,

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

    if network != "mainnet" && network != "sepolia" {
        println!(
            "Please use network name `{}` or `{}`",
            "mainnet".yellow(),
            "testnet".yellow()
        );
        return;
    }

    let file_path = "src/keys/scheduler_key.json";
    let file = env::current_dir().unwrap().join(file_path);
    println!("{:?}", file);
    let file_exists = file.exists();

    let should_update =
        opt.update_verification_key.is_some() && opt.update_verification_key.unwrap();

    if file_exists && !should_update {
        println!("verifiction key exists")
    } else {
        println!("verifiction key does not exist or update requested, downloading...");
        let resp = reqwest::get(VERIFICATION_KEY_FILE_GITHUB).await.expect("request failed");
        let body = resp.text().await.expect("body invalid");
        let mut out = File::create(file_path).expect("failed to create file");
        io::copy(&mut body.as_bytes(), &mut out).expect("failed to copy content");
    }

    println!("{}", "Fetching and validating the proof itself".on_blue());
    if l1_rpc.is_none() {
        println!(
            "{}",
            "Skipping building batch information from Ethereum as no RPC url was provided."
                .yellow()
        );
    } else {
        // Then we verify the public inputs (that contain the circuit code, prev and next root hash etc)
        // To make sure that the proof is matching a correct computation.

        let L1BatchAndProofData {
            aux_output,
            scheduler_proof,
            batch_l1_data,
            verifier_params,
        } = requests::fetch_l1_data(batch_number, &network, &l1_rpc.clone().unwrap()).await;

        let snark_vk_scheduler_key_file = "keys/scheduler_key.json";

        let mut batch_proof = L1BatchProofForL1 {
            aggregation_result_coords: aux_output.prepare_aggregation_result_coords(),
            scheduler_proof,
        };

        let inputs = generate_inputs(batch_l1_data, verifier_params);

        batch_proof.scheduler_proof.inputs = inputs;

        // First, we verify that the proof itself is valid.
        let (public_input, _) =
            verify_snark_from_l1(snark_vk_scheduler_key_file.to_string(), batch_proof)
                .await
                .unwrap();

        println!("\n");

        let public_inputs = compute_public_inputs(network, batch_number, l1_rpc)
            .await
            .unwrap();

        let mut recomputed_input = Fr::zero();
        // Right now we go in reverse order, but it might be changed soon.
        for i in 0..4 {
            // 56 - as we only push 7 bytes.
            for _ in 0..56 {
                recomputed_input.double();
            }
            recomputed_input.add_assign(&Fr::from_str(&format!("{}", public_inputs[i].0)).unwrap());
        }

        println!(
            "{} ",
            "Comparing public input from Ethereum with input for boojum".on_blue()
        );
        println!(
            "Recomputed public input from current prover using L1 data is {}",
            format!("{:?}", recomputed_input).bright_blue()
        );
        println!(
            "Boojum proof's public input is {}",
            format!("{:?}", public_input).green()
        );

        if recomputed_input == public_input {
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
    use crate::inputs::create_input_internal;
    use crate::params::{to_goldilocks, CIRCUIT_V5};
    use crate::proof_from_file;
    use crate::requests::BatchL1Data;
    use circuit_definitions::franklin_crypto::bellman::pairing::bn256::Fr;
    use circuit_definitions::franklin_crypto::bellman::{Field, PrimeField};
    use zksync_types::H256;

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
            prev_batch_commitment: H256::default(),
            curr_batch_commitment: H256::default(),
        };

        println!("proof input: {:?}", public_input);

        let result = create_input_internal(
            l1_data,
            aux_witness,
            leaf_layer_parameters_commitment,
            node_layer_vk_commitment,
            None,
            None,
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

    // this is the proof with fixed public input computation - that includes the full previous block commitment.
    #[tokio::test]
    async fn test_local_proof_v2() {
        let (public_input, aux_witness) = verify_snark(&VerifySnarkWrapperArgs {
            l1_batch_proof_file: "example_proofs/snark_wrapper/v2/l1_batch_proof_1.bin".to_string(),
            snark_vk_scheduler_key_file:
                "example_proofs/snark_wrapper/v2/snark_verification_scheduler_key.json".to_string(),
        })
        .await
        .unwrap();

        // select bootloader_code_hash from protocol_versions
        let bootloader_code =
            hex::decode("010009416e909e0819593a9806bbc841d25c5cdfed3f4a1523497c6814e5194a")
                .unwrap();
        let mut bootloader_code_array = [0u8; 32];
        bootloader_code_array.copy_from_slice(&bootloader_code);

        // select default_account_code_hash from protocol_versions
        let default_aa_code =
            hex::decode("0100065d134a862a777e50059f5e0fbe68b583f3617a67820f7edda0d7f253a0")
                .unwrap();
        let mut default_aa_array = [0u8; 32];
        default_aa_array.copy_from_slice(&default_aa_code);

        // select rollout_last_leaf_incex form l1_batches;
        let prev_enum_counter = 23;
        // select merkle root hash
        let prev_root =
            hex::decode("16914ac26bb9cafa0f1dfaeaab10745a9094e1b60c7076fedf21651d6a25b574")
                .unwrap();

        let enum_counter = 84;
        let root = hex::decode("9cf7bb72401a56039ca097cabed20a72221c944ed9b0e515c083c04663ab45a6")
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
            prev_batch_commitment: H256::default(),
            curr_batch_commitment: H256::default(),
        };

        let previous_meta_hash =
            hex::decode("224e9e504599641655d4041e3776f362d10ea59965bfd2c78c05d8dc5b16ef8e")
                .unwrap();
        let previous_aux_hash =
            hex::decode("7c613c82ec911cf56dd6241854dd87bd538e0201f4ff0735f56a1a013db6466a")
                .unwrap();

        println!("proof input: {:?}", public_input);

        let result = create_input_internal(
            l1_data,
            aux_witness,
            leaf_layer_parameters_commitment,
            node_layer_vk_commitment,
            Some(previous_meta_hash.try_into().unwrap()),
            Some(previous_aux_hash.try_into().unwrap()),
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

    #[tokio::test]
    async fn test_local_proof_v3() {
        let (public_input, aux_witness) = verify_snark(&VerifySnarkWrapperArgs {
            l1_batch_proof_file: "example_proofs/snark_wrapper/v3/l1_batch_proof_1.bin".to_string(),
            snark_vk_scheduler_key_file:
                "example_proofs/snark_wrapper/v3/snark_verification_scheduler_key.json".to_string(),
        })
        .await
        .unwrap();

        // select bootloader_code_hash from protocol_versions
        let bootloader_code =
            hex::decode("010009416e909e0819593a9806bbc841d25c5cdfed3f4a1523497c6814e5194a")
                .unwrap();
        let mut bootloader_code_array = [0u8; 32];
        bootloader_code_array.copy_from_slice(&bootloader_code);

        // select default_account_code_hash from protocol_versions
        let default_aa_code =
            hex::decode("0100065d134a862a777e50059f5e0fbe68b583f3617a67820f7edda0d7f253a0")
                .unwrap();
        let mut default_aa_array = [0u8; 32];
        default_aa_array.copy_from_slice(&default_aa_code);

        // select rollout_last_leaf_incex form l1_batches;
        let prev_enum_counter = 23;
        // select merkle root hash
        let prev_root =
            hex::decode("16914ac26bb9cafa0f1dfaeaab10745a9094e1b60c7076fedf21651d6a25b574")
                .unwrap();

        let enum_counter = 84;
        let root = hex::decode("9cf7bb72401a56039ca097cabed20a72221c944ed9b0e515c083c04663ab45a6")
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
            prev_batch_commitment: H256::default(),
            curr_batch_commitment: H256::default(),
        };

        let previous_meta_hash =
            hex::decode("224e9e504599641655d4041e3776f362d10ea59965bfd2c78c05d8dc5b16ef8e")
                .unwrap();
        let previous_aux_hash =
            hex::decode("7c613c82ec911cf56dd6241854dd87bd538e0201f4ff0735f56a1a013db6466a")
                .unwrap();

        println!("proof input: {:?}", public_input);

        let result = create_input_internal(
            l1_data,
            aux_witness,
            leaf_layer_parameters_commitment,
            node_layer_vk_commitment,
            Some(previous_meta_hash.try_into().unwrap()),
            Some(previous_aux_hash.try_into().unwrap()),
        )
        .await;
        println!("computed proof input: {:?}", result);

        let r = result.unwrap();
        let mut recomputed_input = Fr::zero();
        // Right now we go in reverse order, but it might be changed soon.
        for i in 0..4 {
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
