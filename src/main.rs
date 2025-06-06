#![feature(array_chunks)]

use boojum_os::verify_snark_boojum_os;
use circuit_definitions::circuit_definitions::recursion_layer::scheduler::ConcreteSchedulerCircuitBuilder;

use clap::{Parser, Subcommand};
use colored::Colorize;
use contract::{FFLONK_VERIFICATION_TYPE, PLONK_VERIFICATION_TYPE};
use crypto::types::ProofType;
use gag::Gag;
use serde::Deserialize;
use std::io::Read;
use std::{fs::File, process};

mod batch;
mod boojum_os;
mod contract;
mod inputs;
mod outputs;
mod requests;
mod snark_wrapper_verifier;
mod utils;

use crate::contract::ContractConfig;
use crate::inputs::generate_inputs;
use crate::outputs::{
    construct_vk_output, print_json, BoojumCliJsonOutput, DataJsonOutput, StatusCode,
};
use crate::requests::L1BatchAndProofData;
use crate::snark_wrapper_verifier::{
    generate_solidity_test, verify_snark, verify_snark_from_storage, L1BatchProofForL1,
};
use crate::utils::ensure_key_file_exists;
use crate::utils::{check_verification_key, get_scheduler_key_override};
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
    /// RPC endpoint to use to fetch L1 information
    l1_rpc: Option<String>,
    /// Flag to print output as json
    #[arg(long)]
    json: bool,
    #[arg(long)]
    scheduler_key: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify the proof of the Snark wrapper (which is a wrapped FRI proof).
    VerifySnarkWrapper(VerifySnarkWrapperArgs),
    GenerateSolidityTest(GenerateSolidityTestArgs),
    VerifySnarkBoojumOs(VerifySnarkWrapperArgs),
}

#[derive(Parser, Debug)]
pub struct VerifySnarkWrapperArgs {
    /// Path to the proof file (like l1_batch_proof_17.bin)
    l1_batch_proof_file: String,
    /// Snark verification scheduler key (like snark_verification_scheduler_key.json)
    snark_vk_scheduler_key_file: String,
    fflonk_vk_scheduler_key_file: Option<String>,
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

    let (proof, _) =
        bincode::serde::decode_from_slice(&buffer.as_slice(), bincode::config::legacy()).unwrap();
    proof
}

pub fn proof_from_json_file<T: for<'a> Deserialize<'a>>(proof_path: &str) -> T {
    let mut file = File::open(proof_path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let proof = serde_json::from_slice::<T>(&buffer).unwrap();
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
            Commands::VerifySnarkWrapper(args) => verify_snark_from_storage(&args).await.err(),
            Commands::GenerateSolidityTest(args) => generate_solidity_test(&args).await.err(),
            Commands::VerifySnarkBoojumOs(args) => verify_snark_boojum_os(&args).await.err(),
        };
        if let Some(error) = result {
            println!("Command failed: {:?}", error);
            process::exit(1);
        }
        return;
    }

    let batch_number = opt.batch;
    let network = opt.network.clone().to_string();
    let l1_rpc = opt.l1_rpc;
    let scheduler_key_override = opt.scheduler_key;

    // Gag allows us to stop all normal std out, this is the simplest way to keep the code the same
    // while supporting only printing the desired json
    let gag = if opt.json {
        Some(Gag::stdout().unwrap())
    } else {
        None
    };

    if network != "mainnet" && network != "sepolia" && network != "stage-proofs" {
        println!(
            "Please use network name `{}` or `{}`",
            "mainnet".yellow(),
            "sepolia".yellow()
        );

        if gag.is_some() {
            drop(gag.unwrap());
            print_json(StatusCode::InvalidNetwork, batch_number);
            return;
        }
    }

    let protocol_version = requests::fetch_batch_protocol_version(batch_number, &network)
        .await
        .unwrap();

    let previous_batch_protocol_version =
        requests::fetch_batch_protocol_version(batch_number - 1, &network)
            .await
            .unwrap();

    println!("{}", "Fetching and validating the proof itself".on_blue());
    if l1_rpc.is_none() {
        println!(
            "{}",
            "Skipping building batch information from Ethereum as no RPC url was provided."
                .yellow()
        );

        if gag.is_some() {
            drop(gag.unwrap());
            print_json(StatusCode::InvalidNetwork, batch_number);
            return;
        }
    } else {
        match scheduler_key_override.clone() {
            None => check_verification_key(protocol_version.clone()).await,
            Some(scheduler_key_str) => {
                ensure_key_file_exists(
                    &scheduler_key_str,
                    &format!("Scheduler key at `{}` does not exist", scheduler_key_str),
                )
                .await;
            }
        }

        let protocol_version_id = protocol_version.parse::<u16>().unwrap();
        let previous_protocol_version_id = previous_batch_protocol_version.parse::<u16>().unwrap();

        let contract = ContractConfig::new(l1_rpc.clone().unwrap(), network.clone());

        let resp = requests::fetch_l1_data(
            batch_number,
            protocol_version_id,
            previous_protocol_version_id,
            &network,
            &l1_rpc.clone().unwrap(),
        )
        .await;

        let output = if let Ok(L1BatchAndProofData {
            aux_output,
            scheduler_proof,
            batch_l1_data,
            verifier_params,
            block_number,
        }) = resp.clone()
        {
            let (plonk_vk, flonk_vk) = if protocol_version_id < 27 {
                let plonk_vk_hash = contract
                    .get_verification_key_hash(
                        block_number,
                        protocol_version_id,
                        Some(PLONK_VERIFICATION_TYPE),
                    )
                    .await;
                (plonk_vk_hash, None)
            } else {
                let plonk_vk_hash = contract
                    .get_verification_key_hash(
                        block_number,
                        protocol_version_id,
                        Some(PLONK_VERIFICATION_TYPE),
                    )
                    .await;
                let fflonk_vk_hash = contract
                    .get_verification_key_hash(
                        block_number,
                        protocol_version_id,
                        Some(FFLONK_VERIFICATION_TYPE),
                    )
                    .await;
                (plonk_vk_hash, Some(fflonk_vk_hash))
            };

            let snark_vk_scheduler_key_file = match (
                scheduler_key_override,
                get_scheduler_key_override(&network, &protocol_version, batch_number),
            ) {
                (None, None) => format!(
                    "src/keys/protocol_version/{}/scheduler_key.json",
                    protocol_version.clone()
                ),
                (None, Some(scheduler_key)) => scheduler_key,
                (Some(scheduler_key_str), _) => scheduler_key_str,
            };

            let mut batch_proof = L1BatchProofForL1 {
                aggregation_result_coords: aux_output.prepare_aggregation_result_coords(),
                scheduler_proof,
            };

            let fflonk_scheduler_key = if protocol_version_id >= 27 {
                Some(format!(
                    "src/keys/protocol_version/{}/fflonk_scheduler_key.json",
                    protocol_version.clone()
                ))
            } else {
                None
            };

            let inputs = generate_inputs(batch_l1_data, verifier_params, Some(protocol_version_id));

            match batch_proof.scheduler_proof {
                ProofType::Fflonk(ref mut proof) => {
                    proof.inputs = inputs;
                }
                ProofType::Plonk(ref mut proof) => {
                    proof.inputs = inputs;
                }
            }
            // First, we verify that the proof itself is valid.
            let verify_resp = verify_snark(
                snark_vk_scheduler_key_file.to_string(),
                fflonk_scheduler_key,
                batch_proof,
                Some(plonk_vk),
                flonk_vk,
            )
            .await;

            let mut data = None;
            let mut status_code = StatusCode::Success;

            if let Ok((input, _, computed_vk_hash)) = verify_resp {
                let mut inner_data = DataJsonOutput::from(resp.unwrap());
                inner_data.verification_key_hash = construct_vk_output(
                    plonk_vk.to_fixed_bytes(),
                    computed_vk_hash.to_fixed_bytes(),
                );

                inner_data.public_input = input;
                inner_data.is_proof_valid = true;

                data = Some(inner_data);
            } else {
                status_code = resp.err().unwrap();
                println!(
                    "Failed to verify proof due to error code: {:?}",
                    status_code
                );
            }

            BoojumCliJsonOutput {
                status_code,
                batch_number,
                data,
            }
        } else {
            let status_code = resp.err().unwrap();
            println!(
                "Failed to verify proof due to error code: {:?}",
                status_code
            );
            BoojumCliJsonOutput {
                status_code: status_code.clone(),
                batch_number,
                data: None,
            }
        };

        if let Some(gag) = gag {
            drop(gag);
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    };
}

#[cfg(test)]

mod test {
    use crate::proof_from_file;
    use crate::requests::BatchL1Data;
    use zksync_types::H256;

    use super::*;
    use block_header::VerifierParams;
    use circuit_definitions::{
        circuit_definitions::{
            base_layer::ZkSyncBaseLayerStorage,
            recursion_layer::node_layer::ConcreteNodeLayerCircuitBuilder,
            verifier_builder::StorageApplicationVerifierBuilder,
        },
        ZkSyncDefaultRoundFunction,
    };
    use colored::Colorize;
    use std::str::FromStr;

    #[test]
    fn test_scheduler_proof() {
        verify_scheduler_proof("example_proofs/proof_52272951.bin", 52272951).expect("FAILED");
    }

    #[tokio::test]
    async fn test_local_proof_v3() {
        let (public_input, _, _) = verify_snark_from_storage(&VerifySnarkWrapperArgs {
            l1_batch_proof_file: "example_proofs/snark_wrapper/v3/l1_batch_proof_1.bin".to_string(),
            snark_vk_scheduler_key_file:
                "example_proofs/snark_wrapper/v3/snark_verification_scheduler_key.json".to_string(),
            fflonk_vk_scheduler_key_file: None,
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

        let verifier_params = VerifierParams {
            recursion_node_level_vk_hash: H256::from_str(
                "5a3ef282b21e12fe1f4438e5bb158fc5060b160559c5158c6389d62d9fe3d080",
            )
            .unwrap()
            .to_fixed_bytes(),
            recursion_leaf_level_vk_hash: H256::from_str(
                "14628525c227822148e718ca1138acfc6d25e759e19452455d89f7f610c3dcb8",
            )
            .unwrap()
            .to_fixed_bytes(),
            recursion_circuits_set_vk_hash: [0u8; 32],
        };

        let result = generate_inputs(l1_data, verifier_params, None);

        println!("Computed proof input: {:?}", result[0]);

        assert_eq!(result[0], public_input, "Public input doesn't match");
    }

    #[test]
    fn test_basic_proof() {
        // '10' is the id of the 'Storage Application' circuit (which is the one for which we have the basic_proof.bin)
        let key_10: ZkSyncBaseLayerStorage<VerificationKey<GoldilocksField, BaseProofsTreeHasher>> =
            serde_json::from_slice(include_bytes!("keys/verification_basic_10_key.json")).unwrap();

        let proof: ZkSyncBaseLayerProof = proof_from_file("example_proofs/basic_proof.bin");

        println!("Proof type: {}", proof.short_description().bold());

        let verifier_builder =
            StorageApplicationVerifierBuilder::dyn_verifier_builder::<GoldilocksExt2>();
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
