use std::fs;

use crate::outputs::StatusCode;
use crate::requests::AuxOutputWitnessWrapper;
use crate::{proof_from_file, GenerateSolidityTestArgs, VerifySnarkWrapperArgs};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuitNoLookupCustomGate;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use circuit_definitions::{
    circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit,
    snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript,
};
use colored::Colorize;
use crypto::calculate_fflonk_verification_key_hash;
use crypto::{calculate_verification_key_hash, types::ProofType};
use fflonk::FflonkVerificationKey;
use primitive_types::H256;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BatchProofForL1 {
    pub aggregation_result_coords: [[u8; 32]; 4],
    pub scheduler_proof: ProofType,
}

/// Pulls a SNARK proof from storage and verifies is with the supplied verification key.
pub async fn verify_snark_from_storage(
    args: &VerifySnarkWrapperArgs,
) -> Result<(Fr, AuxOutputWitnessWrapper, H256), StatusCode> {
    let proof: L1BatchProofForL1 = proof_from_file(&args.l1_batch_proof_file);

    verify_snark(
        args.snark_vk_scheduler_key_file.clone(),
        None,
        proof,
        None,
        None,
    )
    .await
}

pub async fn generate_solidity_test(args: &GenerateSolidityTestArgs) -> Result<(), StatusCode> {
    let proof: L1BatchProofForL1 = proof_from_file(&args.l1_batch_proof_file);

    let (inputs, serialized_proof) = match proof.scheduler_proof {
        ProofType::Fflonk(_) => panic!("Unsupported proof type"),
        ProofType::Plonk(proof) => codegen::serialize_proof(&proof),
    };

    println!("const PROOF = {{");
    println!("    publicInputs: ['0x{:x}'],", inputs[0]);
    println!("    serializedProof: [");
    for p in serialized_proof {
        println!("        '0x{:x}',", p);
    }

    println!("],");

    println!("recursiveAggregationInput: [] \n }};");
    Ok(())
}

/// Verifies a SNARK proof with a given verification key, checking the verification key hash if a value is supplied.
/// Returns a result where the Ok value is the public input, aux witness, and computed vk hash. The error value is
/// the status code for the failure.
pub async fn verify_snark(
    snark_vk_scheduler_key_file: String,
    fflonk_verification_key_file: Option<String>,
    proof: L1BatchProofForL1,
    plonk_vk_hash_from_l1: Option<H256>,
    fflonk_vk_hash_from_l1: Option<H256>,
) -> Result<(Fr, AuxOutputWitnessWrapper, H256), StatusCode> {
    println!("Verifying SNARK wrapped FRI proof.");

    println!("=== Aux inputs:");
    println!(
        "  L1 msg linear hash:                  0x{:}",
        hex::encode(proof.aggregation_result_coords[0])
    );
    println!(
        "  Rollup state diff for compression:   0x{:}",
        hex::encode(proof.aggregation_result_coords[1])
    );
    println!(
        "  Bootloader heap initial content:     0x{:}",
        hex::encode(proof.aggregation_result_coords[2])
    );
    println!(
        "  Events queue state:                  0x{:}",
        hex::encode(proof.aggregation_result_coords[3])
    );

    let computed_hash: Result<H256, StatusCode>;

    match proof.scheduler_proof {
        ProofType::Fflonk(mut fflonk_proof) => {
            let verification_key =
                &fs::read_to_string(fflonk_verification_key_file.clone().unwrap());

            if verification_key.is_err() {
                println!(
                    "Unable to load verification key from: {}",
                    fflonk_verification_key_file.clone().unwrap()
                );
                return Err(StatusCode::FailedToLoadVerificationKey);
            }

            use fflonk::verifier::verify;
            let vk_inner: FflonkVerificationKey<
                Bn256,
                ZkSyncSnarkWrapperCircuitNoLookupCustomGate,
            > = serde_json::from_str(&verification_key.as_ref().unwrap()).unwrap();

            fflonk_proof.n = vk_inner.n;
            computed_hash = check_fflonk_verification_key(vk_inner.clone(), fflonk_vk_hash_from_l1);

            println!("Verifying the proof");
            let is_valid =
                verify::<_, _, RollingKeccakTranscript<Fr>>(&vk_inner, &fflonk_proof, None)
                    .unwrap();

            if !is_valid {
                println!("Proof is {}", "INVALID".red());
                return Err(StatusCode::ProofVerificationFailed);
            } else {
                println!("Proof is {}", "VALID".green());
            };

            // We expect only 1 private input.
            assert!(
                fflonk_proof.inputs.len() == 1,
                "Expected exactly 1 public input in the proof"
            );

            let public_input = fflonk_proof.inputs[0];

            println!("Public input is: {}", public_input);
            let aux_witness = AuxOutputWitnessWrapper {
                0 : circuit_definitions::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness{
                    l1_messages_linear_hash: proof.aggregation_result_coords[0],
                    rollup_state_diff_for_compression: proof.aggregation_result_coords[1], bootloader_heap_initial_content: proof.aggregation_result_coords[2], events_queue_state: proof.aggregation_result_coords[3],
                    eip4844_linear_hashes: [[0u8; 32]; 16],
                    eip4844_output_commitment_hashes: [[0u8; 32]; 16],
                },
            };

            Ok((public_input, aux_witness, computed_hash.unwrap()))
        }
        ProofType::Plonk(mut plonk_proof) => {
            println!("=== Loading verification key.");
            let verification_key = &fs::read_to_string(snark_vk_scheduler_key_file.clone());

            if verification_key.is_err() {
                println!(
                    "Unable to load verification key from: {}",
                    snark_vk_scheduler_key_file.clone()
                );
                return Err(StatusCode::FailedToLoadVerificationKey);
            }

            use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
            let vk_inner: VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit> =
                serde_json::from_str(&verification_key.as_ref().unwrap()).unwrap();

            plonk_proof.n = vk_inner.n;
            computed_hash = check_verification_key(vk_inner.clone(), plonk_vk_hash_from_l1);

            if computed_hash.is_err() {
                return Err(computed_hash.err().unwrap());
            }

            println!("Verifying the proof");
            let is_valid =
                verify::<_, _, RollingKeccakTranscript<Fr>>(&vk_inner, &plonk_proof, None).unwrap();

            if !is_valid {
                println!("Proof is {}", "INVALID".red());
                return Err(StatusCode::ProofVerificationFailed);
            } else {
                println!("Proof is {}", "VALID".green());
            };

            // We expect only 1 private input.
            assert!(
                plonk_proof.inputs.len() == 1,
                "Expected exactly 1 public input in the proof"
            );

            let public_input = plonk_proof.inputs[0];

            println!("Public input is: {}", public_input);
            let aux_witness = AuxOutputWitnessWrapper {
                0 : circuit_definitions::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness{
                    l1_messages_linear_hash: proof.aggregation_result_coords[0],
                    rollup_state_diff_for_compression: proof.aggregation_result_coords[1], bootloader_heap_initial_content: proof.aggregation_result_coords[2], events_queue_state: proof.aggregation_result_coords[3],
                    eip4844_linear_hashes: [[0u8; 32]; 16],
                    eip4844_output_commitment_hashes: [[0u8; 32]; 16],
                },
            };

            Ok((public_input, aux_witness, computed_hash.unwrap()))
        }
    }
}

/// Check that the hash of the verificattion key provided is equal to the supplied hash.
fn check_verification_key(
    verification_key: VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit>,
    vk_hash_from_l1: Option<H256>,
) -> Result<H256, StatusCode> {
    if vk_hash_from_l1.is_none() {
        println!("Supplied vk hash is None, skipping check...");
        return Ok(H256::default());
    }

    let computed_vk_hash = calculate_verification_key_hash(verification_key);

    println!("=== Verification Key Hash Check:");
    println!(
        "  Verification Key Hash from L1:       0x{:}",
        hex::encode(vk_hash_from_l1.unwrap())
    );
    println!(
        "  Computed Verification Key Hash:      0x{:}",
        hex::encode(computed_vk_hash)
    );

    assert_eq!(
        computed_vk_hash,
        vk_hash_from_l1.unwrap(),
        "Make sure the verification key is updated."
    );

    if computed_vk_hash != vk_hash_from_l1.unwrap() {
        return Err(StatusCode::VerificationKeyHashMismatch);
    }

    return Ok(computed_vk_hash);
}

/// Check that the hash of the verificattion key provided is equal to the supplied hash.
fn check_fflonk_verification_key(
    verification_key: FflonkVerificationKey<Bn256, ZkSyncSnarkWrapperCircuitNoLookupCustomGate>,
    vk_hash_from_l1: Option<H256>,
) -> Result<H256, StatusCode> {
    if vk_hash_from_l1.is_none() {
        println!("Supplied vk hash is None, skipping check...");
        return Ok(H256::default());
    }

    let computed_vk_hash = calculate_fflonk_verification_key_hash(verification_key);

    println!("=== Verification Key Hash Check:");
    println!(
        "  Verification Key Hash from L1:       0x{:}",
        hex::encode(vk_hash_from_l1.unwrap())
    );
    println!(
        "  Computed Verification Key Hash:      0x{:}",
        hex::encode(computed_vk_hash)
    );

    assert_eq!(
        computed_vk_hash,
        vk_hash_from_l1.unwrap(),
        "Make sure the verification key is updated."
    );

    if computed_vk_hash != vk_hash_from_l1.unwrap() {
        return Err(StatusCode::VerificationKeyHashMismatch);
    }

    return Ok(computed_vk_hash);
}
