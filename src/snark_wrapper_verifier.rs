use std::fs;

use crate::outputs::StatusCode;
use crate::requests::AuxOutputWitnessWrapper;
use crate::{proof_from_file, GenerateSolidityTestArgs, VerifySnarkWrapperArgs};
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use circuit_definitions::{
    circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit,
    snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript,
};
use colored::Colorize;
use crypto::calculate_verification_key_hash;
use primitive_types::H256;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BatchProofForL1 {
    pub aggregation_result_coords: [[u8; 32]; 4],
    pub scheduler_proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit>,
}

/// Pulls a SNARK proof from storage and verifies is with the supplied verification key.
pub async fn verify_snark_from_storage(
    args: &VerifySnarkWrapperArgs,
) -> Result<(Fr, AuxOutputWitnessWrapper, H256), StatusCode> {
    let proof: L1BatchProofForL1 = proof_from_file(&args.l1_batch_proof_file);
    
    verify_snark(
        args.snark_vk_scheduler_key_file.clone(),
        proof,
        None
    ).await
}

pub async fn generate_solidity_test(args: &GenerateSolidityTestArgs) -> Result<(), StatusCode> {
    let proof: L1BatchProofForL1 = proof_from_file(&args.l1_batch_proof_file);

    let (inputs, serialized_proof) = codegen::serialize_proof(&proof.scheduler_proof);

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
    mut proof: L1BatchProofForL1,
    vk_hash_from_l1: Option<H256>,
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

    println!("=== Loading verification key.");
    let verification_key = &fs::read_to_string(snark_vk_scheduler_key_file.clone());

    if verification_key.is_err() {
        println!("Unable to load verification key from: {}", snark_vk_scheduler_key_file.clone());
        return Err(StatusCode::FailedToLoadVerificationKey);
    }

    use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
    let vk_inner : VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit> = serde_json::from_str(
        &verification_key.as_ref().unwrap()
    )
    .unwrap();

    proof.scheduler_proof.n = vk_inner.n;

    let computed_hash = check_verification_key(vk_inner.clone(), vk_hash_from_l1);

    if computed_hash.is_err() {
        return Err(computed_hash.err().unwrap());
    }

    println!("Verifying the proof");
    let is_valid =
        verify::<_, _, RollingKeccakTranscript<Fr>>(&vk_inner, &proof.scheduler_proof, None)
            .unwrap();

    if !is_valid {
        println!("Proof is {}", "INVALID".red());
        return Err(StatusCode::ProofVerificationFailed);
    } else {
        println!("Proof is {}", "VALID".green());
    };

    // We expect only 1 private input.
    assert!(
        proof.scheduler_proof.inputs.len() == 1,
        "Expected exactly 1 public input in the proof"
    );

    let public_input = proof.scheduler_proof.inputs[0];

    println!("Public input is: {}", public_input);
    let aux_witness = AuxOutputWitnessWrapper {
        0 : circuit_definitions::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness{
            l1_messages_linear_hash:proof.aggregation_result_coords[0],
            rollup_state_diff_for_compression: proof.aggregation_result_coords[1], bootloader_heap_initial_content: proof.aggregation_result_coords[2], events_queue_state: proof.aggregation_result_coords[3] },

    };

    Ok((public_input, aux_witness, computed_hash.unwrap()))
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
        computed_vk_hash, vk_hash_from_l1.unwrap(),
        "Make sure the verification key is updated."
    );

    if computed_vk_hash != vk_hash_from_l1.unwrap() {
        return Err(StatusCode::VerificationKeyHashMismatch);
    }

    return Ok(computed_vk_hash);
}
