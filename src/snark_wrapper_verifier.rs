use std::fs;

use crate::crypto::{deserialize_proof, serialize_proof, calculate_verification_key_hash};
use crate::requests::AuxOutputWitnessWrapper;
use crate::{proof_from_file, GenerateSolidityTestArgs, VerifySnarkWrapperArgs};
use circuit_definitions::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::{
    circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit,
    franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript,
};
use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use colored::Colorize;
use primitive_types::H256;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BatchProofForL1 {
    pub aggregation_result_coords: [[u8; 32]; 4],
    pub scheduler_proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit>,
}

pub async fn verify_snark(
    args: &VerifySnarkWrapperArgs,
) -> Result<(Fr, AuxOutputWitnessWrapper), String> {
    println!("Verifying SNARK wrapped FRI proof.");

    let proof: L1BatchProofForL1 = proof_from_file(&args.l1_batch_proof_file);

    let input = proof.scheduler_proof.inputs.clone();

    let (_, serialized_proof) = serialize_proof(&proof.scheduler_proof);

    let mut proof = L1BatchProofForL1 {
        aggregation_result_coords: proof.aggregation_result_coords,
        scheduler_proof: deserialize_proof(serialized_proof),
    };

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
    use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
    let vk_inner : VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit> =
        serde_json::from_str(&fs::read_to_string(args.snark_vk_scheduler_key_file.clone()).unwrap()).unwrap();

    proof.scheduler_proof.n = vk_inner.n;
    proof.scheduler_proof.inputs = input;

    println!("Verifying the proof");
    let is_valid =
        verify::<_, _, RollingKeccakTranscript<Fr>>(&vk_inner, &proof.scheduler_proof, None)
            .unwrap();

    if !is_valid {
        println!("Proof is {}", "INVALID".red());
        return Err("Proof is not valid".to_owned());
    } else {
        println!("Proof is {}", "VALID".green());
    };

    // We expect only 1 public input.
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

    Ok((public_input, aux_witness))
}

pub async fn generate_solidity_test(args: &GenerateSolidityTestArgs) -> Result<(), String> {
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

pub async fn verify_snark_from_l1(
    snark_vk_scheduler_key_file: String,
    mut proof: L1BatchProofForL1,
    vk_hash_from_l1: H256,
) -> Result<(Fr, AuxOutputWitnessWrapper), String> {
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
    use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
    let vk_inner : circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit> =
        serde_json::from_str(&fs::read_to_string(snark_vk_scheduler_key_file.clone()).unwrap()).unwrap();

    proof.scheduler_proof.n = vk_inner.n;

    check_verification_key(vk_inner.clone(), vk_hash_from_l1);

    println!("Verifying the proof");
    let is_valid =
        verify::<_, _, RollingKeccakTranscript<Fr>>(&vk_inner, &proof.scheduler_proof, None)
            .unwrap();

    if !is_valid {
        println!("Proof is {}", "INVALID".red());
        return Err("Proof is not valid".to_owned());
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

    Ok((public_input, aux_witness))
}

fn check_verification_key(
    verification_key: VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit>,
    vk_hash_from_l1: H256,
) {
    let computed_vk_hash = calculate_verification_key_hash(verification_key);

    println!("=== Verification Key Hash Check:");
    println!("  Verification Key Hash from L1:       0x{:}", hex::encode(vk_hash_from_l1));
    println!("  Computed Verification Key Hash:      0x{:}", hex::encode(computed_vk_hash));

    assert_eq!(computed_vk_hash, vk_hash_from_l1, "Make sure the verification key is updated.");
}
