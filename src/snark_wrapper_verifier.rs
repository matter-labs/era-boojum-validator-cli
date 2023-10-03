use std::fs;

use crate::requests::AuxOutputWitnessWrapper;
use crate::{proof_from_file, GenerateSolidityTestArgs, VerifySnarkWrapperArgs};
use circuit_definitions::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::{
    circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit,
    franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript,
};
use colored::Colorize;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BatchProofForL1 {
    pub aggregation_result_coords: [[u8; 32]; 4],
    //pub scheduler_proof: Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>,
    pub scheduler_proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit>,
}

pub async fn verify_snark(
    args: &VerifySnarkWrapperArgs,
) -> Result<(Fr, AuxOutputWitnessWrapper), String> {
    println!("Verifying SNARK wrapped FRI proof.");

    let proof: L1BatchProofForL1 = proof_from_file(&args.l1_batch_proof_file);

    println!("=== Aux inputs:");
    println!(
        "  L1 msg linead hash:                  0x{:}",
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
        serde_json::from_str(&fs::read_to_string(args.snark_vk_scheduler_key_file.clone()).unwrap()).unwrap();

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

    println!("Private input is: {:?}", public_input);
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
