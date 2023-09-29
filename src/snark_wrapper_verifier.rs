use std::fs;

use colored::Colorize;
use crate::{proof_from_file, VerifySnarkWrapperArgs};
use circuit_definitions::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use circuit_definitions::{circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit, franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript};



#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BatchProofForL1 {
    pub aggregation_result_coords: [[u8; 32]; 4],
    //pub scheduler_proof: Proof<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>>,
    pub scheduler_proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit>,
}

pub async fn verify_snark(args: &VerifySnarkWrapperArgs) -> Result<(), String>{
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
    let is_valid = verify::<_, _, RollingKeccakTranscript<Fr>>(&vk_inner, &proof.scheduler_proof, None).unwrap();

    if !is_valid {
        println!("Proof is {}", "INVALID".red());
        Err("Proof is not valid".to_owned())
    } else {
        println!("Proof is {}", "VALID".green());
        Ok(())
    }
}
