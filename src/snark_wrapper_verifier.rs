use std::fs;

use crate::outputs::StatusCode;
use crate::requests::AuxOutputWitnessWrapper;
use crate::{
    proof_from_file, GenerateSolidityTestArgs, VerifySnarkWrapperArgs, VerifySnarkWrapperJsonArgs,
};
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuitNoLookupCustomGate;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::{
    proof::Proof, setup::VerificationKey,
};
use circuit_definitions::{
    circuit_definitions::aux_layer::ZkSyncSnarkWrapperCircuit,
    snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript,
};
use colored::Colorize;
use crypto::calculate_fflonk_verification_key_hash;
use crypto::flonk::FflonkVerificationKey;
use crypto::{calculate_verification_key_hash, types::ProofType};
use primitive_types::H256;
use serde::de::DeserializeOwned;

type AggregationResultCoords = [[u8; 32]; 4];

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct L1BatchProofForL1 {
    pub aggregation_result_coords: AggregationResultCoords,
    pub scheduler_proof: ProofType,
}

// ==============================================================================
// Shared Adapter Helpers
// ==============================================================================
//
// The legacy CLI verifies a SNARK by first deserializing an outer
// `L1BatchProofForL1` envelope. `zkos-wrapper` emits the inner SNARK proof as raw
// JSON instead, so the adapter below shares the core verifier flow while letting
// us omit aux L1 metadata when it is genuinely unavailable.
fn print_aux_inputs(aggregation_result_coords: Option<AggregationResultCoords>) {
    println!("=== Aux inputs:");

    if let Some(aggregation_result_coords) = aggregation_result_coords {
        println!(
            "  L1 msg linear hash:                  0x{:}",
            hex::encode(aggregation_result_coords[0])
        );
        println!(
            "  Rollup state diff for compression:   0x{:}",
            hex::encode(aggregation_result_coords[1])
        );
        println!(
            "  Bootloader heap initial content:     0x{:}",
            hex::encode(aggregation_result_coords[2])
        );
        println!(
            "  Events queue state:                  0x{:}",
            hex::encode(aggregation_result_coords[3])
        );
    } else {
        println!("  Raw JSON adapter mode: no L1 aux inputs were supplied.");
        println!("  Raw JSON adapter mode: only proof validity and public input are checked.");
    }
}

fn build_aux_output_witness(
    aggregation_result_coords: AggregationResultCoords,
) -> AuxOutputWitnessWrapper {
    AuxOutputWitnessWrapper {
        0: circuit_definitions::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness {
            l1_messages_linear_hash: aggregation_result_coords[0],
            rollup_state_diff_for_compression: aggregation_result_coords[1],
            bootloader_heap_initial_content: aggregation_result_coords[2],
            events_queue_state: aggregation_result_coords[3],
            eip4844_linear_hashes: [[0u8; 32]; 16],
            eip4844_output_commitment_hashes: [[0u8; 32]; 16],
        },
    }
}

fn load_json_file<T: DeserializeOwned>(
    file_path: &str,
    load_error: StatusCode,
    parse_error: StatusCode,
    json_label: &str,
) -> Result<T, StatusCode> {
    let json = fs::read_to_string(file_path).map_err(|_| {
        println!("Unable to load {} from: {}", json_label, file_path);
        load_error.clone()
    })?;

    serde_json::from_str(&json).map_err(|_| {
        println!("Unable to parse {} from: {}", json_label, file_path);
        parse_error
    })
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

/// Verifies a raw JSON proof/VK pair emitted by zkos-wrapper.
pub async fn verify_snark_from_json(
    args: &VerifySnarkWrapperJsonArgs,
) -> Result<(Fr, H256), StatusCode> {
    let proof: Proof<Bn256, ZkSyncSnarkWrapperCircuit> = load_json_file(
        &args.snark_proof_file,
        StatusCode::FailedToParseProof,
        StatusCode::FailedToParseProof,
        "proof JSON",
    )?;

    // TODO: Support the raw FFLONK JSON path too if the wrapper starts emitting it.
    let (public_input, _aux_witness, computed_vk_hash) = verify_snark_proof(
        args.snark_vk_scheduler_key_file.clone(),
        None,
        ProofType::Plonk(proof),
        None,
        None,
        None,
    )
    .await?;

    Ok((public_input, computed_vk_hash))
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
    let (public_input, aux_witness, computed_vk_hash) = verify_snark_proof(
        snark_vk_scheduler_key_file,
        fflonk_verification_key_file,
        proof.scheduler_proof,
        Some(proof.aggregation_result_coords),
        plonk_vk_hash_from_l1,
        fflonk_vk_hash_from_l1,
    )
    .await?;

    Ok((
        public_input,
        aux_witness.expect("legacy proofs always include aux inputs"),
        computed_vk_hash,
    ))
}

async fn verify_snark_proof(
    snark_vk_scheduler_key_file: String,
    fflonk_verification_key_file: Option<String>,
    scheduler_proof: ProofType,
    aggregation_result_coords: Option<AggregationResultCoords>,
    plonk_vk_hash_from_l1: Option<H256>,
    fflonk_vk_hash_from_l1: Option<H256>,
) -> Result<(Fr, Option<AuxOutputWitnessWrapper>, H256), StatusCode> {
    println!("Verifying SNARK wrapped FRI proof.");
    print_aux_inputs(aggregation_result_coords);

    let computed_hash: Result<H256, StatusCode>;

    match scheduler_proof {
        ProofType::Fflonk(mut fflonk_proof) => {
            let verification_key_path =
                fflonk_verification_key_file.expect("fflonk verification key is required");

            use crypto::flonk::verifier::verify;
            let vk_inner: crypto::flonk::FflonkVerificationKey<
                Bn256,
                ZkSyncSnarkWrapperCircuitNoLookupCustomGate,
            > = load_json_file(
                &verification_key_path,
                StatusCode::FailedToLoadVerificationKey,
                StatusCode::FailedToLoadVerificationKey,
                "verification key JSON",
            )?;

            fflonk_proof.n = vk_inner.n;
            computed_hash = check_fflonk_verification_key(vk_inner.clone(), fflonk_vk_hash_from_l1);

            if computed_hash.is_err() {
                return Err(computed_hash.err().unwrap());
            }

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
            let aux_witness = aggregation_result_coords.map(build_aux_output_witness);

            Ok((public_input, aux_witness, computed_hash.unwrap()))
        }
        ProofType::Plonk(mut plonk_proof) => {
            println!("=== Loading verification key.");

            use circuit_definitions::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
            let vk_inner: VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit> = load_json_file(
                &snark_vk_scheduler_key_file,
                StatusCode::FailedToLoadVerificationKey,
                StatusCode::FailedToLoadVerificationKey,
                "verification key JSON",
            )?;

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
            let aux_witness = aggregation_result_coords.map(build_aux_output_witness);

            Ok((public_input, aux_witness, computed_hash.unwrap()))
        }
    }
}

/// Check that the hash of the verificattion key provided is equal to the supplied hash.
fn check_verification_key(
    verification_key: VerificationKey<Bn256, ZkSyncSnarkWrapperCircuit>,
    vk_hash_from_l1: Option<H256>,
) -> Result<H256, StatusCode> {
    let computed_vk_hash = calculate_verification_key_hash(verification_key);

    println!("=== Verification Key Hash Check:");
    println!(
        "  Verification Key Hash from L1:       0x{:}",
        hex::encode(vk_hash_from_l1.unwrap_or_default())
    );
    println!(
        "  Computed Verification Key Hash:      0x{:}",
        hex::encode(computed_vk_hash)
    );
    if vk_hash_from_l1.is_none() {
        println!("Supplied vk hash is None, skipping check...");
        return Ok(H256::default());
    }

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
    let computed_vk_hash = calculate_fflonk_verification_key_hash(verification_key);

    println!("=== Verification Key Hash Check:");
    println!(
        "  Verification Key Hash from L1:       0x{:}",
        hex::encode(vk_hash_from_l1.unwrap_or_default())
    );
    println!(
        "  Computed Verification Key Hash:      0x{:}",
        hex::encode(computed_vk_hash)
    );

    if vk_hash_from_l1.is_none() {
        println!("Supplied vk hash is None, skipping check...");
        return Ok(H256::default());
    }

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
