use std::str::FromStr;

use crate::proof_from_json_file;
use crate::snark_wrapper_verifier::verify_snark;
use crate::{snark_wrapper_verifier::L1BatchProofForL1, VerifySnarkWrapperArgs};

use crate::outputs::StatusCode;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use crypto::types::ProofType;
use primitive_types::H256;

/// Pulls a SNARK proof from storage and verifies is with the supplied verification key.
pub async fn verify_snark_boojum_os(
    args: &VerifySnarkWrapperArgs,
) -> Result<(Fr, H256), StatusCode> {
    let subproof = ProofType::Plonk(proof_from_json_file(&args.l1_batch_proof_file));

    let proof = L1BatchProofForL1 {
        // boojum os doesn't use aggregation results anymore.
        aggregation_result_coords: Default::default(),
        scheduler_proof: subproof,
    };

    // Reuse the main logic of snark verification.
    let result = verify_snark(
        args.snark_vk_scheduler_key_file.clone(),
        None,
        proof,
        None,
        None,
    )
    .await;

    match result {
        Ok((public_input, _, computed_hash)) => {
            use zksync_pairing::ff::PrimeField;

            let public_input_h256 = H256::from_str(&public_input.into_repr().to_string()).unwrap();

            // Format is - ignore first 4 bytes, and then 7 bytes for each pair of registers.
            let mut registers = Vec::new();
            let mut queue = Vec::new();
            for i in 0..4 {
                let pos = &public_input_h256.0[4 + i * 7..(4 + (i + 1) * 7)];
                for entry in pos.iter().rev() {
                    queue.push(*entry);
                    if queue.len() == 4 {
                        registers.push(u32::from_le_bytes(queue.clone().try_into().unwrap()));
                        queue.clear();
                    }
                }
            }
            println!("Registers from public input: {:?}", registers);

            Ok((public_input, computed_hash))
        }
        Err(e) => Err(e),
    }
}
