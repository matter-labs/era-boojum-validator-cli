use std::ops::Shr;

use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::Fr;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::PrimeField;

use crate::block_header;
use crate::block_header::VerifierParams;
use crate::requests::BatchL1Data;
use zksync_types::U256;

/// Computes the public inputs for a given batch in a given network.
/// Public inputs require us to fetch multiple data from the l1 (like state hash etc).
pub fn generate_inputs(
    batch_l1_data: BatchL1Data,
    verifier_params: VerifierParams,
    protocol_version: Option<u16>,
) -> Vec<Fr> {
    use self::block_header::to_fixed_bytes;
    use sha3::{Digest, Keccak256};

    let input_fields = if protocol_version.is_some() && protocol_version.unwrap() <= 22 {
        vec![
            batch_l1_data.prev_batch_commitment.to_fixed_bytes(),
            batch_l1_data.curr_batch_commitment.to_fixed_bytes(),
            verifier_params.recursion_node_level_vk_hash,
            verifier_params.recursion_leaf_level_vk_hash,
        ]
    } else {
        vec![
            batch_l1_data.prev_batch_commitment.to_fixed_bytes(),
            batch_l1_data.curr_batch_commitment.to_fixed_bytes(),
        ]
    };
    let encoded_input_params = input_fields.flatten();

    let input_keccak_hash = to_fixed_bytes(Keccak256::digest(&encoded_input_params).as_slice());
    let input_u256 = U256::from_big_endian(&input_keccak_hash);
    let shifted_input = input_u256.shr(U256::from(32));

    vec![Fr::from_str(&shifted_input.to_string()).unwrap()]
}
