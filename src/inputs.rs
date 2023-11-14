use std::ops::Shr;

use circuit_definitions::franklin_crypto::bellman::pairing::bn256::Fr;
use circuit_definitions::franklin_crypto::bellman::PrimeField;

use crate::block_header;
use crate::block_header::VerifierParams;
use crate::params;
use crate::requests;
use crate::requests::AuxOutputWitnessWrapper;
use crate::requests::BatchL1Data;
use colored::Colorize;
use zksync_types::U256;

use circuit_definitions::boojum::field::goldilocks::GoldilocksField;

/// Computes the public inputs for a given batch in a given network.
/// Public inputs require us to fetch multiple data from the l1 (like state hash etc).
pub async fn _compute_public_inputs(
    network: String,
    batch_number: u64,
    l1_rpc: Option<String>,
) -> anyhow::Result<Vec<GoldilocksField>> {
    // Loads verification keys.
    // As our circuits change, the verification keys also change - so depending on the batch number, they might have different values.
    let params = if network == "mainnet" {
        self::params::get_mainnet_params_holder().get_for_index(batch_number as usize)
    } else if network == "sepolia" {
        self::params::get_testnet_params_holder().get_for_index(batch_number as usize)
    } else {
        unreachable!();
    };

    let Some([leaf_layer_parameters_commitment, node_layer_vk_commitment]) = params else {
        anyhow::bail!(format!("Can not get verification keys commitments for batch {}. Either it's too far in the past, or update the CLI", batch_number.to_string().yellow()));
    };

    println!("{}", "Fetching data from Ethereum L1 for state roots, bootloader and default Account Abstraction parameters".on_blue());

    let l1_data =
        requests::fetch_l1_commit_data(batch_number, &network, &l1_rpc.clone().unwrap()).await;
    if l1_data.is_err() {
        if let Err(_err) = l1_data {
            anyhow::bail!(format!("Failed to get data from L1: {}", _err));
        }
        anyhow::bail!("Failed to get data from L1");
    }
    requests::fetch_proof_from_l1(batch_number, &network, &l1_rpc.unwrap()).await;

    let (l1_data, _) = l1_data.unwrap();

    println!("{}", "Fetching auxilary block data".on_blue());
    let aux_data = requests::_fetch_aux_data_from_storage(batch_number, &network).await;
    if aux_data.is_err() {
        anyhow::bail!("Failed to get auxiliary data");
    }
    println!("\n");

    // After fetching the data, we recreate the public input hash (for which we need information from current and previous block).

    let aux_data = aux_data.unwrap();
    create_input_internal(
        l1_data,
        aux_data,
        leaf_layer_parameters_commitment,
        node_layer_vk_commitment,
        None,
        None,
    )
    .await
}

#[allow(dead_code)]
pub async fn create_input_internal(
    l1_data: BatchL1Data,
    aux_data: AuxOutputWitnessWrapper,
    leaf_layer_parameters_commitment: [GoldilocksField; 4],
    node_layer_vk_commitment: [GoldilocksField; 4],
    previous_block_meta_hash: Option<[u8; 32]>,
    previous_block_aux_hash: Option<[u8; 32]>,
) -> anyhow::Result<Vec<GoldilocksField>> {
    // while we do not prove all the blocks we use placeholders for non-state related parts
    // of the previous block
    let previous_block_meta_hash = previous_block_meta_hash.unwrap_or([0u8; 32]);
    let previous_block_aux_hash = previous_block_aux_hash.unwrap_or([0u8; 32]);

    use self::block_header::*;
    use sha3::{Digest, Keccak256};

    let previous_passthrough_data = BlockPassthroughData {
        per_shard_states: [
            PerShardState {
                enumeration_counter: l1_data.previous_enumeration_counter,
                state_root: l1_data.previous_root.try_into().unwrap(),
            },
            // porter shard is not used
            PerShardState {
                enumeration_counter: 0,
                state_root: [0u8; 32],
            },
        ],
    };
    let previous_passthrough_data_hash = to_fixed_bytes(
        Keccak256::digest(&previous_passthrough_data.into_flattened_bytes()).as_slice(),
    );

    let previous_block_content_hash = BlockContentHeader::formal_block_hash_from_partial_hashes(
        previous_passthrough_data_hash,
        previous_block_meta_hash,
        previous_block_aux_hash,
    );

    let new_passthrough_data = BlockPassthroughData {
        per_shard_states: [
            PerShardState {
                enumeration_counter: l1_data.new_enumeration_counter,
                state_root: l1_data.new_root.try_into().unwrap(),
            },
            // porter shard is not used
            PerShardState {
                enumeration_counter: 0,
                state_root: [0u8; 32],
            },
        ],
    };

    let new_meta_params = BlockMetaParameters {
        zkporter_is_available: false,
        bootloader_code_hash: l1_data.bootloader_hash,
        default_aa_code_hash: l1_data.default_aa_hash,
    };

    let aux_data = aux_data.0;

    let new_aux_params = BlockAuxilaryOutput {
        system_logs_hash: aux_data.l1_messages_linear_hash,
        state_diff_hash: aux_data.rollup_state_diff_for_compression,
        bootloader_heap_initial_content_hash: aux_data.bootloader_heap_initial_content,
        event_queue_state_hash: aux_data.events_queue_state,
    };

    let new_header = BlockContentHeader {
        block_data: new_passthrough_data,
        block_meta: new_meta_params,
        auxilary_output: new_aux_params,
    };
    let this_block_content_hash = new_header.into_formal_block_hash().0;

    let mut flattened_public_input = vec![];
    flattened_public_input.extend(previous_block_content_hash);
    flattened_public_input.extend(this_block_content_hash);
    // recursion parameters, for now hardcoded

    let mut recursion_node_verification_key_hash = [0u8; 32];
    for (dst, src) in recursion_node_verification_key_hash
        .array_chunks_mut::<8>()
        .zip(node_layer_vk_commitment.iter())
    {
        let le_bytes = src.to_reduced_u64().to_le_bytes();
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    let mut leaf_layer_parameters_hash = [0u8; 32];
    for (dst, src) in leaf_layer_parameters_hash
        .array_chunks_mut::<8>()
        .zip(leaf_layer_parameters_commitment.iter())
    {
        let le_bytes = src.to_reduced_u64().to_le_bytes();
        dst.copy_from_slice(&le_bytes[..]);
        dst.reverse();
    }

    flattened_public_input.extend(recursion_node_verification_key_hash);
    flattened_public_input.extend(leaf_layer_parameters_hash);

    let input_keccak_hash = to_fixed_bytes(Keccak256::digest(&flattened_public_input).as_slice());

    let mut public_inputs = vec![];
    use circuit_definitions::boojum::field::PrimeField;
    use circuit_definitions::boojum::field::U64Representable;
    use circuit_definitions::zkevm_circuits::scheduler::NUM_SCHEDULER_PUBLIC_INPUTS;
    let take_by = GoldilocksField::CAPACITY_BITS / 8;

    for chunk in input_keccak_hash
        .chunks_exact(take_by)
        .take(NUM_SCHEDULER_PUBLIC_INPUTS)
    {
        let mut buffer = [0u8; 8];
        buffer[1..].copy_from_slice(chunk);
        let as_field_element = GoldilocksField::from_u64_unchecked(u64::from_be_bytes(buffer));
        public_inputs.push(as_field_element);
    }
    Ok(public_inputs)
}

pub fn generate_inputs(batch_l1_data: BatchL1Data, verifier_params: VerifierParams) -> Vec<Fr> {
    use self::block_header::*;
    use sha3::{Digest, Keccak256};

    let input_fields = [
        batch_l1_data.prev_batch_commitment.to_fixed_bytes(),
        batch_l1_data.curr_batch_commitment.to_fixed_bytes(),
        verifier_params.recursion_node_level_vk_hash,
        verifier_params.recursion_leaf_level_vk_hash,
    ];
    let encoded_input_params = input_fields.flatten();

    let input_keccak_hash = to_fixed_bytes(Keccak256::digest(&encoded_input_params).as_slice());
    let input_u256 = U256::from_big_endian(&input_keccak_hash);
    let shifted_input = input_u256.shr(U256::from(32));

    vec![Fr::from_str(&shifted_input.to_string()).unwrap()]
}
