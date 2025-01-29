use ethers::{abi::{Function, ParamType}, utils::keccak256};
use zksync_types::{commitment::SerializeCommitment, l2_to_l1_log::L2ToL1Log, H256};

use crate::outputs::StatusCode;

#[derive(Debug, Clone)]
pub struct BlockAuxilaryOutput {
    pub system_logs_hash: [u8; 32],
    pub state_diff_hash: [u8; 32],
    pub bootloader_heap_initial_content_hash: [u8; 32],
    pub event_queue_state_hash: [u8; 32],
}

impl BlockAuxilaryOutput {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        // everything is BE
        let mut result = vec![];
        result.extend_from_slice(&self.system_logs_hash);
        result.extend_from_slice(&self.state_diff_hash);
        result.extend_from_slice(&self.bootloader_heap_initial_content_hash);
        result.extend_from_slice(&self.event_queue_state_hash);

        result
    }

    pub fn prepare_aggregation_result_coords(&self) -> [[u8; 32]; 4] {
        [
            self.system_logs_hash,
            self.state_diff_hash,
            self.bootloader_heap_initial_content_hash,
            self.event_queue_state_hash,
        ]
    }
}

pub async fn parse_aux_data(func: &Function, calldata: &[u8], protocol_version: u16) -> Result<BlockAuxilaryOutput, StatusCode> {
    use ethers::abi;

    let batch;

    if calldata.len() < 5 {
        return Err(StatusCode::BadCalldataLength);
    }

    let mut parsed_input = func.decode_input(&calldata[4..]).unwrap();

    if protocol_version < 26 {
        let second_param = parsed_input.pop().unwrap();

        let abi::Token::Array(inner) = second_param else {
            return Err(StatusCode::FailedToDeconstruct);
        };

        let mut found_params = None;

        for inner in inner.into_iter() {
            let abi::Token::Tuple(inner) = inner else {
                return Err(StatusCode::FailedToDeconstruct);
            };
            
            let [
                abi::Token::Uint(batch_number), 
                abi::Token::Uint(timestamp), 
                abi::Token::Uint(index_repeated_storage_changes), 
                abi::Token::FixedBytes(new_state_root), 
                abi::Token::Uint(number_l1_txns), 
                abi::Token::FixedBytes(priority_operations_hash), 
                abi::Token::FixedBytes(bootloader_contents_hash), 
                abi::Token::FixedBytes(event_queue_state_hash), 
                abi::Token::Bytes(sys_logs), 
                abi::Token::Bytes(total_pubdata)
            ] =
                inner.as_slice()
            else {
                return Err(StatusCode::FailedToDeconstruct);
            };

            found_params = Some((
                batch_number.clone(),
                timestamp.clone(),
                index_repeated_storage_changes.clone(),
                new_state_root.clone(),
                number_l1_txns.clone(),
                priority_operations_hash.clone(),
                bootloader_contents_hash.clone(),
                event_queue_state_hash.clone(),
                sys_logs.clone(),
                total_pubdata.clone(),
            ));
            
        }

        batch = found_params.unwrap();
    } else {
        assert_eq!(parsed_input.len(), 4);

        let commit_data = parsed_input.pop().unwrap();

        let abi::Token::Bytes(mut commit_data_bytes) = commit_data else {
            return Err(StatusCode::FailedToDeconstruct);
        };

        commit_data_bytes = commit_data_bytes[1..].to_vec();

        let stored_batch_info_params = ParamType::Tuple(
            vec![
                ParamType::Uint(64),
                ParamType::FixedBytes(32),
                ParamType::Uint(64),
                ParamType::Uint(256),
                ParamType::FixedBytes(32),
                ParamType::FixedBytes(32),
                ParamType::Uint(256),
                ParamType::FixedBytes(32),
            ]
        );

        let commit_batch_info_params = ParamType::Tuple(
            vec![
                ParamType::Uint(64),
                ParamType::Uint(64),
                ParamType::Uint(64),
                ParamType::FixedBytes(32),
                ParamType::Uint(256),
                ParamType::FixedBytes(32),
                ParamType::FixedBytes(32),
                ParamType::FixedBytes(32),
                ParamType::Bytes,
                ParamType::Bytes,
            ]
        );

        let combined_params = vec![
            stored_batch_info_params,
            ParamType::Array(Box::new(commit_batch_info_params))
        ];

        let res = ethers::core::abi::decode(&combined_params, &commit_data_bytes);

        
        if res.is_err() {
            return Err(StatusCode::FailedToDeconstruct);
        }
        
        let decoded_input = res.unwrap();
        
        if decoded_input.len() != 2 {
            return Err(StatusCode::FailedToDeconstruct);
        }
        
        let abi::Token::Array(commit_batches) = decoded_input[1].clone() else {
            return Err(StatusCode::FailedToDeconstruct);
        };

        if commit_batches.len() != 1 {
            return Err(StatusCode::FailedToDeconstruct);
        }
        
        let abi::Token::Tuple(commit_batch) = commit_batches[0].clone() else {
            return Err(StatusCode::FailedToDeconstruct);
        };

        if commit_batch.len() != 10 {
            return Err(StatusCode::FailedToDeconstruct);
        };

        let [
                abi::Token::Uint(batch_number), 
                abi::Token::Uint(timestamp), 
                abi::Token::Uint(index_repeated_storage_changes), 
                abi::Token::FixedBytes(new_state_root), 
                abi::Token::Uint(number_l1_txns), 
                abi::Token::FixedBytes(priority_operations_hash), 
                abi::Token::FixedBytes(bootloader_contents_hash), 
                abi::Token::FixedBytes(event_queue_state_hash), 
                abi::Token::Bytes(sys_logs), 
                abi::Token::Bytes(total_pubdata)
            ] = commit_batch.as_slice()
        else {
            return Err(StatusCode::FailedToDeconstruct);
        };

        batch = (
            batch_number.clone(),
            timestamp.clone(),
            index_repeated_storage_changes.clone(),
            new_state_root.clone(),
            number_l1_txns.clone(),
            priority_operations_hash.clone(),
            bootloader_contents_hash.clone(),
            event_queue_state_hash.clone(),
            sys_logs.clone(),
            total_pubdata.clone(),
        );
    }

    let (
        batch_number,
        timestamp,
        index_repeated_storage_changes,
        new_state_root,
        number_l1_txns,
        priority_operations_hash,
        bootloader_contents_hash,
        event_queue_state_hash,
        sys_logs,
        total_pubdata,
    ) = batch;

    assert_eq!(bootloader_contents_hash.len(), 32);
    assert_eq!(event_queue_state_hash.len(), 32);

    let mut bootloader_contents_hash_buffer = [0u8; 32];
    bootloader_contents_hash_buffer.copy_from_slice(&bootloader_contents_hash);

    let mut event_queue_state_hash_buffer = [0u8; 32];
    event_queue_state_hash_buffer.copy_from_slice(&event_queue_state_hash);

    assert!(
        sys_logs.len() % L2ToL1Log::SERIALIZED_SIZE == 0,
        "sys logs length should be a factor of serialized size"
    );
    let state_diff_hash_sys_log = sys_logs
        .chunks(L2ToL1Log::SERIALIZED_SIZE)
        .into_iter()
        .map(L2ToL1Log::from_slice)
        // The value 2 comes from the key in this enum https://github.com/matter-labs/era-system-contracts/blob/d42f707cbe6938a76fa29f4bf76203af1e13f51f/contracts/Constants.sol#L90
        .find(|log| log.key == H256::from_low_u64_be(2_u64))
        .unwrap();

    let system_logs_hash = keccak256(sys_logs);

    Ok(BlockAuxilaryOutput {
        system_logs_hash,
        state_diff_hash: state_diff_hash_sys_log.value.to_fixed_bytes(),
        bootloader_heap_initial_content_hash: bootloader_contents_hash_buffer,
        event_queue_state_hash: event_queue_state_hash_buffer,
    })
}

pub fn to_fixed_bytes(ins: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(ins);

    result
}

/// Verifier config params describing the circuit to be verified.
#[derive(Debug, Copy, Clone)]
pub struct VerifierParams {
    pub recursion_node_level_vk_hash: [u8; 32],
    pub recursion_leaf_level_vk_hash: [u8; 32],
    pub recursion_circuits_set_vk_hash: [u8; 32],
}
