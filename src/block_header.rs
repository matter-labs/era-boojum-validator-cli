use ethers::{abi::Function, utils::keccak256};
use zksync_types::{commitment::SerializeCommitment, l2_to_l1_log::L2ToL1Log, H256};

use crate::{
    batch::{parse_commit_batch_info, CommitBatchInfo},
    outputs::StatusCode,
};

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

pub async fn parse_aux_data(
    func: &Function,
    calldata: &[u8],
    protocol_version: u16,
) -> Result<BlockAuxilaryOutput, StatusCode> {
    let batch = parse_commit_batch_info(func, calldata, protocol_version);

    match batch {
        None => Err(StatusCode::FailedToDeconstruct),
        Some(batch_commit) => {
            let CommitBatchInfo {
                batch_number: _,
                timestamp: _,
                index_repeated_storage_changes: _,
                new_state_root: _,
                number_l1_txns: _,
                priority_operations_hash: _,
                bootloader_contents_hash,
                event_queue_state_hash,
                sys_logs,
                total_pubdata: _,
            } = batch_commit;

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
    }
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
