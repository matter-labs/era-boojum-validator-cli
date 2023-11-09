use ethers::{abi::Function, utils::keccak256};
use sha3::{Digest, Keccak256};
use zksync_types::{commitment::SerializeCommitment, l2_to_l1_log::L2ToL1Log, H256};

pub struct PerShardState {
    pub enumeration_counter: u64,
    pub state_root: [u8; 32],
}

pub const NUM_SHARDS: usize = 2;

pub struct BlockPassthroughData {
    pub per_shard_states: [PerShardState; NUM_SHARDS],
}

#[derive(Debug)]
pub struct BlockMetaParameters {
    pub zkporter_is_available: bool,
    pub bootloader_code_hash: [u8; 32],
    pub default_aa_code_hash: [u8; 32],
}

#[derive(Debug)]
pub struct BlockAuxilaryOutput {
    pub system_logs_hash: [u8; 32],
    pub state_diff_hash: [u8; 32],
    pub bootloader_heap_initial_content_hash: [u8; 32],
    pub event_queue_state_hash: [u8; 32],
}

impl PerShardState {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        // everything is BE
        let mut result = vec![];
        result.extend(self.enumeration_counter.to_be_bytes());
        result.extend_from_slice(&self.state_root);

        result
    }
}

impl BlockPassthroughData {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        // everything is BE
        let mut result = vec![];
        for el in self.per_shard_states.iter() {
            let be_bytes = el.into_flattened_bytes();
            result.extend(be_bytes);
        }

        result
    }
}

impl BlockMetaParameters {
    pub fn into_flattened_bytes(&self) -> Vec<u8> {
        // everything is BE
        let mut result = vec![];
        result.push(self.zkporter_is_available as u8);
        result.extend_from_slice(&self.bootloader_code_hash);
        result.extend_from_slice(&self.default_aa_code_hash);

        result
    }
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

pub fn parse_aux_data(func: &Function, calldata: &[u8]) -> BlockAuxilaryOutput {
    use ethers::abi;

    let mut parsed_calldata = func.decode_input(&calldata[4..]).unwrap();
    assert_eq!(parsed_calldata.len(), 2);

    let committed_batch = parsed_calldata.pop().unwrap();

    let abi::Token::Tuple(committed_batch) = committed_batch else {
        panic!();
    };

    let [abi::Token::Uint(_batch_number), abi::Token::Uint(_timestamp), abi::Token::Uint(_index_repeated_storage_changes), abi::Token::FixedBytes(_new_state_root), abi::Token::Uint(_number_l1_txns), abi::Token::FixedBytes(bootloader_contents_hash), abi::Token::FixedBytes(event_queue_state_hash), abi::Token::Bytes(sys_logs), abi::Token::Bytes(_total_pubdata)] =
        committed_batch.as_slice()
    else {
        panic!();
    };

    assert_eq!(bootloader_contents_hash.len(), 32);
    assert_eq!(event_queue_state_hash.len(), 32);

    let mut bootloader_contents_hash_buffer = [0u8; 32];
    bootloader_contents_hash_buffer.copy_from_slice(bootloader_contents_hash);

    let mut event_queue_state_hash_buffer = [0u8; 32];
    event_queue_state_hash_buffer.copy_from_slice(event_queue_state_hash);

    assert!(sys_logs.len() % L2ToL1Log::SERIALIZED_SIZE == 0);
    let state_diff_hash_sys_log = sys_logs
        .chunks(L2ToL1Log::SERIALIZED_SIZE)
        .into_iter()
        .map(L2ToL1Log::from_slice)
        .find(|log| log.key == H256::from_low_u64_be(2u64))
        .unwrap();

    let system_logs_hash = keccak256(sys_logs);

    BlockAuxilaryOutput {
        system_logs_hash,
        state_diff_hash: state_diff_hash_sys_log.value.to_fixed_bytes(),
        bootloader_heap_initial_content_hash: bootloader_contents_hash_buffer,
        event_queue_state_hash: event_queue_state_hash_buffer,
    }
}

pub struct BlockHeader {
    pub previous_block_content_hash: [u8; 32],
    pub new_block_content_hash: [u8; 32],
}

pub struct BlockContentHeader {
    pub block_data: BlockPassthroughData,
    pub block_meta: BlockMetaParameters,
    pub auxilary_output: BlockAuxilaryOutput,
}

pub fn to_fixed_bytes(ins: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(ins);

    result
}

impl BlockContentHeader {
    pub fn into_formal_block_hash(self) -> ([u8; 32], ([u8; 32], [u8; 32], [u8; 32])) {
        // everything is BE
        let block_data = self.block_data.into_flattened_bytes();
        let block_meta = self.block_meta.into_flattened_bytes();
        let auxilary_output = self.auxilary_output.into_flattened_bytes();

        let block_data_hash = to_fixed_bytes(Keccak256::digest(&block_data).as_slice());

        let block_meta_hash = to_fixed_bytes(Keccak256::digest(&block_meta).as_slice());

        let auxilary_output_hash = to_fixed_bytes(Keccak256::digest(&auxilary_output).as_slice());

        let block_hash = Self::formal_block_hash_from_partial_hashes(
            block_data_hash,
            block_meta_hash,
            auxilary_output_hash,
        );

        (
            block_hash,
            (block_data_hash, block_meta_hash, auxilary_output_hash),
        )
    }

    pub fn formal_block_hash_from_partial_hashes(
        block_data_hash: [u8; 32],
        block_meta_hash: [u8; 32],
        auxilary_output_hash: [u8; 32],
    ) -> [u8; 32] {
        let mut concatenated = vec![];
        concatenated.extend(block_data_hash);
        concatenated.extend(block_meta_hash);
        concatenated.extend(auxilary_output_hash);

        let block_header_hash = to_fixed_bytes(Keccak256::digest(&concatenated).as_slice());

        block_header_hash
    }
}

pub struct VerifierParams {
    pub recursion_node_level_vk_hash: [u8; 32],
    pub recursion_leaf_level_vk_hash: [u8; 32],
    pub recursion_circuits_set_vk_hash: [u8; 32],
}
