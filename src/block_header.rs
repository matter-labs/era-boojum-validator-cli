use sha3::{Digest, Keccak256};

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
    pub l1_messages_linear_hash: [u8; 32],
    pub rollup_state_diff_for_compression: [u8; 32],
    pub bootloader_heap_initial_content: [u8; 32],
    pub events_queue_state: [u8; 32],
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
        result.extend_from_slice(&self.l1_messages_linear_hash);
        result.extend_from_slice(&self.rollup_state_diff_for_compression);
        result.extend_from_slice(&self.bootloader_heap_initial_content);
        result.extend_from_slice(&self.events_queue_state);

        result
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
