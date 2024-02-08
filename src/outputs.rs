use std::process;

use crate::block_header::{BlockAuxilaryOutput, VerifierParams};
use crate::requests::{BatchL1Data, L1BatchAndProofData};
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::Fr;

use serde::ser::SerializeStruct;
use serde::Serialize;
use serde_repr::Serialize_repr;

#[derive(Serialize_repr, PartialEq, Clone, Debug)]
#[repr(u64)]
pub enum StatusCode {
    Success = 0,
    InvalidNetwork,
    NoRPCProvided,
    FailedToDeconstruct,
    FailedToGetDataFromL1,
    FailedToFindCommitTxn,
    InvalidLog,
    FailedToGetTransactionReceipt,
    FailedToGetBatchCommitment,
    ProofDoesntExist,
    FailedToFindProveTxn,
    InvalidTupleTypes,
    FailedToCallRPC,
    VerificationKeyHashMismatch,
    FailedToDownloadVerificationKey,
    FailedToWriteVerificationKeyToDisk,
    ProofVerificationFailed,
    FailedToLoadVerificationKey,
    BadCalldataLength,
    FailedToCallRPCJsonError,
    FailedToCallRPCResponseError,
}

#[derive(Default)]
pub struct VerificationKeyHashJsonOutput {
    layer_1_vk_hash: [u8; 32],
    computed_vk_hash: [u8; 32],
}

pub fn construct_vk_output(
    layer_1_vk_hash: [u8; 32],
    computed_vk_hash: [u8; 32],
) -> VerificationKeyHashJsonOutput {
    VerificationKeyHashJsonOutput {
        layer_1_vk_hash,
        computed_vk_hash,
    }
}

#[derive(Serialize)]
#[serde(rename = "data", rename_all = "camelCase")]
pub struct DataJsonOutput {
    pub batch_l1_data: BatchL1Data,
    pub aux_input: BlockAuxilaryOutput,
    pub verifier_params: VerifierParams,
    pub verification_key_hash: VerificationKeyHashJsonOutput,
    pub public_input: Fr,
    pub is_proof_valid: bool,
}

impl From<L1BatchAndProofData> for DataJsonOutput {
    fn from(batch: L1BatchAndProofData) -> Self {
        Self {
            batch_l1_data: batch.batch_l1_data,
            aux_input: batch.aux_output,
            verifier_params: batch.verifier_params,
            verification_key_hash: VerificationKeyHashJsonOutput::default(),
            public_input: Fr::default(),
            is_proof_valid: false,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoojumCliJsonOutput {
    pub status_code: StatusCode,
    pub batch_number: u64,
    pub data: Option<DataJsonOutput>,
}

impl Serialize for BatchL1Data {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BatchL1Data", 6)?;
        let _ = state.serialize_field("prevStateRoot", &hex::encode(self.previous_root.as_slice()));
        let _ = state.serialize_field("newStateRoot", &hex::encode(self.new_root.as_slice()));
        let _ = state.serialize_field("defaultAAHash", &hex::encode(self.default_aa_hash));
        let _ = state.serialize_field("bootloaderCodeHash", &hex::encode(self.bootloader_hash));
        let _ = state.serialize_field(
            "prevBatchCommitment",
            &hex::encode(self.prev_batch_commitment),
        );
        let _ = state.serialize_field(
            "currBatchCommitment",
            &hex::encode(self.curr_batch_commitment),
        );
        state.end()
    }
}

impl Serialize for BlockAuxilaryOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AuxInput", 4)?;
        let _ = state.serialize_field("systemLogsHash", &hex::encode(self.system_logs_hash));
        let _ = state.serialize_field("stateDiffHash", &hex::encode(self.state_diff_hash));
        let _ = state.serialize_field(
            "bootloaderInitialContentsHash",
            &hex::encode(self.bootloader_heap_initial_content_hash),
        );
        let _ = state.serialize_field(
            "eventQueueStateHash",
            &hex::encode(self.event_queue_state_hash),
        );
        state.end()
    }
}

impl Serialize for VerifierParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("VerifierParams", 3)?;
        let _ = state.serialize_field(
            "recursionNodeLevelVkHash",
            &hex::encode(self.recursion_node_level_vk_hash),
        );
        let _ = state.serialize_field(
            "recursionLeafLevelVkHash",
            &hex::encode(self.recursion_leaf_level_vk_hash),
        );
        let _ = state.serialize_field(
            "recursionCircuitsSetVkHash",
            &hex::encode(self.recursion_circuits_set_vk_hash),
        );
        state.end()
    }
}

impl Serialize for VerificationKeyHashJsonOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("VerificationKeyHash", 2)?;
        let _ = state.serialize_field(
            "layer1VkHash",
            &hex::encode(self.layer_1_vk_hash),
        );
        let _ = state.serialize_field(
            "computedVkHash",
            &hex::encode(self.computed_vk_hash),
        );
        state.end()
    }
}

pub fn print_json(status_code: StatusCode, batch_number: u64) {
    let output = BoojumCliJsonOutput {
        status_code: status_code.clone(),
        batch_number,
        data: None,
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    process::exit(status_code as i32);
}
