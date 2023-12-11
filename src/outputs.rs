use std::process;

use crate::block_header::{BlockAuxilaryOutput, VerifierParams};
use crate::requests::BatchL1Data;
use circuit_definitions::snark_wrapper::franklin_crypto::bellman::pairing::bn256::Fr;

use serde::Serialize;
use serde::ser::SerializeStruct;
use serde_repr::Serialize_repr;

pub enum Output {
    StdOut(&'static str),
    Json(DataJsonOutput),
}

#[derive(Serialize_repr, PartialEq, Clone)]
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationKeyHashJsonOutput {
    layer_1_vk_hash: [u8; 32],
    computed_vk_hash: [u8; 32],
}

#[derive(Serialize)]
#[serde(rename = "data", rename_all = "camelCase")]
pub struct DataJsonOutput {
    pub batch_number: u64,
    pub batch_l1_data: BatchL1Data,
    pub aux_input: BlockAuxilaryOutput,
    pub verifier_params: VerifierParams,
    pub verification_key_hash: VerificationKeyHashJsonOutput,
    pub public_input: Fr,
    pub is_proof_valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoojumCliJsonOutput {
    pub status_code: StatusCode,
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
        let _ = state.serialize_field("prevBatchCommitment", &hex::encode(self.prev_batch_commitment));
        let _ = state.serialize_field("currBatchCommitment", &hex::encode(self.curr_batch_commitment));
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
        let _ = state.serialize_field("bootloaderInitialContentsHash", &hex::encode(self.bootloader_heap_initial_content_hash));
        let _ = state.serialize_field("eventQueueStateHash", &hex::encode(self.event_queue_state_hash));
        state.end()
    }
}

impl Serialize for VerifierParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("VerifierParams", 3)?;
        let _ = state.serialize_field("recursionNodeLevelVkHash", &hex::encode(self.recursion_node_level_vk_hash));
        let _ = state.serialize_field("recursionLeafLevelVkHash", &hex::encode(self.recursion_leaf_level_vk_hash));
        let _ = state.serialize_field("recursionCircuitsSetVkHash", &hex::encode(self.recursion_circuits_set_vk_hash));
        state.end()
    }
}

impl StatusCode {
    fn print_std_out(&self, msg: &str) {
        match self {
            StatusCode::Success => {
                println!("{}", msg);
            },
            _ => {
                println!("{}", msg);
                process::exit((*self).clone() as i32);       
            }
        }
    }

    fn print_json(&self, data: DataJsonOutput) {
        match self {
            StatusCode::Success => {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            },
            _ => {
                process::exit((*self).clone() as i32);
            }
        }
    }

    pub fn print(&self, output: Output) {
        match output {
            Output::StdOut(msg) => self.print_std_out(msg),
            Output::Json(data) => self.print_json(data)
        }
    }
}
