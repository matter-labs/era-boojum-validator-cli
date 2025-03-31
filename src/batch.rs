use crypto::{deserialize_fflonk_proof, deserialize_proof, types::ProofType};
use ethers::abi::{Function, ParamType, Token};
use once_cell::sync::Lazy;
use primitive_types::U256;

use crate::contract::FFLONK_VERIFICATION_TYPE;

static COMMIT_BATCH_INFO_PARAMS: Lazy<ParamType> = Lazy::new(|| {
    ParamType::Tuple(vec![
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
    ])
});

static STORED_BATCH_INFO_PARAMS: Lazy<ParamType> = Lazy::new(|| {
    ParamType::Tuple(vec![
        ParamType::Uint(64),
        ParamType::FixedBytes(32),
        ParamType::Uint(64),
        ParamType::Uint(256),
        ParamType::FixedBytes(32),
        ParamType::FixedBytes(32),
        ParamType::Uint(256),
        ParamType::FixedBytes(32),
    ])
});

#[allow(dead_code)]
pub struct CommitBatchInfo {
    pub batch_number: U256,
    pub timestamp: U256,
    pub index_repeated_storage_changes: U256,
    pub new_state_root: Vec<u8>,
    pub number_l1_txns: U256,
    pub priority_operations_hash: Vec<u8>,
    pub bootloader_contents_hash: Vec<u8>,
    pub event_queue_state_hash: Vec<u8>,
    pub sys_logs: Vec<u8>,
    pub total_pubdata: Vec<u8>,
}

pub fn parse_commit_batch_info(
    func: &Function,
    calldata: &[u8],
    protocol_version: u16,
) -> Option<CommitBatchInfo> {
    use ethers::abi;

    if calldata.len() < 5 {
        return None;
    }

    let mut parsed_input = func.decode_input(&calldata[4..]).unwrap();

    if protocol_version < 26 {
        let second_param = parsed_input.pop().unwrap();

        let abi::Token::Array(inner) = second_param else {
            return None;
        };

        let mut batch = None;

        for inner in inner.into_iter() {
            let abi::Token::Tuple(inner) = inner else {
                return None;
            };

            let [abi::Token::Uint(batch_number), abi::Token::Uint(timestamp), abi::Token::Uint(index_repeated_storage_changes), abi::Token::FixedBytes(new_state_root), abi::Token::Uint(number_l1_txns), abi::Token::FixedBytes(priority_operations_hash), abi::Token::FixedBytes(bootloader_contents_hash), abi::Token::FixedBytes(event_queue_state_hash), abi::Token::Bytes(sys_logs), abi::Token::Bytes(total_pubdata)] =
                inner.as_slice()
            else {
                return None;
            };

            batch = Some(CommitBatchInfo {
                batch_number: batch_number.clone(),
                timestamp: timestamp.clone(),
                index_repeated_storage_changes: index_repeated_storage_changes.clone(),
                new_state_root: new_state_root.clone(),
                number_l1_txns: number_l1_txns.clone(),
                priority_operations_hash: priority_operations_hash.clone(),
                bootloader_contents_hash: bootloader_contents_hash.clone(),
                event_queue_state_hash: event_queue_state_hash.clone(),
                sys_logs: sys_logs.clone(),
                total_pubdata: total_pubdata.clone(),
            });
        }

        return batch;
    } else {
        assert_eq!(parsed_input.len(), 4);

        let commit_data = parsed_input.pop().unwrap();

        let abi::Token::Bytes(mut commit_data_bytes) = commit_data else {
            return None;
        };

        commit_data_bytes = commit_data_bytes[1..].to_vec();

        let combined_params = vec![
            (*STORED_BATCH_INFO_PARAMS).clone(),
            ParamType::Array(Box::new((*COMMIT_BATCH_INFO_PARAMS).clone())),
        ];

        let res = ethers::core::abi::decode(&combined_params, &commit_data_bytes);

        if res.is_err() {
            return None;
        }

        let decoded_input = res.unwrap();

        if decoded_input.len() != 2 {
            return None;
        }

        let abi::Token::Array(commit_batches) = decoded_input[1].clone() else {
            return None;
        };

        if commit_batches.len() != 1 {
            return None;
        }

        let abi::Token::Tuple(commit_batch) = commit_batches[0].clone() else {
            return None;
        };

        if commit_batch.len() != 10 {
            return None;
        };

        let [abi::Token::Uint(batch_number), abi::Token::Uint(timestamp), abi::Token::Uint(index_repeated_storage_changes), abi::Token::FixedBytes(new_state_root), abi::Token::Uint(number_l1_txns), abi::Token::FixedBytes(priority_operations_hash), abi::Token::FixedBytes(bootloader_contents_hash), abi::Token::FixedBytes(event_queue_state_hash), abi::Token::Bytes(sys_logs), abi::Token::Bytes(total_pubdata)] =
            commit_batch.as_slice()
        else {
            return None;
        };

        return Some(CommitBatchInfo {
            batch_number: batch_number.clone(),
            timestamp: timestamp.clone(),
            index_repeated_storage_changes: index_repeated_storage_changes.clone(),
            new_state_root: new_state_root.clone(),
            number_l1_txns: number_l1_txns.clone(),
            priority_operations_hash: priority_operations_hash.clone(),
            bootloader_contents_hash: bootloader_contents_hash.clone(),
            event_queue_state_hash: event_queue_state_hash.clone(),
            sys_logs: sys_logs.clone(),
            total_pubdata: total_pubdata.clone(),
        });
    }
}

pub fn parse_batch_proof(
    function: &Function,
    calldata: &[u8],
    protocol_version: u16,
    network: &str,
) -> Option<ProofType> {
    let parsed_input = function.decode_input(&calldata[4..]).unwrap();

    if protocol_version < 26 {
        let Token::Tuple(proof) = parsed_input.as_slice().last().unwrap() else {
            return None;
        };

        assert_eq!(proof.len(), 2);

        let Token::Array(serialized_proof) = proof[1].clone() else {
            return None;
        };

        let proof = serialized_proof
            .iter()
            .filter_map(|e| {
                if let Token::Uint(x) = e {
                    Some(x.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<U256>>();

        if network != "mainnet" && serialized_proof.len() == 0 {
            return None;
        }

        Some(ProofType::Plonk(deserialize_proof(proof)))
    } else {
        let Token::Bytes(proof_data) = parsed_input.as_slice().last().unwrap() else {
            return None;
        };

        let stored_batch_info_params = ParamType::Tuple(vec![
            ParamType::Uint(64),
            ParamType::FixedBytes(32),
            ParamType::Uint(64),
            ParamType::Uint(256),
            ParamType::FixedBytes(32),
            ParamType::FixedBytes(32),
            ParamType::Uint(256),
            ParamType::FixedBytes(32),
        ]);

        let combined_params = vec![
            stored_batch_info_params.clone(),
            ParamType::Array(Box::new(stored_batch_info_params)),
            ParamType::Array(Box::new(ParamType::Uint(256))),
        ];

        let proof = ethers::core::abi::decode(&combined_params, &proof_data[1..]).unwrap();

        assert_eq!(proof.len(), 3);

        let Token::Array(serialized_proof) = proof[2].clone() else {
            return None;
        };

        let proof = serialized_proof
            .iter()
            .filter_map(|e| {
                if let Token::Uint(x) = e {
                    Some(x.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<U256>>();

        if network != "mainnet" && serialized_proof.len() == 0 {
            return None;
        }

        if protocol_version == 26 {
            return Some(ProofType::Plonk(deserialize_proof(proof)));
        }

        if proof[0] == FFLONK_VERIFICATION_TYPE {
            Some(ProofType::Fflonk(deserialize_fflonk_proof(
                proof[1..].to_vec(),
            )))
        } else {
            Some(ProofType::Plonk(deserialize_proof(proof[1..].to_vec())))
        }
    }
}
