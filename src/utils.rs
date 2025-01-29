use std::env;

use ethers::abi::{Abi, Function};

/// Checks to see if the verification key exists for a given protocol version or an update has been requested and downloads it from github if needed.
pub async fn check_verification_key(protocol_version: String) {
    let file_path = format!(
        "src/keys/protocol_version/{}/scheduler_key.json",
        protocol_version
    );
    // If the key for the latest protocol version is not available in this repo yet, you can always find it at https://github.com/matter-labs/era-contracts/blob/main/tools/data/scheduler_key.json
    let err_msg = format!(
        "Verification key for protocol version {} is missing. Please add it to the keys folder.",
        protocol_version
    );
    ensure_key_file_exists(&file_path, &err_msg).await;
}

pub async fn ensure_key_file_exists(file_path: &String, err_msg: &String) {
    let file = env::current_dir().unwrap().join(file_path);
    let file_exists = file.exists();

    if !file_exists {
        eprintln!("{}", err_msg);
        std::process::exit(1)
    }
}

pub fn get_scheduler_key_override(
    network: &str,
    protocol_version: &str,
    batch_number: u64,
) -> Option<String> {
    // This override is needed because we discovered a deviation between our in and out of circuit
    // vms. The choice was made to update the verifier vs bumping the protocol version as it would have
    // required a batch rollback.
    if network == "sepolia" {
        if protocol_version == "24" {
            if batch_number <= 8853u64 {
                return Some("src/keys/protocol_version/24/scheduler_key_v0.json".to_string());
            } else if batch_number < 8923u64 {
                return Some("src/keys/protocol_version/24/scheduler_key_v1.json".to_string());
            } else if batch_number < 9218u64 {
                return Some("src/keys/protocol_version/24/scheduler_key_v2.json".to_string());
            }
        }
    }
    None
}

pub fn get_abi_for_protocol_version(protocol_version: u16) -> Abi {
    if protocol_version < 26 {
        Abi::load(&include_bytes!("../abis/IZkSync.json")[..]).unwrap()
    } else {
        Abi::load(&include_bytes!("../abis/IZKChain.json")[..]).unwrap()
    }
}

pub fn get_commit_function_for_protocol_version(
    protocol_version: u16,
) -> (Function, Option<Function>) {
    let contract_abi = get_abi_for_protocol_version(protocol_version);
    let function_name = if protocol_version < 23 {
        "commitBatches"
    } else {
        "commitBatchesSharedBridge"
    };

    let function = contract_abi.functions_by_name(&function_name).unwrap()[0].clone();

    (function, None)
}

pub fn get_prove_function_for_protocol_version(
    protocol_version: u16,
) -> (Function, Option<Function>) {
    let contract_abi = get_abi_for_protocol_version(protocol_version);
    let function_name = if protocol_version < 23 {
        "proveBatches"
    } else {
        "proveBatchesSharedBridge"
    };

    let function = contract_abi.functions_by_name(&function_name).unwrap()[0].clone();

    (function, None)
}
