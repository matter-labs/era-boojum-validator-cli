use std::env;

/// Checks to see if the verification key exists for a given protocol version or an update has been requested and downloads it from github if needed.
pub async fn check_verification_key(protocol_version: String) {
    let file_path = format!("src/keys/protocol_version/{}/scheduler_key.json", protocol_version);
    // If the key for the latest protocol version is not available in this repo yet, you can always find it at https://github.com/matter-labs/era-contracts/blob/main/tools/data/scheduler_key.json
    let err_msg = format!("Verification key for protocol version {} is missing. Please add it to the keys folder.", protocol_version);
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
