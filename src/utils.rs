use std::{env, fs::File, io};

const VERIFICATION_KEY_FILE_GITHUB: &str = "https://raw.githubusercontent.com/matter-labs/era-contracts/main/tools/data/scheduler_key.json";

pub async fn update_verification_key_if_needed(update_verification_key: Option<bool>) {
    let file_path = "src/keys/scheduler_key.json";
    let file = env::current_dir().unwrap().join(file_path);
    let file_exists = file.exists();

    let should_update = update_verification_key.unwrap_or_default();

    if file_exists && !should_update {
        println!("verification key exists")
    } else {
        println!("verification key does not exist or update requested, downloading...");
        let resp = reqwest::get(VERIFICATION_KEY_FILE_GITHUB)
            .await
            .expect(&format!("failed to download file from {VERIFICATION_KEY_FILE_GITHUB}"));
        let body = resp.text().await.expect("body invalid");
        let mut out = File::create(file_path).expect(&format!("failed to create file {file_path}"));
        io::copy(&mut body.as_bytes(), &mut out).expect(&format!("failed to write verification key to {file_path}"));
    }
}
