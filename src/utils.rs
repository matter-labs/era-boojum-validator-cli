use std::{env, fs::File, io};

const VERIFICATION_KEY_FILE_GITHUB: &str = "https://raw.githubusercontent.com/matter-labs/era-contracts/main/tools/data/scheduler_key.json";

pub async fn check_should_download_verification_key(update_verification_key: Option<bool>) {
    let file_path = "src/keys/scheduler_key.json";
    let file = env::current_dir().unwrap().join(file_path);
    let file_exists = file.exists();

    let should_update =
        update_verification_key.is_some() && update_verification_key.unwrap();

    if file_exists && !should_update {
        println!("verifiction key exists")
    } else {
        println!("verifiction key does not exist or update requested, downloading...");
        let resp = reqwest::get(VERIFICATION_KEY_FILE_GITHUB).await.expect("request failed");
        let body = resp.text().await.expect("body invalid");
        let mut out = File::create(file_path).expect("failed to create file");
        io::copy(&mut body.as_bytes(), &mut out).expect("failed to copy content");
    }
}
