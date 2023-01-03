use anyhow::Result;
use rand::distributions::DistString;

pub fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

pub fn rand_string(length: usize) -> String {
    rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), length)
}
