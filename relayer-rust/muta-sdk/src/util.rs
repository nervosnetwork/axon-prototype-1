use muta_protocol::types as muta_types;
use rand::random;

pub fn clean_0x(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s[2..].to_owned()
    } else {
        s.to_owned()
    }
}

pub fn hex_to_bytes(s: &str) -> Result<muta_types::Bytes, hex::FromHexError> {
    Ok(muta_types::Bytes::from(hex::decode(&clean_0x(s))?))
}

pub fn hex_to_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    Ok(u64::from_str_radix(&clean_0x(s), 16)?)
}

pub fn u64_to_hex(n: u64) -> String {
    "0x".to_owned() + &hex::encode(n.to_be_bytes().to_vec())
}

pub fn bytes_to_hex(b: muta_types::Bytes) -> String {
    "0x".to_owned() + &hex::encode(b.as_ref())
}

pub fn random_nonce() -> muta_types::Hash {
    let vec: Vec<u8> = (0..32).map(|_| random::<u8>()).collect();
    muta_types::Hash::digest(muta_types::Bytes::from(vec))
}
