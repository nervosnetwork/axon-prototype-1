use ckb_handler::types::{BatchMintSudt, CKBMessage, MintSudt};
use common_crypto::{HashValue, PrivateKey, Secp256k1PrivateKey, Signature};
use muta_protocol::types as muta_types;
use muta_protocol::types::JsonString;
use rand::random;
use std::convert::TryFrom;

pub fn get_random_bytes(len: usize) -> muta_types::Bytes {
    let vec: Vec<u8> = (0..len).map(|_| random::<u8>()).collect();
    muta_types::Bytes::from(vec)
}

pub fn get_chain_id() -> muta_types::Hash {
    muta_types::Hash::from_hex("0xb6a4d7da21443f5e816e8700eea87610e6d769657d6b8ec73028457bf2ca4036")
        .unwrap()
}

pub fn gen_nonce() -> muta_types::Hash {
    muta_types::Hash::digest(get_random_bytes(10))
}

pub fn gen_raw_tx(payload: JsonString) -> muta_types::RawTransaction {
    muta_types::RawTransaction {
        chain_id:     get_chain_id(),
        nonce:        gen_nonce(),
        timeout:      36499,
        cycles_price: 1,
        cycles_limit: 100,
        request:      gen_transaction_request(payload),
    }
}

pub fn gen_transaction_request(paload: JsonString) -> muta_types::TransactionRequest {
    muta_types::TransactionRequest {
        service_name: "ckb_handler".to_owned(),
        method:       "submit_message".to_owned(),
        payload:      paload,
    }
}

pub fn gen_ckb_message(batch_mints: Vec<MintSudt>) -> String {
    let batch_mint_payload = BatchMintSudt { batch: batch_mints };
    let batch_mint_payload =
        muta_types::Bytes::from(serde_json::to_vec(&batch_mint_payload).unwrap());
    let ckb_message_payload = "0x".to_owned() + &hex::encode(batch_mint_payload.clone());
    let payload_hash = muta_types::Hash::digest(batch_mint_payload);
    let hash_value = HashValue::try_from(payload_hash.as_bytes().as_ref()).unwrap();
    let private_key = muta_types::Hex::from_string(
        "0x30269d47fcf602b889243722b666881bf953f1213228363d34cf04ddcd51dfd2".to_owned(),
    )
    .unwrap()
    .as_bytes()
    .unwrap();
    let secp_private = Secp256k1PrivateKey::try_from(private_key.as_ref()).unwrap();
    let signature = secp_private.sign_message(&hash_value).to_bytes();
    let signature = "0x".to_owned() + &hex::encode(signature.clone());
    let ckb_message = CKBMessage {
        payload:   muta_types::Hex::from_string(ckb_message_payload).unwrap(),
        signature: muta_types::Hex::from_string(signature).unwrap(),
    };
    serde_json::to_string(&ckb_message).unwrap()
}
