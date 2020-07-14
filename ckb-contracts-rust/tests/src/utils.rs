use super::*;
use types::*;
use molecule::prelude::*;
use ckb_tool::ckb_crypto::secp::{Privkey, Signature as CkbSignature};
use ckb_tool::ckb_hash;
use ckb_tool::ckb_types::{
    H256
};
use secp256k1::{SecretKey, PublicKey};

pub fn gen_witness(raw_sigs: Vec<&str>) -> molecule::bytes::Bytes {
    let height = 99u64;
    let header = MutaHeader::new_builder()
        .height(Uint64::from_slice(&height.to_le_bytes()).unwrap())
        .build();

    let message = Message::new_builder()
        .header(header)
        .build();

    let messages = MessageVec::new_builder()
        .push(message)
        .build();

    let raw_msg: Vec<u8> = messages.as_bytes().into();
    let sig_vec = raw_sigs
        .into_iter()
        .map(|sk| {
            let privkey_bytes = hex::decode(sk).unwrap();
            let privkey = Privkey::from_slice(privkey_bytes.as_slice());
            let ckb_sig: CkbSignature = sign_msg(raw_msg.as_slice(), &privkey);

            Signature::from_slice(ckb_sig.serialize().as_slice()).unwrap()
        }).collect::<Vec<_>>();

    println!("origin sig_vec: {:#?}", sig_vec.clone());

    let sigs = SignatureVec::new_builder()
        .set(sig_vec)
        .build();

    let wit = CrosschainWitnessBuilder::default()
        .messages(messages)
        .proof(sigs)
        .build();

    wit.as_bytes()
}

pub fn sign_msg(raw_msg: &[u8], privkey: &Privkey) -> CkbSignature {
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(raw_msg);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    privkey.sign_recoverable(&message).expect("sign")
}

pub fn gen_crosschain_data(secret_keys: Vec<&str>, threshold: u8) -> molecule::bytes::Bytes {
    let hash_vec = secret_keys
        .into_iter()
        .map(
            |sk| {
                let privkey_bytes = hex::decode(sk).unwrap();
                let secret_key = SecretKey::parse_slice(privkey_bytes.as_slice()).unwrap();
                let secp_pubkey = PublicKey::from_secret_key(&secret_key);

                let mut blake2b = ckb_hash::new_blake2b();
                let mut pubkey_hash = [0u8; 32];
                blake2b.update(secp_pubkey.serialize_compressed().to_vec().as_slice());
                blake2b.finalize(&mut pubkey_hash);

                Hash::from_slice(&pubkey_hash.to_vec().as_slice()[0..20]).unwrap()
            })
        .collect::<Vec<_>>();

    let hashes = Hashes::new_builder()
        .set(hash_vec)
        .build();


    let cc_data = CrosschainData::new_builder()
        .pubkey_hashes(hashes)
        .threshold(Byte::new(threshold))
        .build();

    cc_data.as_bytes()
}