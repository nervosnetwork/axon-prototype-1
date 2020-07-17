use super::*;
use types::*;
use molecule::prelude::*;
use ckb_tool::ckb_crypto::secp::{Privkey, Signature as CkbSignature};
use ckb_tool::ckb_hash;
use ckb_tool::ckb_types::{
    H256
};

pub fn gen_witness() -> molecule::bytes::Bytes {
    let height = 99u64;
    /*
        let assert_id =
        let event1 = Event::new_builder()
            .asset_id(assert_id)
            .ckb_receiver()
            .amount()
            .build();

        let event2 = Event::new_builder()
            .asset_id()
            .ckb_receiver()
            .amount()
            .build();

        let events = EventsVec::new_builder()
            .push( event1 )
            .push(event2)
            .build();
    */

    let header = MutaHeader::new_builder()
        .height(Uint64::from_slice(&height.to_le_bytes()).unwrap())
        .build();

    let message = Message::new_builder()
        .header(header)
        // .events(events)
        .build();

    let messages = MessageVec::new_builder()
        .push(message)
        .build();

    let privkey_bytes = hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0").unwrap();
    let privkey = Privkey::from_slice(privkey_bytes.as_slice());

    let raw_msg: Vec<u8> = messages.as_bytes().into();
    let proof: CkbSignature = sign_msg(raw_msg.as_slice(), &privkey);
    let wit = CrosschainWitnessBuilder::default()
        .messages(messages)
        .proof(Signature::from_slice(proof.serialize().as_slice()).unwrap())
        .build();

    println!("witness.proof: {:?}", proof.serialize());
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

pub fn gen_crosschain_data(pubkey_hash: &[u8]) -> molecule::bytes::Bytes {
    println!("gen_crosschain_data pubkey_hash:  {:?}", pubkey_hash);

    let cc_data = CrosschainData::new_builder()
        .pubkey_hash(Hash::from_slice(pubkey_hash).unwrap())
        .build();

    cc_data.as_bytes()
}
