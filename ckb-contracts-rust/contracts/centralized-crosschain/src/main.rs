#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

mod types;

// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    debug, default_alloc, entry,
    error::SysError,
    high_level::{
        load_cell, load_cell_data, load_cell_data_hash, load_input_out_point, load_script,
        load_witness_args, QueryIter,
    },
};
use types::{CrosschainData, CrosschainDataReader, CrosschainWitness, CrosschainWitnessReader};

use blake2b_ref::{Blake2b, Blake2bBuilder};

use secp256k1::{recover, Message, RecoveryId, Signature};

const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

entry!(entry);
default_alloc!();

/// Program entry
fn entry() -> i8 {
    // Call main function and return error code
    match main() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

/// Error
#[repr(i8)]
enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    ArgsInvalid,
    GroupOutputNotOne,
    GroupInputMoreThanOne,
    CapacityInvalid,
    OutDataInvalid,
    WitnessMissInputType,
    WitnessInvalidEncoding,
    CrosschainInputDataEncodingInvalid,
    InvalidSignature,
    PubkeyHashMismatch,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}

fn verify_init() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    let outpoint = load_input_out_point(0, Source::Input)?.as_bytes();

    if &args[..] != outpoint.as_ref() {
        Err(Error::ArgsInvalid)
    } else {
        Ok(())
    }
}

fn verify_transfer() -> Result<(), Error> {
    /*
     * First, ensures that the input capacity is not less than output capacity in
     * typescript groups for the input and output cells.
     */
    debug!("begin verify_transfer");

    let inputs_capacity = QueryIter::new(load_cell, Source::GroupInput)
        .map(|cell| cell.capacity().unpack())
        .sum::<u64>();
    let outputs_capacity = QueryIter::new(load_cell, Source::GroupOutput)
        .map(|cell| cell.capacity().unpack())
        .sum::<u64>();
    if inputs_capacity > outputs_capacity {
        return Err(Error::CapacityInvalid);
    }

    debug!("after capacity cmp");

    // ensure data does not change
    let input_data_hash = load_cell_data_hash(0, Source::GroupInput)?;
    let output_data_hash = load_cell_data_hash(0, Source::GroupOutput)?;

    debug!("input_data_hash: {:?}, output_data_hash: {:?}", input_data_hash, output_data_hash);

    if input_data_hash != output_data_hash {
        return Err(Error::OutDataInvalid);
    }

    debug!("before verify signature");
    let witness_args = load_witness_args(0, Source::Input)?.input_type();
    if witness_args.is_none() {
        return Err(Error::WitnessMissInputType);
    }
    let witness_args: Bytes = witness_args.to_opt().unwrap().unpack();

    debug!("witness_args: {:?}", &witness_args[..]);
    debug!("before CrosschainWitnessReader::verify");
    if CrosschainWitnessReader::verify(&witness_args, true).is_err() {
        return Err(Error::WitnessInvalidEncoding);
    }
    let crosschain_witness = CrosschainWitness::new_unchecked(witness_args.into());
    let messages = crosschain_witness.messages().as_bytes();
    let proof = crosschain_witness.proof();


    debug!("proof: {:?}",proof);
    debug!("before load_cell_data");
    let crosschain_data_raw = load_cell_data(0, Source::GroupInput)?;
    debug!("crosschain_data_raw: {:?}", crosschain_data_raw);


    if CrosschainDataReader::verify(&crosschain_data_raw, false).is_err() {
        return Err(Error::CrosschainInputDataEncodingInvalid);
    }
    let crosschain_data = CrosschainData::new_unchecked(crosschain_data_raw.into());
    let pubkey_hash = crosschain_data.pubkey_hash().as_bytes();

    debug!("pubkey_hash from crosschain_data: {:?}", pubkey_hash);

    let mut blake2b = new_blake2b();
    let mut message_hash = [0u8; 32];
    blake2b.update(messages.as_ref() );
    blake2b.finalize(&mut message_hash);


    debug!("message_hash.len = {}", message_hash.len() );
    debug!("before Signature parse_slice");


    let sig = Signature::parse_slice(&proof.as_slice()[0..64]).unwrap();
    let rec_id = RecoveryId::parse(proof.as_slice()[64]).unwrap();
    let msg = Message::parse_slice(&message_hash).unwrap();
    let recover_pubkey = recover(&msg, &sig, &rec_id)
        .map_err(|_e| Error::InvalidSignature)?
        .serialize_compressed();

    let mut blake2b = new_blake2b();
    let mut recover_pubkey_hash = [0u8; 32];
    blake2b.update(recover_pubkey.as_ref());
    blake2b.finalize(&mut recover_pubkey_hash);


    debug!("recover_pubkey_hash: {:?}", recover_pubkey_hash);

    if &recover_pubkey_hash[0..20] != pubkey_hash.as_ref() {
        return Err(Error::PubkeyHashMismatch);
    }

    debug!("sig verified");
    Ok(())
}

fn main() -> Result<(), Error> {
    let input_group_num = QueryIter::new(load_cell, Source::GroupInput).count();
    let output_group_num = QueryIter::new(load_cell, Source::GroupOutput).count();
    debug!("input_group_num: {}", input_group_num);
    debug!("output_group_num: {}", output_group_num);

    if output_group_num != 1 {
        return Err(Error::GroupOutputNotOne);
    }
    if input_group_num != 0 && input_group_num != 1 {
        return Err(Error::GroupInputMoreThanOne);
    }

    if input_group_num == 0 {
        verify_init()
    } else {
        verify_transfer()
    }
}
