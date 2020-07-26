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
    high_level::{load_cell, load_cell_data, load_cell_lock_hash, load_script, QueryIter},
};
use types::{CrosschainData, CrosschainDataReader, CrosschainWitness, CrosschainWitnessReader};

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

fn verify_init() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    let lock_hash = load_cell_lock_hash(0, Source::Output)?;

    debug!("args: {:?}, lock_hash: {:?}", &args[..], lock_hash);

    if &args[..] != lock_hash.as_ref() {
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
    let inputs_capacity = QueryIter::new(load_cell, Source::GroupInput)
        .map(|cell| cell.capacity().unpack())
        .sum::<u64>();
    let outputs_capacity = QueryIter::new(load_cell, Source::GroupOutput)
        .map(|cell| cell.capacity().unpack())
        .sum::<u64>();
    if inputs_capacity > outputs_capacity {
        return Err(Error::CapacityInvalid);
    }

    /*
     * Second, ensure crosschain cell is not changed
     */
    let input_data = load_cell_data(0, Source::GroupInput)?;
    let output_data = load_cell_data(0, Source::GroupOutput)?;
    if input_data != output_data {
        return Err(Error::OutDataInvalid);
    }

    /*
     * Third, check if args == hash of lockscript in the current cell
     */
    verify_init()
}

fn main() -> Result<(), Error> {
    let input_group_num = QueryIter::new(load_cell, Source::GroupInput).count();
    let output_group_num = QueryIter::new(load_cell, Source::GroupOutput).count();
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
