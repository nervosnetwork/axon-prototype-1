use ckb_types::{
    bytes::Bytes,
    core::{cell::resolve_transaction, Capacity, Cycle, ScriptHashType},
    packed::{Byte32, CellInput, CellOutput, OutPoint, Script, WitnessArgs, Transaction},
    prelude::*,
    H160, H256,
};


use ckb_sdk::{
    rpc::{
        HttpRpcClient,
        LiveCell
    },
    constants::{
        SIGHASH_TYPE_HASH
    },

};

use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{
    CellDep,
    LockHashIndexState,
    // LiveCell
};
use faster_hex::{hex_decode, hex_string};
use lazy_static::lazy_static;
use ckb_sdk::rpc::TransactionView;


pub fn get_privkey_from_hex(privkey_hex: String) -> secp256k1::SecretKey {
    let mut privkey_bytes = [0u8; 32];
    hex_decode(&privkey_hex.as_bytes()[2..], &mut privkey_bytes);
    secp256k1::SecretKey::from_slice(&privkey_bytes[..]).unwrap()
}

pub fn gen_lock_hash(privkey_hex: String) -> H256 {
    let privkey = get_privkey_from_hex(privkey_hex);
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);

    let lock_arg = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed");

    dbg!( hex_string(&lock_arg.0[..]) );

    let lock_script = Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(lock_arg.as_bytes().to_vec()).pack())
        .build();

    lock_script.calc_script_hash().unpack()
}


pub fn gen_tx(ckb_client: &mut HttpRpcClient, lock_hash: H256) -> Transaction {
    let unspentCells = ckb_client.get_live_cells_by_lock_hash(
        lock_hash.clone(),
        0,
        20,
        None
    );


/*
    // build transaction
    let tx = Transaction::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(vec![crosschain_data].pack())
        .witness(witness.as_bytes().pack())
        .cell_dep(cross_lock_script_dep)
        .cell_dep(cross_type_script_dep)
        .build();

*/
    println!("lock_hash: {:?}",  hex_string(&lock_hash.0[..]));
    Transaction::default()
}

fn collect_live_cells(ckb_client: &mut HttpRpcClient, lock_hash: H256, capacity: Capacity) -> Vec<LiveCell> {
    const PER_PAGE: u64 = 20u64;

    let mut live_cells = Vec::new();
    let mut collected_capacity = 0;

    for i in 0.. {
        let cells = ckb_client.get_live_cells_by_lock_hash(
            lock_hash.clone(),
            i as u64,
            PER_PAGE,
            None,
        ).unwrap();

        if cells.is_empty() {
            panic!("can't find enough live cells");
        }
        let iter = cells.into_iter().filter(|cell| {
            cell.cell_output.type_.is_none()
        });
        for cell in iter {
            // let cell_capacity = cell.cell_output.capacity.value();
            let cell_capacity = cell.cell_output.capacity;
            dbg!(cell_capacity);
            // live_cells.push(cell);
            // collected_capacity += cell_capacity;
            // if collected_capacity > capacity.as_u64() {
            //     break;
            // }
        }
        if collected_capacity > capacity.as_u64() {
            break;
        }
    }
    live_cells
}