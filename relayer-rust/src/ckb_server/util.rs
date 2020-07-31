use crate::ckb_server::{
    centralized_witness::gen_witness,
    indexer::{Cell, IndexerRpcClient, Order, Pagination, ScriptType, SearchKey},
};

use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    packed,
    prelude::*,
    H160, H256,
};

use crate::config::{Loader, RelayerConfig};
use ckb_crypto::secp::{Privkey, SECP256K1};
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::{
    JsonBytes, Script as JsonScript, ScriptHashType as JsonScriptHashType, Uint32,
};
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::{HttpRpcClient, Script},
    GenesisInfo,
};
use faster_hex::{hex_decode, hex_string};
use muta_protocol::types as muta_types;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

const TX_FEE: u64 = 1_0000_0000;
const SIGNATURE_SIZE: usize = 65;
const SUDT_CELL_CAPACITY: u64 = 16 * 100000000 + 14100000000;

pub fn get_privkey_from_hex(privkey_hex: String) -> secp256k1::SecretKey {
    let mut privkey_bytes = [0u8; 32];
    hex_decode(&privkey_hex.as_bytes()[2..], &mut privkey_bytes)
        .expect("hex decode privkey_hex error");
    secp256k1::SecretKey::from_slice(&privkey_bytes[..]).unwrap()
}

pub fn gen_lock_args(privkey_hex: String) -> H160 {
    let privkey = get_privkey_from_hex(privkey_hex);
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &privkey);

    let lock_arg = H160::from_slice(&blake2b_256(&pubkey.serialize()[..])[0..20])
        .expect("Generate hash(H160) from pubkey failed");
    lock_arg
}

pub fn gen_lock_hash(privkey_hex: String) -> H256 {
    let lock_args = gen_lock_args(privkey_hex);
    let lock_script = gen_lockscript(lock_args);
    let lock_hash: H256 = lock_script.calc_script_hash().unpack();
    println!("lock_hash: {:?}", hex_string(&lock_hash.0[..]));
    lock_hash
}

pub fn gen_lockscript(lock_args: H160) -> packed::Script {
    packed::Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(lock_args.as_bytes().to_vec()).pack())
        .build()
}

pub fn gen_unlock_sudt_tx(
    genesis_info: &GenesisInfo,
    ckb_client: &mut HttpRpcClient,
    ckb_indexer_client: &mut IndexerRpcClient,
    balance_sum: &mut HashMap<muta_types::Hash, u128>,
    assets: &mut HashMap<muta_types::Hash, HashMap<String, u128>>,
) -> packed::Transaction {
    let relayer_config = Loader::default().load_relayer_config();
    let validator_privkey_hex = relayer_config["ckb"]["privateKey"]
        .as_str()
        .expect("validator private key invalid");
    let deploy_tx_hash = relayer_config.get_tx_hash("deployTxHash");
    let crosschain_cell_tx_hash = relayer_config.get_tx_hash("createCrosschainCellTxHash");

    // outpoint
    let sudt_type_out_point = packed::OutPoint::new_builder()
        .tx_hash(deploy_tx_hash.clone())
        .index(0u32.pack())
        .build();
    let cross_type_out_point = packed::OutPoint::new_builder()
        .tx_hash(deploy_tx_hash.clone())
        .index(1u32.pack())
        .build();
    let cross_lock_out_point = packed::OutPoint::new_builder()
        .tx_hash(deploy_tx_hash.clone())
        .index(2u32.pack())
        .build();
    let crosschain_cell_out_point = packed::OutPoint::new_builder()
        .tx_hash(crosschain_cell_tx_hash.clone())
        .index(1u32.pack())
        .build();

    // get crosschain cell
    let (input_ckb, input_data) = {
        let cell_with_status = ckb_client
            .get_live_cell(crosschain_cell_out_point.clone(), true)
            .expect("get_live_cell error");
        let cell_info = cell_with_status.cell.expect("cell is none");

        let input_ckb = cell_info.output.capacity.value();
        let cell_data = cell_info.data.expect("cell data is none");

        (input_ckb, cell_data.content.into_bytes())
    };

    // cell deps
    let secp256_dep: packed::CellDep = genesis_info.sighash_dep();
    let cross_type_script_dep = packed::CellDep::new_builder()
        .out_point(cross_type_out_point.clone())
        .build();
    let cross_lock_script_dep = packed::CellDep::new_builder()
        .out_point(cross_lock_out_point.clone())
        .build();
    let sudt_script_dep = packed::CellDep::new_builder()
        .out_point(sudt_type_out_point.clone())
        .build();

    // lockscript && typescript
    let cross_lockscript: Script = relayer_config.get_script("crosschainLockscript");
    let validators_lockscript: Script = relayer_config.get_script("validatorsLockscript");
    let cross_typescript: Script = relayer_config.get_script("crosschainTypescript");
    let sudt_typescript: Script = relayer_config.get_script("udtScript");

    // get input from crosschainCell
    let input = packed::CellInput::new_builder()
        .previous_output(crosschain_cell_out_point.clone())
        .build();
    let mut inputs = vec![input];

    // generate output cell of crosschain
    let output_ckb = input_ckb;
    let output = packed::CellOutput::new_builder()
        .capacity(output_ckb.pack())
        .lock(validators_lockscript.into())
        .type_(Some(packed::Script::from(cross_typescript)).pack())
        .build();
    let mut outputs = vec![output];

    // outputs_data
    let mut outputs_data: Vec<Bytes> = vec![input_data];

    // add inputs of cc_lockscript to unlock the sudt which is in balance_sum
    let (inputs_cc_sudt, back_to_cc, inputs_capacity) =
        collect_inputs_cc_sudt(ckb_indexer_client, balance_sum, cross_lockscript.clone());
    inputs.extend(inputs_cc_sudt);

    // add outputs of sudt to unlock
    let mut outputs_capacity = 0u64;
    for (asset_id, asset_map) in assets.iter() {
        for (receiver, amount) in asset_map {
            let receiver_lockscript = {
                let mut data = [0u8; 20];
                hex_decode(&receiver.as_bytes()[2..], &mut data[..])
                    .expect("decode receiver error");
                let lock_args = H160::from(data);

                gen_lockscript(lock_args)
            };
            let typescript = Script {
                code_hash: sudt_typescript.code_hash.clone(),
                hash_type: sudt_typescript.hash_type.clone(),
                args:      JsonBytes::from_bytes(asset_id.as_bytes()),
            };

            outputs.push(
                packed::CellOutput::new_builder()
                    .capacity(SUDT_CELL_CAPACITY.pack())
                    .lock(receiver_lockscript.into())
                    .type_(Some(packed::Script::from(typescript)).pack())
                    .build(),
            );

            let data = &amount.to_le_bytes()[..];
            outputs_data.push(Bytes::copy_from_slice(data));
            outputs_capacity += SUDT_CELL_CAPACITY;
        }
    }

    // add outputs of sudt change from back_to_cc
    for (asset_id, amount) in back_to_cc.iter() {
        let typescript = Script {
            code_hash: sudt_typescript.code_hash.clone(),
            hash_type: sudt_typescript.hash_type.clone(),
            args:      JsonBytes::from_bytes(asset_id.as_bytes()),
        };

        outputs.push(
            packed::CellOutput::new_builder()
                .capacity(SUDT_CELL_CAPACITY.pack())
                .lock(cross_lockscript.clone().into())
                .type_(Some(packed::Script::from(typescript)).pack())
                .build(),
        );

        let data = &amount.to_le_bytes()[..];
        outputs_data.push(Bytes::copy_from_slice(data));
        outputs_capacity += SUDT_CELL_CAPACITY;
    }

    // add fee payer
    // need capacity under this condition
    if outputs_capacity + TX_FEE > inputs_capacity {
        let need_capacity = outputs_capacity + TX_FEE - inputs_capacity;

        let lock_args = gen_lock_args(validator_privkey_hex.to_owned());
        let (inputs_payer, payer_given_capacity, lock_payer) =
            collect_live_inputs(ckb_indexer_client, need_capacity, lock_args);
        inputs.extend(inputs_payer);

        let payer_change: u64 = payer_given_capacity + inputs_capacity - TX_FEE - outputs_capacity;
        // add outputs of payer
        outputs.push(
            packed::CellOutput::new_builder()
                .capacity(payer_change.pack())
                .lock(lock_payer.into())
                .build(),
        );
        outputs_data.push(Bytes::new());
    }

    // prepare witness for WitnessArgs.InputType
    let cc_witness: Vec<u8> = gen_witness();
    let _witness = packed::WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(cc_witness)).pack())
        .build();

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(secp256_dep)
        .cell_dep(cross_type_script_dep)
        .cell_dep(cross_lock_script_dep)
        .cell_dep(sudt_script_dep)
        .build();

    // sign
    let bytes = hex::decode(&validator_privkey_hex.as_bytes()[2..]).unwrap();
    let privkey = Privkey::from_slice(bytes.as_ref());
    let tx = sign_tx(tx, &privkey);
    tx.data()
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = packed::WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_SIZE, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn collect_live_inputs(
    ckb_indexer_client: &mut IndexerRpcClient,
    need_capacity: u64,
    lock_args: H160,
) -> (Vec<packed::CellInput>, u64, Script) {
    let rpc_lock = JsonScript {
        code_hash: SIGHASH_TYPE_HASH.clone(),
        hash_type: JsonScriptHashType::Type,
        args:      JsonBytes::from_vec(lock_args.0.to_vec()),
    };

    // no need inputs, just gen the lockscript returned
    if need_capacity == 0 {
        return (vec![], 0, Script::from(rpc_lock));
    }

    let search_key = SearchKey {
        script:      rpc_lock.clone(),
        script_type: ScriptType::Lock,
        args_len:    None,
    };
    let limit = Uint32::try_from(100u32).unwrap();

    let live_cells: Pagination<Cell> = ckb_indexer_client
        .get_cells(search_key, Order::Asc, limit, None)
        .unwrap();

    // unspent_cells -> inputs
    let mut actual_capacity = 0u64;
    let mut inputs = vec![];
    for (_index, cell) in live_cells.objects.iter().enumerate() {
        // must no type script in case that using the special cells
        if cell.output.type_.is_some() {
            continue;
        }

        let input_out_point: packed::OutPoint = cell.out_point.clone().into();
        let input = packed::CellInput::new_builder()
            .previous_output(input_out_point.clone())
            .build();

        actual_capacity += cell.output.capacity.value();
        inputs.push(input);
        if actual_capacity >= need_capacity {
            break;
        }
    }

    (inputs, actual_capacity, Script::from(rpc_lock))
}

pub fn collect_inputs_cc_sudt(
    ckb_indexer_client: &mut IndexerRpcClient,
    balance_sum: &mut HashMap<muta_types::Hash, u128>,
    cross_lockscript: Script,
) -> (Vec<packed::CellInput>, HashMap<muta_types::Hash, u128>, u64) {
    let rpc_lock = JsonScript {
        code_hash: cross_lockscript.code_hash,
        hash_type: cross_lockscript.hash_type,
        args:      cross_lockscript.args,
    };

    let search_key = SearchKey {
        script:      rpc_lock,
        script_type: ScriptType::Lock,
        args_len:    None,
    };
    let limit = Uint32::try_from(100u32).unwrap();
    let live_cells: Pagination<Cell> = ckb_indexer_client
        .get_cells(search_key, Order::Asc, limit, None)
        .unwrap();

    let mut inputs = vec![];
    let mut inputs_capacity = 0u64;
    let mut back_to_cc = HashMap::<muta_types::Hash, u128>::new();

    for (_index, cell) in live_cells.objects.iter().enumerate() {
        // just collect the sudt typescript
        if cell.output.type_.is_none() {
            continue;
        }
        let sudt_id = {
            let typescript = cell.output.type_.clone().unwrap();
            typescript.args
        };

        let res = muta_types::Hash::from_bytes(sudt_id.into_bytes());
        if res.is_err() {
            continue;
        }
        let asset_id = res.unwrap();
        if !balance_sum.contains_key(&asset_id) {
            continue;
        }
        let given_amount: u128 = {
            let mut data = [0u8; 16];
            data.copy_from_slice(cell.output_data.as_bytes());
            u128::from_le_bytes(data)
        };

        let input_out_point: packed::OutPoint = cell.out_point.clone().into();
        let input = packed::CellInput::new_builder()
            .previous_output(input_out_point.clone())
            .build();
        inputs.push(input);
        inputs_capacity += cell.output.capacity.value();

        let need_amount = balance_sum.entry(asset_id.clone()).or_insert(0);
        if *need_amount > given_amount {
            *need_amount -= given_amount;
        } else {
            *back_to_cc.entry(asset_id.clone()).or_insert(0) += given_amount - *need_amount;
            balance_sum.remove(&asset_id);
        }
    }

    (inputs, back_to_cc, inputs_capacity)
}

fn multi_sign_tx(
    tx: TransactionView,
    multi_sign_script: &Bytes,
    keys: &[&Privkey],
) -> TransactionView {
    let tx_hash = tx.hash();
    let signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == 0 {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                let witness = packed::WitnessArgs::new_unchecked(Unpack::<Bytes>::unpack(
                    &tx.witnesses().get(0).unwrap(),
                ));
                let mut lock = multi_sign_script.to_vec();
                let lock_without_sig = {
                    let sig_len = keys.len() * SIGNATURE_SIZE;
                    let mut buf = lock.clone();
                    buf.resize(buf.len() + sig_len, 0);
                    buf
                };
                let witness_without_sig = witness
                    .clone()
                    .as_builder()
                    .lock(Some(Bytes::from(lock_without_sig)).pack())
                    .build();
                let len = witness_without_sig.as_bytes().len() as u64;
                blake2b.update(&len.to_le_bytes());
                blake2b.update(&witness_without_sig.as_bytes());
                (1..tx.witnesses().len()).for_each(|n| {
                    let witness: Bytes = tx.witnesses().get(n).unwrap().unpack();
                    let len = witness.len() as u64;
                    blake2b.update(&len.to_le_bytes());
                    blake2b.update(&witness);
                });
                blake2b.finalize(&mut message);
                let message = H256::from(message);
                keys.iter().for_each(|key| {
                    let sig = key.sign_recoverable(&message).expect("sign");
                    lock.extend_from_slice(&sig.serialize());
                });
                witness
                    .as_builder()
                    .lock(Some(Bytes::from(lock)).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}
