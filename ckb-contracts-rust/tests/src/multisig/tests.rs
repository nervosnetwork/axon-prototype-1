use super::*;

use ckb_system_scripts::BUNDLED_CELL;
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::{self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use ckb_tool::{
    ckb_error::assert_error_eq,
    ckb_hash::{self, blake2b_256, new_blake2b},
    ckb_script::ScriptError,
};
use secp256k1::{PublicKey, SecretKey};

const MAX_CYCLES: u64 = 1000_000_000;

// errors
const ERROR_AMOUNT: i8 = 5;
const SIGNATURE_SIZE: usize = 65;

use utils::{gen_crosschain_data, gen_witness};

fn build_test_init_context(
    _inputs_token: Vec<u128>,
    outputs_token: Vec<u128>,
    is_init_mode: bool,
) -> (Context, TransactionView) {
    // deploy cross typescript
    let mut context = Context::default();
    let cross_type_bin: Bytes = Loader::default().load_binary("multisig-crosschain");
    let cross_type_out_point = context.deploy_contract(cross_type_bin);
    // deploy always_success script
    let always_success_out_point = context.deploy_contract(ALWAYS_SUCCESS.clone());

    // deploy lockscript script
    let cross_lock_bin: Bytes = Loader::default().load_binary("lockscript");
    let cross_lock_out_point = context.deploy_contract(cross_lock_bin);

    // build always success lock script
    let always_success_lock_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("script");
    let always_success_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // prepare inputs
    let input_ckb = Capacity::bytes(1000).unwrap().as_u64();
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(input_ckb.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let inputs = vec![input];

    // build cross typescript
    let cross_typescript_args: Bytes = if is_init_mode {
        // use tx.input[0].outpoint as args
        inputs[0].previous_output().as_bytes()
    } else {
        // use zero hash as owner's lock which implies we can never enter owner mode
        [0u8; 32].to_vec().into()
    };

    println!(
        "cross_typescript_args: {:?}",
        cross_typescript_args.to_vec()
    );
    println!(
        "tx.inputs[0].outpoint: {:?}",
        inputs[0].previous_output().as_bytes().to_vec()
    );

    let cross_typescript = context
        .build_script(&cross_type_out_point, cross_typescript_args)
        .expect("script");
    let cross_type_script_dep = CellDep::new_builder()
        .out_point(cross_type_out_point)
        .build();

    // build crosschain lock script
    let type_args: Byte32 = cross_typescript.calc_script_hash();
    println!("typescript hash: {:?}", type_args.clone());
    let cross_lock_script = context
        .build_script(&cross_lock_out_point, type_args.as_bytes())
        .expect("script");
    let cross_lock_script_dep = CellDep::new_builder()
        .out_point(cross_lock_out_point)
        .build();

    // prepare outputs
    let output_ckb = input_ckb;
    let outputs = outputs_token.iter().map(|_token| {
        CellOutput::new_builder()
            .capacity(output_ckb.pack())
            .lock(cross_lock_script.clone())
            .type_(Some(cross_typescript.clone()).pack())
            .build()
    });
    let output_data = Bytes::new();
    let outputs_data = vec![output_data];

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(always_success_script_dep)
        .cell_dep(cross_lock_script_dep)
        .cell_dep(cross_type_script_dep)
        .build();
    (context, tx)
}

fn build_test_transfer_context(
    _inputs_token: Vec<u128>,
    outputs_token: Vec<u128>,
) -> (Context, TransactionView) {
    // deploy cross typescript
    let mut context = Context::default();
    let cross_type_bin: Bytes = Loader::default().load_binary("multisig-crosschain");
    let cross_type_out_point = context.deploy_contract(cross_type_bin);
    // deploy lockscript script
    let cross_lock_bin: Bytes = Loader::default().load_binary("lockscript");
    let cross_lock_out_point = context.deploy_contract(cross_lock_bin);

    // build cross typescript
    // let cross_typescript_args: Bytes = inputs[0].previous_output().as_bytes();
    let cross_typescript_args: Bytes = [0u8; 32].to_vec().into();
    let cross_typescript = context
        .build_script(&cross_type_out_point, cross_typescript_args)
        .expect("script");
    let cross_type_script_dep = CellDep::new_builder()
        .out_point(cross_type_out_point)
        .build();

    // build crosschain lock script
    let type_args: Byte32 = cross_typescript.calc_script_hash();
    println!(
        "typescript hash: {:?}",
        type_args.clone().as_bytes().to_vec()
    );
    let cross_lock_script = context
        .build_script(&cross_lock_out_point, type_args.as_bytes())
        .expect("script");
    let cross_lock_script_dep = CellDep::new_builder()
        .out_point(cross_lock_out_point)
        .build();

    // prepare inputs
    let crosschain_data = {
        let secret_keys = vec![
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "0000000000000000000000000000000000000000000000000000000000000005",
        ];

        let cc_data: Vec<u8> = gen_crosschain_data(secret_keys, 4u8).into();
        Bytes::from(cc_data)
    };

    println!("crosschain_data: {:?}", crosschain_data.to_vec());

    let input_ckb = Capacity::bytes(1000).unwrap().as_u64();
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(input_ckb.pack())
            .lock(cross_lock_script.clone())
            .type_(Some(cross_typescript.clone()).pack())
            .build(),
        crosschain_data.clone(),
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let inputs = vec![input];

    // prepare outputs
    let output_ckb = input_ckb;
    let outputs = outputs_token.iter().map(|_token| {
        CellOutput::new_builder()
            .capacity(output_ckb.pack())
            .lock(cross_lock_script.clone())
            .type_(Some(cross_typescript.clone()).pack())
            .build()
    });

    // prepare witness for WitnessArgs.InputType
    let cc_witness: Vec<u8> = gen_witness(vec![
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000003",
        "0000000000000000000000000000000000000000000000000000000000000004",
        "0000000000000000000000000000000000000000000000000000000000000005",
    ])
    .into();

    println!("origin CrosschainWitness: {:?}", cc_witness.clone());
    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(cc_witness)).pack())
        .build();

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(vec![crosschain_data].pack())
        .witness(witness.as_bytes().pack())
        .cell_dep(cross_lock_script_dep)
        .cell_dep(cross_type_script_dep)
        .build();
    (context, tx)
}

fn build_test_transfer_context_v2(
    _inputs_token: Vec<u128>,
    outputs_token: Vec<u128>,
    validator_privkeys: Vec<Privkey>,
    threshold: u8,
) -> (Context, TransactionView) {
    // deploy cross typescript
    let mut context = Context::default();
    let cross_type_bin: Bytes = Loader::default().load_binary("centralized-crosschain-v2");
    let cross_type_out_point = context.deploy_contract(cross_type_bin);

    // deploy multisig secp256 script
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_multisig_all_bin = BUNDLED_CELL
        .get("specs/cells/secp256k1_blake160_multisig_all")
        .unwrap();
    let secp256k1_data_out_point = context.deploy_contract(secp256k1_data_bin.to_vec().into());
    let lock_out_point = context.deploy_contract(secp256k1_multisig_all_bin.to_vec().into());

    // multisig lock args
    let multi_sign_script = gen_multi_sign_script(&validator_privkeys, threshold, 0);
    let lock_args: [u8; 20] = blake160(&multi_sign_script);

    let lock_script = context
        .build_script(&lock_out_point, Default::default())
        .expect("script")
        .as_builder()
        .args(lock_args.to_vec().pack())
        .build();
    let secp256k1_multisig_dep = CellDep::new_builder().out_point(lock_out_point).build();
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    // build cross typescript
    // the difference between v1 and v2
    let cross_typescript_args = lock_script.calc_script_hash().as_bytes();
    let cross_typescript = context
        .build_script(&cross_type_out_point, cross_typescript_args)
        .expect("script");
    let cross_type_script_dep = CellDep::new_builder()
        .out_point(cross_type_out_point)
        .build();

    // prepare inputs
    let crosschain_data = {
        let secret_keys = vec![
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "0000000000000000000000000000000000000000000000000000000000000005",
        ];

        let cc_data: Vec<u8> = gen_crosschain_data(secret_keys, 4u8).into();
        Bytes::from(cc_data)
    };

    println!("crosschain_data: {:?}", crosschain_data.to_vec());

    let input_ckb = Capacity::bytes(1000).unwrap().as_u64();
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(input_ckb.pack())
            .lock(lock_script.clone())
            .type_(Some(cross_typescript.clone()).pack())
            .build(),
        crosschain_data.clone(),
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let inputs = vec![input];

    // prepare outputs
    let output_ckb = input_ckb;
    let outputs = outputs_token.iter().map(|_token| {
        CellOutput::new_builder()
            .capacity(output_ckb.pack())
            .lock(lock_script.clone())
            .type_(Some(cross_typescript.clone()).pack())
            .build()
    });

    // prepare witness for WitnessArgs.InputType
    let cc_witness: Vec<u8> = gen_witness(vec![
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000003",
        "0000000000000000000000000000000000000000000000000000000000000004",
        "0000000000000000000000000000000000000000000000000000000000000005",
    ])
    .into();
    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(cc_witness)).pack())
        .build();

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(vec![crosschain_data].pack())
        .witness(witness.as_bytes().pack())
        .cell_dep(secp256k1_data_dep)
        .cell_dep(secp256k1_multisig_dep)
        .cell_dep(cross_type_script_dep)
        .build();
    (context, tx)
}

#[test]
fn test_init() {
    let (mut context, tx) = build_test_init_context(vec![], vec![100], true);
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    dbg!("init tx", &cycles);
}

#[test]
fn test_transfer() {
    let (mut context, tx) = build_test_transfer_context(vec![100], vec![100]);
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");

    dbg!("transfer tx", &cycles);
}

#[test]
fn test_transfer_v2() {
    let keys = generate_keys(3);
    let threshold = 2u8;
    let (mut context, tx) =
        build_test_transfer_context_v2(vec![100], vec![100], keys.clone(), threshold);
    let tx = context.complete_tx(tx);

    // sign
    let wrong_keys = generate_keys(3);
    let multi_sign_script = gen_multi_sign_script(&keys, threshold, 0);
    let tx = multi_sign_tx(tx.clone(), &multi_sign_script, &[&keys[0], &keys[2]]);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");

    dbg!("transfer tx v2", &cycles);
}

fn generate_keys(n: usize) -> Vec<Privkey> {
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        keys.push(Generator::random_privkey());
    }

    keys
}

fn gen_multi_sign_script(keys: &[Privkey], threshold: u8, require_first_n: u8) -> Bytes {
    let pubkeys = keys
        .iter()
        .map(|key| key.pubkey().unwrap())
        .collect::<Vec<_>>();
    let mut script = vec![0u8, require_first_n, threshold, pubkeys.len() as u8];
    pubkeys.iter().for_each(|pubkey| {
        script.extend_from_slice(&blake160(&pubkey.serialize()));
    });
    script.into()
}

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
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
                let witness = WitnessArgs::new_unchecked(Unpack::<Bytes>::unpack(
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
