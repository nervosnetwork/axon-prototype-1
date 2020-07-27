use super::*;

use ckb_system_scripts::BUNDLED_CELL;
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
    H256,
};
use ckb_tool::{
    ckb_error::assert_error_eq,
    ckb_hash::{blake2b_256, new_blake2b},
    ckb_script::ScriptError,
};
use secp256k1::{PublicKey, SecretKey};

const MAX_CYCLES: u64 = 10000_0000;

// errors
const ERROR_AMOUNT: i8 = 5;

use utils::{gen_crosschain_data, gen_witness};

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    const SIGNATURE_SIZE: usize = 65;

    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
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

fn build_test_init_context(
    _inputs_token: Vec<u128>,
    outputs_token: Vec<u128>,
    is_v2: bool,
) -> (Context, TransactionView) {
    // deploy cross typescript
    let mut context = Context::default();
    let cross_type_bin: Bytes = if is_v2 {
        Loader::default().load_binary("crosschain-v2")
    } else {
        Loader::default().load_binary("centralized-crosschain")
    };

    let cross_type_out_point = context.deploy_contract(cross_type_bin);
    // deploy always_success script
    let always_success_out_point = context.deploy_contract(ALWAYS_SUCCESS.clone());

    // build lock script
    let lock_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // prepare inputs
    let input_ckb = Capacity::bytes(1000).unwrap().as_u64();
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(input_ckb.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let inputs = vec![input];

    // build cross typescript
    let cross_typescript_args: Bytes = if is_v2 {
        // hash of lockscript in the current cell
        lock_script.calc_script_hash().as_bytes()
    } else {
        // use tx.input[0].outpoint as args
        inputs[0].previous_output().as_bytes()
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

    // prepare outputs
    let output_ckb = input_ckb;
    let outputs = outputs_token.iter().map(|_token| {
        CellOutput::new_builder()
            .capacity(output_ckb.pack())
            .lock(lock_script.clone())
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
        .cell_dep(lock_script_dep)
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
    let cross_type_bin: Bytes = Loader::default().load_binary("centralized-crosschain");
    let cross_type_out_point = context.deploy_contract(cross_type_bin);
    // deploy always_success script
    let always_success_out_point = context.deploy_contract(ALWAYS_SUCCESS.clone());

    // build lock script
    let lock_script = context
        .build_script(&always_success_out_point, Default::default())
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    // build cross typescript
    // let cross_typescript_args: Bytes = inputs[0].previous_output().as_bytes();
    let cross_typescript_args: Bytes = [0u8; 32].to_vec().into();
    let cross_typescript = context
        .build_script(&cross_type_out_point, cross_typescript_args)
        .expect("script");
    let cross_type_script_dep = CellDep::new_builder()
        .out_point(cross_type_out_point)
        .build();

    // prepare inputs
    let crosschain_data = {
        let privkey_bytes =
            hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0")
                .unwrap();
        let secret_key = SecretKey::parse_slice(privkey_bytes.as_slice()).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&secret_key);

        let mut blake2b = new_blake2b();
        let mut pubkey_hash = [0u8; 32];
        blake2b.update(secp_pubkey.serialize_compressed().to_vec().as_slice());
        blake2b.finalize(&mut pubkey_hash);

        dbg!(&pubkey_hash.len());

        let cc_data: Vec<u8> = gen_crosschain_data(&pubkey_hash.to_vec().as_slice()[0..20]).into();
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
    let cc_witness: Vec<u8> = gen_witness().into();
    let witness = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(cc_witness)).pack())
        .build();

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(vec![crosschain_data].pack())
        .witness(witness.as_bytes().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(cross_type_script_dep)
        .build();
    (context, tx)
}

fn build_test_transfer_context_v2(
    _inputs_token: Vec<u128>,
    outputs_token: Vec<u128>,
    validator_privkey: Privkey,
) -> (Context, TransactionView) {
    // deploy cross typescript
    let mut context = Context::default();
    let cross_type_bin: Bytes = Loader::default().load_binary("crosschain-v2");
    let cross_type_out_point = context.deploy_contract(cross_type_bin);

    // get pubkey_hash of the validator
    let pubkey = validator_privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());

    // deploy secp256 script
    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_sighash_all_bin = BUNDLED_CELL
        .get("specs/cells/secp256k1_blake160_sighash_all")
        .unwrap();
    let secp256k1_data_out_point = context.deploy_contract(secp256k1_data_bin.to_vec().into());
    let lock_out_point = context.deploy_contract(secp256k1_sighash_all_bin.to_vec().into());
    let lock_script = context
        .build_script(&lock_out_point, Default::default())
        .expect("script")
        .as_builder()
        .args(pubkey_hash.to_vec().pack())
        .build();
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
        let privkey_bytes =
            hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0")
                .unwrap();
        let secret_key = SecretKey::parse_slice(privkey_bytes.as_slice()).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&secret_key);

        let mut blake2b = new_blake2b();
        let mut pubkey_hash = [0u8; 32];
        blake2b.update(secp_pubkey.serialize_compressed().to_vec().as_slice());
        blake2b.finalize(&mut pubkey_hash);

        dbg!(&pubkey_hash.len());

        let cc_data: Vec<u8> = gen_crosschain_data(&pubkey_hash.to_vec().as_slice()[0..20]).into();
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
    let cc_witness: Vec<u8> = gen_witness().into();
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
        .cell_dep(cross_type_script_dep)
        .build();
    (context, tx)
}

#[test]
fn test_init() {
    let (mut context, tx) = build_test_init_context(vec![], vec![100], false);
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    dbg!("init crosschain tx v1", &cycles);
}

#[test]
fn test_init_v2() {
    let (mut context, tx) = build_test_init_context(vec![], vec![100], true);
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    dbg!("init crosschain tx v2", &cycles);
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
    let privkey = Generator::random_privkey();
    let (mut context, tx) = build_test_transfer_context_v2(vec![100], vec![100], privkey.clone());
    let tx = context.complete_tx(tx);

    // sign
    let tx = sign_tx(tx, &privkey);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");

    dbg!("transfer tx v2", &cycles);
}
