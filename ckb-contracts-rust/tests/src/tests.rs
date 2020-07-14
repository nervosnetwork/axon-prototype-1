use super::*;

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::*,
    prelude::*,
};
use ckb_tool::{
    ckb_hash,
    ckb_error::assert_error_eq,
    ckb_script::ScriptError,
};

const MAX_CYCLES: u64 = 1000_000_000;

// errors
const ERROR_AMOUNT: i8 = 5;

use utils::{
    gen_witness,
    gen_crosschain_data,
};

fn build_test_init_context(
    _inputs_token: Vec<u128>,
    outputs_token: Vec<u128>,
    is_init_mode: bool,
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
    let cross_typescript_args: Bytes = if is_init_mode {
        // use tx.input[0].outpoint as args
        inputs[0].previous_output().as_bytes()
    } else {
        // use zero hash as owner's lock which implies we can never enter owner mode
        [0u8; 32].to_vec().into()
    };

    println!("cross_typescript_args: {:?}", cross_typescript_args.to_vec());
    println!("tx.inputs[0].outpoint: {:?}", inputs[0].previous_output().as_bytes().to_vec());

    let cross_typescript = context
        .build_script(&cross_type_out_point, cross_typescript_args)
        .expect("script");
    let cross_type_script_dep = CellDep::new_builder().out_point(cross_type_out_point).build();

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
    let cross_type_script_dep = CellDep::new_builder().out_point(cross_type_out_point).build();


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
    ]).into();

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
        .cell_dep(lock_script_dep)
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
    println!("cycles: {}", cycles);
}

#[test]
fn test_transfer() {
    let (mut context, tx) = build_test_transfer_context(vec![100], vec![100]);
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");

    println!("tmp tx cycles: {}", cycles);
}

