mod config;
mod ckb_server;
mod muta_server;
mod tests;

use std::fs;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::{thread, time::Duration};

use anyhow::{anyhow, Result};
use ckb_sdk::rpc::{HttpRpcClient, CellOutput};
use ckb_types::packed;
use muta_protocol::types as muta_types;
use muta_sdk::rpc::client::HttpRpcClient as MutaClient;

use ckb_handler::types::{CKBMessage, BatchMintSudt, MintSudt};
use muta_protocol::{
    fixed_codec::FixedCodec,
    codec::ProtocolCodec,
};
use common_crypto::{
    Crypto, PrivateKey, PublicKey, Secp256k1, Secp256k1PrivateKey, Secp256k1PublicKey,
    Secp256k1Signature, Signature, ToPublicKey,
};
use muta_protocol::ProtocolResult;
use std::convert::TryInto;


use ckb_types::packed::Script;
use ckb_types::prelude::Entity;
use ckb_crypto::secp::SECP256K1;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types as json_types;
use ckb_types::{
    core::{capacity_bytes, BlockView, Capacity, HeaderView},
    h256,
    packed::CellDep,
};
use ckb_server::{
    util::{get_privkey_from_hex, gen_lock_hash, gen_tx},
    listener::CkbListener,
    handler::CkbHandler,
};
use muta_server::{
    listener::MutaListener,
    handler::MutaHandler,
};

use config::Config;

fn main() -> Result<()> {
    common_logger::init(
        "info".to_owned(),
        true,
        true,
        false,
        false,
        "/tmp".into(),
        HashMap::new(),
    );

    // let host = "http://127.0.0.1";
    let host = "http://192.168.10.2";
    // let host = "http://c2020m2020.dscloud.me";
    // let host = "http://192.168.31.222";
    let ckb_url = host.to_owned() + ":8114";
    let ckb_config_path = "config.toml";
    let muta_url = host.to_owned() + ":8000/graphql";
    let relayer_pk = "0x1".to_owned();

    // load config
    let ckb_toml = fs::read_to_string(ckb_config_path)?;
    dbg!(&ckb_toml);
    let ckb_config: Config = toml::from_str(&ckb_toml)?;


    // ckb -> muta
    let (ckb_tx, ckb_rx) = channel();
    let ckb_listener = CkbListener::new(ckb_url.clone(), 1);
    let ckb_listener_thread = thread::spawn(move || ckb_listener.start(ckb_tx));
    let ckb_handler = CkbHandler::new(relayer_pk.clone(), muta_url.clone(), ckb_config);
    let ckb_handler_thread = thread::spawn(move || {
        for block in ckb_rx {
            ckb_handler.handle(block);
        }
    });

    // muta -> ckb
    let (muta_tx, muta_rx) = channel();
    let muta_listener = MutaListener::new(muta_url.clone(), 1);
    let muta_listener_thread = thread::spawn(move || muta_listener.start(muta_tx));
    let mut muta_handler = MutaHandler::new(relayer_pk.clone(), ckb_url.clone());
    let muta_handler_thread = thread::spawn(move || {
        for receipt in muta_rx {
            muta_handler.handle(receipt);
        }
    });

    ckb_listener_thread.join().unwrap();
    ckb_handler_thread.join().unwrap();

    muta_listener_thread.join().unwrap();
    muta_handler_thread.join().unwrap();

    Ok(())
}
