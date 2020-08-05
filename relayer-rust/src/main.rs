#![feature(in_band_lifetimes)]

mod cfg;
mod ckb_server;
mod muta_server;
mod tests;

use anyhow::Result;
use cfg::{Loader, RelayerConfig};
use ckb_sdk::rpc::Script;
use ckb_server::{handler::CkbHandler, listener::CkbListener};
use muta_server::{handler::MutaHandler, listener::MutaListener};
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::mpsc::channel;
use std::thread;

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

    // load config
    let relayer_config = Loader::default().load_relayer_config();
    let cross_lockscript: Script = relayer_config.ckb.crosschain_lockscript;
    let cross_typescript: Script = relayer_config.ckb.crosschain_typescript;
    let relayer_sk = relayer_config.muta.private_key;
    let ckb_url = relayer_config.ckb.url;
    let ckb_indexer_url = relayer_config.ckb.url_indexer;
    let muta_url = relayer_config.muta.endpoint;

    // ckb -> muta
    let (ckb_tx, ckb_rx) = channel();
    let ckb_listener = CkbListener::new(ckb_url.clone(), 1);
    let ckb_listener_thread = thread::spawn(move || ckb_listener.start(ckb_tx));
    let ckb_handler = CkbHandler::new(
        relayer_sk.clone(),
        muta_url.clone(),
        cross_lockscript.clone(),
        cross_typescript,
    );
    let ckb_handler_thread = thread::spawn(move || {
        for block in ckb_rx {
            ckb_handler.handle(block);
        }
    });

    // muta -> ckb
    let (muta_tx, muta_rx) = channel();
    let muta_listener = MutaListener::new(muta_url.clone(), 1);
    let muta_listener_thread = thread::spawn(move || muta_listener.start(muta_tx));
    let mut muta_handler = MutaHandler::new(relayer_sk, ckb_url.clone(), ckb_indexer_url.clone());
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
