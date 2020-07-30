mod ckb_server;
mod config;
mod muta_server;
mod tests;

use anyhow::Result;
use ckb_sdk::rpc::Script;
use ckb_server::{handler::CkbHandler, listener::CkbListener};
use config::{ConfigScript, Loader};
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

    // let host = "http://127.0.0.1";
    let host = "http://192.168.10.2";
    // let host = "http://c2020m2020.dscloud.me";
    // let host = "http://192.168.31.222";
    let ckb_url = host.to_owned() + ":8114";
    let _ckb_config_path = "config.toml";
    let muta_url = host.to_owned() + ":8000/graphql";
    let ckb_indexer_url = host.to_owned() + ":8116";

    // load config
    let relayer_config = Loader::default().load_relayer_config();
    let cross_lockscript: Script = {
        let config_script = serde_json::from_str::<ConfigScript>(
            relayer_config["crosschainLockscript"].to_string().as_ref(),
        )
        .unwrap();
        config_script.try_into().unwrap()
    };
    let cross_typescript: Script = {
        let config_script = serde_json::from_str::<ConfigScript>(
            relayer_config["crosschainTypescript"].to_string().as_ref(),
        )
        .unwrap();
        config_script.try_into().unwrap()
    };
    let relayer_sk = relayer_config["muta"]["privateKey"].as_str().unwrap();

    // temporarily use json
    // let ckb_toml = fs::read_to_string(ckb_config_path)?;
    // dbg!(&ckb_toml);
    // let ckb_config: Config = toml::from_str(&ckb_toml)?;

    // ckb -> muta
    let (ckb_tx, ckb_rx) = channel();
    let ckb_listener = CkbListener::new(ckb_url.clone(), 1);
    let ckb_listener_thread = thread::spawn(move || ckb_listener.start(ckb_tx));
    let ckb_handler = CkbHandler::new(
        relayer_sk.to_string(),
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
    let mut muta_handler = MutaHandler::new(
        relayer_sk.to_string(),
        ckb_url.clone(),
        ckb_indexer_url.clone(),
    );
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
