use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::{thread, time::Duration};

use anyhow::{anyhow, Result};
use ckb_sdk::rpc::HttpRpcClient;
use ckb_types::packed;
use muta_protocol::types as muta_types;
use muta_sdk::rpc::client::HttpRpcClient as MutaClient;

pub struct MutaListener {
    url:           String,
    interval:      u64,
    latest_height: Option<u64>,
}

impl MutaListener {
    fn new(url: String, interval: u64) -> Self {
        Self {
            url,
            interval,
            latest_height: None,
        }
    }

    fn start(mut self, sender: Sender<muta_types::BlockHookReceipt>) -> Result<()> {
        let muta_client = MutaClient::new(self.url);
        loop {
            let latest_block = muta_client.get_block(None).unwrap();
            let current_latest_height = latest_block.header.height;
            if self.latest_height.is_none() {
                let receipt = muta_client
                    .get_block_hook_receipt(current_latest_height)
                    .unwrap();
                sender.send(receipt)?;
            } else {
                let latest = self.latest_height.unwrap();
                for h in (latest + 1..=current_latest_height) {
                    let receipt = muta_client.get_block_hook_receipt(h).unwrap();
                    sender.send(receipt)?;
                }
            }
            self.latest_height = Some(current_latest_height);
            thread::sleep(Duration::from_secs(self.interval));
        }
    }
}

pub struct CkbListener {
    url:              String,
    interval:         u64,
    tip_block_number: Option<u64>,
}

impl CkbListener {
    pub fn new(url: String, interval: u64) -> Self {
        Self {
            url,
            interval,
            tip_block_number: None,
        }
    }

    pub fn start(mut self, sender: Sender<ckb_sdk::rpc::BlockView>) -> Result<()> {
        let mut ckb_rpc_client = HttpRpcClient::new(self.url);
        loop {
            let tip_block_number = ckb_rpc_client.get_tip_block_number().unwrap();
            if self.tip_block_number.is_none() {
                let block = ckb_rpc_client
                    .get_block_by_number(tip_block_number)
                    .unwrap()
                    .ok_or(anyhow!("empty block"))?;
                sender.send(block)?;
            } else {
                let latest = self.tip_block_number.unwrap();
                for h in (latest + 1..=tip_block_number) {
                    let block = ckb_rpc_client
                        .get_block_by_number(h)
                        .unwrap()
                        .ok_or(anyhow!("empty block"))?;
                    sender.send(block)?;
                }
            }
            self.tip_block_number = Some(tip_block_number);
            thread::sleep(Duration::from_secs(self.interval));
        }
    }
}

pub struct CkbHandler {
    // private key of relayer_pk, in hex format
    relayer_pk:  String,
    muta_client: MutaClient,
}

impl CkbHandler {
    pub fn new(relayer_pk: String, muta_url: String) -> Self {
        Self {
            muta_client: MutaClient::new(muta_url),
            relayer_pk,
        }
    }

    fn transform(
        &self,
        ckb_block: &ckb_sdk::rpc::BlockView,
    ) -> Result<Vec<muta_types::SignedTransaction>> {
        // todo: parse ckb block, format txs send to muta
        Ok(vec![])
    }

    pub fn handle(&self, ckb_block: ckb_sdk::rpc::BlockView) -> Result<()> {
        // dbg!(ckb_block);
        log::info!(
            "handle ckb block @ height {:?}",
            ckb_block.header.inner.number
        );
        let txs = self.transform(&ckb_block)?;
        for tx in txs {
            let hash = self.muta_client.send_transaction(tx).unwrap();
            dbg!(&hash);
        }
        Ok(())
    }
}

pub struct MutaHandler {
    relayer_pk: String,
    ckb_client: HttpRpcClient,
}

impl MutaHandler {
    pub fn new(relayer_pk: String, ckb_url: String) -> Self {
        Self {
            relayer_pk,
            ckb_client: HttpRpcClient::new(ckb_url),
        }
    }

    fn transform(
        &self,
        muta_receipt: muta_types::BlockHookReceipt,
    ) -> Result<Vec<packed::Transaction>> {
        // todo: implement the transform logics
        Ok(vec![])
    }

    pub fn handle(&mut self, muta_receipt: muta_types::BlockHookReceipt) -> Result<()> {
        log::info!("handle muta block @ height {}", muta_receipt.height);
        for tx in self.transform(muta_receipt)? {
            self.ckb_client.send_transaction(tx).unwrap();
        }
        Ok(())
    }
}

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

    let ckb_url = "http://127.0.0.1:8114".to_owned();
    let muta_url = "http://127.0.0.1:8000/graphql".to_owned();
    let relayer_pk = "0x1".to_owned();

    // ckb -> muta
    let (ckb_tx, ckb_rx) = channel();
    let ckb_listener = CkbListener::new(ckb_url.clone(), 1);
    let ckb_listener_thread = thread::spawn(move || ckb_listener.start(ckb_tx));
    let ckb_handler = CkbHandler::new(relayer_pk.clone(), muta_url.clone());
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
