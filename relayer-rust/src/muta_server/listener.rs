use std::sync::mpsc::{channel, Sender};
use std::{thread, time::Duration};
use anyhow::{anyhow, Result};
use muta_protocol::types as muta_types;
use muta_sdk::rpc::client::HttpRpcClient as MutaClient;


pub struct MutaListener {
    url: String,
    interval: u64,
    latest_height: Option<u64>,
}

impl MutaListener {
    pub fn new(url: String, interval: u64) -> Self {
        Self {
            url,
            interval,
            latest_height: None,
        }
    }

    pub fn start(mut self, sender: Sender<muta_types::BlockHookReceipt>) -> Result<()> {
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
