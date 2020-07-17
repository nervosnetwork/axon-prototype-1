use std::sync::mpsc::{channel, Sender};
use std::{thread, time::Duration};
use anyhow::{anyhow, Result};
use ckb_sdk::rpc::{HttpRpcClient, CellOutput};

pub struct CkbListener {
    url: String,
    interval: u64,
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
