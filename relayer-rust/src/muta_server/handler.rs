use crate::ckb_server::{
    indexer::IndexerRpcClient,
    util::{
        gen_lock_hash, gen_unlock_sudt_tx,
    },
};
use ckb_sdk::{
    rpc::{HttpRpcClient, CellOutput},
    GenesisInfo,
};

use ckb_types::{packed};
use anyhow::{anyhow, Result};
use muta_protocol::types as muta_types;
use crate::ckb_server::util::gen_lock_args;
use ckb_types::core::BlockView;
use faster_hex::hex_string;
use std::thread::sleep;
use std::thread;
use std::time::Duration;

pub struct MutaHandler {
    relayer_pk: String,
    ckb_client: HttpRpcClient,
    ckb_indexer_client: IndexerRpcClient,
    ckb_genesis_info: GenesisInfo,
}

impl MutaHandler {
    pub fn new(relayer_pk: String, ckb_url: String, ckb_indexer_url: String) -> Self {
        let mut ckb_client = HttpRpcClient::new(ckb_url);
        let block: BlockView = ckb_client.get_block_by_number(0)
            .expect("get genesis block failed from ckb")
            .expect("genesis block is none")
            .into();

        let ckb_genesis_info =
            GenesisInfo::from_block(&block)
                .expect("ckb genesisInfo generated failed");

        dbg!(&ckb_genesis_info);
        Self {
            relayer_pk,
            ckb_client,
            ckb_indexer_client: IndexerRpcClient::new(ckb_indexer_url),
            ckb_genesis_info,
        }
    }

    fn transform(
        &mut self,
        muta_receipt: muta_types::BlockHookReceipt,
    ) -> Result<Vec<packed::Transaction>> {
        // todo: implement the transform logic
        // transform muta_receipt to ckb outputs
        muta_receipt.events.iter().map(
            |event| {
                let data: serde_json::Value = serde_json::from_str(event.data.as_str()).unwrap();
                let asset_id = data["id"].as_str().unwrap();
                let receiver = data["receiver"].as_str().unwrap();
                let amount = data["amount"].as_u64().unwrap();
            }
        );

        // generate the tx
        let tx = gen_unlock_sudt_tx(&self.ckb_genesis_info, &mut self.ckb_client, &mut self.ckb_indexer_client);
        Ok(vec![tx])
    }

    pub fn handle(&mut self, muta_receipt: muta_types::BlockHookReceipt) -> Result<()> {
        log::info!("handle muta block @ height {}", muta_receipt.height);
        for tx in self.transform(muta_receipt)? {
            dbg!(tx.clone());
            let res = self.ckb_client.send_transaction(tx);
            dbg!(hex_string(res.unwrap().as_bytes()));
            thread::sleep(Duration::from_secs(1000000));
        }
        Ok(())
    }
}
