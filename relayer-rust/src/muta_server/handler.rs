use crate::ckb_server::{
    indexer::IndexerRpcClient,
    util::{
        gen_lock_hash, gen_unlock_sudt_tx,
    },
};
use ckb_sdk::{
    rpc::{HttpRpcClient, CellOutput, Script},
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
use serde_json;
use ckb_sudt::types::{
    BurnSudtEvent
};

use std::collections::HashMap;
use std::cell::RefCell;
use std::rc::Rc;

type AssetMap = HashMap::<String, u128>;

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
        if muta_receipt.events.is_empty() {
            return Err(anyhow!("no muta receipt"));
        }

        // gen asset_id -> balance_sum_sheet, to collect the corresponding input cells
        let mut balance_sum = HashMap::<muta_types::Hash, u128>::new();
        // gen asset_id -> AssetMap
        let mut assets = HashMap::<muta_types::Hash, AssetMap>::new();

        for event in muta_receipt.events.iter() {
            let burn_event: BurnSudtEvent =
                serde_json::from_str(event.data.as_str()).expect("json decode burn sudt event failed");
            let receiver = burn_event.receiver.as_string();
            let asset_id = burn_event.id;
            let asset_map = assets.entry( asset_id.clone() ).or_insert( AssetMap::new() );

            *asset_map.entry(receiver ).or_insert(0) += burn_event.amount;
            *balance_sum.entry(asset_id).or_insert(0) += burn_event.amount;
        }

        dbg!( &assets, &balance_sum );

        // generate the tx
        let tx = gen_unlock_sudt_tx(
            &self.ckb_genesis_info,
            &mut self.ckb_client,
            &mut self.ckb_indexer_client,
            &mut balance_sum,
            &mut assets,
        );
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


#[test]
fn test_map() {
    // gen asset_id => balance_sum_sheet, to collect the corresponding input cells
    let mut balance_sum: HashMap<muta_types::Hash, u128> = HashMap::<muta_types::Hash, u128>::new();
    // gen receiver => balance, to gen the corresponding outputs
    // let mut receiver_balance: HashMap<muta_types::Hex, u128> = HashMap::new();


    let id_btc = muta_types::Hash::from_hex("0x111e555f3ff8135cece1351a6a2971518392c1e30375c1e006ad0ce8eac07947").unwrap();
    let id_eth = muta_types::Hash::from_hex("0x222e555f3ff8e35cece1351a6a2971518392c1e30375c1e006ad0ce8eac07947").unwrap();

    *balance_sum.entry(id_btc.clone()).or_insert(0) += 11;
    *balance_sum.entry(id_btc.clone()).or_insert(0) += 22;
    *balance_sum.entry(id_btc.clone()).or_insert(0) += 33;
    dbg!(balance_sum);

    // assets: asset_id -> asset
    // asset : receiver -> amount
    type AssetMap = HashMap::<String, u128>;
    let mut asset = HashMap::<String, u128>::new();
    let mut assets = HashMap::<muta_types::Hash, AssetMap>::new();
    asset.insert("ethan".to_string(), 123);
    asset.insert("vincent".to_string(), 456);

    assets.insert( id_btc, asset );
    dbg!(assets);
}

