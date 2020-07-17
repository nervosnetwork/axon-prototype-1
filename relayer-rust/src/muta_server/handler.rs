use crate::ckb_server::util::{
    gen_lock_hash, gen_tx
};
use ckb_sdk::rpc::{HttpRpcClient, CellOutput};
use ckb_types::packed;
use anyhow::{anyhow, Result};
use muta_protocol::types as muta_types;

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
        &mut self,
        muta_receipt: muta_types::BlockHookReceipt,
    ) -> Result<Vec<packed::Transaction>> {
        // todo: implement the transform logic
        let lock_hash = gen_lock_hash("0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc".to_owned());
        let lock_hash = gen_lock_hash("0x63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d".to_owned());
        let tx = gen_tx(&mut self.ckb_client, lock_hash);
        Ok(vec![tx])
    }

    pub fn handle(&mut self, muta_receipt: muta_types::BlockHookReceipt) -> Result<()> {
        log::info!("handle muta block @ height {}", muta_receipt.height);
        for tx in self.transform(muta_receipt)? {
            self.ckb_client.send_transaction(tx).unwrap();
        }
        Ok(())
    }
}
