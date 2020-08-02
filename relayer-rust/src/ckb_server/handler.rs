use crate::muta_server::util::{gen_ckb_message, gen_raw_tx};
use anyhow::Result;
use ckb_handler::types::MintSudt;
use ckb_sdk::rpc::Script;
use ckb_types::H256;
use common_crypto::{
    Crypto, PrivateKey, PublicKey, Secp256k1, Secp256k1PrivateKey, Signature, ToPublicKey,
};
use muta_protocol::fixed_codec::FixedCodec;
use muta_protocol::types as muta_types;
use muta_sdk::rpc::client::HttpRpcClient as MutaClient;
use std::convert::{TryFrom, TryInto};

pub struct CkbHandler {
    // secret key of relayer_pk, in hex format
    relayer_sk:       H256,
    muta_client:      MutaClient,
    cross_lockscript: Script,
    cross_typescript: Script,
}

impl CkbHandler {
    pub fn new(
        relayer_sk: H256,
        muta_url: String,
        cross_lockscript: Script,
        cross_typescript: Script,
    ) -> Self {
        Self {
            muta_client: MutaClient::new(muta_url),
            relayer_sk,
            cross_lockscript,
            cross_typescript,
        }
    }

    fn transform(
        &self,
        ckb_block: ckb_sdk::rpc::BlockView,
    ) -> Result<Vec<muta_types::SignedTransaction>> {
        let mut batch_mints: Vec<MintSudt> = vec![];
        dbg!(ckb_block.transactions.len());
        let mut tx_mints = vec![];
        for tx_view in ckb_block.transactions.into_iter() {
            // sum the cross tx and gen tx_mints
            for (_index, output) in tx_view.inner.outputs.iter().enumerate() {
                if output.type_.is_none() {
                    continue;
                }
                // the unlock tx by validators
                let typescript = output.type_.to_owned().unwrap();
                if typescript == self.cross_typescript {
                    tx_mints.clear();
                    break;
                }

                // listening the cross
                if output.lock == self.cross_lockscript {
                    let id = typescript.args.into_bytes();

                    let receiver = tx_view
                        .inner
                        .witnesses
                        .last()
                        .unwrap()
                        .to_owned()
                        .into_bytes();

                    let amount_bytes = tx_view
                        .inner
                        .outputs_data
                        .last()
                        .unwrap()
                        .to_owned()
                        .into_bytes();

                    let amount: &[u8; 16] = amount_bytes.as_ref().try_into().unwrap();

                    let mint_sudt = MintSudt {
                        id:       muta_types::Hash::from_bytes(id).unwrap(),
                        receiver: muta_types::Address::from_bytes(receiver).unwrap(),
                        amount:   u128::from_le_bytes(amount.to_owned()),
                    };

                    tx_mints.push(mint_sudt);
                    break;
                }
            }
            batch_mints.append(&mut tx_mints);
        }

        if batch_mints.is_empty() {
            return Ok(vec![]);
        }

        // outputs -> ckbMessage
        let payload = gen_ckb_message(batch_mints, self.relayer_sk.clone());

        // generate tx
        let raw_tx = gen_raw_tx(payload);
        let raw_bytes = raw_tx.encode_fixed().unwrap();
        let tx_hash = muta_types::Hash::digest(raw_bytes);

        let privkey = Secp256k1PrivateKey::try_from(self.relayer_sk.as_bytes())?;
        let signature =
            Secp256k1::sign_message(&tx_hash.as_bytes(), &privkey.clone().to_bytes()).unwrap();

        let tx = muta_types::SignedTransaction {
            raw: raw_tx,
            tx_hash,
            pubkey: privkey.pub_key().to_bytes(),
            signature: signature.to_bytes(),
        };

        Ok(vec![tx])
    }

    pub fn handle(&self, ckb_block: ckb_sdk::rpc::BlockView) -> Result<()> {
        // dbg!(ckb_block);
        log::info!(
            "handle ckb block @ height {:?}",
            ckb_block.header.inner.number
        );
        let txs = self.transform(ckb_block)?;
        dbg!(txs.len());
        for tx in txs {
            let muta_tx_hash = self.muta_client.send_transaction(tx).unwrap();
            dbg!(&muta_tx_hash);
        }
        Ok(())
    }
}
