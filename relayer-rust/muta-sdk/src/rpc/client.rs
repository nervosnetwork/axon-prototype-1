use crate::rpc::types::*;
use crate::utils::{bytes_to_hex, u64_to_hex};
use graphql_client::{GraphQLQuery, Response};
use muta_protocol::types as muta_types;
use std::convert::TryInto;

// const DEFAULT_MUTA_URL: &str = "http://127.0.0.1:8000/graphql";
const DEFAULT_MUTA_URL: &str = "http://192.168.10.2:8000/graphql";

pub struct HttpRpcClient {
    pub url: String,
    client:  reqwest::Client,
}

impl Default for HttpRpcClient {
    fn default() -> Self {
        Self::new(DEFAULT_MUTA_URL.to_owned())
    }
}

impl HttpRpcClient {
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::new();
        Self { url, client }
    }

    pub fn get_block_raw(
        &self,
        height: Option<u64>,
    ) -> Result<rpc_block::RpcBlockGetBlock, RpcError> {
        let q = RpcBlock::build_query(rpc_block::Variables {
            height: height.map(u64_to_hex),
        });
        let mut res = self.client.post(&self.url).json(&q).send()?;
        let response_body: Response<rpc_block::ResponseData> = res.json()?;
        if let Some(errors) = response_body.errors {
            return Err(RpcError::GraphQLError(errors));
        }
        Ok(response_body.data.ok_or(RpcError::DataIsNone)?.get_block)
    }

    pub fn get_block(&self, height: Option<u64>) -> Result<muta_types::Block, RpcError> {
        self.get_block_raw(height)?.try_into()
    }

    pub fn get_block_hook_receipt_raw(
        &self,
        height: u64,
    ) -> Result<rpc_block_hook_receipt::RpcBlockHookReceiptGetBlockHookReceipt, RpcError> {
        let q = RpcBlockHookReceipt::build_query(rpc_block_hook_receipt::Variables {
            height: u64_to_hex(height),
        });
        let mut res = self.client.post(&self.url).json(&q).send()?;
        let response_body: Response<rpc_block_hook_receipt::ResponseData> = res.json()?;
        if let Some(errors) = response_body.errors {
            return Err(RpcError::GraphQLError(errors));
        }
        Ok(response_body
            .data
            .ok_or(RpcError::DataIsNone)?
            .get_block_hook_receipt)
    }

    pub fn get_block_hook_receipt(
        &self,
        height: u64,
    ) -> Result<muta_types::BlockHookReceipt, RpcError> {
        self.get_block_hook_receipt_raw(height)?.try_into()
    }

    pub fn send_transaction(
        &self,
        signed_tx: muta_types::SignedTransaction,
    ) -> Result<muta_types::Hash, RpcError> {
        let q = SendTransaction::build_query(send_transaction::Variables {
            input_encryption: send_transaction::InputTransactionEncryption {
                pubkey:    bytes_to_hex(signed_tx.pubkey),
                signature: bytes_to_hex(signed_tx.signature),
                tx_hash:   signed_tx.tx_hash.as_hex(),
            },
            input_raw:        send_transaction::InputRawTransaction {
                chain_id:     signed_tx.raw.chain_id.as_hex(),
                cycles_limit: u64_to_hex(signed_tx.raw.cycles_limit),
                cycles_price: u64_to_hex(signed_tx.raw.cycles_price),
                nonce:        signed_tx.raw.nonce.as_hex(),
                timeout:      u64_to_hex(signed_tx.raw.timeout),
                method:       signed_tx.raw.request.method,
                payload:      signed_tx.raw.request.payload,
                service_name: signed_tx.raw.request.service_name,
            },
        });
        let mut res = self.client.post(&self.url).json(&q).send()?;
        let response_body: Response<send_transaction::ResponseData> = res.json()?;
        if let Some(errors) = response_body.errors {
            return Err(RpcError::GraphQLError(errors));
        }
        let raw_hash = response_body
            .data
            .ok_or(RpcError::DataIsNone)?
            .send_transaction;
        Ok(muta_types::Hash::from_hex(&raw_hash)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_client_get_block_works() {
        let client = HttpRpcClient::default();
        let res = client.get_block(None).unwrap();
        dbg!(&res);
    }
}
