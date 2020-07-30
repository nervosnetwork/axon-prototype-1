use muta_protocol::traits as muta_traits;
use muta_protocol::types as muta_types;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::convert::TryInto;

use super::request::{
    GET_BLOCK, GET_BLOCK_HOOK_RECEIPT, GET_BLOCK_HOOK_RECEIPT_QUERY, GET_BLOCK_QUERY, GET_RECEIPT,
    GET_RECEIPT_QUERY, GET_TRANSACTION, GET_TRANSACTION_QUERY, SEND_TRANSACTION,
    SEND_TRANSACTION_MUTATION, SERVICE, SERVICE_QUERY,
};
use super::rpc_types::{
    Block, BlockHookReceipt, Hash, Receipt, RpcError, ServiceResponse, SignedTransaction,
};
use crate::util::u64_to_hex;

pub struct Config {
    pub url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8000/graphql".to_owned(),
        }
    }
}

pub struct HttpRpcClient {
    config: Config,
    client: reqwest::Client,
}

impl Default for HttpRpcClient {
    fn default() -> Self {
        let config = Config::default();
        Self::new(config)
    }
}

impl HttpRpcClient {
    pub fn new(config: Config) -> Self {
        let client = reqwest::Client::new();
        Self { config, client }
    }

    pub async fn raw<T: Serialize + ?Sized, U: DeserializeOwned>(
        &self,
        q: &T,
        method: &str,
    ) -> Result<U, RpcError> {
        let mut resp: Value = self
            .client
            .post(&self.config.url)
            .json(&q)
            .send()
            .await?
            .json()
            .await?;

        if let Some(errs) = resp.get("errors") {
            return Err(RpcError::GraphQLError(errs.to_string()));
        }

        Ok(serde_json::from_value(
            resp.get_mut("data")
                .ok_or(RpcError::DataIsNone)?
                .get_mut(method)
                .ok_or(RpcError::DataIsNone)?
                .take(),
        )?)
    }

    pub async fn get_block(&self, height: Option<u64>) -> Result<muta_types::Block, RpcError> {
        let q = json!({
            "query": GET_BLOCK_QUERY,
            "variables": {
                "h": height.map(u64_to_hex),
            },
        });
        let rpc_block: Block = self.raw(&q, GET_BLOCK).await?;
        Ok(rpc_block.try_into()?)
    }

    pub async fn get_transaction(
        &self,
        tx_hash: muta_types::Hash,
    ) -> Result<muta_types::SignedTransaction, RpcError> {
        let q = json!({
            "query": GET_TRANSACTION_QUERY,
            "variables": {
                "txHash": tx_hash.as_hex(),
            },
        });
        let rpc_transaction: SignedTransaction = self.raw(&q, GET_TRANSACTION).await?;
        Ok(rpc_transaction.try_into()?)
    }

    pub async fn get_receipt(
        &self,
        tx_hash: muta_types::Hash,
    ) -> Result<muta_types::Receipt, RpcError> {
        let q = json!({
            "query": GET_RECEIPT_QUERY,
            "variables": {
                "txHash": tx_hash.as_hex(),
            },
        });
        let rpc_receipt: Receipt = self.raw(&q, GET_RECEIPT).await?;
        Ok(rpc_receipt.try_into()?)
    }

    pub async fn get_block_hook_receipt(
        &self,
        height: u64,
    ) -> Result<muta_types::BlockHookReceipt, RpcError> {
        let q = json!({
            "query": GET_BLOCK_HOOK_RECEIPT_QUERY,
            "variables": {
                "height": u64_to_hex(height),
            },
        });
        let rpc_block_hook_receipt: BlockHookReceipt = self.raw(&q, GET_BLOCK_HOOK_RECEIPT).await?;
        Ok(rpc_block_hook_receipt.try_into()?)
    }

    pub async fn query_service(
        &self,
        height: Option<u64>,
        cycles_limit: Option<u64>,
        cycles_price: Option<u64>,
        caller: muta_types::Address,
        service_name: String,
        method: String,
        payload: String,
    ) -> Result<muta_traits::ServiceResponse<String>, RpcError> {
        let q = json!({
            "query": SERVICE_QUERY,
            "variables": {
                "height": height.map(u64_to_hex),
                "cyclesLimit": cycles_limit.map(u64_to_hex),
                "cyclesPrice": cycles_price.map(u64_to_hex),
                "caller": caller,
                "serviceName": service_name,
                "method": method,
                "payload": payload,
            },
        });
        let rpc_service: ServiceResponse = self.raw(&q, SERVICE).await?;
        Ok(rpc_service.try_into()?)
    }

    pub async fn send_transaction(
        &self,
        tx: muta_types::SignedTransaction,
    ) -> Result<muta_types::Hash, RpcError> {
        let q = json!({
            "query": SEND_TRANSACTION_MUTATION,
            "variables": {
                "input_raw": {
                    "chainId": tx.raw.chain_id.as_hex(),
                    "cyclesLimit": u64_to_hex(tx.raw.cycles_limit),
                    "cyclesPrice": u64_to_hex(tx.raw.cycles_price),
                    "nonce": tx.raw.nonce.as_hex(),
                    "timeout": u64_to_hex(tx.raw.timeout),
                    "serviceName": tx.raw.request.service_name,
                    "method": tx.raw.request.method,
                    "payload": tx.raw.request.payload
                },
                "input_encryption": {
                    "txHash": tx.tx_hash.as_hex(),
                    "pubkey": "0x".to_owned() + &hex::encode(tx.pubkey),
                    "signature": "0x".to_owned() + &hex::encode(tx.signature)
                }
            },
        });

        let rpc_hash: Hash = self.raw(&q, SEND_TRANSACTION).await?;
        Ok(muta_types::Hash::from_hex(&rpc_hash)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::util::random_nonce;

    #[tokio::test]
    async fn client_get_block_works() {
        let client = HttpRpcClient::default();
        let res = client.get_block(None).await.unwrap();
        println!("{:?}", res);
    }

    #[tokio::test]
    async fn client_get_block_hook_receipt() {
        let client = HttpRpcClient::default();
        let res = client.get_block_hook_receipt(1).await.unwrap();
        println!("{:?}", res);
    }

    #[tokio::test]
    async fn client_query_service() {
        let client = HttpRpcClient::default();
        let res = client
            .query_service(
                None,
                None,
                None,
                muta_types::Address::from_hex("0x0000000000000000000000000000000000000000")
                    .unwrap(),
                "metadata".to_string(),
                "get_metadata".to_string(),
                "".to_string(),
            )
            .await
            .unwrap();
        println!("{:?}", res);
    }

    #[tokio::test]
    async fn client_send_transaction() {
        let client = HttpRpcClient::default();
        let account =
            Account::from_hex("45c56be699dca666191ad3446897e0f480da234da896270202514a0e1a587c3f")
                .unwrap();

        let chain_id = muta_types::Hash::from_hex(
            "0xb6a4d7da21443f5e816e8700eea87610e6d769657d6b8ec73028457bf2ca4036",
        )
        .unwrap();
        let nonce = random_nonce();
        let payload = r#"
        {
            "name": "test",
            "symbol": "test",
            "supply": 1024 * 1024,
        }"#;

        let block = client.get_block(None).await.unwrap();
        let latest_height = block.header.height;
        let raw = muta_types::RawTransaction {
            chain_id,
            nonce,
            timeout: latest_height + 20,
            cycles_price: 1,
            cycles_limit: 1,
            request: muta_types::TransactionRequest {
                service_name: "asset".to_owned(),
                method:       "create_asset".to_owned(),
                payload:      payload.to_owned(),
            },
        };
        let signed_transaction = account.sign_raw_tx(raw).unwrap();

        let tx_hash = client.send_transaction(signed_transaction).await.unwrap();
        println!("{:?}", tx_hash);

        let transaction = client.get_transaction(tx_hash.clone()).await.unwrap();
        println!("{:?}", transaction);
        let receipt = client.get_receipt(tx_hash.clone()).await.unwrap();
        println!("{:?}", receipt);
    }
}
