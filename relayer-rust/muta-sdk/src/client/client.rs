use std::convert::TryInto;

use muta_protocol::traits as muta_traits;
use muta_protocol::types as muta_types;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

use super::request::{
    GET_BLOCK_HOOK_QUERY, GET_BLOCK_QUERY, GET_RECEIPT_QUERY, GET_TRANSACTION_QUERY,
    SEND_TRANSACTION, SERVICE_QUERY,
};
use super::rpc_types::{
    Block, BlockHookReceipt, InputRawTransaction, Receipt, RpcError, ServiceResponse,
    SignedTransaction,
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
        let rpc_block: Block = self.raw(&q, "getBlock").await?;
        Ok(rpc_block.try_into()?)
    }

    pub async fn get_transaction(
        &self,
        tx_hash: muta_types::Hash,
    ) -> Result<muta_types::SignedTransaction, RpcError> {
        let q = json!({
            "query": GET_TRANSACTION_QUERY,
            "variables": {
                "txHash": tx_hash,
            },
        });
        let rpc_transaction: SignedTransaction = self.raw(&q, "getTransaction").await?;
        Ok(rpc_transaction.try_into()?)
    }

    pub async fn get_receipt(
        &self,
        tx_hash: muta_types::Hash,
    ) -> Result<muta_types::Receipt, RpcError> {
        let q = json!({
            "query": GET_RECEIPT_QUERY,
            "variables": {
                "txHash": tx_hash,
            },
        });
        let rpc_receipt: Receipt = self.raw(&q, "getReceipt").await?;
        Ok(rpc_receipt.try_into()?)
    }

    pub async fn get_block_hook_receipt(
        &self,
        height: u64,
    ) -> Result<muta_types::BlockHookReceipt, RpcError> {
        let q = json!({
            "query": GET_BLOCK_HOOK_QUERY,
            "variables": {
                "height": u64_to_hex(height),
            },
        });
        let rpc_block_hook_receipt: BlockHookReceipt = self.raw(&q, "getBlockHookReceipt").await?;
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
        let rpc_service: ServiceResponse = self.raw(&q, "queryService").await?;
        Ok(rpc_service.try_into()?)
    }

    pub async fn send_transaction(
        &self,
        _tx: muta_types::SignedTransaction,
    ) -> Result<muta_types::Hash, RpcError> {
        // let q = json!({
        //     "mutation": SEND_TRANSACTION,
        //     "variables": {
        //         "input_raw": InputRawTransaction{
        //             chain_id:
        //         },
        //     },
        // });
        // let rpc_service: ServiceResponse = self.raw(&q, "sendTransaction").await?;
        // Ok(rpc_service.try_into()?)
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_get_block_works() {
        let client = HttpRpcClient::default();
        let res = client.get_block(None).await.unwrap();
        println!("{:?}", res);
    }

    #[tokio::test]
    async fn client_get_transaction_works() {
        let client = HttpRpcClient::default();

        let tx_hash = muta_types::Hash::from_hex(
            "0x56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432",
        )
        .unwrap();
        let res = client.get_transaction(tx_hash).await.unwrap();
        println!("{:?}", res);
    }

    #[tokio::test]
    async fn client_get_receipt() {
        let client = HttpRpcClient::default();

        let tx_hash = muta_types::Hash::from_hex(
            "0x56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432",
        )
        .unwrap();
        let res = client.get_receipt(tx_hash).await.unwrap();
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
                muta_types::Address::from_hex(
                    "
                    0x0000000000000000000000000000000000000000",
                )
                .unwrap(),
                "metadata".to_string(),
                "get_metadata".to_string(),
                "".to_string(),
            )
            .await
            .unwrap();
        println!("{:?}", res);
    }
}
