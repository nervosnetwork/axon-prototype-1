use std::convert::{TryFrom, TryInto};

use muta_protocol::traits as muta_traits;
use muta_protocol::types as muta_types;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::util::{hex_to_bytes, hex_to_u64};

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("request error")]
    Request(#[from] reqwest::Error),
    #[error("parse Uint64 error")]
    ParseUint64(#[from] std::num::ParseIntError),
    #[error("parse muta types error")]
    ParseMutaTypes(#[from] muta_protocol::ProtocolError),
    #[error("parse hex error")]
    ParseHex(#[from] hex::FromHexError),
    #[error("convert Int to u32 error")]
    ConvertIntToU32(#[from] std::num::TryFromIntError),
    #[error("serde error")]
    Serde(#[from] serde_json::Error),
    #[error("data is none")]
    DataIsNone,
    #[error("graphql error: {0}")]
    GraphQLError(String),
}

pub type Uint64 = String;
pub type Hash = String;
pub type Address = String;
pub type Bytes = String;
pub type MerkleRoot = String;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    header:            BlockHeader,
    ordered_tx_hashes: Vec<Hash>,
    hash:              Hash,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub chain_id:          Hash,
    pub height:            Uint64,
    pub exec_height:       Uint64,
    pub pre_hash:          Hash,
    pub timestamp:         Uint64,
    pub order_root:        MerkleRoot,
    pub confirm_root:      Vec<MerkleRoot>,
    pub state_root:        MerkleRoot,
    pub receipt_root:      Vec<MerkleRoot>,
    pub cycles_used:       Vec<Uint64>,
    pub proposer:          Address,
    pub proof:             Proof,
    pub validator_version: Uint64,
    pub validators:        Vec<Validator>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTransaction {
    pub chain_id:     Hash,
    pub cycles_limit: Uint64,
    pub cycles_price: Uint64,
    pub nonce:        Hash,
    pub timeout:      Uint64,
    pub service_name: String,
    pub method:       String,
    pub payload:      String,
    pub tx_hash:      Hash,
    pub pubkey:       Bytes,
    pub signature:    Bytes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub state_root:  MerkleRoot,
    pub height:      Uint64,
    pub tx_hash:     Hash,
    pub cycles_used: Uint64,
    pub events:      Vec<Event>,
    pub response:    ReceiptResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptResponse {
    pub service_name: String,
    pub method:       String,
    pub response:     ServiceResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceResponse {
    pub code:          Uint64,
    pub succeed_data:  String,
    pub error_message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub height:     Uint64,
    pub round:      Uint64,
    pub block_hash: Hash,
    pub signature:  Bytes,
    pub bitmap:     Bytes,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Validator {
    pub address:        Address,
    pub propose_weight: i32,
    pub vote_weight:    i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub service: String,
    pub topic:   String,
    pub data:    String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHookReceipt {
    pub height:     Uint64,
    pub state_root: MerkleRoot,
    pub events:     Vec<Event>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputRawTransaction {
    pub chain_id:     Hash,
    pub cycles_limit: Uint64,
    pub cycles_price: Uint64,
    pub nonce:        Hash,
    pub timeout:      Uint64,
    pub service_name: String,
    pub method:       String,
    pub payload:      String,
}

impl TryFrom<Block> for muta_types::Block {
    type Error = RpcError;

    fn try_from(block: Block) -> Result<Self, Self::Error> {
        Ok(Self {
            header:            block.header.try_into()?,
            ordered_tx_hashes: block
                .ordered_tx_hashes
                .into_iter()
                .map(|s| muta_types::Hash::from_hex(&s))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<BlockHeader> for muta_types::BlockHeader {
    type Error = RpcError;

    fn try_from(header: BlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id:          muta_types::Hash::from_hex(&header.chain_id)?,
            height:            hex_to_u64(&header.height)?,
            exec_height:       hex_to_u64(&header.exec_height)?,
            pre_hash:          muta_types::Hash::from_hex(&header.pre_hash)?,
            timestamp:         hex_to_u64(&header.timestamp)?,
            order_root:        muta_types::Hash::from_hex(&header.order_root)?,
            confirm_root:      header
                .confirm_root
                .into_iter()
                .map(|s| muta_types::Hash::from_hex(&s))
                .collect::<Result<Vec<_>, _>>()?,
            state_root:        muta_types::Hash::from_hex(&header.state_root)?,
            receipt_root:      header
                .receipt_root
                .into_iter()
                .map(|s| muta_types::Hash::from_hex(&s))
                .collect::<Result<Vec<_>, _>>()?,
            cycles_used:       header
                .cycles_used
                .into_iter()
                .map(|s| hex_to_u64(&s))
                .collect::<Result<Vec<_>, _>>()?,
            proposer:          muta_types::Address::from_hex(&header.proposer)?,
            proof:             header.proof.try_into()?,
            validator_version: hex_to_u64(&header.validator_version)?,
            validators:        header
                .validators
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<Validator> for muta_types::Validator {
    type Error = RpcError;

    fn try_from(validator: Validator) -> Result<Self, Self::Error> {
        Ok(Self {
            address:        muta_types::Address::from_hex(&validator.address)?,
            propose_weight: validator.propose_weight.try_into()?,
            vote_weight:    validator.vote_weight.try_into()?,
        })
    }
}

impl TryFrom<Proof> for muta_types::Proof {
    type Error = RpcError;

    fn try_from(proof: Proof) -> Result<Self, Self::Error> {
        Ok(Self {
            height:     hex_to_u64(&proof.height)?,
            round:      hex_to_u64(&proof.round)?,
            block_hash: muta_types::Hash::from_hex(&proof.block_hash)?,
            signature:  hex_to_bytes(&proof.signature)?,
            bitmap:     hex_to_bytes(&proof.bitmap)?,
        })
    }
}

impl TryFrom<Event> for muta_types::Event {
    type Error = RpcError;

    fn try_from(event: Event) -> Result<Self, Self::Error> {
        Ok(Self {
            service: event.service,
            topic:   event.topic,
            data:    event.data,
        })
    }
}

impl TryFrom<BlockHookReceipt> for muta_types::BlockHookReceipt {
    type Error = RpcError;

    fn try_from(receipt: BlockHookReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            height:     hex_to_u64(&receipt.height)?,
            state_root: muta_types::Hash::from_hex(&receipt.state_root)?,
            events:     receipt
                .events
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl TryFrom<SignedTransaction> for muta_types::SignedTransaction {
    type Error = RpcError;

    fn try_from(tx: SignedTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            raw:       muta_types::RawTransaction {
                chain_id:     muta_types::Hash::from_hex(&tx.chain_id)?,
                cycles_price: hex_to_u64(&tx.cycles_price)?,
                cycles_limit: hex_to_u64(&tx.cycles_limit)?,
                nonce:        muta_types::Hash::from_hex(&tx.nonce)?,
                request:      muta_types::TransactionRequest {
                    method:       tx.method,
                    service_name: tx.service_name,
                    payload:      tx.payload,
                },
                timeout:      hex_to_u64(&tx.timeout)?,
            },
            tx_hash:   muta_types::Hash::from_hex(&tx.tx_hash)?,
            pubkey:    hex_to_bytes(&tx.pubkey)?,
            signature: hex_to_bytes(&tx.signature)?,
        })
    }
}

impl TryFrom<Receipt> for muta_types::Receipt {
    type Error = RpcError;

    fn try_from(receipt: Receipt) -> Result<Self, Self::Error> {
        Ok(Self {
            state_root:  muta_types::MerkleRoot::from_hex(&receipt.state_root)?,
            height:      hex_to_u64(&receipt.height)?,
            tx_hash:     muta_types::Hash::from_hex(&receipt.tx_hash)?,
            cycles_used: hex_to_u64(&receipt.cycles_used)?,
            events:      receipt
                .events
                .into_iter()
                .map(|s| s.try_into())
                .collect::<Result<Vec<_>, _>>()?,
            response:    receipt.response.try_into()?,
        })
    }
}

impl TryFrom<ReceiptResponse> for muta_types::ReceiptResponse {
    type Error = RpcError;

    fn try_from(response: ReceiptResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            service_name: response.service_name,
            method:       response.method,
            response:     response.response.try_into()?,
        })
    }
}

impl TryFrom<ServiceResponse> for muta_traits::ServiceResponse<String> {
    type Error = RpcError;

    fn try_from(response: ServiceResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            code:          hex_to_u64(&response.code)?,
            succeed_data:  response.succeed_data,
            error_message: response.error_message,
        })
    }
}
