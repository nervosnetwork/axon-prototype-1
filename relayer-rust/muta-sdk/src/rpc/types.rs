use crate::utils::{hex_to_bytes, hex_to_u64};
use graphql_client::GraphQLQuery;
use muta_protocol::types as muta_types;
use std::convert::TryFrom;
use std::convert::TryInto;
use thiserror::Error;

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
    #[error("graphql return error")]
    GraphQLError(Vec<graphql_client::Error>),
    #[error("data is none")]
    DataIsNone,
}

type Hash = String;
type Uint64 = String;
type Bytes = String;
type Address = String;

#[derive(GraphQLQuery)]
#[graphql(
    query_path = "schema/queries.graphql",
    schema_path = "schema/muta.graphql",
    response_derives = "Debug,PartialEq"
)]
pub struct RpcBlock;

#[derive(GraphQLQuery)]
#[graphql(
    query_path = "schema/queries.graphql",
    schema_path = "schema/muta.graphql",
    response_derives = "Debug,PartialEq"
)]
pub struct RpcTransaction;

#[derive(GraphQLQuery)]
#[graphql(
    query_path = "schema/queries.graphql",
    schema_path = "schema/muta.graphql",
    response_derives = "Debug,PartialEq"
)]
pub struct RpcBlockHookReceipt;

#[derive(GraphQLQuery)]
#[graphql(
    query_path = "schema/queries.graphql",
    schema_path = "schema/muta.graphql",
    response_derives = "Debug,PartialEq"
)]
pub struct SendTransaction;

impl TryFrom<rpc_block::RpcBlockGetBlock> for muta_types::Block {
    type Error = RpcError;

    fn try_from(block: rpc_block::RpcBlockGetBlock) -> Result<Self, Self::Error> {
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

impl TryFrom<rpc_block::RpcBlockGetBlockHeader> for muta_types::BlockHeader {
    type Error = RpcError;

    fn try_from(header: rpc_block::RpcBlockGetBlockHeader) -> Result<Self, Self::Error> {
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

impl TryFrom<rpc_block::RpcBlockGetBlockHeaderValidators> for muta_types::Validator {
    type Error = RpcError;

    fn try_from(
        validator: rpc_block::RpcBlockGetBlockHeaderValidators,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            address:        muta_types::Address::from_hex(&validator.address)?,
            propose_weight: validator.propose_weight.try_into()?,
            vote_weight:    validator.vote_weight.try_into()?,
        })
    }
}

impl TryFrom<rpc_block::RpcBlockGetBlockHeaderProof> for muta_types::Proof {
    type Error = RpcError;

    fn try_from(proof: rpc_block::RpcBlockGetBlockHeaderProof) -> Result<Self, Self::Error> {
        Ok(Self {
            height:     hex_to_u64(&proof.height)?,
            round:      hex_to_u64(&proof.round)?,
            block_hash: muta_types::Hash::from_hex(&proof.block_hash)?,
            signature:  hex_to_bytes(&proof.signature)?,
            bitmap:     hex_to_bytes(&proof.bitmap)?,
        })
    }
}

impl TryFrom<rpc_block_hook_receipt::RpcBlockHookReceiptGetBlockHookReceiptEvents>
    for muta_types::Event
{
    type Error = RpcError;

    fn try_from(
        event: rpc_block_hook_receipt::RpcBlockHookReceiptGetBlockHookReceiptEvents,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            service: event.service,
            topic:   event.topic,
            data:    event.data,
        })
    }
}

impl TryFrom<rpc_block_hook_receipt::RpcBlockHookReceiptGetBlockHookReceipt>
    for muta_types::BlockHookReceipt
{
    type Error = RpcError;

    fn try_from(
        receipt: rpc_block_hook_receipt::RpcBlockHookReceiptGetBlockHookReceipt,
    ) -> Result<Self, Self::Error> {
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
