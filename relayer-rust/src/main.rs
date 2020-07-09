use ckb_sdk::rpc::HttpRpcClient;
use graphql_client::{GraphQLQuery, Response};
use serde_json::json;
use std::error;

#[derive(GraphQLQuery)]
#[graphql(
    query_path = "schema/queries.graphql",
    schema_path = "schema/muta.graphql",
    response_derives = "Debug,PartialEq"
)]
pub struct BlockView;

type Hash = String;
type Uint64 = String;
type Bytes = String;
type Address = String;

// #[tokio::main]
fn main() -> Result<(), Box<dyn error::Error>> {
    // ckb client
    // let mut ckb_rpc_client = HttpRpcClient::new("http://127.0.0.1:8114".into());
    // let res = ckb_rpc_client.get_tip_block_number();
    // dbg!(&res);
    // let latest_block = ckb_rpc_client.get_block_by_number(31676)?;
    // dbg!(&latest_block.unwrap().transactions);

    // muta client
    let muta_client = reqwest::Client::new();
    // let h = "0x1";
    // let q = json!({
    //     "query": "query ($h: Uint64) { getBlock(height:$h) { hash } } ",
    //     "variables": {"h": h},
    // });
    // let res: serde_json::Value = muta_client
    //     .post("http://127.0.0.1:8000/graphql")
    //     .json(&q)
    //     .send()
    //     .await?
    //     .json()
    //     .await?;
    // dbg!(&res);
    let q = BlockView::build_query(block_view::Variables {
        height: Some("0x10000000".to_owned()),
    });
    let mut res = muta_client
        .post("http://127.0.0.1:8000/graphql")
        .json(&q)
        .send()?;
    let response_body: Response<block_view::ResponseData> = res.json()?;
    dbg!(&response_body);

    Ok(())
}
