use ckb_sdk::rpc::Script;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Hash)]
pub struct Config {
    pub lockscript: Script
}
