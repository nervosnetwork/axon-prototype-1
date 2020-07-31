use ckb_sdk::rpc::Script;
use serde::{Deserialize, Serialize};

// config file
use serde_json;
use std::env;
use std::fs;
use std::path::PathBuf;

use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
use ckb_types::H256;
use ckb_types::{bytes::Bytes, packed, prelude::*};
use faster_hex::hex_decode;
use std::convert::{TryFrom, TryInto};

const RELAYER_CONFIG_NAME: &str = "relayer_config.json";

pub struct Loader(PathBuf);

impl Default for Loader {
    fn default() -> Self {
        Self::with_current_dir()
    }
}

impl Loader {
    fn with_current_dir() -> Self {
        let dir = env::current_dir().unwrap();
        let mut base_path = PathBuf::new();
        base_path.push(dir);
        Loader(base_path)
    }

    pub fn load_binary(&self, name: &str) -> Bytes {
        let mut path = self.0.clone();
        path.push(name);
        fs::read(path).expect("binary").into()
    }

    pub fn load_relayer_config(&self) -> serde_json::Value {
        let mut config_path = self.0.clone();
        config_path.push(RELAYER_CONFIG_NAME);
        let json_str = fs::read_to_string(&config_path).expect("relayer config load failed");
        serde_json::from_str(&json_str).expect("invalid relayer config json")
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigScript {
    pub code_hash: String,
    pub hash_type: String,
    pub args:      String,
}

impl TryFrom<ConfigScript> for Script {
    type Error = hex::FromHexError;

    fn try_from(script: ConfigScript) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&script.code_hash.as_bytes()[2..])?;
        let code_hash = H256::from_slice(bytes.as_slice()).expect("code_hash invalid");

        let bytes = hex::decode(&script.args.as_bytes()[2..])?;
        let args = JsonBytes::from_vec(bytes);

        let hash_type = match script.hash_type.as_str() {
            "data" => ScriptHashType::Data,
            "type" => ScriptHashType::Type,
            _ => panic!("hash_type invalid"),
        };

        Ok(Self {
            code_hash,
            hash_type,
            args,
        })
    }
}

pub trait RelayerConfig {
    fn get_script(&self, name: &str) -> Script;
    fn get_tx_hash(&self, name: &str) -> packed::Byte32;
}

impl RelayerConfig for serde_json::Value {
    fn get_script(&self, name: &str) -> Script {
        let config_script =
            serde_json::from_str::<ConfigScript>(self[name].to_string().as_ref()).unwrap();

        config_script
            .try_into()
            .expect("get script from config failed")
    }

    fn get_tx_hash(&self, name: &str) -> packed::Byte32 {
        let str = relayer_config[name]
            .as_str()
            .expect("get tx_hash from config failed");
        let mut dst = [0u8; 32];
        hex_decode(&str.as_bytes()[2..], &mut dst).expect("tx_hash decode error");
        packed::Byte32::from_slice(dst.as_ref()).expect("transfer tx_hash to Byte32 failed")
    }
}

#[test]
fn test_config() {
    let relayer_config = Loader::default().load_relayer_config();
    let cross_lockscript: Script = relayer_config.get_script("crosschainLockscript");
    let cross_typescript: Script = relayer_config.get_script("crosschainTypescript");

    dbg!(cross_lockscript, cross_typescript);
}
