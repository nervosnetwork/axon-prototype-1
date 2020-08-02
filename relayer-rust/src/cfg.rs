use ckb_sdk::rpc::Script;
use serde::{Deserialize, Deserializer, Serialize};

// config file
use serde_json;
use std::env;
use std::fs;
use std::path::PathBuf;

use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
use ckb_types::{bytes::Bytes, packed, prelude::*};
use ckb_types::{H160, H256};
use config::{Config, File, FileFormat};
use faster_hex::hex_decode;
use std::convert::{TryFrom, TryInto};

const RELAYER_CONFIG_NAME: &str = "relayer_config.toml";

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

    pub fn load_relayer_config(&self) -> RelayerConfig {
        let mut c = Config::default();
        c.merge(File::new("relayer_config", FileFormat::Toml))
            .unwrap();
        c.try_into()
            .map_err(|e| panic!("load relayer_config error: {}", e))
            .unwrap()
    }
}

#[derive(Debug, Deserialize)]
pub struct CkbConfig {
    pub url:                  String,
    pub url_indexer:          String,
    pub crosschain_cell_data: String,

    pub create_crosschain_cell_tx_hash: H256,
    pub crosschain_lockscript_hash:     H256,
    pub crosschain_typescript_hash:     H256,
    pub deploy_tx_hash:                 H256,
    pub issue_tx_hash:                  H256,
    pub private_key:                    H256,
    pub udt_script_hash:                H256,

    pub crosschain_lockscript: Script,
    pub crosschain_typescript: Script,
    pub udt_script:            Script,
    pub validators_lockscript: Script,
}

#[derive(Debug, Deserialize)]
pub struct MutaConfig {
    pub address:     H160,
    pub endpoint:    String,
    pub private_key: H256,
}

#[derive(Debug, Deserialize)]
pub struct RelayerConfig {
    pub ckb:      CkbConfig,
    pub muta:     MutaConfig,
    pub sudt_ids: Vec<H256>,
}

#[test]
fn test_config_toml() {}
