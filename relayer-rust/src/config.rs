use ckb_sdk::rpc::Script;
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

// config file
use std::env;
use std::fs;
use std::path::PathBuf;
use serde_json::json;

use ckb_types::bytes::Bytes;
use ckb_types::H256;
use faster_hex::hex_decode;

use std::convert::{TryFrom, TryInto};
use ckb_jsonrpc_types::{JsonBytes, ScriptHashType};
const RELAYER_CONFIG_NAME: &str = "relayer_config.json";

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Hash)]
pub struct Config {
    pub lockscript: Script
}

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
        println!("binary_path: {:?}", path);
        fs::read(path).expect("binary").into()
    }

    pub fn load_relayer_config(&self) -> serde_json::Value {
        let mut config_path = self.0.clone();
        dbg!(&config_path);
        // config_path.push();

        // TODO: !!! just for Debug, it will be removed after
        let mut config_path = PathBuf::new();
        config_path.push("/Users/hyz/WebstormProjects/axon_copy/relayer/config.json");
        // Just for Debug

        let json_str = fs::read_to_string(&config_path).expect("relayer config load failed");
        serde_json::from_str(&json_str).expect("invalid relayer config json")
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigScript {
    pub code_hash: String,
    pub hash_type: String,
    pub args: String,
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
            _ => panic!("hash_type invalid")
        };

        Ok(Self {
            code_hash,
            hash_type,
            args,
        })
    }
}

#[test]
fn test_load() {
    let config: serde_json::Value = Loader::default().load_relayer_config();
    let lock_script = serde_json::from_str::<ConfigScript>(config["crosschainLockscript"].to_string().as_ref()).unwrap();
    dbg!(&lock_script);

    let script: Script = lock_script.try_into().unwrap();
    dbg!(script.args.as_bytes());

    let privkey_hex = config["ckb"]["privateKey"].as_str().unwrap();
    assert_eq!(privkey_hex, "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2b0");
}
