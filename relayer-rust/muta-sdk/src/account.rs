use bytes::Bytes;
use common_crypto::{
    HashValue, PublicKey, Secp256k1, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
    ToPublicKey,
};
use muta_protocol::types::{Address, Hash, RawTransaction, SignedTransaction};

pub struct Account {
    private_key: Secp256k1PrivateKey,
    public_key:  Secp256k1PublicKey,
    address:     Address,
}

impl Account {
    pub fn new(private_key: Secp256k1PrivateKey) -> Self {
        let public_key = private_key.pub_key();
        let address =
            Address::from_hash(Hash::digest(public_key.to_bytes())).expect("should not happen");
        Self {
            private_key,
            public_key,
            address,
        }
    }

    pub fn from_hex(_hex_priv_key: &str) -> Self {
        todo!()
    }

    pub fn from_bytes(_bytes_priv_key: &[u8]) -> Self {
        todo!()
    }

    /// generate account randomly
    pub fn generate() -> Self {
        todo!()
    }

    pub fn get_public_key(&self) -> Secp256k1PublicKey {
        self.public_key.clone()
    }

    pub fn get_address(&self) -> Address {
        todo!()
    }

    // ref: https://github.com/mkxbl/muta/blob/axon-single-operator/core/api/src/lib.rs#L188
    pub fn sign_hash(_hash: HashValue) -> Secp256k1Signature {
        todo!()
    }

    pub fn sign_raw(_raw: Bytes) -> Secp256k1Signature {
        todo!()
    }

    pub fn sign_raw_tx(_tx: RawTransaction) -> SignedTransaction {
        todo!()
    }
}
