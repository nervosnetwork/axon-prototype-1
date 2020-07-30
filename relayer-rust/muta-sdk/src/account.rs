use bytes::Bytes;
use common_crypto::{
    HashValue, PrivateKey, PublicKey, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
    Signature, ToPublicKey,
};
use muta_protocol::fixed_codec::FixedCodec;
use muta_protocol::types::{Address, Hash, RawTransaction, SignedTransaction};
use rand::rngs::OsRng;
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccountError {
    #[error("parse error")]
    Crypto(#[from] common_crypto::Error),
    #[error("from hex error")]
    FromHex(#[from] hex::FromHexError),
    #[error("muta error")]
    MutaProtocol(#[from] muta_protocol::ProtocolError),
}

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

    pub fn from_hex(hex_priv_key: &str) -> Result<Self, AccountError> {
        let hex_privkey = hex::decode(hex_priv_key)?;
        Ok(Account::from_bytes(hex_privkey.as_ref())?)
    }

    pub fn from_bytes(bytes_priv_key: &[u8]) -> Result<Self, AccountError> {
        let private_key = Secp256k1PrivateKey::try_from(bytes_priv_key)?;
        Ok(Account::new(private_key))
    }

    /// generate account randomly
    pub fn generate() -> Self {
        let private_key = Secp256k1PrivateKey::generate(&mut OsRng);
        Account::new(private_key)
    }

    pub fn get_public_key(&self) -> Secp256k1PublicKey {
        self.public_key.clone()
    }

    pub fn get_address(&self) -> Address {
        self.address.clone()
    }

    // ref: https://github.com/mkxbl/muta/blob/axon-single-operator/core/api/src/lib.rs#L188
    pub fn sign_hash(&self, hash: HashValue) -> Secp256k1Signature {
        self.private_key.sign_message(&hash)
    }

    pub fn sign_raw(_raw: Bytes) -> Secp256k1Signature {
        todo!()
    }

    pub fn sign_raw_tx(&self, raw: RawTransaction) -> Result<SignedTransaction, AccountError> {
        let bytes = raw.encode_fixed()?;
        let tx_hash = Hash::digest(bytes);
        let hash_value = HashValue::try_from(tx_hash.as_bytes().as_ref()).expect("mismatch length");
        let signature = self.private_key.sign_message(&hash_value);

        let pubkey = self.get_public_key();
        Ok(SignedTransaction {
            raw,
            tx_hash,
            pubkey: pubkey.to_bytes(),
            signature: signature.to_bytes(),
        })
    }
}
