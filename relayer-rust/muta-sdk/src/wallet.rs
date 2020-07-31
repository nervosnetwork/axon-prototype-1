use bip39::{Language, Mnemonic, MnemonicType, Seed};
use common_crypto::Secp256k1PrivateKey;
use std::convert::TryFrom;
use tiny_hderive::bip32::ExtendedPrivKey;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("parse error")]
    Crypto(#[from] common_crypto::Error),
    #[error("mnemonic error")]
    MnemonicError,
}

pub struct Wallet {
    mnemonic: Mnemonic,
    seed:     Seed,
}

impl Wallet {
    pub fn new(phrase: &str, password: &str) -> Self {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).expect("wrong phrase");
        let seed = Seed::new(&mnemonic, password);

        Self { mnemonic, seed }
    }

    /// generate wallet randomly
    pub fn generate(password: &str) -> Self {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, password);

        Self { mnemonic, seed }
    }

    pub fn get_mnemonic(&self) -> String {
        let m = self.mnemonic.clone();
        String::from(m)
    }

    pub fn derive_privatekey(
        &self,
        account_index: u64,
    ) -> Result<Secp256k1PrivateKey, WalletError> {
        let hd_path = Wallet::get_hd_path(account_index);
        let ext_private_key =
            ExtendedPrivKey::derive(self.seed.as_bytes(), hd_path.as_str()).expect("derive error");

        let priv_bytes: &[u8] = &ext_private_key.secret();
        Ok(Secp256k1PrivateKey::try_from(priv_bytes)?)
    }

    fn get_hd_path(account_index: u64) -> String {
        format!("m/44'/918'/{}'/0/0", account_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_crypto::PrivateKey;
    #[test]
    fn test_wallet() {
        let wallet = Wallet::new(
            "drastic behave exhaust enough tube judge real logic escape critic horror gold",
            "",
        );

        let private_key0 = wallet.derive_privatekey(0).unwrap();
        let private_key1 = wallet.derive_privatekey(1).unwrap();

        assert_eq!(
            hex::encode(private_key0.to_bytes()),
            "8ceac4c591bfb13c6cc4b211f83df53f1edd54a88970f1ee88eeda8d07c0e161"
        );
        assert_eq!(
            hex::encode(private_key1.to_bytes()),
            "7dab2ed67c2dd811139b2bb257cd998f38dc5b05c7377a143e143e45708e34c8"
        )
    }
}
