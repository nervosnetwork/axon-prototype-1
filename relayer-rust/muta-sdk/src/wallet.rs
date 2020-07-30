use bip39::{Language, Mnemonic, MnemonicType, Seed};
use common_crypto::Secp256k1PrivateKey;
use std::convert::TryFrom;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::DerivationPath;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("parse error")]
    Crypto(#[from] common_crypto::Error),
}

pub struct Wallet {
    mnemonic: Mnemonic,
    seed:     Seed,
}

impl Wallet {
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
        let ext_private_key =
            ExtendedPrivKey::derive(self.seed.as_bytes(), Wallet::get_hd_path(account_index))
                .expect("derive error");

        let priv_bytes: &[u8] = &ext_private_key.secret();
        Ok(Secp256k1PrivateKey::try_from(priv_bytes)?)
    }

    fn get_hd_path(account_index: u64) -> DerivationPath {
        let path: DerivationPath = format!("m/44'/918/{}'/0/0", account_index)
            .parse()
            .expect("format derivation path");
        return path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_crypto::PrivateKey;

    #[test]
    fn test_wallet() {
        let wallet = Wallet::generate("123456");
        let mnemonic = wallet.get_mnemonic();
        println!("mnemonic {}", mnemonic);

        let private_key = wallet.derive_privatekey(0).unwrap();
        println!(
            "private_key {}",
            hex::encode(&private_key.to_bytes().as_ref())
        );
    }
}
