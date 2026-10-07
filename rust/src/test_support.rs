//! Keys a custody layer would derive from a mnemonic, the BIP352 and BIP86
//! way, for the unit tests. Derived here with rust-bitcoin directly, not
//! through bwk, so a test comparing them with what the account reports checks
//! bwk against an independent derivation.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Network, PrivateKey};
use bwk_sp::receiver::bip39::Mnemonic;

pub const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const OTHER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
pub const NETWORK: Network = Network::Regtest;
pub const PLACEHOLDER_BLINDBIT_URL: &str = "http://localhost:3000";

pub struct Derived {
    pub master_fingerprint: Fingerprint,
    /// `m/352'/1'/0'/1'/0`
    pub scan_sk: SecretKey,
    /// `m/352'/1'/0'/0'/0`
    pub b_spend: SecretKey,
    pub spend_pk: PublicKey,
    /// `sp(scan_wif, spend_pub)`: what the watch-only account receives.
    pub sp_descriptor: String,
    /// `sp(scan_wif, spend_wif)`: a descriptor the account must refuse.
    pub sp_descriptor_with_spend_secret: String,
    /// `m/86'/1'/0'`
    pub taproot_account_xprv: Xpriv,
    /// `tr([fingerprint/86'/1'/0']tpub/<0;1>/*)`
    pub taproot_descriptor: String,
}

pub fn derive(mnemonic: &str) -> Derived {
    let secp = Secp256k1::new();
    let seed = Mnemonic::from_str(mnemonic).unwrap().to_seed("");
    let master = Xpriv::new_master(NETWORK, &seed).unwrap();
    let at = |path: &str| {
        master
            .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
            .unwrap()
    };
    let scan_sk = at("m/352'/1'/0'/1'/0").private_key;
    let b_spend = at("m/352'/1'/0'/0'/0").private_key;
    let spend_pk = b_spend.public_key(&secp);
    let taproot_account_xprv = at("m/86'/1'/0'");
    let master_fingerprint = master.fingerprint(&secp);
    let wif = |sk: SecretKey| PrivateKey::new(sk, NETWORK).to_wif();
    Derived {
        master_fingerprint,
        scan_sk,
        b_spend,
        spend_pk,
        sp_descriptor: format!("sp({},{})", wif(scan_sk), spend_pk),
        sp_descriptor_with_spend_secret: format!("sp({},{})", wif(scan_sk), wif(b_spend)),
        taproot_account_xprv,
        taproot_descriptor: format!(
            "tr([{master_fingerprint}/86'/1'/0']{}/<0;1>/*)",
            Xpub::from_priv(&secp, &taproot_account_xprv)
        ),
    }
}

/// Every encoding of every secret of `keys` a store could plausibly hold:
/// raw bytes, hex in both cases, WIF, the extended private key, the full
/// descriptors, and the mnemonic.
pub fn secret_needles(keys: &Derived, mnemonic: &str) -> Vec<(String, Vec<u8>)> {
    let mut needles = Vec::new();
    let mut key = |label: &str, sk: SecretKey| {
        needles.push((format!("{label} raw"), sk.secret_bytes().to_vec()));
        let hex = hex::encode(sk.secret_bytes());
        needles.push((format!("{label} hex"), hex.clone().into_bytes()));
        needles.push((format!("{label} HEX"), hex.to_uppercase().into_bytes()));
        for network in [Network::Regtest, Network::Bitcoin] {
            needles.push((
                format!("{label} wif"),
                PrivateKey::new(sk, network).to_wif().into_bytes(),
            ));
        }
    };
    key("scan secret", keys.scan_sk);
    key("spend secret", keys.b_spend);
    key(
        "taproot account private key",
        keys.taproot_account_xprv.private_key,
    );
    needles.push((
        "taproot account xprv".to_string(),
        keys.taproot_account_xprv.to_string().into_bytes(),
    ));
    needles.push((
        "sp descriptor".to_string(),
        keys.sp_descriptor.clone().into_bytes(),
    ));
    needles.push(("mnemonic".to_string(), mnemonic.as_bytes().to_vec()));
    needles
}

/// `(file, needle label)` for every needle found in any file under `dir`.
pub fn find_secrets(dir: &Path, needles: &[(String, Vec<u8>)]) -> Vec<(PathBuf, String)> {
    let mut hits = Vec::new();
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        for (label, needle) in needles {
            if bytes
                .windows(needle.len())
                .any(|window| window == &needle[..])
            {
                hits.push((entry.path().to_path_buf(), label.clone()));
            }
        }
    }
    hits
}

/// The files under `dir`, for a report.
pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}
