//! Shared fixtures for the integration tests: the keys a custody layer
//! derives from a mnemonic (BIP352 and BIP86, test-network coin type 1), and a
//! watch-only account built from them.
#![allow(dead_code)]

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bwk_sp::receiver::bip39::Mnemonic;
use dart_bwk::api::sp_account::SpAccount;
use dart_bwk::api::types::SpNetwork;

pub const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const OTHER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

pub struct Derived {
    /// `sp(scan_wif, spend_pub)`
    pub sp_descriptor: String,
    /// `tr([fingerprint/86'/1'/0']tpub/<0;1>/*)`
    pub taproot_descriptor: String,
    /// The BIP352 spend secret key, lent to the signer for one call.
    pub b_spend: Vec<u8>,
    /// The BIP86 account key `m/86'/1'/0'`, lent to the signer for one call.
    pub taproot_account_xprv: String,
}

pub fn derive(mnemonic: &str) -> Derived {
    let secp = Secp256k1::new();
    let network = bitcoin::Network::Regtest;
    let seed = Mnemonic::from_str(mnemonic).unwrap().to_seed("");
    let master = Xpriv::new_master(network, &seed).unwrap();
    let at = |path: &str| {
        master
            .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
            .unwrap()
    };
    let scan = at("m/352'/1'/0'/1'/0").private_key;
    let spend = at("m/352'/1'/0'/0'/0").private_key;
    let taproot_account = at("m/86'/1'/0'");
    Derived {
        sp_descriptor: format!(
            "sp({},{})",
            bitcoin::PrivateKey::new(scan, network).to_wif(),
            spend.public_key(&secp)
        ),
        taproot_descriptor: format!(
            "tr([{}/86'/1'/0']{}/<0;1>/*)",
            master.fingerprint(&secp),
            Xpub::from_priv(&secp, &taproot_account)
        ),
        b_spend: spend.secret_bytes().to_vec(),
        taproot_account_xprv: taproot_account.to_string(),
    }
}

pub fn watch_only_account(
    name: &str,
    dir: &std::path::Path,
    keys: &Derived,
    blindbit_url: String,
    electrum_url: String,
) -> SpAccount {
    SpAccount::create_from_descriptors(
        name.to_string(),
        SpNetwork::Regtest,
        keys.sp_descriptor.clone(),
        Some(keys.taproot_descriptor.clone()),
        blindbit_url,
        electrum_url,
        dir.to_str().unwrap().to_string(),
        None,
        None,
        None,
        None,
    )
    .expect("create watch-only account")
}

/// Minimal noop-waker block_on for the few async helpers the tests drive.
pub fn block_on<F: std::future::Future>(mut fut: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let raw = RawWaker::new(std::ptr::null(), &VTABLE);
    // SAFETY: vtable is all no-ops; data pointer never dereferenced.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: fut owned by this function, not moved across polls.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
}

/// Wait for the one-shot scan `scan_once` started to finish (2 minutes at most).
pub fn wait_for_scan(account: &SpAccount) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    // The scan thread may not be marked running yet right after scan_once.
    std::thread::sleep(std::time::Duration::from_millis(200));
    while account.is_scanning().expect("is_scanning") {
        assert!(
            std::time::Instant::now() < deadline,
            "scan still running after 2 minutes"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
