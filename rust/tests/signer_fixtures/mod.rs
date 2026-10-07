//! Chain-free fixtures: watch-only accounts from `sp(scan_priv,spend_pub)`
//! descriptors, synthetic silent-payment and BIP32 coins, and a reference
//! signer reproducing bwk's own test harness (`sp/tests/common/mod.rs`:
//! `write_bip32_sp_shares` + `sign_v2` + BIP32 hot signing).
#![allow(dead_code)]

use std::str::FromStr;

use bwk::miniscript::{Descriptor, DescriptorPublicKey};
use bwk_coin::{Coin, CoinSpendInfo, CoinStatus, KeyChain};
use bwk_sp::{
    account::{config::Config, recipient::TxBuilderSpExt, Account},
    bitcoin::{
        bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
        hashes::Hash,
        key::{TapTweak, TweakedPublicKey},
        secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey},
        Amount, Network, OutPoint, ScriptBuf, Sequence, TxOut, Txid,
    },
    bwk_sign::bwk_descriptor::sp_descriptor::SpDescriptor,
    receiver::{derive_spend_key, scan_path},
};

pub const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const RECIPIENT_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
pub const NETWORK: Network = Network::Regtest;
pub const PLACEHOLDER_BLINDBIT_URL: &str = "https://blindbit.test.example.com";

pub fn account_index() -> ChildNumber {
    ChildNumber::from_hardened_idx(0).unwrap()
}

/// Master xpriv with the empty BIP39 passphrase, as `SpSigner::from_mnemonic`.
pub fn master(mnemonic: &str) -> Xpriv {
    let seed = bwk_sp::receiver::bip39::Mnemonic::from_str(mnemonic)
        .unwrap()
        .to_seed("");
    Xpriv::new_master(NETWORK, &seed).unwrap()
}

/// What the custody layer would derive and lend for one call.
pub fn b_spend(mnemonic: &str) -> SecretKey {
    derive_spend_key(
        &master(mnemonic),
        &Secp256k1::new(),
        NETWORK,
        account_index(),
    )
    .unwrap()
}

/// `sp(scan_priv_wif, spend_pub)`: the only thing the watch-only account gets.
pub fn sp_descriptor(mnemonic: &str) -> SpDescriptor {
    let secp = Secp256k1::new();
    let scan_sk = master(mnemonic)
        .derive_priv(&secp, &scan_path(NETWORK, account_index()))
        .unwrap()
        .private_key;
    let spend_pk = b_spend(mnemonic).public_key(&secp);
    let scan_wif = bwk_sp::bitcoin::PrivateKey::new(scan_sk, NETWORK).to_wif();
    SpDescriptor::from_str(&format!("sp({scan_wif},{spend_pk})")).unwrap()
}

pub fn watch_only_account(name: &str, mnemonic: &str) -> Account {
    let config = Config::from_descriptor(
        name.to_string(),
        NETWORK,
        sp_descriptor(mnemonic),
        PLACEHOLDER_BLINDBIT_URL.to_string(),
        std::path::PathBuf::from("/unused"),
    )
    .with_persistence(None);
    Account::new(config).unwrap()
}

pub fn outpoint(byte: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([byte; 32]),
        vout: 0,
    }
}

/// A silent-payment coin paying `spend_pk + tweak·G`, as the scanner would
/// record it (unlabeled output, tweak `t_k`).
pub fn sp_coin(spend_pk: PublicKey, tweak_byte: u8, outpoint_byte: u8, sats: u64) -> Coin {
    let secp = Secp256k1::new();
    let tweak = SecretKey::from_slice(&[tweak_byte; 32]).unwrap();
    let output_key = spend_pk.add_exp_tweak(&secp, &tweak.into()).unwrap();
    let (x_only, _) = output_key.x_only_public_key();
    Coin {
        txout: TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                x_only,
            )),
        },
        outpoint: outpoint(outpoint_byte),
        height: Some(1),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        status: CoinStatus::Confirmed,
        label: None,
        satisfaction_size: bwk_coin::TAPROOT_KEYSPEND_SATISFACTION_WU,
        spend_info: CoinSpendInfo::Sp {
            tweak: tweak.secret_bytes(),
        },
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Bip32Kind {
    Wpkh,
    Tr,
}

/// Account-level xpriv (`m/84'/1'/0'` or `m/86'/1'/0'`) with its master
/// fingerprint: what the custody layer would lend for BIP32 inputs.
pub fn account_xpriv(mnemonic: &str, kind: Bip32Kind) -> (Fingerprint, Xpriv) {
    let secp = Secp256k1::new();
    let master = master(mnemonic);
    let purpose = match kind {
        Bip32Kind::Wpkh => 84,
        Bip32Kind::Tr => 86,
    };
    let path = DerivationPath::from_str(&format!("m/{purpose}'/1'/0'")).unwrap();
    (
        master.fingerprint(&secp),
        master.derive_priv(&secp, &path).unwrap(),
    )
}

/// A BIP32 coin at receive index 0 of the account descriptor.
pub fn bip32_coin(mnemonic: &str, kind: Bip32Kind, outpoint_byte: u8, sats: u64) -> Coin {
    let secp = Secp256k1::new();
    let (fingerprint, xpriv) = account_xpriv(mnemonic, kind);
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let origin = format!(
        "[{fingerprint}/{}'/1'/0']{xpub}/<0;1>/*",
        match kind {
            Bip32Kind::Wpkh => 84,
            Bip32Kind::Tr => 86,
        }
    );
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&match kind {
        Bip32Kind::Wpkh => format!("wpkh({origin})"),
        Bip32Kind::Tr => format!("tr({origin})"),
    })
    .unwrap();
    let single = descriptor.clone().into_single_descriptors().unwrap()[0].clone();
    let script_pubkey = single.at_derivation_index(0).unwrap().script_pubkey();
    Coin {
        txout: TxOut {
            value: Amount::from_sat(sats),
            script_pubkey,
        },
        outpoint: outpoint(outpoint_byte),
        height: Some(1),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        status: CoinStatus::Confirmed,
        label: None,
        satisfaction_size: single.max_weight_to_satisfy().unwrap().to_wu(),
        spend_info: CoinSpendInfo::Bip32 {
            coin_path: (KeyChain::Receive, 0),
            descriptor,
        },
    }
}

/// Builds an unsigned PSBTv2 through the watch-only account's real builder:
/// `send_to_sp(recipient)` + explicit inputs, SP change from the account.
pub fn build_v2(
    account: &Account,
    recipient: &Account,
    coins: Vec<Coin>,
    amount: u64,
) -> bwk_psbt::PsbtV2 {
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(recipient.sp_address(), amount);
    for coin in coins {
        builder.add_input(coin);
    }
    builder.generate_v2().unwrap()
}

/// bwk harness `bip32_secret_key`, with BIP341 parity normalization.
fn harness_bip32_secret_key(
    input: &bwk_sp::bitcoin::psbt::Input,
    master: &Xpriv,
) -> Option<SecretKey> {
    let secp = Secp256k1::new();
    let derive =
        |path: &DerivationPath| master.derive_priv(&secp, path).ok().map(|k| k.private_key);
    let sk = if let Some((_, (_, path))) = input.bip32_derivation.iter().next() {
        derive(path)
    } else if let Some((_, (_, (_, path)))) = input.tap_key_origins.iter().next() {
        derive(path)
    } else {
        None
    }?;
    if input
        .witness_utxo
        .as_ref()
        .is_some_and(|utxo| utxo.script_pubkey.is_p2tr())
    {
        let tweaked = Keypair::from_secret_key(&secp, &sk)
            .tap_tweak(&secp, None)
            .to_keypair();
        let (_, parity) = tweaked.x_only_public_key();
        Some(match parity {
            bwk_sp::bitcoin::secp256k1::Parity::Odd => tweaked.secret_key().negate(),
            bwk_sp::bitcoin::secp256k1::Parity::Even => tweaked.secret_key(),
        })
    } else {
        Some(sk)
    }
}

/// Reference signing path, as bwk's harness `sign_and_finalize_v2` minus the
/// finalize: per-input BIP375 shares for BIP32 inputs, then
/// `SpSigner::from_mnemonic(..).sign`, then BIP32 signatures through
/// rust-bitcoin's `Psbt::sign` with the master xpriv.
pub fn reference_sign(mnemonic: &str, psbt: &mut bwk_psbt::PsbtV2) {
    let secp = Secp256k1::new();
    let master = master(mnemonic);
    let scan_keys = bwk_sp::account::bip375::scan_keys(psbt).unwrap();
    if !scan_keys.is_empty() {
        let aux_rand = [0x11u8; 32];
        for input in &mut psbt.inputs {
            if bwk_psbt::sp::sp_input_tweak(&input.psbt).unwrap().is_some() {
                continue;
            }
            let Some(sk) = harness_bip32_secret_key(&input.psbt, &master) else {
                continue;
            };
            bwk_sp::signer::write_input_ecdh_share(
                &mut input.psbt,
                &scan_keys,
                sk,
                aux_rand,
                &secp,
            )
            .unwrap();
        }
    }
    bwk_sp::signer::SpSigner::from_mnemonic(mnemonic, NETWORK, account_index())
        .unwrap()
        .sign(psbt)
        .unwrap();
    let mut v0 = psbt.clone().into_bitcoin_psbt().unwrap();
    let _ = v0.sign(&master, &secp);
    // `PsbtV2::from_bitcoin_psbt` resets `tx_modifiable` to `None`, which
    // `PsbtV2::validate` then rejects for a PSBT with computed SP scripts;
    // carry the frozen flags across the v0 round trip.
    let tx_modifiable = psbt.tx_modifiable;
    *psbt = bwk_psbt::PsbtV2::from_bitcoin_psbt(v0).unwrap();
    psbt.tx_modifiable = tx_modifiable;
}
