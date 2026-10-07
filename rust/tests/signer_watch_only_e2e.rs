//! End to end without a chain: a watch-only `Account` built only from
//! `sp(scan_priv, spend_pub)` builds a PSBTv2 with an SP recipient and SP
//! change, the stateless signer completes and signs it with a lent
//! `b_spend`, and the same keyless account verifies and finalizes it. Both
//! the recipient and the sender's change are then discoverable by BIP352
//! scanning of the final transaction.
//!
//! What is synthetic: the spent coin. `TxBuilder::add_input` accepts any
//! `bwk_coin::Coin`, so the SP coin is fabricated (as the scanner would have
//! recorded it) instead of being found by a blindbit scan. Nothing is
//! broadcast; the account's coin store, scanner and broadcaster need
//! bitcoind + blindbit (bwk's `TestEnv`) and are not exercised here.

mod signer_fixtures;

use bwk_sp::{
    bitcoin::{secp256k1::Secp256k1, Transaction, XOnlyPublicKey},
    core::receiving::{calculate_ecdh_shared_secret, calculate_tweak_data, eligible_input_pubkey},
};
use dart_bwk::psbt_signer::sign_silent_payment_psbt;
use signer_fixtures::*;

/// Outputs of `tx` that `account` discovers by BIP352 scanning, with
/// whether each was found under a label (the change label).
fn discovered(
    account: &bwk_sp::account::Account,
    tx: &Transaction,
    prevouts: &[bwk_sp::bitcoin::TxOut],
) -> Vec<(XOnlyPublicKey, bool)> {
    let pubkeys: Vec<_> = tx
        .input
        .iter()
        .zip(prevouts)
        .filter_map(|(txin, prevout)| eligible_input_pubkey(txin, prevout).unwrap())
        .collect();
    let pubkey_refs: Vec<_> = pubkeys.iter().collect();
    let outpoints: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();
    let tweak_data = calculate_tweak_data(&pubkey_refs, &outpoints).unwrap();
    let shared = calculate_ecdh_shared_secret(&tweak_data, &account.sp_receiver().get_scan_key());
    let candidates: Vec<XOnlyPublicKey> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..34]).unwrap())
        .collect();
    account
        .sp_receiver()
        .receiver
        .scan_transaction(shared, &candidates)
        .unwrap()
        .into_iter()
        .flat_map(|(label, found)| found.into_keys().map(move |k| (k, label.is_some())))
        .collect()
}

#[test]
fn watch_only_account_build_sign_finalize() {
    let sender = watch_only_account("e2e-sender", MNEMONIC);
    let recipient = watch_only_account("e2e-recipient", RECIPIENT_MNEMONIC);

    // The account holds no secret at all: no mnemonic, no signer, and the
    // spend key it knows is public.
    assert!(sender.get_config().mnemonic.is_none());
    assert!(sender.signers().is_empty());
    assert!(sender.mnemonic_fingerprint().is_none());

    let spend_pk = sender.sp_receiver().spend_pubkey();
    assert_eq!(spend_pk, b_spend(MNEMONIC).public_key(&Secp256k1::new()));
    let coin = sp_coin(spend_pk, 9, 1, 500_000);
    let prevouts = vec![coin.txout.clone()];

    let unsigned = build_v2(&sender, &recipient, vec![coin], 100_000);
    unsigned.validate().unwrap();
    assert_eq!(unsigned.tx_modifiable, None);
    assert_eq!(unsigned.outputs.len(), 2, "recipient + SP change");
    let change_spend_key = sender
        .sp_receiver()
        .receiver
        .get_change_address()
        .get_spend_key();
    let change = unsigned
        .outputs
        .iter()
        .find(|o| {
            bwk_psbt::sp::sp_v0_output(&o.psbt)
                .unwrap()
                .is_some_and(|info| info.spend_key == change_spend_key)
        })
        .expect("change is a silent-payment output to our own change address");
    assert!(
        change.script_pubkey.is_none(),
        "watch-only cannot script it"
    );
    // The tweak the signer needs travels in the PSBT; no BIP376 spend
    // derivation hint, since a watch-only account knows no fingerprint.
    assert_eq!(
        bwk_psbt::sp::sp_input_tweak(&unsigned.inputs[0].psbt).unwrap(),
        Some([9u8; 32])
    );
    assert_eq!(
        bwk_psbt::sp::sp_input_spend_bip32_derivation(&unsigned.inputs[0].psbt, spend_pk),
        Ok(None)
    );

    // Custody lends b_spend for one stateless call.
    let signed =
        sign_silent_payment_psbt(&unsigned.serialize().unwrap(), &b_spend(MNEMONIC), &[]).unwrap();

    // The keyless account re-verifies and extracts.
    let tx = sender.finalize(&signed).unwrap();
    assert_eq!(tx.output.len(), 2);
    assert!(tx.output.iter().all(|o| o.script_pubkey.is_p2tr()));

    let to_recipient = discovered(&recipient, &tx, &prevouts);
    assert_eq!(to_recipient.len(), 1);
    assert!(!to_recipient[0].1, "recipient output is unlabeled");
    let to_sender = discovered(&sender, &tx, &prevouts);
    assert_eq!(to_sender.len(), 1);
    assert!(to_sender[0].1, "change is found under the change label");
    let recipient_out = tx
        .output
        .iter()
        .find(|o| o.script_pubkey.as_bytes()[2..34] == to_recipient[0].0.serialize())
        .unwrap();
    assert_eq!(recipient_out.value.to_sat(), 100_000);
}

/// A watch-only BIP32 sub-account can be declared without a mnemonic by
/// pushing a `SubAccountConfig` with `mnemonic: None` into the public
/// `Config::descriptors`; only the convenience helpers require a mnemonic.
/// Mixed SP + BIP32 spend through it is covered with `TxBuilder::add_input`
/// in `equivalence.rs`; this test only pins that the account accepts the
/// keyless sub-account config offline.
#[test]
fn watch_only_sub_account_from_public_descriptor() {
    use bwk::miniscript::{Descriptor, DescriptorPublicKey};
    use bwk_sp::account::config::{Config, SubAccountConfig};
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let (fingerprint, xpriv) = account_xpriv(MNEMONIC, Bip32Kind::Wpkh);
    let xpub = bwk_sp::bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!(
        "wpkh([{fingerprint}/84'/1'/0']{xpub}/<0;1>/*)"
    ))
    .unwrap();

    let mut config = Config::from_descriptor(
        "e2e-sub".to_string(),
        NETWORK,
        sp_descriptor(MNEMONIC),
        PLACEHOLDER_BLINDBIT_URL.to_string(),
        std::path::PathBuf::from("/unused"),
    )
    .with_persistence(None);
    assert!(
        config.add_default_segwit_sub_account().is_err(),
        "helper needs a mnemonic"
    );
    config.descriptors.push(SubAccountConfig {
        descriptor: descriptor.into(),
        mnemonic: None,
        endpoint: Default::default(),
    });
    let account = bwk_sp::account::Account::new(config).unwrap();
    assert_eq!(account.scanners().count(), 1);
    assert!(account.signers().is_empty());
}
