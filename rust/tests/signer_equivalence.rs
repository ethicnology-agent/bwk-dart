//! The stateless signer produces what bwk's own signing path produces:
//! same output scripts, same combined ECDH share, same unsigned transaction,
//! and a PSBT both `bip375::verify_signed` and `Account::finalize` accept.
//! Signatures and DLEQ proofs differ only by aux randomness.

mod signer_fixtures;

use bwk_sp::{
    account::bip375,
    bitcoin::{
        absolute,
        secp256k1::{Secp256k1, SecretKey},
        transaction, Transaction,
    },
};
use dart_bwk::psbt_signer::sign_silent_payment_psbt;
use signer_fixtures::*;

struct Signed {
    psbt: bwk_psbt::PsbtV2,
    tx: Transaction,
}

fn sign_both(
    sender: &bwk_sp::account::Account,
    unsigned: &bwk_psbt::PsbtV2,
    xprivs: &[(
        bwk_sp::bitcoin::bip32::Fingerprint,
        bwk_sp::bitcoin::bip32::Xpriv,
    )],
) -> (Signed, Signed) {
    let mut reference = unsigned.clone();
    reference_sign(MNEMONIC, &mut reference);
    bip375::verify_signed(&reference).expect("reference PSBT verifies");
    let reference_tx = sender
        .finalize(&reference.serialize().unwrap())
        .expect("reference PSBT finalizes");

    let bytes =
        sign_silent_payment_psbt(&unsigned.serialize().unwrap(), &b_spend(MNEMONIC), xprivs)
            .expect("stateless signer accepts the PSBT");
    let ours = bwk_psbt::PsbtV2::deserialize(&bytes).unwrap();
    bip375::verify_signed(&ours).expect("stateless PSBT verifies");
    let ours_tx = sender.finalize(&bytes).expect("stateless PSBT finalizes");

    (
        Signed {
            psbt: reference,
            tx: reference_tx,
        },
        Signed {
            psbt: ours,
            tx: ours_tx,
        },
    )
}

fn assert_equivalent(reference: &Signed, ours: &Signed) {
    // Same SP output scripts and amounts.
    assert_eq!(reference.psbt.outputs.len(), ours.psbt.outputs.len());
    for (r, o) in reference.psbt.outputs.iter().zip(&ours.psbt.outputs) {
        assert_eq!(r.amount, o.amount);
        assert!(o.script_pubkey.is_some());
        assert_eq!(r.script_pubkey, o.script_pubkey);
    }
    // The global share equals the sum of the reference's shares.
    for scan_key in bip375::scan_keys(&ours.psbt).unwrap() {
        assert_eq!(
            bip375::combined_share(&reference.psbt, scan_key).unwrap(),
            bip375::combined_share(&ours.psbt, scan_key).unwrap()
        );
        assert!(bwk_psbt::sp::sp_global_ecdh_share_v2(&ours.psbt, scan_key)
            .unwrap()
            .is_some());
    }
    assert_eq!(reference.psbt.tx_modifiable, ours.psbt.tx_modifiable);
    // Same transaction modulo witnesses: txid excludes the witness.
    assert_eq!(reference.tx.compute_txid(), ours.tx.compute_txid());
    assert_eq!(reference.tx.output, ours.tx.output);
    assert_eq!(reference.tx.input.len(), ours.tx.input.len());
    for input in &ours.tx.input {
        assert!(!input.witness.is_empty(), "every input is signed");
    }
}

#[test]
fn sp_input_to_sp_recipient_with_sp_change() {
    let sender = watch_only_account("eq-sp", MNEMONIC);
    let recipient = watch_only_account("eq-sp-recipient", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let unsigned = build_v2(
        &sender,
        &recipient,
        vec![sp_coin(spend_pk, 5, 1, 500_000)],
        100_000,
    );
    // Recipient + SP change, both left unscripted for the signer.
    assert_eq!(bip375::scan_keys(&unsigned).unwrap().len(), 2);
    assert!(unsigned.outputs.iter().all(|o| o.script_pubkey.is_none()));

    let (reference, ours) = sign_both(&sender, &unsigned, &[]);
    assert_equivalent(&reference, &ours);
}

#[test]
fn two_sp_inputs() {
    let sender = watch_only_account("eq-sp2", MNEMONIC);
    let recipient = watch_only_account("eq-sp2-recipient", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let unsigned = build_v2(
        &sender,
        &recipient,
        vec![
            sp_coin(spend_pk, 5, 1, 60_000),
            sp_coin(spend_pk, 6, 2, 70_000),
        ],
        100_000,
    );
    let (reference, ours) = sign_both(&sender, &unsigned, &[]);
    assert_equivalent(&reference, &ours);
}

#[test]
fn mixed_sp_and_wpkh_inputs() {
    let sender = watch_only_account("eq-wpkh", MNEMONIC);
    let recipient = watch_only_account("eq-wpkh-recipient", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let unsigned = build_v2(
        &sender,
        &recipient,
        vec![
            sp_coin(spend_pk, 5, 1, 60_000),
            bip32_coin(MNEMONIC, Bip32Kind::Wpkh, 2, 70_000),
        ],
        100_000,
    );
    let (reference, ours) = sign_both(
        &sender,
        &unsigned,
        &[account_xpriv(MNEMONIC, Bip32Kind::Wpkh)],
    );
    assert_equivalent(&reference, &ours);
}

#[test]
fn mixed_sp_and_taproot_inputs() {
    let sender = watch_only_account("eq-tr", MNEMONIC);
    let recipient = watch_only_account("eq-tr-recipient", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let unsigned = build_v2(
        &sender,
        &recipient,
        vec![
            sp_coin(spend_pk, 5, 1, 60_000),
            bip32_coin(MNEMONIC, Bip32Kind::Tr, 2, 70_000),
            bip32_coin(MNEMONIC, Bip32Kind::Wpkh, 3, 30_000),
        ],
        100_000,
    );
    let (reference, ours) = sign_both(
        &sender,
        &unsigned,
        &[
            account_xpriv(MNEMONIC, Bip32Kind::Tr),
            account_xpriv(MNEMONIC, Bip32Kind::Wpkh),
        ],
    );
    assert_equivalent(&reference, &ours);
}

/// Hand-built PSBT, as `sp/src/signer.rs`'s `generates_shares_and_scripts`:
/// one owned SP input, one SP output, no `Account` builder involved.
#[test]
fn hand_built_psbt_matches_sp_signer() {
    let secp = Secp256k1::new();
    let spend_pk = b_spend(MNEMONIC).public_key(&secp);
    let coin = sp_coin(spend_pk, 3, 5, 10_000);
    let mut psbt_input = bwk_sp::bitcoin::psbt::Input {
        witness_utxo: Some(coin.txout.clone()),
        ..Default::default()
    };
    bwk_psbt::sp::set_sp_input_tweak(&mut psbt_input, [3u8; 32]);
    let scan_key = SecretKey::from_slice(&[11u8; 32])
        .unwrap()
        .public_key(&secp);
    let recipient_spend = SecretKey::from_slice(&[12u8; 32])
        .unwrap()
        .public_key(&secp);
    let mut output = bwk_sp::bitcoin::psbt::Output::default();
    bwk_psbt::sp::set_sp_v0_output(&mut output, scan_key, recipient_spend, None);
    let unsigned = bwk_psbt::PsbtV2 {
        tx_version: transaction::Version::TWO,
        fallback_lock_time: Some(absolute::LockTime::ZERO),
        tx_modifiable: None,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: vec![bwk_psbt::Input {
            previous_output: coin.outpoint,
            sequence: coin.sequence,
            required_time_lock_time: None,
            required_height_lock_time: None,
            psbt: psbt_input,
        }],
        outputs: vec![bwk_psbt::Output {
            amount: bwk_sp::bitcoin::Amount::from_sat(9_000),
            script_pubkey: None,
            psbt: output,
        }],
    };
    let sender = watch_only_account("eq-hand", MNEMONIC);
    let (reference, ours) = sign_both(&sender, &unsigned, &[]);
    assert_equivalent(&reference, &ours);
    // SpSigner owns every input here, so it writes the same global share.
    assert_eq!(
        bwk_psbt::sp::sp_global_ecdh_share_v2(&reference.psbt, scan_key).unwrap(),
        bwk_psbt::sp::sp_global_ecdh_share_v2(&ours.psbt, scan_key).unwrap()
    );
}
