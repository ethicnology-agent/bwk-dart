//! The FFI entry point of the signer: keys arrive as bytes and strings, the
//! account-level BIP86 key is matched without a master fingerprint, and every
//! refusal is a typed `SpError::Signing` carrying no key material.

mod signer_fixtures;

use bwk_sp::bitcoin::secp256k1::Secp256k1;
use dart_bwk::api::sp_signer::sign_silent_payment_psbt;
use dart_bwk::api::types::SpError;
use signer_fixtures::*;

fn mixed_psbt(name: &str) -> (bwk_sp::account::Account, Vec<u8>) {
    let sender = watch_only_account(name, MNEMONIC);
    let recipient = watch_only_account(&format!("{name}-recipient"), RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let psbt = build_v2(
        &sender,
        &recipient,
        vec![
            sp_coin(spend_pk, 5, 1, 60_000),
            bip32_coin(MNEMONIC, Bip32Kind::Tr, 2, 70_000),
        ],
        100_000,
    );
    (sender, psbt.serialize().unwrap())
}

fn b_spend_bytes(mnemonic: &str) -> Vec<u8> {
    b_spend(mnemonic).secret_bytes().to_vec()
}

fn taproot_xprv(mnemonic: &str) -> String {
    account_xpriv(mnemonic, Bip32Kind::Tr).1.to_string()
}

fn assert_no_key_material(err: &SpError) {
    let rendered = format!("{err} {err:?}");
    for needle in [
        hex::encode(b_spend(MNEMONIC).secret_bytes()),
        taproot_xprv(MNEMONIC),
        hex::encode(
            account_xpriv(MNEMONIC, Bip32Kind::Tr)
                .1
                .private_key
                .secret_bytes(),
        ),
    ] {
        assert!(!rendered.contains(&needle), "key material in {rendered}");
    }
}

#[test]
fn signs_sp_and_taproot_inputs_with_an_account_level_key() {
    let (sender, psbt) = mixed_psbt("ffi-mixed");
    let signed =
        sign_silent_payment_psbt(psbt, b_spend_bytes(MNEMONIC), Some(taproot_xprv(MNEMONIC)))
            .expect("both keys lent");
    let tx = sender
        .finalize(&signed)
        .expect("the account verifies and extracts");
    assert_eq!(tx.input.len(), 2);
    assert!(tx.input.iter().all(|i| !i.witness.is_empty()));
}

#[test]
fn signs_an_sp_only_psbt_without_a_taproot_key() {
    let sender = watch_only_account("ffi-sp-only", MNEMONIC);
    let recipient = watch_only_account("ffi-sp-only-r", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let psbt = build_v2(
        &sender,
        &recipient,
        vec![sp_coin(spend_pk, 5, 1, 500_000)],
        100_000,
    );
    let signed = sign_silent_payment_psbt(psbt.serialize().unwrap(), b_spend_bytes(MNEMONIC), None)
        .expect("an SP input needs only b_spend");
    sender.finalize(&signed).expect("finalizes");
}

#[test]
fn refusals_are_typed_and_carry_no_key_material() {
    let (_, psbt) = mixed_psbt("ffi-refusals");
    let cases: Vec<(&str, Vec<u8>, Option<String>)> = vec![
        ("no taproot key", b_spend_bytes(MNEMONIC), None),
        (
            "foreign taproot key",
            b_spend_bytes(MNEMONIC),
            Some(taproot_xprv(RECIPIENT_MNEMONIC)),
        ),
        (
            "foreign spend key",
            b_spend_bytes(RECIPIENT_MNEMONIC),
            Some(taproot_xprv(MNEMONIC)),
        ),
        (
            "short spend key",
            vec![1u8; 31],
            Some(taproot_xprv(MNEMONIC)),
        ),
        (
            "zero spend key",
            vec![0u8; 32],
            Some(taproot_xprv(MNEMONIC)),
        ),
        (
            "malformed taproot key",
            b_spend_bytes(MNEMONIC),
            Some(taproot_xprv(MNEMONIC)[..40].to_string()),
        ),
    ];
    for (case, b_spend, xprv) in cases {
        let err = sign_silent_payment_psbt(psbt.clone(), b_spend, xprv)
            .err()
            .unwrap_or_else(|| panic!("{case}: refused"));
        assert!(matches!(err, SpError::Signing { .. }), "{case}: {err:?}");
        assert_no_key_material(&err);
    }
    let err = sign_silent_payment_psbt(b"garbage".to_vec(), b_spend_bytes(MNEMONIC), None)
        .expect_err("not a PSBT");
    assert!(matches!(err, SpError::Signing { .. }), "{err:?}");
}
