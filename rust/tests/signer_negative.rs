//! The signer refuses what it cannot fully handle, and bwk's verifier
//! rejects a PSBT tampered with after signing.

mod signer_fixtures;

use bwk_sp::{
    account::bip375,
    bitcoin::{
        key::TweakedPublicKey,
        psbt::PsbtSighashType,
        secp256k1::{Secp256k1, SecretKey},
        Amount, EcdsaSighashType, ScriptBuf,
    },
};
use dart_bwk::psbt_signer::{sign_silent_payment_psbt, Error};
use signer_fixtures::*;

fn unsigned_sp_psbt(name: &str) -> (bwk_sp::account::Account, bwk_psbt::PsbtV2) {
    let sender = watch_only_account(name, MNEMONIC);
    let recipient = watch_only_account(&format!("{name}-recipient"), RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let psbt = build_v2(
        &sender,
        &recipient,
        vec![sp_coin(spend_pk, 5, 1, 500_000)],
        100_000,
    );
    (sender, psbt)
}

fn sign(psbt: &bwk_psbt::PsbtV2) -> Result<Vec<u8>, Error> {
    sign_silent_payment_psbt(&psbt.serialize().unwrap(), &b_spend(MNEMONIC), &[])
}

#[test]
fn wrong_b_spend_is_refused_without_output() {
    let (_, psbt) = unsigned_sp_psbt("neg-wrong-key");
    let wrong = b_spend(RECIPIENT_MNEMONIC);
    let result = sign_silent_payment_psbt(&psbt.serialize().unwrap(), &wrong, &[]);
    assert_eq!(result, Err(Error::SpInputNotOwned { input: 0 }));
    // The API has no out-parameter: on error no bytes, hence no signature
    // and no share, ever leave the call.
    let arbitrary = SecretKey::from_slice(&[7u8; 32]).unwrap();
    assert!(sign_silent_payment_psbt(&psbt.serialize().unwrap(), &arbitrary, &[]).is_err());
}

#[test]
fn wrong_b_spend_on_one_of_two_sp_inputs_is_refused() {
    let sender = watch_only_account("neg-foreign-sp", MNEMONIC);
    let recipient = watch_only_account("neg-foreign-sp-r", RECIPIENT_MNEMONIC);
    let secp = Secp256k1::new();
    let ours = b_spend(MNEMONIC).public_key(&secp);
    let foreign = b_spend(RECIPIENT_MNEMONIC).public_key(&secp);
    let psbt = build_v2(
        &sender,
        &recipient,
        vec![sp_coin(ours, 5, 1, 60_000), sp_coin(foreign, 6, 2, 70_000)],
        100_000,
    );
    let foreign_index = psbt
        .inputs
        .iter()
        .position(|i| i.previous_output == outpoint(2))
        .unwrap();
    assert_eq!(
        sign(&psbt),
        Err(Error::SpInputNotOwned {
            input: foreign_index
        })
    );
}

#[test]
fn bip32_input_without_xpriv_is_refused() {
    let sender = watch_only_account("neg-no-xpriv", MNEMONIC);
    let recipient = watch_only_account("neg-no-xpriv-r", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let psbt = build_v2(
        &sender,
        &recipient,
        vec![
            sp_coin(spend_pk, 5, 1, 60_000),
            bip32_coin(MNEMONIC, Bip32Kind::Wpkh, 2, 70_000),
        ],
        100_000,
    );
    let bip32_index = psbt
        .inputs
        .iter()
        .position(|i| i.previous_output == outpoint(2))
        .unwrap();
    assert_eq!(
        sign(&psbt),
        Err(Error::Bip32InputNotOwned { input: bip32_index })
    );
    // The right fingerprint with the wrong account (BIP86 xpriv for a BIP84
    // input) is refused too, not used to sign.
    assert_eq!(
        sign_silent_payment_psbt(
            &psbt.serialize().unwrap(),
            &b_spend(MNEMONIC),
            &[account_xpriv(MNEMONIC, Bip32Kind::Tr)],
        ),
        Err(Error::Bip32InputNotOwned { input: bip32_index })
    );
}

#[test]
fn already_signed_psbt_is_refused() {
    let (_, psbt) = unsigned_sp_psbt("neg-twice");
    let signed = bwk_psbt::PsbtV2::deserialize(&sign(&psbt).unwrap()).unwrap();
    assert!(matches!(sign(&signed), Err(Error::AlreadyStarted { .. })));
}

#[test]
fn non_default_sighash_is_refused() {
    let (_, mut psbt) = unsigned_sp_psbt("neg-sighash");
    psbt.inputs[0].psbt.sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::None));
    assert_eq!(sign(&psbt), Err(Error::Sighash { input: 0 }));
}

#[test]
fn garbage_is_refused() {
    assert_eq!(
        sign_silent_payment_psbt(b"not a psbt", &b_spend(MNEMONIC), &[]),
        Err(Error::Decode)
    );
}

/// The core redirect attack: after signing, someone swaps a silent-payment
/// output's script for one they control. The signatures are still present,
/// but the script no longer matches the shares, so the account refuses.
#[test]
fn tampered_sp_output_script_is_rejected() {
    let (sender, psbt) = unsigned_sp_psbt("neg-tamper-script");
    let signed = sign(&psbt).unwrap();
    sender.finalize(&signed).expect("untampered PSBT finalizes");

    let mut tampered = bwk_psbt::PsbtV2::deserialize(&signed).unwrap();
    let secp = Secp256k1::new();
    let (attacker, _) = SecretKey::from_slice(&[0x42; 32])
        .unwrap()
        .x_only_public_key(&secp);
    let index = tampered
        .outputs
        .iter()
        .position(|o| bwk_psbt::sp::sp_v0_output(&o.psbt).unwrap().is_some())
        .unwrap();
    tampered.outputs[index].script_pubkey = Some(ScriptBuf::new_p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(attacker),
    ));

    assert!(bip375::verify_signed(&tampered).is_err());
    assert!(sender.finalize(&tampered.serialize().unwrap()).is_err());
}

/// Swapping the claimed silent-payment recipient (spend key) after signing:
/// the existing script no longer derives from the PSBT's SP fields.
#[test]
fn tampered_sp_recipient_key_is_rejected() {
    let (sender, psbt) = unsigned_sp_psbt("neg-tamper-key");
    let mut tampered = bwk_psbt::PsbtV2::deserialize(&sign(&psbt).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let index = tampered
        .outputs
        .iter()
        .position(|o| bwk_psbt::sp::sp_v0_output(&o.psbt).unwrap().is_some())
        .unwrap();
    let info = bwk_psbt::sp::sp_v0_output(&tampered.outputs[index].psbt)
        .unwrap()
        .unwrap();
    let other_spend = SecretKey::from_slice(&[0x43; 32])
        .unwrap()
        .public_key(&secp);
    bwk_psbt::sp::set_sp_v0_output(
        &mut tampered.outputs[index].psbt,
        info.scan_key,
        other_spend,
        None,
    );
    assert!(bip375::verify_signed(&tampered).is_err());
    assert!(sender.finalize(&tampered.serialize().unwrap()).is_err());
}

/// An amount change after signing leaves every SP script valid (BIP352
/// scripts do not commit to amounts), so `bip375::verify_signed` passes;
/// the signatures commit to amounts, and `Account::finalize` (miniscript's
/// `finalize_mut`, which checks signatures) refuses to extract.
#[test]
fn tampered_amount_passes_bip375_but_fails_finalize() {
    let (sender, psbt) = unsigned_sp_psbt("neg-tamper-amount");
    let mut tampered = bwk_psbt::PsbtV2::deserialize(&sign(&psbt).unwrap()).unwrap();
    tampered.outputs[0].amount = tampered.outputs[0].amount - Amount::from_sat(1_000);
    assert!(bip375::verify_signed(&tampered).is_ok());
    let err = sender
        .finalize(&tampered.serialize().unwrap())
        .expect_err("a signature over the old amount must not finalize");
    assert!(
        matches!(err, bwk_sp::account::AccountError::Finalize(_)),
        "{err:?}"
    );
}
