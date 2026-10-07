//! Executable evidence for two pitfalls in bwk PR #114's signing path that
//! this signer avoids. Both are pinned against bwk's public API as it is at
//! 912eb7c; if either test starts failing, bwk changed behavior.

mod signer_fixtures;

use bwk_sp::{
    account::bip375,
    bitcoin::{
        key::TapTweak,
        secp256k1::{Keypair, Parity, Secp256k1},
    },
};
use dart_bwk::psbt_signer::sign_silent_payment_psbt;
use signer_fixtures::*;

/// `PsbtV2::from_bitcoin_psbt` sets `tx_modifiable: None`. A completed SP
/// PSBT taken through a v0 signer and back (as bwk's harness
/// `sign_and_finalize_v2` does for BIP32 inputs) then fails
/// `verify_signed` and no longer serializes, until the flag is restored.
#[test]
fn v0_round_trip_drops_tx_modifiable() {
    let sender = watch_only_account("find-roundtrip", MNEMONIC);
    let recipient = watch_only_account("find-roundtrip-r", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&Secp256k1::new());
    let unsigned = build_v2(
        &sender,
        &recipient,
        vec![sp_coin(spend_pk, 5, 1, 500_000)],
        100_000,
    );
    let signed = bwk_psbt::PsbtV2::deserialize(
        &sign_silent_payment_psbt(&unsigned.serialize().unwrap(), &b_spend(MNEMONIC), &[]).unwrap(),
    )
    .unwrap();
    assert_eq!(signed.tx_modifiable, Some(bwk_psbt::TxModifiable::none()));

    let mut round_tripped =
        bwk_psbt::PsbtV2::from_bitcoin_psbt(signed.clone().into_bitcoin_psbt().unwrap()).unwrap();
    assert_eq!(round_tripped.tx_modifiable, None);
    assert!(bip375::verify_signed(&round_tripped).is_err());
    // `PsbtV2::serialize` validates too, so the bytes for `finalize` cannot
    // even be produced.
    assert!(round_tripped.serialize().is_err());

    round_tripped.tx_modifiable = signed.tx_modifiable;
    assert!(bip375::verify_signed(&round_tripped).is_ok());
    sender
        .finalize(&round_tripped.serialize().unwrap())
        .unwrap();
}

/// bwk's harness `bip32_secret_key` tap-tweaks a BIP86 key but keeps the
/// secret of the full tweaked point. When that point has odd Y (the
/// "abandon … about" BIP86 key at m/86'/1'/0'/0/0 does), the per-input
/// ECDH share and DLEQ proof are computed for -P while BIP352 sums the
/// even lift P, so `complete_output_scripts` rejects the proof. The
/// harness's own BIP32 mnemonic ("legal winner …") happens to have an
/// even key at index 0, which hides this.
#[test]
fn unnormalized_taproot_key_breaks_per_input_share() {
    let secp = Secp256k1::new();
    let sender = watch_only_account("find-parity", MNEMONIC);
    let recipient = watch_only_account("find-parity-r", RECIPIENT_MNEMONIC);
    let spend_pk = b_spend(MNEMONIC).public_key(&secp);
    let unsigned = build_v2(
        &sender,
        &recipient,
        vec![
            sp_coin(spend_pk, 5, 1, 60_000),
            bip32_coin(MNEMONIC, Bip32Kind::Tr, 2, 70_000),
        ],
        100_000,
    );
    let tr_index = unsigned
        .inputs
        .iter()
        .position(|i| i.previous_output == outpoint(2))
        .unwrap();
    let (_, (_, path)) = unsigned.inputs[tr_index]
        .psbt
        .tap_key_origins
        .values()
        .next()
        .unwrap()
        .clone();
    let internal_sk = master(MNEMONIC)
        .derive_priv(&secp, &path)
        .unwrap()
        .private_key;
    let tweaked = Keypair::from_secret_key(&secp, &internal_sk)
        .tap_tweak(&secp, None)
        .to_keypair();
    assert_eq!(
        tweaked.x_only_public_key().1,
        Parity::Odd,
        "fixture premise"
    );

    let scan_keys = bip375::scan_keys(&unsigned).unwrap();
    let sp_signer =
        bwk_sp::signer::SpSigner::from_mnemonic(MNEMONIC, NETWORK, account_index()).unwrap();

    // Harness behavior: full tweaked secret, odd point.
    let mut harness = unsigned.clone();
    bwk_sp::signer::write_input_ecdh_share(
        &mut harness.inputs[tr_index].psbt,
        &scan_keys,
        tweaked.secret_key(),
        [1u8; 32],
        &secp,
    )
    .unwrap();
    assert!(sp_signer.sign(&mut harness).is_err());

    // Parity-normalized secret: accepted.
    let mut normalized = unsigned.clone();
    bwk_sp::signer::write_input_ecdh_share(
        &mut normalized.inputs[tr_index].psbt,
        &scan_keys,
        tweaked.secret_key().negate(),
        [1u8; 32],
        &secp,
    )
    .unwrap();
    sp_signer.sign(&mut normalized).unwrap();
}
