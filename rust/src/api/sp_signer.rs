//! The spend side of a watch-only account: a stateless signer that receives
//! the spend keys for one call.

use std::str::FromStr;

use bitcoin::bip32::{Fingerprint, Xpriv};
use bitcoin::secp256k1::SecretKey;

use crate::api::sp_account::wipe_string;
use crate::api::types::SpError;
use crate::psbt_signer;

fn signing(reason: impl Into<String>) -> SpError {
    SpError::Signing {
        reason: reason.into(),
    }
}

/// Overwrite a secret buffer this crate was handed, before it is dropped.
fn wipe_bytes(secret: &mut Vec<u8>) {
    for byte in secret.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    secret.clear();
}

/// Complete the silent-payment fields of the unsigned PSBTv2 a
/// [`crate::api::sp_account::SpAccount::prepare_psbt`] simulation carries,
/// and sign every input. Returns the signed PSBTv2, for
/// [`crate::api::sp_account::SpAccount::finalize`].
///
/// A free function on purpose: it holds nothing, and the account it signs for
/// never sees a key. `b_spend` is the BIP352 spend secret key (32 bytes,
/// `m/352'/coin'/0'/0'/0`); `taproot_account_xprv` is the extended private
/// key of the BIP86 account (`m/86'/coin'/0'`, not the master key), needed
/// only when the PSBT spends a taproot sub-account coin. Both are wiped
/// before returning, on every path; copies made on the way in (FFI decoding)
/// are out of this function's reach.
///
/// All or nothing: an input neither key can be proven to own, an unsupported
/// script, a non-default sighash or a PSBT already carrying signatures or
/// shares is refused with [`SpError::Signing`], and no bytes are returned.
/// The result is checked with the same BIP375 verifier `finalize` runs.
pub fn sign_silent_payment_psbt(
    psbt: Vec<u8>,
    mut b_spend: Vec<u8>,
    taproot_account_xprv: Option<String>,
) -> Result<Vec<u8>, SpError> {
    let mut taproot_account_xprv = taproot_account_xprv;
    let result = sign_with_lent_keys(&psbt, &b_spend, taproot_account_xprv.as_deref());
    wipe_bytes(&mut b_spend);
    if let Some(xprv) = taproot_account_xprv.as_mut() {
        wipe_string(xprv);
    }
    result
}

fn sign_with_lent_keys(
    psbt: &[u8],
    b_spend: &[u8],
    taproot_account_xprv: Option<&str>,
) -> Result<Vec<u8>, SpError> {
    let b_spend: [u8; 32] = b_spend
        .try_into()
        .map_err(|_| signing("spend key must be 32 bytes"))?;
    let mut b_spend = SecretKey::from_slice(&b_spend).map_err(|_| signing("invalid spend key"))?;
    let mut xpriv = taproot_account_xprv
        .map(|xprv| Xpriv::from_str(xprv).map_err(|_| signing("invalid taproot account key")))
        .transpose();

    let result = match &xpriv {
        Ok(xpriv) => {
            // The account-level key does not know its master fingerprint; the
            // signer matches a key origin by fingerprint, then proves the
            // derived key against the input's own key. Offering the key under
            // every fingerprint the PSBT names keeps the proof as the only gate.
            let mut lent: Vec<(Fingerprint, Xpriv)> = xpriv
                .iter()
                .flat_map(|xpriv| origin_fingerprints(psbt).into_iter().map(|fp| (fp, *xpriv)))
                .collect();
            let signed = psbt_signer::sign_silent_payment_psbt(psbt, &b_spend, &lent)
                .map_err(|e| signing(e.to_string()));
            for (_, copy) in &mut lent {
                copy.private_key.non_secure_erase();
            }
            signed
        }
        Err(e) => Err(e.clone()),
    };
    b_spend.non_secure_erase();
    if let Ok(Some(xpriv)) = &mut xpriv {
        xpriv.private_key.non_secure_erase();
    }
    result
}

/// The master fingerprints of every BIP32 key origin the PSBT's inputs carry.
fn origin_fingerprints(psbt: &[u8]) -> Vec<Fingerprint> {
    let Ok(psbt) = bwk_psbt::PsbtV2::deserialize(psbt) else {
        return Vec::new();
    };
    let mut fingerprints: Vec<Fingerprint> = psbt
        .inputs
        .iter()
        .flat_map(|input| {
            let tap = input.psbt.tap_key_origins.values().map(|(_, (fp, _))| *fp);
            let ecdsa = input.psbt.bip32_derivation.values().map(|(fp, _)| *fp);
            tap.chain(ecdsa).collect::<Vec<_>>()
        })
        .collect();
    fingerprints.sort();
    fingerprints.dedup();
    fingerprints
}
