//! A stateless silent-payment signer for the PSBTv2s a watch-only bwk
//! account builds (bwk PR #114).
//!
//! Outside `api` on purpose: the FFI surface is
//! [`crate::api::sp_signer::sign_silent_payment_psbt`], which decodes the
//! lent keys and wipes them. This module is public for the integration tests.
//!
//! The custody layer lends `b_spend` (and optionally account-level BIP32
//! xprivs) for exactly one call. The call completes the BIP375 fields
//! (ECDH shares, DLEQ proofs, silent-payment output scripts) and signs every
//! input, using only bwk's public API, then returns the serialized PSBTv2.
//! The watch-only `bwk_sp::account::Account` re-verifies the returned bytes
//! in `Account::finalize` before extracting the transaction.
//!
//! # Scope
//!
//! The signer is all-or-nothing: it must own every input of the PSBT. An
//! input it cannot prove it owns (an SP input whose tweak does not
//! reconstruct against `b_spend`, a BIP32 input with no matching xpriv, an
//! unsupported script type, a script-path spend) is an error, never a
//! partial signature. Because it owns every eligible input, it always
//! publishes one global ECDH share and DLEQ proof per scan key, as
//! `bwk_sp::signer::SpSigner` does when it owns all eligible inputs.
//!
//! Supported inputs:
//! - silent-payment P2TR key spends carrying `PSBT_IN_SP_TWEAK`;
//! - BIP32 P2WPKH and P2SH-P2WPKH (ECDSA, `SIGHASH_ALL`);
//! - BIP32 BIP86 P2TR key spends (no script tree).
//!
//! # Key material
//!
//! No key is stored beyond the call, logged, or written into the PSBT. Every
//! secret this module derives itself (per-input signing keys, their sum) is
//! wiped with `SecretKey::non_secure_erase` on every exit path through
//! [`Secrets`]'s `Drop`. What cannot be wiped from here:
//! - the caller's own `b_spend` and `Xpriv` values (borrowed, the caller owns
//!   their lifetime; `SecretKey` and `Xpriv` are `Copy`, so any by-value
//!   handling upstream leaves copies the compiler may not clear);
//! - transient keys inside bwk and rust-bitcoin: the `b_spend + tweak`
//!   candidate in `bwk_sp::signer::reconstruct_signing_key`, the `Keypair` in
//!   `bwk_sp::signer::sign_taproot_key_spend`, intermediate chain codes and
//!   keys in `Xpriv::derive_priv`, the DLEQ nonce in
//!   `bwk_sp::core::dleq::generate_proof`, and the `Keypair`s built here for
//!   tap-tweaking (rust-bitcoin exposes no erase on `Keypair`/`ChainCode`);
//! - `non_secure_erase` itself is a best-effort volatile write, not a
//!   guarantee against copies made by moves or register spills.

use std::fmt;

use bwk_sp::{
    account::bip375,
    bitcoin::{
        self,
        bip32::{DerivationPath, Fingerprint, KeySource, Xpriv},
        ecdsa,
        key::TapTweak,
        psbt::PsbtSighashType,
        secp256k1::{All, Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey},
        sighash::SighashCache,
        EcdsaSighashType, ScriptBuf, TxOut,
    },
    core::dleq,
    signer::{reconstruct_signing_key, sign_taproot_key_spend},
};

/// Why a PSBT was refused. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a well-formed PSBTv2.
    Decode,
    /// The PSBT already carries signatures, finalized scripts, or BIP375
    /// shares/proofs; this signer only completes a fresh, unsigned PSBT.
    AlreadyStarted { input: Option<usize> },
    /// Input `input` uses a script type or spend path this signer does not
    /// handle, or lacks the `witness_utxo` it needs.
    Unsupported { input: usize, reason: &'static str },
    /// Input `input` carries `PSBT_IN_SP_TWEAK` but `b_spend + tweak` does not
    /// reproduce its prevout key.
    SpInputNotOwned { input: usize },
    /// Input `input` has no key origin matching one of the supplied xprivs, or
    /// the derived key does not reproduce its prevout.
    Bip32InputNotOwned { input: usize },
    /// Input `input` requests a sighash type other than the one this signer
    /// produces.
    Sighash { input: usize },
    /// bwk's BIP375 completion or verification rejected the PSBT.
    Bip375(String),
    /// A key operation failed (zero sum, invalid tweak, etc.).
    Crypto,
    /// The OS RNG failed.
    Rng,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode => write!(f, "not a valid PSBTv2"),
            Error::AlreadyStarted { input: Some(i) } => {
                write!(f, "input {i} is already signed or carries BIP375 fields")
            }
            Error::AlreadyStarted { input: None } => {
                write!(f, "psbt already carries global BIP375 fields")
            }
            Error::Unsupported { input, reason } => {
                write!(f, "input {input} unsupported: {reason}")
            }
            Error::SpInputNotOwned { input } => {
                write!(
                    f,
                    "silent-payment input {input} does not match the spend key"
                )
            }
            Error::Bip32InputNotOwned { input } => {
                write!(f, "input {input} is not controlled by any supplied xpriv")
            }
            Error::Sighash { input } => write!(f, "input {input} requests an unsupported sighash"),
            Error::Bip375(msg) => write!(f, "bip375: {msg}"),
            Error::Crypto => write!(f, "key operation failed"),
            Error::Rng => write!(f, "random number generator failed"),
        }
    }
}

impl std::error::Error for Error {}

/// How one input is signed.
#[derive(Clone, Copy)]
enum Spend {
    /// Taproot key spend; the key is the parity-normalized output secret.
    TaprootKey,
    /// Segwit v0 P2WPKH (possibly P2SH-wrapped): ECDSA over `p2wpkh_spk`.
    P2wpkh,
}

struct OwnedInput {
    index: usize,
    spend: Spend,
    /// For P2WPKH: the P2WPKH script (the redeem script when wrapped).
    p2wpkh_spk: Option<ScriptBuf>,
}

/// Owns every secret this module derives; wipes them on drop, including on
/// early `?` returns.
struct Secrets(Vec<SecretKey>);

impl Drop for Secrets {
    fn drop(&mut self) {
        for sk in &mut self.0 {
            sk.non_secure_erase();
        }
    }
}

fn fresh_aux() -> Result<[u8; 32], Error> {
    let mut aux = [0u8; 32];
    getrandom::getrandom(&mut aux).map_err(|_| Error::Rng)?;
    Ok(aux)
}

fn bip375_err(err: bwk_sp::account::AccountError) -> Error {
    Error::Bip375(err.to_string())
}

/// Completes the BIP375 fields of `psbt_v2_bytes` and signs every input.
///
/// * `b_spend` - the BIP352 spend secret, lent for this call only.
/// * `bip32_account_xprivs` - `(master fingerprint, account-level xpriv)`
///   pairs for BIP32 inputs, as found in the inputs' key origins; may be
///   empty when every input is a silent-payment input. A master (depth 0)
///   xpriv is accepted too.
///
/// Order of operations, mirroring `SpSigner::sign` plus the bwk test
/// harness's `write_bip32_sp_shares` and BIP32 signing:
/// 1. refuse a PSBT that is already started or that this signer does not
///    fully own;
/// 2. write one global ECDH share + DLEQ proof per scan key over the sum of
///    every eligible input key;
/// 3. `bip375::complete_output_scripts` (derives SP scripts, freezes
///    `tx_modifiable`);
/// 4. sign every input;
/// 5. self-check with `bip375::verify_signed` before returning bytes.
///
/// On error nothing is returned: there is no partially signed output.
pub fn sign_silent_payment_psbt(
    psbt_v2_bytes: &[u8],
    b_spend: &SecretKey,
    bip32_account_xprivs: &[(Fingerprint, Xpriv)],
) -> Result<Vec<u8>, Error> {
    let secp = Secp256k1::new();
    let mut psbt = bwk_psbt::PsbtV2::deserialize(psbt_v2_bytes).map_err(|_| Error::Decode)?;
    psbt.validate().map_err(|_| Error::Decode)?;

    refuse_started(&psbt)?;

    // 1. Resolve a key for every input, or refuse.
    let mut secrets = Secrets(Vec::with_capacity(psbt.inputs.len() + 1));
    let mut owned = Vec::with_capacity(psbt.inputs.len());
    for (index, input) in psbt.inputs.iter().enumerate() {
        let (sk, spend, p2wpkh_spk) =
            resolve_input(index, input, b_spend, bip32_account_xprivs, &secp)?;
        // Push first so the key is wiped even if a later check fails.
        secrets.0.push(sk);
        // BIP352 sums each eligible input's key as recovered from the
        // script; the key we sign with must be exactly that key.
        if let Some(expected) = bip375::eligible_input_pubkey(input).map_err(bip375_err)? {
            if sk.public_key(&secp) != expected {
                return Err(match spend {
                    Spend::TaprootKey if is_sp_input(input) => {
                        Error::SpInputNotOwned { input: index }
                    }
                    _ => Error::Bip32InputNotOwned { input: index },
                });
            }
        }
        owned.push(OwnedInput {
            index,
            spend,
            p2wpkh_spk,
        });
    }

    // 2. Global ECDH shares + DLEQ proofs.
    let scan_keys = bip375::scan_keys(&psbt).map_err(bip375_err)?;
    if !scan_keys.is_empty() {
        let mut sum: Option<SecretKey> = None;
        for (input, sk) in psbt.inputs.iter().zip(secrets.0.iter()) {
            if bip375::eligible_input_pubkey(input)
                .map_err(bip375_err)?
                .is_none()
            {
                continue;
            }
            sum = Some(match sum {
                Some(acc) => acc
                    .add_tweak(&Scalar::from(*sk))
                    .map_err(|_| Error::Crypto)?,
                None => *sk,
            });
        }
        let mut sum = sum.ok_or(Error::Bip375("no eligible input".into()))?;
        secrets.0.push(sum);
        for scan_key in scan_keys {
            let share = scan_key
                .mul_tweak(&secp, &Scalar::from(sum))
                .map_err(|_| Error::Crypto)?;
            let proof =
                dleq::generate_proof(sum, scan_key, fresh_aux()?, bip375::generator(), None)
                    .ok_or(Error::Crypto)?;
            bwk_psbt::sp::set_sp_global_ecdh_share_v2(&mut psbt, scan_key, share);
            bwk_psbt::sp::set_sp_global_dleq_v2(&mut psbt, scan_key, *proof.as_bytes());
        }
        sum.non_secure_erase();
    }

    // 3. Derive every silent-payment output script; freezes tx_modifiable.
    bip375::complete_output_scripts(&mut psbt).map_err(bip375_err)?;

    // 4. Sign. Sighashes are computed only now, over the final outputs.
    let tx = psbt.unsigned_tx().map_err(|_| Error::Decode)?;
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input.psbt.witness_utxo.clone().ok_or(Error::Unsupported {
                input: i,
                reason: "missing witness_utxo",
            })
        })
        .collect::<Result<_, _>>()?;
    let mut cache = SighashCache::new(&tx);
    for owned_input in &owned {
        let idx = owned_input.index;
        let sk = &secrets.0[idx];
        match owned_input.spend {
            Spend::TaprootKey => {
                let sig =
                    sign_taproot_key_spend(&mut cache, &prevouts, idx, sk, &secp, &fresh_aux()?)
                        .map_err(|_| Error::Crypto)?;
                psbt.inputs[idx].psbt.tap_key_sig = Some(sig);
            }
            Spend::P2wpkh => {
                let spk = owned_input.p2wpkh_spk.as_ref().ok_or(Error::Crypto)?;
                let sighash = cache
                    .p2wpkh_signature_hash(idx, spk, prevouts[idx].value, EcdsaSighashType::All)
                    .map_err(|_| Error::Crypto)?;
                let msg = Message::from(sighash);
                let signature = secp.sign_ecdsa(&msg, sk);
                let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
                psbt.inputs[idx].psbt.partial_sigs.insert(
                    pk,
                    ecdsa::Signature {
                        signature,
                        sighash_type: EcdsaSighashType::All,
                    },
                );
            }
        }
    }
    drop(secrets);

    // 5. Self-check with the exact verifier `Account::finalize` runs.
    bip375::verify_signed(&psbt).map_err(bip375_err)?;
    psbt.serialize().map_err(|_| Error::Decode)
}

fn is_sp_input(input: &bwk_psbt::Input) -> bool {
    matches!(bwk_psbt::sp::sp_input_tweak(&input.psbt), Ok(Some(_)))
}

fn refuse_started(psbt: &bwk_psbt::PsbtV2) -> Result<(), Error> {
    let global_shares = bwk_psbt::sp::sp_global_ecdh_shares_v2(psbt).map_err(|_| Error::Decode)?;
    let global_proofs = bwk_psbt::sp::sp_global_dleqs_v2(psbt).map_err(|_| Error::Decode)?;
    if !global_shares.is_empty() || !global_proofs.is_empty() {
        return Err(Error::AlreadyStarted { input: None });
    }
    for (i, input) in psbt.inputs.iter().enumerate() {
        let p = &input.psbt;
        let shares = bwk_psbt::sp::sp_input_ecdh_shares(p).map_err(|_| Error::Decode)?;
        let proofs = bwk_psbt::sp::sp_input_dleqs(p).map_err(|_| Error::Decode)?;
        if p.tap_key_sig.is_some()
            || !p.tap_script_sigs.is_empty()
            || !p.partial_sigs.is_empty()
            || p.final_script_sig.is_some()
            || p.final_script_witness.is_some()
            || !shares.is_empty()
            || !proofs.is_empty()
        {
            return Err(Error::AlreadyStarted { input: Some(i) });
        }
    }
    Ok(())
}

/// Finds the key for input `index` and how to sign it.
fn resolve_input(
    index: usize,
    input: &bwk_psbt::Input,
    b_spend: &SecretKey,
    xprivs: &[(Fingerprint, Xpriv)],
    secp: &Secp256k1<All>,
) -> Result<(SecretKey, Spend, Option<ScriptBuf>), Error> {
    let unsupported = |reason| Error::Unsupported {
        input: index,
        reason,
    };
    let witness_utxo = input
        .psbt
        .witness_utxo
        .as_ref()
        .ok_or(unsupported("missing witness_utxo"))?;
    // Cross-checks witness_utxo against non_witness_utxo when both exist.
    let script = bip375::input_script_pubkey(input)
        .map_err(bip375_err)?
        .ok_or(unsupported("unknown prevout"))?;
    if script != witness_utxo.script_pubkey {
        return Err(unsupported("inconsistent prevout"));
    }

    if is_sp_input(input) {
        check_sighash(index, input, Spend::TaprootKey)?;
        let tweak = bwk_psbt::sp::sp_input_tweak(&input.psbt)
            .map_err(|_| Error::Decode)?
            .ok_or(Error::Decode)?;
        let tweak =
            SecretKey::from_slice(&tweak).map_err(|_| Error::SpInputNotOwned { input: index })?;
        let sk = reconstruct_signing_key(*b_spend, tweak, &script, secp)
            .ok_or(Error::SpInputNotOwned { input: index })?;
        return Ok((sk, Spend::TaprootKey, None));
    }

    if script.is_p2tr() {
        check_sighash(index, input, Spend::TaprootKey)?;
        if input.psbt.tap_merkle_root.is_some() || !input.psbt.tap_scripts.is_empty() {
            return Err(unsupported("taproot script tree"));
        }
        let internal = input
            .psbt
            .tap_internal_key
            .ok_or(unsupported("missing tap_internal_key"))?;
        let (leaves, source) = input
            .psbt
            .tap_key_origins
            .get(&internal)
            .ok_or(Error::Bip32InputNotOwned { input: index })?;
        if !leaves.is_empty() {
            return Err(unsupported("internal key used in script leaves"));
        }
        let mut sk = derive_origin(source, xprivs, secp, |pk| {
            pk.x_only_public_key().0 == internal
        })
        .ok_or(Error::Bip32InputNotOwned { input: index })?;
        let keypair = Keypair::from_secret_key(secp, &sk);
        sk.non_secure_erase();
        let tweaked = keypair.tap_tweak(secp, None).to_keypair();
        let (x_only, parity) = tweaked.x_only_public_key();
        if script.as_bytes()[2..34] != x_only.serialize() {
            return Err(Error::Bip32InputNotOwned { input: index });
        }
        let out_sk = match parity {
            Parity::Odd => tweaked.secret_key().negate(),
            Parity::Even => tweaked.secret_key(),
        };
        return Ok((out_sk, Spend::TaprootKey, None));
    }

    let p2wpkh_spk = if script.is_p2wpkh() {
        script.clone()
    } else if script.is_p2sh() {
        match &input.psbt.redeem_script {
            Some(redeem)
                if redeem.is_p2wpkh() && ScriptBuf::new_p2sh(&redeem.script_hash()) == script =>
            {
                redeem.clone()
            }
            _ => return Err(unsupported("p2sh other than p2sh-p2wpkh")),
        }
    } else {
        return Err(unsupported("script type"));
    };
    check_sighash(index, input, Spend::P2wpkh)?;
    for (pubkey, source) in &input.psbt.bip32_derivation {
        if !bip375::bip32_pubkey_matches_script(*pubkey, &script, input.psbt.redeem_script.as_ref())
        {
            continue;
        }
        if let Some(sk) = derive_origin(source, xprivs, secp, |pk| pk == *pubkey) {
            return Ok((sk, Spend::P2wpkh, Some(p2wpkh_spk)));
        }
    }
    Err(Error::Bip32InputNotOwned { input: index })
}

fn check_sighash(index: usize, input: &bwk_psbt::Input, spend: Spend) -> Result<(), Error> {
    let allowed = match (input.psbt.sighash_type, spend) {
        (None, _) => true,
        // Taproot: this signer always produces SIGHASH_DEFAULT (0).
        (Some(t), Spend::TaprootKey) => t == PsbtSighashType::from_u32(0),
        (Some(t), Spend::P2wpkh) => t == PsbtSighashType::from(EcdsaSighashType::All),
    };
    allowed.then_some(()).ok_or(Error::Sighash { input: index })
}

/// Derives the private key for a key origin `(master fingerprint, full
/// path)` from an account-level (or master) xpriv, returning it only if its
/// public key satisfies `expected`. Several xprivs commonly share one master
/// fingerprint (BIP84 and BIP86 accounts of one seed) and the account-path
/// prefix of the origin is not otherwise authenticated, so every candidate
/// matching fingerprint, depth and child number is tried and checked.
fn derive_origin(
    (fingerprint, path): &KeySource,
    xprivs: &[(Fingerprint, Xpriv)],
    secp: &Secp256k1<All>,
    expected: impl Fn(PublicKey) -> bool,
) -> Option<SecretKey> {
    let path: Vec<_> = path.into_iter().copied().collect();
    for (fg, xpriv) in xprivs {
        if fg != fingerprint {
            continue;
        }
        let depth = xpriv.depth as usize;
        let suffix = if depth == 0 {
            &path[..]
        } else {
            if path.len() < depth || path[depth - 1] != xpriv.child_number {
                continue;
            }
            &path[depth..]
        };
        let Ok(mut child) = xpriv.derive_priv(secp, &DerivationPath::from(suffix.to_vec())) else {
            continue;
        };
        let mut sk = child.private_key;
        child.private_key.non_secure_erase();
        if expected(sk.public_key(secp)) {
            return Some(sk);
        }
        sk.non_secure_erase();
    }
    None
}
