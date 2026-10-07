use std::{
    collections::BTreeSet,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread::JoinHandle,
    time::Duration,
};

use bitcoin::{consensus::encode::deserialize_hex, Network, NetworkKind};
use flutter_rust_bridge::frb;

use bwk::bwk_electrum::{
    coin_store::{CoinEntry, PaymentStatus, PaymentType},
    header_store::{HeaderProgressEvent, HeaderProgressPhase as BwkHeaderProgressPhase},
    notification::{Notification as BwkNotification, SpNotification as BwkSpNotification},
    profile::{DefaultBackend, RamProfile},
    scanner::ElectrumScanner,
    url::{parse_electrum_url, ElectrumScheme},
};
use bwk::miniscript::{Descriptor, DescriptorPublicKey};
use bwk_sp::account::config::{Config as SpConfig, SubAccountConfig};
use bwk_sp::account::recipient::SpRecipientAddress;
use bwk_sp::account::{self as sp_account, Account as SpAccountInner};
use bwk_sp::bwk_sign::bwk_descriptor::sp_descriptor::SpDescriptor;
use bwk_sp::receiver::RecipientAddress;
use bwk_sp::scan::{ScanRuntimeConfig, DEFAULT_FETCH_CONCURRENCY_FACTOR};

use crate::api::types::{
    CoinSource, HeaderProgressPhase, OutputDestination, RecipientView, SimulatedOutput,
    SpBalanceView, SpCoinView, SpError, SpNetwork, SpNotification, SpOwnedOutput,
    SpPaymentDirection, SpPaymentStatus, SpPaymentView, SpRecipientAddressKind, SubAccountKind,
    TxSimulation, UnifiedCoinStatus, UnifiedCoinView,
};
use crate::frb_generated::StreamSink;

// Under the `bull_sdk` aggregation feature, `StreamSink` is an alias for the
// FRB-shared `StreamSinkBase` (so it is the SAME nominal type the aggregator's
// generated wire function constructs). `StreamSinkBase` has no typed `add()`,
// so the typed `add(SpNotification)` is provided by this extension trait. In a
// standalone build `StreamSink` is the macro-generated wrapper which already
// has an inherent `add()`, so the trait is not imported there.
#[cfg(feature = "bull_sdk")]
use crate::frb_generated::SpStreamSinkExt as _;

// Prevent anyone from enabling continuous-scan mode across the FRB boundary.
#[cfg(feature = "continuous-scan")]
compile_error!(
    "ScanMode::Continuous is intentionally not exposed across FRB. \
     Removing this guard requires a deliberate design change."
);

/// The most coins automatic coin selection searches: bwk-tx's exhaustive
/// selector gives up on more (`coin_selection::all_coins_combinations`), and
/// reports it only as a generic selection failure.
const MAX_AUTO_SELECTED_COINS: usize = 20;

type SubAccountScanner = ElectrumScanner<RamProfile<DefaultBackend>>;

/// A watch-only Silent Payments account.
///
/// It holds the BIP352 scan secret key, which scanning needs, and nothing that
/// can spend: the spend key it knows is public, and its optional BIP86
/// sub-account is an xpub descriptor. Spending goes through
/// [`crate::api::sp_signer::sign_silent_payment_psbt`], which receives the
/// spend keys for that one call.
#[frb(opaque)]
pub struct SpAccount {
    inner: Arc<Mutex<SpAccountInner>>,
    sink: Mutex<Option<StreamSink<SpNotification>>>,

    // Cooperative shutdown for the notification-forwarding thread spawned in
    // `init()`. `dispose()` (FFI) and `Drop` both flip this flag and join the
    // handle so the thread, the inner Account, and its sqlite handle are
    // released deterministically. Without this, every WalletBloc refresh that
    // replaced `state.spWallet` would leak a thread blocked on `rx.recv()`
    // plus an open sqlite connection.
    shutdown: Arc<AtomicBool>,
    notif_handle: Mutex<Option<JoinHandle<()>>>,

    // Cancel signal for an in-flight `scan_once`. This is a clone of the
    // bwk_sp::Account's internal `scanner_stop`. Flipping it to `true`
    // causes the scan to bail at the next per-block checkpoint, releasing
    // the inner mutex without us ever needing to touch it. `stop_scan` MUST
    // NOT take the inner mutex; `dispose()` flips this flag so a running
    // scan releases the lock promptly and the next account opened on the
    // same `data_dir` doesn't race the sqlite handle.
    scan_cancel: Arc<AtomicBool>,
}

/// Test-only counter incremented when the notification thread exits cleanly.
/// Used by the Drop test to assert the thread actually terminates instead of
/// leaking. Fully gated behind `#[cfg(test)]`: in non-test builds the recorder
/// is an inlined no-op, so neither the counter nor the increment is compiled in.
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
static NOTIF_THREAD_EXITS: AtomicUsize = AtomicUsize::new(0);

/// Record a clean notification-thread exit. Increments the test counter under
/// test; a zero-cost no-op in production.
#[cfg(test)]
fn record_notif_thread_exit() {
    NOTIF_THREAD_EXITS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(not(test))]
#[inline(always)]
fn record_notif_thread_exit() {}

#[cfg(test)]
fn notif_thread_exit_count() -> usize {
    NOTIF_THREAD_EXITS.load(Ordering::Relaxed)
}

/// Take the SP-account mutex, mapping a poisoned lock to a recoverable error.
///
/// A panic in a holder of this lock (e.g. the notification thread) used to
/// poison it permanently, after which every subsequent FFI call would itself
/// panic via `.unwrap()` — bricking the wallet for the rest of the process.
/// Returning `Err` instead lets the cubit surface a "wallet stopped" state
/// and lets the user recover by restarting the app (no data loss: state is
/// persisted to sqlite on every coin update).
fn lock_inner(inner: &Mutex<SpAccountInner>) -> Result<MutexGuard<'_, SpAccountInner>, String> {
    inner
        .lock()
        .map_err(|_| "SP wallet lock poisoned; restart required".to_string())
}

fn to_bitcoin_network(n: SpNetwork) -> bitcoin::Network {
    match n {
        SpNetwork::Bitcoin => bitcoin::Network::Bitcoin,
        SpNetwork::Signet => bitcoin::Network::Signet,
        SpNetwork::Testnet => bitcoin::Network::Testnet,
        SpNetwork::Regtest => bitcoin::Network::Regtest,
    }
}

fn sp_network_matches(
    address_network: bwk_sp::core::utils::common::Network,
    network: Network,
) -> bool {
    match address_network {
        bwk_sp::core::utils::common::Network::Mainnet => network == Network::Bitcoin,
        bwk_sp::core::utils::common::Network::Testnet => {
            network == Network::Testnet || network == Network::Signet
        }
        bwk_sp::core::utils::common::Network::Regtest => network == Network::Regtest,
    }
}

pub fn validate_recipient_address(
    address: String,
    network: SpNetwork,
) -> Result<SpRecipientAddressKind, String> {
    let network = to_bitcoin_network(network);
    if let Ok(sp_address) =
        bwk_sp::core::utils::common::SilentPaymentAddress::try_from(address.as_str())
    {
        if !sp_network_matches(sp_address.get_network(), network) {
            return Err(format!("wrong network for '{address}'"));
        }
        return Ok(SpRecipientAddressKind::Sp);
    }

    bitcoin::Address::from_str(&address)
        .map_err(|e| format!("invalid address '{address}': {e}"))?
        .require_network(network)
        .map_err(|e| format!("wrong network for '{address}': {e}"))?;
    Ok(SpRecipientAddressKind::Standard)
}

/// Test a blindbit URL by fetching its current block height. Standalone (no live
/// account); async so the HTTP GET runs off the Dart UI isolate.
pub fn test_blindbit_url(url: String) -> Result<(), String> {
    let agent = bwk_sp::blindbit::agent().map_err(|e| e.to_string())?;
    bwk_sp::blindbit::block_height(&agent, &url)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Test an electrum URL by connecting and requesting `server.version`. Standalone;
/// async so the TCP/SSL handshake runs off the Dart UI isolate. 5s timeout.
pub fn test_electrum_url(url: String) -> Result<(), String> {
    use bwk::bwk_electrum::electrum::request::Request;
    let (host, port, scheme) = parse_electrum_url(&url)?;
    let host = host.ok_or_else(|| format!("missing host in '{url}'"))?;
    let port = port.ok_or_else(|| format!("missing port in '{url}'"))?;
    let ssl = matches!(scheme, ElectrumScheme::Ssl);
    let mut client = bwk::bwk_electrum::raw_client::Client::new_ssl_maybe(&host, port, ssl);
    client
        .try_connect(Some(Duration::from_secs(5)))
        .map_err(|e| format!("connection failed: {e}"))?;
    let req = Request::version("bullbitcoin".to_string(), "1.4".to_string());
    client
        .try_send(&req)
        .map_err(|e| format!("send failed: {e}"))?;
    client.recv_str().map_err(|e| format!("no response: {e}"))?;
    Ok(())
}

/// The kind of a sub-account, read from its descriptor.
fn sub_account_kind(scanner: &SubAccountScanner) -> Option<SubAccountKind> {
    match scanner.wallet_descriptor().as_miniscript()? {
        Descriptor::Wpkh(_) => Some(SubAccountKind::Segwit),
        Descriptor::Tr(_) => Some(SubAccountKind::Taproot),
        _ => None,
    }
}

fn coin_source_of(scanner: &SubAccountScanner) -> CoinSource {
    match sub_account_kind(scanner) {
        Some(SubAccountKind::Segwit) => CoinSource::Segwit,
        Some(SubAccountKind::Taproot) => CoinSource::Taproot,
        None => CoinSource::Other,
    }
}

fn find_scanner(inner: &SpAccountInner, kind: SubAccountKind) -> Option<&SubAccountScanner> {
    inner.scanners().find(|scanner| {
        matches!(
            (sub_account_kind(scanner), &kind),
            (Some(SubAccountKind::Segwit), SubAccountKind::Segwit)
                | (Some(SubAccountKind::Taproot), SubAccountKind::Taproot)
        )
    })
}

type Outputs = Vec<Box<dyn bwk_tx::recipient::RecipientProvider>>;

/// The outputs `recipients` ask for, as the builder takes them, and whether
/// one of them drains the wallet.
fn build_outputs(
    network: Network,
    recipients: &[RecipientView],
) -> Result<(Outputs, bool), String> {
    let mut outputs: Outputs = Vec::with_capacity(recipients.len());
    let mut has_max = false;
    for r in recipients {
        let is_max = match r {
            RecipientView::Sp { is_max, .. } | RecipientView::Standard { is_max, .. } => *is_max,
        };
        if is_max {
            // Drain all spendable coins to this output; bwk computes the amount
            // (total - fee). RecipientAddress handles both SP and standard.
            if has_max {
                return Err("only one max output is allowed".to_string());
            }
            has_max = true;
            let address = match r {
                RecipientView::Sp { address, .. } | RecipientView::Standard { address, .. } => {
                    address
                }
            };
            let addr = RecipientAddress::try_from(address.clone())
                .map_err(|e| format!("invalid address '{address}': {e}"))?;
            let mut recip = SpRecipientAddress::new(addr, 0, network);
            recip.amount = bwk_tx::transaction::Amount::Max(None);
            outputs.push(Box::new(recip));
            continue;
        }
        match r {
            RecipientView::Sp {
                address,
                amount_sat,
                ..
            } => {
                let sp_addr =
                    bwk_sp::core::utils::common::SilentPaymentAddress::try_from(address.as_str())
                        .map_err(|e| format!("invalid SP address '{address}': {e}"))?;
                if !sp_network_matches(sp_addr.get_network(), network) {
                    return Err(format!("Wrong network for SP address {sp_addr}"));
                }
                // As `TxBuilderSpExt::send_to_sp`.
                outputs.push(Box::new(SpRecipientAddress::from_sp(
                    sp_addr,
                    *amount_sat,
                    network,
                )));
            }
            RecipientView::Standard {
                address,
                amount_sat,
                ..
            } => {
                let addr = bitcoin::Address::from_str(address)
                    .map_err(|e| format!("invalid address '{address}': {e}"))?
                    .require_network(network)
                    .map_err(|e| format!("wrong network for '{address}': {e}"))?;
                // As `TxBuilder::send_to`.
                outputs.push(Box::new(bwk_tx::recipient::Recipient {
                    address: addr.as_unchecked().clone(),
                    amount: bwk_tx::transaction::Amount::Value(*amount_sat),
                    label: None,
                    origin: None,
                    descriptor: None,
                }));
            }
        }
    }
    Ok((outputs, has_max))
}

fn build_tx_with_coin_selection(
    inner: &SpAccountInner,
    outputs: &Outputs,
    has_max: bool,
    feerate_sat_vb: u64,
) -> bwk_tx::tx_builder::TxBuilder {
    let feerate_msat_vb = feerate_sat_vb.saturating_mul(1_000);
    let mut builder = inner
        .tx_builder()
        .feerate(feerate_msat_vb)
        .outputs(outputs.clone());
    if has_max {
        builder.drain_inputs();
    }
    builder
}

/// Run a bwk-tx builder step, turning a panic into an error.
///
/// bwk #114's `process_transaction` hits `unreachable!()` on a max send whose
/// remainder after the fee is under the dust limit (`tx/src/transaction.rs`,
/// the final `match (maxed_output, max, change)`). [max_send_shortfall] keeps
/// that case away from the builder; this is the backstop, so a divergence
/// between the two never unwinds through the account lock (which would poison
/// it) or across the FFI boundary.
fn guard_builder<T>(step: impl FnOnce() -> T) -> Result<T, SpError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)).map_err(|_| SpError::Other {
        message: "the transaction builder panicked".to_string(),
    })
}

/// For a max send, the sats left after the fee when that is under the dust
/// limit, computed the way bwk-tx's `process_transaction` does before it
/// would reach its `unreachable!()`: every spendable coin as input, the
/// requested outputs, and the account's SP change output weight.
fn max_send_shortfall(
    inner: &SpAccountInner,
    outputs: &Outputs,
    feerate_sat_vb: u64,
) -> Option<u64> {
    use bwk_tx::recipient::RecipientProvider as _;
    use bwk_tx::transaction::{self as tx, Amount, Drain, Fees, TxTemplate};

    let template = TxTemplate {
        inputs: spendable_candidates(inner),
        outputs: outputs.clone(),
        fees: Fees::MilliSatsVb(feerate_sat_vb.saturating_mul(1_000)),
    };
    if template.inputs.is_empty() {
        return None;
    }
    let change = bwk_sp::account::recipient::SpChangeRecipientProvider::new(
        inner.sp_receiver().receiver.get_change_address(),
        inner.network(),
    );
    let weight_wo_change = tx::tx_estimated_weight(&template);
    let weight_with_change = weight_wo_change + change.output_weight();
    let sum_inputs: u64 = template.inputs.iter().map(|c| c.txout.value.to_sat()).sum();
    let sum_outputs: u64 = template
        .outputs
        .iter()
        .map(|o| match o.amount() {
            Amount::Value(sats) => sats,
            Amount::Max(_) | Amount::Anchor => 0,
        })
        .sum();
    let result = tx::process_fees(
        template.fees.clone(),
        weight_wo_change,
        weight_with_change,
        sum_inputs,
        sum_outputs,
        Drain::Max,
    );
    if result.error.is_some() || result.max.is_some() {
        return None;
    }
    max_under_dust(&result.warnings)
}

fn parse_bwk_electrum_endpoint(url: &str) -> Result<(Option<String>, Option<u16>), String> {
    let (host, port, scheme) = parse_electrum_url(url)?;
    let host = host.map(|host| match scheme {
        ElectrumScheme::Tcp => host,
        ElectrumScheme::Ssl => format!("ssl://{host}"),
    });
    Ok((host, port))
}

/// Overwrite a secret string this crate was handed, before it is dropped.
/// Best effort: copies made before the call (FFI decoding, moves) are out of
/// reach.
pub(crate) fn wipe_string(secret: &mut String) {
    // SAFETY: zero bytes are valid UTF-8, so the string stays valid.
    for byte in unsafe { secret.as_bytes_mut() } {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    secret.clear();
}

fn invalid_descriptor(reason: &str) -> SpError {
    SpError::InvalidDescriptor {
        reason: reason.to_string(),
    }
}

/// Parse a BIP392 `sp(scan_priv, spend_pub)` descriptor for a watch-only
/// account on `network`.
///
/// Errors are fixed strings: the parser's own messages may quote the input,
/// and the input carries the scan secret key.
fn parse_watch_only_sp_descriptor(
    descriptor: &str,
    network: Network,
) -> Result<SpDescriptor, SpError> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let parsed = SpDescriptor::from_str(descriptor.trim())
        .map_err(|_| invalid_descriptor("not a valid sp() descriptor"))?;
    if parsed.scan_secret_key(&secp).is_err() {
        return Err(invalid_descriptor(
            "the sp() descriptor must carry the scan secret key",
        ));
    }
    match parsed.is_watch_only(&secp) {
        Ok(true) => {}
        Ok(false) => {
            return Err(invalid_descriptor(
                "the sp() descriptor carries a secret spend key; pass the spend public key",
            ))
        }
        Err(_) => return Err(invalid_descriptor("not a valid sp() descriptor")),
    }
    if parsed.network_kind() != NetworkKind::from(network) {
        return Err(invalid_descriptor(
            "the sp() descriptor is for another network",
        ));
    }
    Ok(parsed)
}

/// Parse the public descriptor of a BIP86 taproot sub-account: a single
/// extended public key with its origin, no script tree, for `network`.
///
/// Errors are fixed strings, for the same reason as
/// [parse_watch_only_sp_descriptor]: a refused descriptor may carry a private
/// key.
fn parse_taproot_descriptor(
    descriptor: &str,
    network: Network,
) -> Result<Descriptor<DescriptorPublicKey>, SpError> {
    let descriptor = descriptor.trim();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    // `parse_descriptor` accepts private keys and hands them back in a key
    // map: a non-empty map is a descriptor that must not reach the account.
    if let Ok((_, keys)) = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, descriptor) {
        if !keys.is_empty() {
            return Err(invalid_descriptor(
                "the taproot descriptor carries a private key; pass the xpub",
            ));
        }
    }
    let parsed = Descriptor::<DescriptorPublicKey>::from_str(descriptor)
        .map_err(|_| invalid_descriptor("not a valid taproot descriptor"))?;
    let Descriptor::Tr(tr) = &parsed else {
        return Err(invalid_descriptor("expected a single-key tr() descriptor"));
    };
    if tr.tap_tree().is_some() {
        return Err(invalid_descriptor("expected a single-key tr() descriptor"));
    }
    let (xkey, has_origin) = match tr.internal_key() {
        DescriptorPublicKey::MultiXPub(x) => (x.xkey, x.origin.is_some()),
        DescriptorPublicKey::XPub(x) => (x.xkey, x.origin.is_some()),
        DescriptorPublicKey::Single(_) => {
            return Err(invalid_descriptor(
                "the taproot descriptor needs an extended key with its origin",
            ))
        }
    };
    if !has_origin {
        return Err(invalid_descriptor(
            "the taproot descriptor needs an extended key with its origin",
        ));
    }
    if xkey.network != NetworkKind::from(network) {
        return Err(invalid_descriptor(
            "the taproot descriptor is for another network",
        ));
    }
    if !parsed.has_wildcard() {
        return Err(invalid_descriptor(
            "the taproot descriptor must derive addresses (end in /*)",
        ));
    }
    Ok(parsed)
}

impl SpAccount {
    #[allow(clippy::too_many_arguments)]
    fn from_descriptors_with_runtime(
        name: String,
        network: SpNetwork,
        sp_descriptor: &str,
        taproot_descriptor: Option<&str>,
        blindbit_url: String,
        electrum_url: String,
        data_dir: String,
        birthday_height: Option<u32>,
        dust_limit: Option<u64>,
        scan_runtime: ScanRuntimeConfig,
    ) -> Result<SpAccount, SpError> {
        let btc_net = to_bitcoin_network(network);
        let descriptor = parse_watch_only_sp_descriptor(sp_descriptor, btc_net)?;
        let taproot = taproot_descriptor
            .map(|d| parse_taproot_descriptor(d, btc_net))
            .transpose()?;

        let mut config = SpConfig::from_descriptor(
            name,
            btc_net,
            descriptor,
            blindbit_url,
            PathBuf::from(&data_dir),
        )
        .with_persistence(Some(bwk::persist::PersistenceKind::Sqlite));
        config.birthday_height = birthday_height;
        config.dust_limit = dust_limit;

        // The bwk_sp broadcast reads the account's own endpoint; the
        // sub-accounts stay offline until `set_electrum_url` + `start_electrum`.
        if let Ok((Some(host), Some(port))) = parse_bwk_electrum_endpoint(&electrum_url) {
            config.set_electrum_endpoint(host, port);
        }

        // A keyless sub-account: bwk has no helper for one, the config takes
        // it directly. `mnemonic: None` means no signer is ever attached.
        if let Some(taproot) = taproot {
            config.descriptors.push(SubAccountConfig {
                descriptor: taproot.into(),
                mnemonic: None,
                endpoint: Default::default(),
            });
        }

        let account = SpAccountInner::with_runtime_config(config, scan_runtime).map_err(|e| {
            SpError::Other {
                message: e.to_string(),
            }
        })?;
        let scan_cancel = account.cancel_flag();

        Ok(SpAccount {
            inner: Arc::new(Mutex::new(account)),
            sink: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
            notif_handle: Mutex::new(None),
            scan_cancel,
        })
    }

    fn runtime_from_factors(
        fetch_concurrency_factor: Option<u32>,
        match_concurrency_factor: Option<u32>,
    ) -> Result<ScanRuntimeConfig, String> {
        let _ = match_concurrency_factor;
        let fetch_concurrency_factor = fetch_concurrency_factor
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_FETCH_CONCURRENCY_FACTOR);
        ScanRuntimeConfig::from_fetch_concurrency_factor(fetch_concurrency_factor)
            .map_err(|e| e.to_string())
    }

    /// Open a watch-only SP account, creating its store under
    /// `data_dir/name` or reopening the one already there.
    ///
    /// `sp_descriptor` is a BIP392 `sp(scan_priv, spend_pub)` descriptor. A
    /// descriptor carrying the spend secret key is refused: the account holds
    /// no spend authority. `taproot_descriptor`, when given, is the public
    /// descriptor of the BIP86 sub-account,
    /// `tr([fingerprint/86'/coin'/0']xpub/<0;1>/*)`; private keys in it are
    /// refused. Neither descriptor is written to disk: only coins, labels,
    /// history and scan progress are persisted (sqlite), so a caller reopens
    /// an account by passing the descriptors again.
    ///
    /// Not `#[frb(sync)]`: this opens `account.sqlite`, opens the header store
    /// and spawns the scan runtime, which would freeze the Dart UI isolate for
    /// the whole of it, on first setup and on every session re-establish
    /// including cold start. Async rather than the usual notification-thread
    /// pattern because there is no sink to push to yet: this call creates the
    /// `SpAccount` that owns the single `StreamSink<SpNotification>`. FRB runs
    /// it on a worker isolate.
    #[allow(clippy::too_many_arguments)]
    pub fn create_from_descriptors(
        name: String,
        network: SpNetwork,
        mut sp_descriptor: String,
        taproot_descriptor: Option<String>,
        blindbit_url: String,
        electrum_url: String,
        data_dir: String,
        birthday_height: Option<u32>,
        dust_limit: Option<u64>,
        fetch_concurrency_factor: Option<u32>,
        match_concurrency_factor: Option<u32>,
    ) -> Result<SpAccount, SpError> {
        let account =
            Self::runtime_from_factors(fetch_concurrency_factor, match_concurrency_factor)
                .map_err(SpError::from)
                .and_then(|scan_runtime| {
                    Self::from_descriptors_with_runtime(
                        name,
                        network,
                        &sp_descriptor,
                        taproot_descriptor.as_deref(),
                        blindbit_url,
                        electrum_url,
                        data_dir,
                        birthday_height,
                        dust_limit,
                        scan_runtime,
                    )
                });
        // The account keeps its own parsed copy of the scan key; this one is
        // ours to clear. A refused descriptor may also have carried a spend
        // secret or a private taproot key.
        wipe_string(&mut sp_descriptor);
        if let Some(mut taproot_descriptor) = taproot_descriptor {
            wipe_string(&mut taproot_descriptor);
        }
        account
    }

    #[frb(sync)]
    pub fn init(&self, sink: StreamSink<SpNotification>) -> Result<(), String> {
        let rx = lock_inner(&self.inner)?
            .receiver()
            .ok_or_else(|| "init() already called — receiver already taken".to_string())?;

        let inner_arc = self.inner.clone();
        let thread_sink = sink.clone();
        let shutdown = self.shutdown.clone();
        *self
            .sink
            .lock()
            .map_err(|_| "sink mutex poisoned".to_string())? = Some(sink);

        let handle = std::thread::spawn(move || {
            // Snapshot existing sub-account outpoints so we only fire ElectrumTx
            // for NEW coins that arrive after init() is called.
            // A poisoned lock on the initial snapshot means the wallet is
            // already in a broken state — emit BackendOffline and exit.
            let mut sub_snap: Vec<BTreeSet<bitcoin::OutPoint>> = match inner_arc.lock() {
                Ok(inner) => inner
                    .scanners()
                    .map(|sub| sub.coins().into_keys().collect())
                    .collect(),
                Err(_) => {
                    log::error!("SpAccount::init: inner lock poisoned at snapshot");
                    let _ = thread_sink.add(SpNotification::BackendOffline);
                    record_notif_thread_exit();
                    return;
                }
            };

            // Drain the channel with a short timeout so we can check the
            // cooperative shutdown flag. The Sender lives inside the Account
            // (held by `inner_arc`); when SpAccount drops, the Account drops,
            // the Sender drops, and `rx.recv_timeout` would return Disconnected
            // — but we cannot rely on that alone because the JoinHandle is
            // joined from Drop while the strong Arc count is still >0.
            'outer: loop {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(n) => {
                        for mapped in map_notification(n, &inner_arc, &mut sub_snap) {
                            if thread_sink.add(mapped).is_err() {
                                break 'outer;
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            record_notif_thread_exit();
        });

        if let Ok(mut slot) = self.notif_handle.lock() {
            *slot = Some(handle);
        }

        Ok(())
    }

    /// Cooperatively stop the notification thread and release the inner
    /// Account (and its sqlite handle). Safe to call multiple times; the
    /// second call is a no-op.
    ///
    /// Dart callers MUST invoke this before dropping the last reference to
    /// `SpAccount` (typically from `SpWalletEntity.dispose()` which is in
    /// turn called from `WalletBloc._onRefreshSpWallet` before reassigning
    /// `state.spWallet`). Relying on `Drop` alone is risky because the FRB
    /// Arc may outlive the Dart-side handle for a finalizer cycle, leaking
    /// an open sqlite connection in the meantime.
    ///
    /// If a `scan_once` is in flight when `dispose()` is called, flipping
    /// `scan_cancel` makes the scan bail at the next per-block checkpoint and
    /// the inner Account becomes free to drop. Without this signal, the next
    /// account opened on the same `data_dir` would open `account.sqlite`
    /// while the previous scan was still writing — the exact double-handle
    /// race we are trying to prevent.
    ///
    /// Not `#[frb(sync)]`: dispose() waits for an in-flight call to release
    /// the lock, which can take seconds. Running that on the Dart UI isolate
    /// would freeze the UI. FRB dispatches `async` methods on a worker isolate.
    ///
    /// Return contract: returns `Ok(())` when the inner mutex became
    /// reacquirable within the bounded budget. Returns
    /// [`SpError::DisposeTimedOut`] when the budget elapsed without the lock
    /// becoming free. The caller MUST treat the timeout case as "previous
    /// SpAccount is still in flight" and MUST NOT open another account on the
    /// same `data_dir`.
    ///
    /// We still flip the cancel + shutdown flags, join the notification
    /// thread, and drop the cached sink on the timeout path so the
    /// notification side of cleanup is best-effort idempotent and a
    /// subsequent dispose() call observes a clean state. Only the
    /// inner-lock contract is violated.
    pub async fn dispose(&self) -> Result<(), SpError> {
        // 1. Signal any in-flight scan to bail at the next block checkpoint.
        self.scan_cancel.store(true, Ordering::Relaxed);

        // 2. Flip the notification-thread shutdown flag.
        self.shutdown.store(true, Ordering::Release);

        // 3. Wait (bounded) for the inner mutex to be free.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut lock_freed = false;
        while std::time::Instant::now() < deadline {
            if self.inner.try_lock().is_ok() {
                lock_freed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        // Stop the electrum listener thread so it releases the sqlite handle and
        // the `.lock` file. Without this the listener keeps running and a later
        // account-dir delete (revoke) fails file-locked.
        if let Ok(mut g) = self.inner.try_lock() {
            g.stop_electrum();
        }

        // 4. Take the JoinHandle out before joining so a second dispose()
        //    call (or Drop running after dispose) is a no-op.
        let handle = self
            .notif_handle
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(h) = handle {
            // Ignore JoinError (poison) — the thread is gone either way.
            let _ = h.join();
        }

        // 5. Drop the cached sink so any outstanding `add()` returns Err
        //    and does not pin Dart-side resources.
        if let Ok(mut sink) = self.sink.lock() {
            *sink = None;
        }

        if lock_freed {
            Ok(())
        } else {
            Err(SpError::DisposeTimedOut)
        }
    }

    #[frb(sync)]
    pub fn sp_address(&self) -> Result<String, String> {
        Ok(lock_inner(&self.inner)?.sp_address().to_string())
    }

    #[frb(sync)]
    pub fn confirmed_balance(&self) -> Result<u64, String> {
        Ok(lock_inner(&self.inner)?.balance())
    }

    #[frb(sync)]
    pub fn last_scanned_height(&self) -> Result<Option<u32>, String> {
        Ok(lock_inner(&self.inner)?.last_scanned_height())
    }

    /// Earliest height a scan may start from (taproot activation on mainnet, a
    /// low constant on test networks). The scan start chooser uses this as its
    /// floor.
    #[frb(sync)]
    pub fn min_birthday_height(&self) -> Result<u32, String> {
        Ok(lock_inner(&self.inner)?.min_birthday_height())
    }

    #[frb(sync)]
    pub fn is_scanning(&self) -> Result<bool, String> {
        Ok(lock_inner(&self.inner)?.is_scanning())
    }

    pub fn clear_scan_state(&self) -> Result<(), String> {
        lock_inner(&self.inner)?
            .clear_scan_state()
            .map_err(|e| e.to_string())
    }

    /// USER-TRIGGERED ONLY. The bb-mobile app contract is that this method
    /// is invoked exclusively from `ScanSpWalletUsecase`, which itself is
    /// invoked exclusively from `SpCubit.scan()` (the Scan button handler).
    /// Do not call from app lifecycle hooks, route observers, timers, or
    /// background services. Doing so violates the documented invariant.
    ///
    /// Starts a one-shot scan from `start_height` (None resumes from the last
    /// scanned position; bwk_sp clamps it to the birthday height). The scan
    /// itself runs on a bwk_sp thread and reports through the notification
    /// channel; poll [is_scanning] or wait for `ScanCompleted`.
    ///
    /// Cancellation: `stop_scan` flips `self.scan_cancel` (a clone of the
    /// bwk_sp::Account's internal `scanner_stop`), which causes the scan
    /// to bail at the next per-block checkpoint. bwk_sp resets the cancel
    /// flag at the start of every OneShot run, so a stale `true` from a
    /// previous cancel does not affect subsequent scans.
    pub fn scan_once(&self, start_height: Option<u32>) -> Result<(), SpError> {
        // Explicitly clear the cancel flag here too, even though bwk_sp's
        // scan_oneshot resets it: this guards against the edge case where
        // a previous `dispose()` flipped the flag and a brand-new
        // SpAccount is being scanned. Cheap relaxed store.
        self.scan_cancel.store(false, Ordering::Relaxed);
        let mut g = lock_inner(&self.inner)?;
        g.start_scan(sp_account::ScanMode::OneShot, start_height)
            .map_err(|e| match e {
                // Preserved as a variant: callers skip a redundant start
                // instead of matching on the message.
                sp_account::AccountError::ScannerAlreadyRunning => SpError::ScannerAlreadyRunning,
                other => SpError::Other {
                    message: other.to_string(),
                },
            })
    }

    /// Cooperatively cancel an in-flight `scan_once`. Returns immediately
    /// without touching the inner mutex; the scan observes `scan_cancel`
    /// between blocks and returns after persisting state.
    ///
    /// Idempotent: re-flipping an already-`true` flag is a no-op.
    pub async fn stop_scan(&self) -> Result<(), String> {
        self.scan_cancel.store(true, Ordering::Relaxed);
        Ok(())
    }

    #[frb(sync)]
    pub fn coins(&self) -> Result<Vec<SpCoinView>, String> {
        let map = lock_inner(&self.inner)?.coins();
        Ok(map
            .into_values()
            .map(|entry| SpCoinView {
                outpoint: entry.outpoint().to_string(),
                amount_sat: entry.amount_sat(),
                height: entry.height(),
                is_spendable: entry.is_spendable(),
                label: None,
            })
            .collect())
    }

    #[frb(sync)]
    pub fn block_height(&self) -> Result<u32, String> {
        lock_inner(&self.inner)?
            .block_height()
            .map_err(|e| e.to_string())
    }

    #[frb(sync)]
    pub fn backend_online(&self) -> Result<bool, String> {
        Ok(lock_inner(&self.inner)?.backend_online())
    }

    #[frb(sync)]
    pub fn name(&self) -> Result<String, String> {
        Ok(lock_inner(&self.inner)?.name().to_string())
    }

    /// Returns the wallet's network as an `SpNetwork`.
    ///
    /// `bitcoin::Network` is upstream-marked `#[non_exhaustive]`; rather than
    /// silently mapping a future variant to one of our known cases (which
    /// would corrupt downstream address validation), we return an explicit
    /// `Err` so the caller is forced to handle the unknown case.
    #[frb(sync)]
    pub fn network(&self) -> Result<SpNetwork, String> {
        match lock_inner(&self.inner)?.network() {
            bitcoin::Network::Bitcoin => Ok(SpNetwork::Bitcoin),
            bitcoin::Network::Signet => Ok(SpNetwork::Signet),
            bitcoin::Network::Testnet => Ok(SpNetwork::Testnet),
            bitcoin::Network::Regtest => Ok(SpNetwork::Regtest),
            other => Err(format!("unsupported bitcoin::Network variant: {other:?}")),
        }
    }

    /// Reveal a fresh receive address for the BIP86 taproot sub-account.
    ///
    /// Each call derives the next never-before-issued address, bumping and
    /// persisting the receive-chain tip *before* deriving. So an address is
    /// never handed out twice — even across restarts, and regardless of
    /// whether the previously revealed one has received a coin yet. Callers
    /// MUST treat this as "give me a new address to hand out" (an explicit
    /// user action), never as a stable display getter.
    ///
    /// Store-only / pure-descriptor: it never contacts Electrum or Blindbit,
    /// so it does not violate the no-chain-query-outside-`scan_once` invariant.
    ///
    /// Fails when the account was opened without a taproot descriptor.
    pub fn new_taproot_address(&self) -> Result<String, String> {
        let mut guard = lock_inner(&self.inner)?;
        let scanner = guard
            .scanners_mut()
            .find(|scanner| matches!(sub_account_kind(scanner), Some(SubAccountKind::Taproot)))
            .ok_or_else(|| "taproot sub-account missing".to_string())?;
        Ok(scanner.new_addr().value())
    }

    /// Confirmed balance of one sub-account in satoshis.
    #[frb(sync)]
    pub fn sub_account_balance(&self, kind: SubAccountKind) -> Result<u64, String> {
        let inner = lock_inner(&self.inner)?;
        Ok(find_scanner(&inner, kind)
            .map(|sub| sub.balance().0)
            .unwrap_or(0))
    }

    /// Aggregated balance across SP + all sub-accounts.
    #[frb(sync)]
    pub fn unified_balance(&self) -> Result<SpBalanceView, String> {
        let inner = lock_inner(&self.inner)?;
        // inner.balance() is SP-only, so the sub-accounts' confirmed coins are
        // added explicitly, the same way the desktop wallet sums
        // spendable_coins().
        let confirmed_sat = inner.balance()
            + inner
                .scanners()
                .map(|sub| sub.spendable_coins().confirmed_balance)
                .sum::<u64>();
        Ok(SpBalanceView {
            confirmed_sat,
            total_unified_sat: inner.total_balance(),
            last_scanned_height: inner.last_scanned_height(),
        })
    }

    /// Aggregated coins across SP + all sub-accounts, each tagged with its source.
    pub fn unified_coins(&self) -> Result<Vec<UnifiedCoinView>, String> {
        let inner = lock_inner(&self.inner)?;
        let mut result = Vec::new();

        for (outpoint, entry) in inner.coins() {
            // SP coins come from scanned (mined) blocks, so they are always
            // confirmed; only spent-ness varies.
            let status = match entry.status() {
                bwk_sp::receiver::OutputSpendStatus::Unspent => UnifiedCoinStatus::Unspent,
                bwk_sp::receiver::OutputSpendStatus::Spent { .. }
                | bwk_sp::receiver::OutputSpendStatus::Mined(_) => UnifiedCoinStatus::Spent,
            };
            result.push(UnifiedCoinView {
                source: CoinSource::Sp,
                outpoint: outpoint.to_string(),
                amount_sat: entry.amount_sat(),
                height: Some(entry.height()),
                status,
            });
        }

        for sub in inner.scanners() {
            let source = coin_source_of(sub);
            for (outpoint, entry) in sub.coins() {
                result.push(UnifiedCoinView {
                    source: source.clone(),
                    outpoint: outpoint.to_string(),
                    amount_sat: entry.amount_sat(),
                    height: entry.height().map(|h| h as u32),
                    status: unified_status(entry.status()),
                });
            }
        }

        Ok(result)
    }

    /// Aggregated payment history across SP + all sub-accounts.
    pub fn unified_history(&self) -> Result<Vec<SpPaymentView>, String> {
        let inner = lock_inner(&self.inner)?;

        // payment_history() is the unified, deduped history across the SP
        // account and every sub-account (bwk's generic aggregator). Amount is
        // owned_in - owned_out (sent + fee, change netted); height/timestamp are
        // stamped by the scan + the Electrum listener.
        let result = inner
            .payment_history()
            .into_iter()
            .map(|p| SpPaymentView {
                txid: p.txid,
                direction: match p.payment_type {
                    PaymentType::Receive => SpPaymentDirection::Receive,
                    PaymentType::Send => SpPaymentDirection::Send,
                    PaymentType::ToSelf => SpPaymentDirection::SelfSend,
                },
                status: match p.status {
                    PaymentStatus::Unconfirmed => SpPaymentStatus::Unconfirmed,
                    PaymentStatus::ConfirmedUnverified => SpPaymentStatus::ConfirmedUnverified,
                    PaymentStatus::Verified => SpPaymentStatus::Verified,
                    PaymentStatus::VerifyFailed => SpPaymentStatus::VerifyFailed,
                },
                amount_sat: p.amount,
                fee_sat: None,
                height: p.height.map(|h| h as u32),
                timestamp: p.timestamp,
                label: Some(p.label).filter(|l| !l.is_empty()),
            })
            .collect();

        Ok(result)
    }

    /// Point every sub-account, the header validator and the broadcaster at
    /// this Electrum server (in memory: the account's config is not
    /// persisted). Accepts `[scheme://]host[:port]` with `scheme` ∈ `{tcp, ssl}`.
    #[frb(sync)]
    pub fn set_electrum_url(&self, url: String) -> Result<(), String> {
        let (host, port) = parse_bwk_electrum_endpoint(&url)?;
        lock_inner(&self.inner)?.set_electrum_settings(host, port);
        Ok(())
    }

    /// Start the always-on electrum listeners for every sub-account so
    /// incoming txs are pushed in real time without a chain scan. Set the
    /// sub-account electrum URL first via `set_electrum_url`. Not
    /// `#[frb(sync)]` so the listener setup runs off the Dart UI isolate.
    pub fn start_electrum(&self) -> Result<(), String> {
        let mut g = lock_inner(&self.inner)?;
        g.start_electrum();
        Ok(())
    }

    /// Restart the sub-account electrum listeners in place (stop then start),
    /// keeping the account and its notification channel alive. Used on app
    /// foreground to recover after Android killed the backgrounded socket.
    pub fn restart_electrum(&self) -> Result<(), String> {
        let mut g = lock_inner(&self.inner)?;
        g.stop_electrum();
        g.start_electrum();
        Ok(())
    }

    /// Build the transaction to confirm: run coin selection, build the
    /// unsigned PSBTv2 with the selected coins pinned, and describe it.
    ///
    /// The returned [`TxSimulation`] carries the PSBT to sign
    /// ([`crate::api::sp_signer::sign_silent_payment_psbt`]) and what it
    /// spends and pays, read from that PSBT. Silent-payment outputs are left
    /// unscripted: the signer derives them, and `finalize` verifies them.
    ///
    /// feerate_sat_vb: fee rate in satoshis per virtual byte.
    pub fn prepare_psbt(
        &self,
        recipients: Vec<RecipientView>,
        feerate_sat_vb: u64,
    ) -> Result<TxSimulation, SpError> {
        let inner = lock_inner(&self.inner)?;
        let (outputs, has_max) = build_outputs(inner.network(), &recipients)?;
        if has_max {
            if let Some(remainder_sat) = max_send_shortfall(&inner, &outputs, feerate_sat_vb) {
                return Err(SpError::NothingToSendAfterFee { remainder_sat });
            }
        }
        let mut builder = build_tx_with_coin_selection(&inner, &outputs, has_max, feerate_sat_vb);
        let result = guard_builder(|| builder.simulate())?;

        if let Some(err) = result.error {
            return Err(map_simulation_error(&inner, err, has_max, feerate_sat_vb));
        }
        if has_max {
            if let Some(remainder_sat) = max_under_dust(&result.warnings) {
                return Err(SpError::NothingToSendAfterFee { remainder_sat });
            }
        }

        // Pin the coins the simulation selected, so building the PSBT does
        // not select again.
        let selected = result.tx_template.inputs;
        for coin in &selected {
            builder.add_input(coin.clone());
        }
        let psbt = guard_builder(|| builder.generate_v2())?.map_err(|e| SpError::Other {
            message: format!("PSBT generation failed: {e:?}"),
        })?;
        let described = describe_psbt(&inner, &psbt)?;
        let outputs = resolve_recipients(&inner, recipients, &described.tx_outputs)?;
        let bytes = psbt.serialize().map_err(|e| SpError::Other {
            message: format!("PSBT serialization failed: {e:?}"),
        })?;

        let inputs = described
            .inputs
            .into_iter()
            .map(|(outpoint, amount_sat)| {
                let coin = selected.iter().find(|c| c.outpoint == outpoint);
                UnifiedCoinView {
                    source: match coin.map(|c| c.source()) {
                        Some(bwk_coin::CoinSourceKind::SilentPayment) => CoinSource::Sp,
                        Some(bwk_coin::CoinSourceKind::Segwit) => CoinSource::Segwit,
                        Some(bwk_coin::CoinSourceKind::Taproot) => CoinSource::Taproot,
                        Some(bwk_coin::CoinSourceKind::Other) | None => CoinSource::Other,
                    },
                    outpoint: outpoint.to_string(),
                    amount_sat,
                    height: coin.and_then(|c| c.height).map(|h| h as u32),
                    // Selected tx inputs are unspent UTXOs being spent.
                    status: UnifiedCoinStatus::Unspent,
                }
            })
            .collect();

        Ok(TxSimulation {
            inputs,
            outputs,
            change_sat: described
                .tx_outputs
                .iter()
                .filter(|o| o.is_change)
                .map(|o| o.amount_sat)
                .sum(),
            tx_outputs: described.tx_outputs,
            fee_sat: described.fee_sat,
            fee_rate_sat_vb: feerate_sat_vb,
            psbt: bytes,
        })
    }

    /// Verify a signed PSBT against the simulation the user confirmed and
    /// extract the transaction. Returns the raw serialized transaction;
    /// hex-encode it for [broadcast].
    ///
    /// Refused, with nothing extracted, when:
    /// - `simulation` no longer describes its own unsigned PSBT, or
    ///   `signed_psbt` spends other inputs, pays other outputs (amount,
    ///   script, silent-payment recipient keys) or pays another fee:
    ///   [`SpError::SignedPsbtMismatch`];
    /// - a spent coin is no longer in the wallet or no longer spendable:
    ///   [`SpError::SimulationDrifted`];
    /// - the account's BIP375 verification (shares, DLEQ proofs, every
    ///   silent-payment output script) or the signatures fail:
    ///   [`SpError::Verification`].
    pub fn finalize(
        &self,
        simulation: TxSimulation,
        signed_psbt: Vec<u8>,
    ) -> Result<Vec<u8>, SpError> {
        let inner = lock_inner(&self.inner)?;
        let mismatch = |detail: &str| SpError::SignedPsbtMismatch {
            detail: detail.to_string(),
        };

        let unsigned = bwk_psbt::PsbtV2::deserialize(&simulation.psbt)
            .map_err(|_| mismatch("the simulation carries no valid PSBTv2"))?;
        let described = describe_psbt(&inner, &unsigned)?;
        let simulated_inputs: Vec<(String, u64)> = simulation
            .inputs
            .iter()
            .map(|i| (i.outpoint.clone(), i.amount_sat))
            .collect();
        let described_inputs: Vec<(String, u64)> = described
            .inputs
            .iter()
            .map(|(outpoint, amount)| (outpoint.to_string(), *amount))
            .collect();
        if simulated_inputs != described_inputs
            || simulation.tx_outputs != described.tx_outputs
            || simulation.fee_sat != described.fee_sat
        {
            return Err(mismatch("the simulation does not describe its PSBT"));
        }

        let signed = bwk_psbt::PsbtV2::deserialize(&signed_psbt)
            .map_err(|_| mismatch("the signed PSBT is not a valid PSBTv2"))?;
        pin_signed_to_unsigned(&unsigned, &signed).map_err(mismatch)?;

        for input in &unsigned.inputs {
            if !coin_is_spendable(&inner, &input.previous_output) {
                return Err(SpError::SimulationDrifted {
                    detail: format!(
                        "coin {} is no longer in the wallet or no longer spendable",
                        input.previous_output
                    ),
                });
            }
        }

        let tx = inner.finalize(&signed_psbt).map_err(|e| match e {
            sp_account::AccountError::Finalize(_) => SpError::Verification {
                reason: "the signatures do not finalize".to_string(),
            },
            sp_account::AccountError::Bip375(reason) => SpError::Verification { reason },
            sp_account::AccountError::PsbtV2 | sp_account::AccountError::PsbtDecode => {
                SpError::Verification {
                    reason: e.to_string(),
                }
            }
            other => SpError::Other {
                message: other.to_string(),
            },
        })?;
        Ok(bitcoin::consensus::encode::serialize(&tx))
    }

    /// The outputs of a signed transaction (the raw bytes [finalize]
    /// returns) that this account owns. They are found the way the scanner
    /// finds payments, from the scan key, the transaction's input public keys
    /// and the account's labels, independently of the code that built the
    /// transaction. Call it before broadcast to check that the expected SP
    /// change is there, reported with `is_change`.
    ///
    /// Every input must spend a coin of this account (SP or sub-account), to
    /// know its prevout; otherwise the call fails.
    pub fn owned_outputs(&self, tx_bytes: Vec<u8>) -> Result<Vec<SpOwnedOutput>, SpError> {
        use bwk_sp::core::receiving::{
            calculate_ecdh_shared_secret, calculate_tweak_data, eligible_input_pubkey, Label,
        };
        let other = |message: String| SpError::Other { message };

        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&tx_bytes)
            .map_err(|e| other(format!("invalid transaction bytes: {e}")))?;
        let inner = lock_inner(&self.inner)?;
        let prevouts = tx
            .input
            .iter()
            .map(|input| own_prevout(&inner, &input.previous_output))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| other("transaction spends a coin this account does not hold".into()))?;

        let mut input_keys = Vec::new();
        for (input, prevout) in tx.input.iter().zip(&prevouts) {
            if let Some(key) = eligible_input_pubkey(input, prevout)
                .map_err(|e| other(format!("input key: {e}")))?
            {
                input_keys.push(key);
            }
        }
        // No eligible input, no silent payment.
        if input_keys.is_empty() {
            return Ok(Vec::new());
        }
        let key_refs: Vec<_> = input_keys.iter().collect();
        let outpoints: Vec<_> = tx.input.iter().map(|i| i.previous_output).collect();
        let tweak_data = calculate_tweak_data(&key_refs, &outpoints)
            .map_err(|e| other(format!("tweak data: {e}")))?;

        let receiver = inner.sp_receiver();
        let mut scan_sk = receiver.get_scan_key();
        let shared = calculate_ecdh_shared_secret(&tweak_data, &scan_sk);
        let change_label = Label::new(scan_sk, 0);
        scan_sk.non_secure_erase();

        let candidates: Vec<(u32, bitcoin::XOnlyPublicKey, u64)> = tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, o)| o.script_pubkey.is_p2tr())
            .filter_map(|(vout, o)| {
                bitcoin::XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..34])
                    .ok()
                    .map(|key| (vout as u32, key, o.value.to_sat()))
            })
            .collect();
        let keys: Vec<_> = candidates.iter().map(|(_, key, _)| *key).collect();
        let found = receiver
            .receiver
            .scan_transaction(shared, &keys)
            .map_err(|e| other(format!("scan: {e}")))?;

        let mut owned: Vec<SpOwnedOutput> = found
            .into_iter()
            .flat_map(|(label, outputs)| {
                let is_change = label.as_ref() == Some(&change_label);
                outputs.into_keys().map(move |key| (key, is_change))
            })
            .filter_map(|(key, is_change)| {
                candidates
                    .iter()
                    .find(|(_, candidate, _)| *candidate == key)
                    .map(|(vout, _, amount_sat)| SpOwnedOutput {
                        vout: *vout,
                        amount_sat: *amount_sat,
                        is_change,
                    })
            })
            .collect();
        owned.sort_by_key(|o| o.vout);
        Ok(owned)
    }

    /// Start broadcasting a signed transaction to the network via Electrum.
    /// tx_hex: hex-encoded raw transaction bytes.
    /// Completion is delivered as Broadcasted or BroadcastFailed notification.
    pub fn broadcast(&self, tx_hex: String) -> Result<(), String> {
        let tx: bitcoin::Transaction =
            deserialize_hex(&tx_hex).map_err(|e| format!("invalid tx hex: {e}"))?;
        lock_inner(&self.inner)?.broadcast(tx);
        Ok(())
    }

    /// Update the Blindbit backend URL at runtime.
    #[frb(sync)]
    pub fn set_blindbit_url(&self, url: String) -> Result<(), String> {
        lock_inner(&self.inner)?.set_blindbit_url(url);
        Ok(())
    }
}

impl Drop for SpAccount {
    fn drop(&mut self) {
        // Mirror `dispose()` but defensive against a caller that didn't
        // invoke it explicitly. Also flip the scan-cancel flag so an
        // in-flight `scan_once` bails promptly.
        self.scan_cancel.store(true, Ordering::Relaxed);
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.notif_handle.get_mut().ok().and_then(|s| s.take()) {
            let _ = h.join();
        }
        if let Ok(mut sink) = self.sink.lock() {
            *sink = None;
        }
        // The inner Account (and its sqlite handle) is dropped as part of
        // the normal struct field drop after this function returns.
    }
}

fn unified_status(status: bwk_coin::CoinStatus) -> UnifiedCoinStatus {
    match status {
        bwk_coin::CoinStatus::Unconfirmed => UnifiedCoinStatus::Unconfirmed,
        bwk_coin::CoinStatus::Confirmed | bwk_coin::CoinStatus::ConfirmedUnverified => {
            UnifiedCoinStatus::Unspent
        }
        bwk_coin::CoinStatus::Spent | bwk_coin::CoinStatus::BeingSpend => UnifiedCoinStatus::Spent,
    }
}

fn map_notification(
    n: BwkNotification,
    inner: &Arc<Mutex<SpAccountInner>>,
    sub_snap: &mut Vec<BTreeSet<bitcoin::OutPoint>>,
) -> Vec<SpNotification> {
    match n {
        BwkNotification::Sp(sp) => map_sp_notification(sp, inner).into_iter().collect(),
        BwkNotification::CoinUpdate => map_coin_update(inner, sub_snap),
        BwkNotification::PaymentHistoryUpdated => vec![SpNotification::PaymentHistoryUpdated],
        BwkNotification::Electrum(_) => {
            log::trace!("SpAccount::map_notification: Electrum connection event");
            vec![]
        }
        BwkNotification::HeaderStoreUpdated => {
            log::trace!("SpAccount::map_notification: HeaderStoreUpdated");
            vec![SpNotification::PaymentHistoryUpdated]
        }
        BwkNotification::HeaderProgress(event) => vec![map_header_progress(event)],
        BwkNotification::ValidationFailed(e) => {
            log::warn!("SpAccount::map_notification: validation failed: {e:?}");
            vec![]
        }
        BwkNotification::AddressTipChanged => {
            log::trace!("SpAccount::map_notification: AddressTipChanged");
            vec![]
        }
        BwkNotification::InvalidElectrumConfig => {
            log::trace!("SpAccount::map_notification: InvalidElectrumConfig");
            vec![]
        }
        BwkNotification::InvalidLookAhead => {
            log::trace!("SpAccount::map_notification: InvalidLookAhead");
            vec![]
        }
        BwkNotification::HeaderStoreRestart => {
            log::warn!("SpAccount::map_notification: header store could not restart");
            vec![]
        }
        BwkNotification::MerkleFetchStopped => {
            log::warn!("SpAccount::map_notification: merkle proof fetching stopped");
            vec![]
        }
        // A watch-only account attaches no signing manager.
        BwkNotification::Signer(_) => {
            log::trace!("SpAccount::map_notification: signer event");
            vec![]
        }
    }
}

fn map_header_progress(event: HeaderProgressEvent) -> SpNotification {
    fn phase(phase: BwkHeaderProgressPhase) -> HeaderProgressPhase {
        match phase {
            BwkHeaderProgressPhase::Replay => HeaderProgressPhase::Replay,
            BwkHeaderProgressPhase::InitialSync => HeaderProgressPhase::InitialSync,
        }
    }

    match event {
        HeaderProgressEvent::Started {
            phase: p,
            start,
            end,
        } => SpNotification::HeaderProgressStarted {
            phase: phase(p),
            start,
            end,
        },
        HeaderProgressEvent::Progress {
            phase: p,
            current,
            end,
        } => SpNotification::HeaderProgress {
            phase: phase(p),
            current,
            end,
        },
        HeaderProgressEvent::Completed { phase: p } => {
            SpNotification::HeaderProgressCompleted { phase: phase(p) }
        }
        HeaderProgressEvent::Failed { phase: p } => {
            SpNotification::HeaderProgressFailed { phase: phase(p) }
        }
    }
}

/// Diff sub-account coin stores against `sub_snap`; emit one `ElectrumTx`
/// per new coin. Updates `sub_snap` after each comparison. Snapshots follow
/// `scanners()` order; the kind is read from each sub-account's descriptor.
fn map_coin_update(
    inner: &Arc<Mutex<SpAccountInner>>,
    sub_snap: &mut Vec<BTreeSet<bitcoin::OutPoint>>,
) -> Vec<SpNotification> {
    let mut result = Vec::new();

    // try_lock, not lock: a long call may hold the inner lock, and a blocking
    // lock here would stall the notification thread and freeze ScanProgress.
    // If busy (or poisoned), skip this update; the post-scan snapshot
    // reconciles the coin set.
    #[allow(clippy::type_complexity)]
    let current_sub_coins: Vec<(
        CoinSource,
        std::collections::BTreeMap<bitcoin::OutPoint, CoinEntry>,
    )> = match inner.try_lock() {
        Ok(inner) => inner
            .scanners()
            .map(|sub| (coin_source_of(sub), sub.coins()))
            .collect(),
        Err(_) => return result,
    };

    // Grow snapshot vec if sub-accounts were added after init (shouldn't happen, but defensive).
    while sub_snap.len() < current_sub_coins.len() {
        sub_snap.push(BTreeSet::new());
    }

    for (i, (source, coins)) in current_sub_coins.iter().enumerate() {
        let snap = &mut sub_snap[i];
        for (outpoint, entry) in coins {
            if snap.insert(*outpoint) {
                result.push(SpNotification::ElectrumTx {
                    kind: source.clone(),
                    txid: outpoint.txid.to_string(),
                    amount_sat: entry.amount_sat(),
                    height: entry.height().map(|h| h as u32),
                });
            }
        }
    }

    result
}

fn map_sp_notification(
    sp: BwkSpNotification,
    inner: &Arc<Mutex<SpAccountInner>>,
) -> Option<SpNotification> {
    match sp {
        BwkSpNotification::StartingScan => {
            log::trace!("SpAccount: StartingScan (skipped)");
            None
        }
        BwkSpNotification::ScanStarted { start, end } => Some(SpNotification::ScanStarted {
            from: start,
            to: end,
        }),
        BwkSpNotification::FailStartScanning { message } => {
            Some(SpNotification::ScanFailed { message })
        }
        BwkSpNotification::FailScan { message } => Some(SpNotification::ScanFailed { message }),
        BwkSpNotification::StoppingScan => {
            log::trace!("SpAccount: StoppingScan (skipped)");
            None
        }
        BwkSpNotification::ScanStopped => Some(SpNotification::ScanStopped),
        BwkSpNotification::ScanReceiveProgress { current, end } => {
            Some(SpNotification::ScanReceiveProgress { current, end })
        }
        BwkSpNotification::ScanSpendProgress { current, end } => {
            Some(SpNotification::ScanSpendProgress { current, end })
        }
        BwkSpNotification::ScanCompleted => Some(SpNotification::ScanCompleted),
        BwkSpNotification::NewOutput(outpoint) => {
            // try_lock: blocking here would stall the notification thread and
            // freeze ScanProgress. If busy, emit amount 0; the post-scan
            // refresh reconciles it.
            let amount_sat = match inner.try_lock() {
                Ok(g) => g.get_coin(&outpoint).map(|c| c.amount_sat()).unwrap_or(0),
                Err(_) => 0,
            };
            Some(SpNotification::NewOutput {
                outpoint: outpoint.to_string(),
                amount_sat,
            })
        }
        BwkSpNotification::OutputSpent(outpoint) => Some(SpNotification::OutputSpent {
            outpoint: outpoint.to_string(),
        }),
        BwkSpNotification::Broadcasted { txid } => Some(SpNotification::Broadcasted {
            txid: txid.to_string(),
        }),
        BwkSpNotification::FailBroadcast { message } => {
            Some(SpNotification::BroadcastFailed { message })
        }
        BwkSpNotification::WaitingForBlocks { .. } => {
            log::trace!("SpAccount: WaitingForBlocks (continuous-mode, skipped)");
            None
        }
        BwkSpNotification::NewBlocksDetected { .. } => {
            log::trace!("SpAccount: NewBlocksDetected (continuous-mode, skipped)");
            None
        }
    }
}

/// What an unsigned PSBTv2 spends and pays, as the simulation shows it.
struct DescribedPsbt {
    /// `(outpoint, amount)` per input, in transaction order.
    inputs: Vec<(bitcoin::OutPoint, u64)>,
    tx_outputs: Vec<SimulatedOutput>,
    fee_sat: u64,
}

fn describe_psbt(
    inner: &SpAccountInner,
    psbt: &bwk_psbt::PsbtV2,
) -> Result<DescribedPsbt, SpError> {
    let other = |message: &str| SpError::Other {
        message: message.to_string(),
    };
    let network = inner.network();
    let sp_network = bwk_sp::account::recipient::to_sp_network(network);
    let change = inner.sp_receiver().receiver.get_change_address();

    let mut inputs = Vec::with_capacity(psbt.inputs.len());
    for input in &psbt.inputs {
        let prevout = input
            .psbt
            .witness_utxo
            .as_ref()
            .ok_or_else(|| other("a PSBT input has no witness_utxo"))?;
        inputs.push((input.previous_output, prevout.value.to_sat()));
    }

    let mut tx_outputs = Vec::with_capacity(psbt.outputs.len());
    for (vout, output) in psbt.outputs.iter().enumerate() {
        let sp = bwk_psbt::sp::sp_v0_output(&output.psbt)
            .map_err(|_| other("a PSBT output carries malformed silent-payment fields"))?;
        let (destination, is_change) = match (sp, &output.script_pubkey) {
            (Some(info), _) => {
                let address = bwk_sp::core::utils::common::SilentPaymentAddress::new(
                    info.scan_key,
                    info.spend_key,
                    sp_network,
                    bwk_sp::core::SpVersion::V0,
                )
                .map_err(|_| other("a silent-payment output has invalid keys"))?;
                let is_change = info.scan_key == change.get_scan_key()
                    && info.spend_key == change.get_spend_key();
                (
                    OutputDestination::SilentPayment {
                        address: address.to_string(),
                        scan_key: info.scan_key.to_string(),
                        spend_key: info.spend_key.to_string(),
                        label: info.label,
                    },
                    is_change,
                )
            }
            (None, Some(script)) => (
                match bitcoin::Address::from_script(script, network) {
                    Ok(address) => OutputDestination::Address {
                        address: address.to_string(),
                    },
                    Err(_) => OutputDestination::Script {
                        script_hex: script.to_hex_string(),
                    },
                },
                false,
            ),
            (None, None) => return Err(other("a PSBT output has neither script nor SP fields")),
        };
        tx_outputs.push(SimulatedOutput {
            vout: vout as u32,
            amount_sat: output.amount.to_sat(),
            destination,
            is_change,
        });
    }

    let input_total: u64 = inputs.iter().map(|(_, amount)| amount).sum();
    let output_total: u64 = tx_outputs.iter().map(|o| o.amount_sat).sum();
    let fee_sat = input_total
        .checked_sub(output_total)
        .ok_or_else(|| other("the PSBT pays more than it spends"))?;
    Ok(DescribedPsbt {
        inputs,
        tx_outputs,
        fee_sat,
    })
}

/// The requested recipients with what the transaction actually pays each,
/// matched to its non-change outputs. A recipient with no matching output, or
/// paid another amount than requested, is a builder bug, refused here rather
/// than shown to the user.
fn resolve_recipients(
    inner: &SpAccountInner,
    recipients: Vec<RecipientView>,
    tx_outputs: &[SimulatedOutput],
) -> Result<Vec<RecipientView>, SpError> {
    let network = inner.network();
    let mut taken = vec![false; tx_outputs.len()];
    let mut resolved = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let (address, requested, is_max) = match &recipient {
            RecipientView::Sp {
                address,
                amount_sat,
                is_max,
                ..
            }
            | RecipientView::Standard {
                address,
                amount_sat,
                is_max,
            } => (address.clone(), *amount_sat, *is_max),
        };
        let wanted = recipient_destination(&address, network)?;
        let index = tx_outputs
            .iter()
            .enumerate()
            .position(|(i, o)| {
                !taken[i] && !o.is_change && same_destination(&o.destination, &wanted)
            })
            .ok_or_else(|| SpError::Other {
                message: format!("the transaction has no output paying '{address}'"),
            })?;
        taken[index] = true;
        let paid = tx_outputs[index].amount_sat;
        if !is_max && paid != requested {
            return Err(SpError::Other {
                message: format!("'{address}' is paid {paid} sats instead of {requested}"),
            });
        }
        resolved.push(match recipient {
            RecipientView::Sp {
                address,
                label,
                is_max,
                ..
            } => RecipientView::Sp {
                address,
                amount_sat: paid,
                label,
                is_max,
            },
            RecipientView::Standard {
                address, is_max, ..
            } => RecipientView::Standard {
                address,
                amount_sat: paid,
                is_max,
            },
        });
    }
    Ok(resolved)
}

/// What a recipient address string pays to: SP keys, or a script.
enum WantedDestination {
    Sp {
        scan_key: bitcoin::secp256k1::PublicKey,
        spend_key: bitcoin::secp256k1::PublicKey,
    },
    Script(bitcoin::ScriptBuf),
}

fn recipient_destination(address: &str, network: Network) -> Result<WantedDestination, SpError> {
    if let Ok(sp) = bwk_sp::core::utils::common::SilentPaymentAddress::try_from(address) {
        return Ok(WantedDestination::Sp {
            scan_key: sp.get_scan_key(),
            spend_key: sp.get_spend_key(),
        });
    }
    let address = bitcoin::Address::from_str(address)
        .map_err(|e| format!("invalid address '{address}': {e}"))?
        .require_network(network)
        .map_err(|e| format!("wrong network for '{address}': {e}"))?;
    Ok(WantedDestination::Script(address.script_pubkey()))
}

fn same_destination(output: &OutputDestination, wanted: &WantedDestination) -> bool {
    match (output, wanted) {
        (
            OutputDestination::SilentPayment {
                scan_key,
                spend_key,
                ..
            },
            WantedDestination::Sp {
                scan_key: want_scan,
                spend_key: want_spend,
            },
        ) => *scan_key == want_scan.to_string() && *spend_key == want_spend.to_string(),
        (OutputDestination::Address { address }, WantedDestination::Script(script)) => {
            bitcoin::Address::from_str(address)
                .map(|a| a.assume_checked().script_pubkey() == *script)
                .unwrap_or(false)
        }
        (OutputDestination::Script { script_hex }, WantedDestination::Script(script)) => {
            *script_hex == script.to_hex_string()
        }
        _ => false,
    }
}

/// Refuse a signed PSBT whose transaction is not the unsigned one's: same
/// version and lock time, same inputs (outpoint, sequence, prevout), same
/// outputs (amount, silent-payment recipient keys, script where the unsigned
/// one had one). Silent-payment output scripts appear only once signed; that
/// they derive from the recipient keys is what the BIP375 verification in
/// `finalize` checks.
fn pin_signed_to_unsigned(
    unsigned: &bwk_psbt::PsbtV2,
    signed: &bwk_psbt::PsbtV2,
) -> Result<(), &'static str> {
    if unsigned.tx_version != signed.tx_version
        || unsigned.fallback_lock_time != signed.fallback_lock_time
    {
        return Err("version or lock time changed");
    }
    if unsigned.inputs.len() != signed.inputs.len() {
        return Err("the inputs changed");
    }
    for (u, s) in unsigned.inputs.iter().zip(&signed.inputs) {
        if u.previous_output != s.previous_output
            || u.sequence != s.sequence
            || u.required_time_lock_time != s.required_time_lock_time
            || u.required_height_lock_time != s.required_height_lock_time
            || u.psbt.witness_utxo != s.psbt.witness_utxo
        {
            return Err("the inputs changed");
        }
    }
    if unsigned.outputs.len() != signed.outputs.len() {
        return Err("the outputs changed");
    }
    for (u, s) in unsigned.outputs.iter().zip(&signed.outputs) {
        if u.amount != s.amount {
            return Err("an output amount changed");
        }
        let u_sp = bwk_psbt::sp::sp_v0_output(&u.psbt).map_err(|_| "malformed SP output")?;
        let s_sp = bwk_psbt::sp::sp_v0_output(&s.psbt).map_err(|_| "malformed SP output")?;
        match (u_sp, s_sp) {
            (Some(u_sp), Some(s_sp)) => {
                if u_sp.scan_key != s_sp.scan_key
                    || u_sp.spend_key != s_sp.spend_key
                    || u_sp.label != s_sp.label
                {
                    return Err("a silent-payment recipient changed");
                }
                if u.script_pubkey.is_some() && u.script_pubkey != s.script_pubkey {
                    return Err("an output script changed");
                }
                if s.script_pubkey.is_none() {
                    return Err("a silent-payment output was left unscripted");
                }
            }
            (None, None) => {
                if u.script_pubkey != s.script_pubkey {
                    return Err("an output script changed");
                }
            }
            _ => return Err("an output changed kind"),
        }
    }
    Ok(())
}

/// The prevout `outpoint` names, from the account's SP coins or its
/// sub-accounts' coins.
fn own_prevout(account: &SpAccountInner, outpoint: &bitcoin::OutPoint) -> Option<bitcoin::TxOut> {
    if let Some(coin) = account.get_coin(outpoint) {
        return Some(bitcoin::TxOut {
            value: coin.amount(),
            script_pubkey: coin.script().clone(),
        });
    }
    account
        .scanners()
        .find_map(|sub| sub.get_coin(outpoint))
        .map(|coin| coin.txout)
}

/// Whether `outpoint` is still an unspent coin of the account (SP or a
/// sub-account).
fn coin_is_spendable(inner: &SpAccountInner, outpoint: &bitcoin::OutPoint) -> bool {
    if let Some(entry) = inner.get_coin(outpoint) {
        return entry.is_spendable();
    }
    inner.scanners().any(|scanner| {
        scanner.coins().get(outpoint).is_some_and(|entry| {
            !matches!(
                entry.status(),
                bwk_coin::CoinStatus::Spent | bwk_coin::CoinStatus::BeingSpend
            )
        })
    })
}

/// The sats a max send leaves after the fee, when that is too little to make
/// an output: bwk-tx then drops the max output and reports it as a warning.
fn max_under_dust(warnings: &[bwk_tx::transaction::Warning]) -> Option<u64> {
    warnings.iter().find_map(|w| match w {
        bwk_tx::transaction::Warning::MaxUnderDust(lost)
        | bwk_tx::transaction::Warning::MaxCreateDust(lost) => Some(*lost),
        _ => None,
    })
}

/// Every coin automatic selection would consider, as the account's own coin
/// source lists them: SP coins and every sub-account's spendable coins.
fn spendable_candidates(inner: &SpAccountInner) -> Vec<bwk_coin::Coin> {
    use bwk_coin::CoinSource as _;
    let mut coins: Vec<bwk_coin::Coin> = inner
        .spendable_coins()
        .coins
        .iter()
        .map(|(outpoint, entry)| sp_account::sp_coin_entry_to_coin(*outpoint, entry))
        .collect();
    for scanner in inner.scanners() {
        coins.extend(scanner.coin_source().spendable_coins());
    }
    coins
}

/// The simulation errors a caller can act on keep their own variant; the rest
/// stay in [SpError::Other], for logs.
///
/// bwk-tx reports a wallet holding more coins than its exhaustive selector
/// searches as a plain `CoinSelection` failure, so the count is checked here,
/// over the same non-dust candidates the selector keeps.
fn map_simulation_error(
    inner: &SpAccountInner,
    err: bwk_tx::transaction::Error,
    has_max: bool,
    feerate_sat_vb: u64,
) -> SpError {
    if matches!(err, bwk_tx::transaction::Error::CoinSelection) && !has_max {
        let candidates = spendable_candidates(inner);
        let kept = bwk_tx::coin_selection::discard_dust(
            candidates.iter().collect(),
            feerate_sat_vb.saturating_mul(1_000),
        )
        .len();
        if let Some(error) = too_many_coins(kept) {
            return error;
        }
    }
    SpError::Other {
        message: format!("simulation failed: {err:?}"),
    }
}

fn too_many_coins(count: usize) -> Option<SpError> {
    (count > MAX_AUTO_SELECTED_COINS).then(|| SpError::TooManyCoins {
        count: u32::try_from(count).unwrap_or(u32::MAX),
        max: MAX_AUTO_SELECTED_COINS as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{self as keys, derive, Derived, MNEMONIC, PLACEHOLDER_BLINDBIT_URL};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use tempfile::tempdir;

    fn test_bitcoin_address(network: Network) -> String {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
        let public_key = bitcoin::CompressedPublicKey(PublicKey::from_secret_key(&secp, &secret));
        bitcoin::Address::p2wpkh(&public_key, network).to_string()
    }

    fn test_sp_address(network: bwk_sp::core::utils::common::Network) -> String {
        let secp = Secp256k1::new();
        let scan_secret = SecretKey::from_slice(&[1u8; 32]).expect("valid scan key");
        let spend_secret = SecretKey::from_slice(&[2u8; 32]).expect("valid spend key");
        let scan = PublicKey::from_secret_key(&secp, &scan_secret);
        let spend = PublicKey::from_secret_key(&secp, &spend_secret);
        bwk_sp::core::utils::common::SilentPaymentAddress::new(
            scan,
            spend,
            network,
            bwk_sp::core::SpVersion::V0,
        )
        .expect("valid sp address")
        .to_string()
    }

    fn open(
        name: &str,
        dir: &std::path::Path,
        sp_descriptor: &str,
        taproot_descriptor: Option<&str>,
    ) -> Result<SpAccount, SpError> {
        SpAccount::create_from_descriptors(
            name.to_string(),
            SpNetwork::Regtest,
            sp_descriptor.to_string(),
            taproot_descriptor.map(str::to_string),
            PLACEHOLDER_BLINDBIT_URL.to_string(),
            String::new(),
            dir.to_str().unwrap().to_string(),
            None,
            None,
            None,
            None,
        )
    }

    /// A watch-only account for [MNEMONIC]'s keys, with its taproot sub-account.
    fn watch_only(name: &str, dir: &std::path::Path) -> SpAccount {
        let keys = derive(MNEMONIC);
        open(
            name,
            dir,
            &keys.sp_descriptor,
            Some(&keys.taproot_descriptor),
        )
        .expect("create watch-only account")
    }

    /// What a refused descriptor's error must never contain.
    fn assert_no_key_material(err: &SpError, keys: &Derived) {
        let rendered = [err.to_string(), format!("{err:?}")];
        for (label, needle) in keys::secret_needles(keys, MNEMONIC) {
            let Ok(needle) = String::from_utf8(needle) else {
                continue;
            };
            for text in &rendered {
                assert!(!text.contains(&needle), "{label} leaked into: {text}");
            }
        }
        for text in &rendered {
            assert!(!text.contains("tprv"), "a private key leaked into: {text}");
        }
    }

    #[test]
    fn validate_recipient_address_accepts_standard_address() {
        let address = test_bitcoin_address(Network::Bitcoin);
        let kind = validate_recipient_address(address, SpNetwork::Bitcoin).expect("valid address");
        assert_eq!(kind, SpRecipientAddressKind::Standard);
    }

    #[test]
    fn validate_recipient_address_accepts_sp_address() {
        let address = test_sp_address(bwk_sp::core::utils::common::Network::Mainnet);
        let kind = validate_recipient_address(address, SpNetwork::Bitcoin).expect("valid address");
        assert_eq!(kind, SpRecipientAddressKind::Sp);
    }

    #[test]
    fn validate_recipient_address_rejects_wrong_standard_network() {
        let address = test_bitcoin_address(Network::Bitcoin);
        let err = validate_recipient_address(address, SpNetwork::Testnet)
            .expect_err("wrong network must fail");
        assert!(err.contains("wrong network"));
    }

    #[test]
    fn validate_recipient_address_rejects_wrong_sp_network() {
        let address = test_sp_address(bwk_sp::core::utils::common::Network::Mainnet);
        let err = validate_recipient_address(address, SpNetwork::Testnet)
            .expect_err("wrong network must fail");
        assert!(err.contains("wrong network"));
    }

    /// The account built from the descriptors gives the SP address BIP352
    /// derives from the mnemonic, here derived outside bwk.
    #[test]
    fn sp_address_is_the_bip352_derivation_of_the_mnemonic() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let acc = watch_only("bip352", dir.path());
        let secp = Secp256k1::new();
        let expected = bwk_sp::core::utils::common::SilentPaymentAddress::new(
            keys.scan_sk.public_key(&secp),
            keys.spend_pk,
            bwk_sp::core::utils::common::Network::Regtest,
            bwk_sp::core::SpVersion::V0,
        )
        .unwrap()
        .to_string();
        assert_eq!(acc.sp_address().unwrap(), expected);
        assert!(expected.starts_with("sprt1"), "{expected}");
    }

    /// Nothing the account holds can spend: no mnemonic, no spend secret, no
    /// signer, and a public sub-account descriptor. The scan key is the only
    /// secret, and scanning needs it.
    #[test]
    fn the_account_holds_no_spend_secret() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let acc = watch_only("holds-nothing", dir.path());
        let inner = acc.inner.lock().unwrap();
        let config = inner.get_config();
        let secp = Secp256k1::new();

        assert!(config.mnemonic.is_none());
        assert!(config.descriptor.is_watch_only(&secp).unwrap());
        assert_eq!(config.descriptor.spend_secret_key(&secp).unwrap(), None);
        assert_eq!(
            config.descriptor.scan_secret_key(&secp).unwrap(),
            keys.scan_sk
        );
        assert_eq!(config.descriptors.len(), 1);
        for sub in &config.descriptors {
            assert!(sub.mnemonic.is_none());
            let rendered = sub.descriptor.to_string();
            assert!(rendered.contains("tpub"), "{rendered}");
            assert!(!rendered.contains("tprv"), "{rendered}");
        }
        assert!(inner.signers().is_empty());
        assert!(inner.signing_manager_names().is_empty());
        assert!(inner.mnemonic_fingerprint().is_none());
        assert_eq!(inner.sp_receiver().spend_pubkey(), keys.spend_pk);
    }

    #[test]
    fn create_refuses_a_spend_secret_and_never_echoes_it() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let err = open(
            "spend-secret",
            dir.path(),
            &keys.sp_descriptor_with_spend_secret,
            None,
        )
        .err()
        .expect("a secret spend key is refused");
        assert!(
            matches!(&err, SpError::InvalidDescriptor { reason } if reason.contains("secret spend key")),
            "{err:?}"
        );
        assert_no_key_material(&err, &keys);
    }

    #[test]
    fn create_refuses_malformed_or_foreign_sp_descriptors() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let secp = Secp256k1::new();
        let scan_wif = bitcoin::PrivateKey::new(keys.scan_sk, Network::Bitcoin).to_wif();
        let mainnet = format!("sp({scan_wif},{})", keys.spend_pk);
        let scan_pub = format!("sp({},{})", keys.scan_sk.public_key(&secp), keys.spend_pk);
        // A truncated descriptor still carries most of the scan key.
        let truncated = &keys.sp_descriptor[..keys.sp_descriptor.len() - 10];
        for (case, descriptor) in [
            ("garbage", "not a descriptor".to_string()),
            ("truncated", truncated.to_string()),
            ("mainnet", mainnet),
            ("public scan key", scan_pub),
            ("taproot instead", keys.taproot_descriptor.clone()),
        ] {
            let err = open("foreign", dir.path(), &descriptor, None)
                .err()
                .unwrap_or_else(|| panic!("{case}: refused"));
            assert!(
                matches!(err, SpError::InvalidDescriptor { .. }),
                "{case}: {err:?}"
            );
            assert_no_key_material(&err, &keys);
        }
    }

    #[test]
    fn create_refuses_unusable_taproot_descriptors() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let secp = Secp256k1::new();
        let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &keys.taproot_account_xprv);
        let origin = format!("[{}/86'/1'/0']", keys.master_fingerprint);
        let mainnet_xpub = bitcoin::bip32::Xpub {
            network: NetworkKind::Main,
            ..xpub
        };
        let other_key = SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .x_only_public_key(&secp)
            .0;
        for (case, descriptor) in [
            (
                "private key",
                format!("tr({origin}{}/<0;1>/*)", keys.taproot_account_xprv),
            ),
            ("no origin", format!("tr({xpub}/<0;1>/*)")),
            ("not taproot", format!("wpkh({origin}{xpub}/<0;1>/*)")),
            (
                "script tree",
                format!("tr({origin}{xpub}/<0;1>/*,pk({other_key}))"),
            ),
            ("no wildcard", format!("tr({origin}{xpub}/0/0)")),
            ("mainnet", format!("tr({origin}{mainnet_xpub}/<0;1>/*)")),
            ("garbage", "tr(".to_string()),
        ] {
            let err = open(
                "taproot",
                dir.path(),
                &keys.sp_descriptor,
                Some(&descriptor),
            )
            .err()
            .unwrap_or_else(|| panic!("{case}: refused"));
            assert!(
                matches!(err, SpError::InvalidDescriptor { .. }),
                "{case}: {err:?}"
            );
            assert_no_key_material(&err, &keys);
        }
    }

    #[test]
    fn an_account_without_taproot_descriptor_has_no_sub_account() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let acc = open("sp-only", dir.path(), &keys.sp_descriptor, None).expect("create");
        assert!(acc.new_taproot_address().is_err());
        assert_eq!(acc.sub_account_balance(SubAccountKind::Taproot).unwrap(), 0);
        assert!(acc.unified_coins().unwrap().is_empty());
    }

    /// No key material reaches the disk: every file the account writes,
    /// across create, use, reopen and drop, is searched for every encoding of
    /// every secret. The positive controls prove the search finds the scan
    /// key where bwk would serialize it (its config file) and as raw bytes.
    #[test]
    fn no_key_material_is_written_to_disk() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let needles = keys::secret_needles(&keys, MNEMONIC);
        {
            let acc = watch_only("on-disk", dir.path());
            for _ in 0..3 {
                acc.new_taproot_address().unwrap();
            }
            acc.set_blindbit_url("http://localhost:3001".to_string())
                .unwrap();
            acc.set_electrum_url("tcp://127.0.0.1:1".to_string())
                .unwrap();
            let _ = acc.prepare_psbt(
                vec![RecipientView::Sp {
                    address: acc.sp_address().unwrap(),
                    amount_sat: 10_000,
                    label: None,
                    is_max: false,
                }],
                1,
            );
            acc.inner.lock().unwrap().persist();
            let _ = futures_lite_block_on(acc.dispose());
        }
        // Reopening reads the stores back and writes them again.
        drop(watch_only("on-disk", dir.path()));

        let files = keys::files_under(dir.path());
        assert!(
            files.iter().any(|f| f.ends_with("account.sqlite")),
            "the account persisted to sqlite: {files:?}"
        );
        let hits = keys::find_secrets(dir.path(), &needles);
        assert!(hits.is_empty(), "key material on disk: {hits:?}");

        // Positive control 1: the config bwk would persist with a file store
        // carries the scan key, and the search finds it.
        let control = tempdir().unwrap();
        {
            use bwk::persist::config_store::{ConfigStore, FileConfigStore};
            let acc = watch_only("control", dir.path());
            let config = acc.inner.lock().unwrap().get_config();
            FileConfigStore::<SpConfig>::new(control.path().join("config.json"))
                .save(&config)
                .unwrap();
        }
        let hits = keys::find_secrets(control.path(), &needles);
        assert!(
            hits.iter().any(|(_, label)| label == "scan secret wif"),
            "the search must find a serialized scan key: {hits:?}"
        );
        // Positive control 2: raw bytes inside a binary blob.
        let mut blob = vec![0xa5u8; 4096];
        blob[1000..1032].copy_from_slice(&keys.b_spend.secret_bytes());
        std::fs::write(control.path().join("blob.bin"), blob).unwrap();
        let hits = keys::find_secrets(control.path(), &needles);
        assert!(
            hits.iter().any(|(_, label)| label == "spend secret raw"),
            "the search must find raw key bytes: {hits:?}"
        );
    }

    #[test]
    fn accessors_zero_state() {
        let dir = tempdir().unwrap();
        let acc = watch_only("zero", dir.path());

        assert_eq!(acc.confirmed_balance().unwrap(), 0);
        assert!(acc.coins().unwrap().is_empty());
        assert!(acc.unified_history().unwrap().is_empty());
        assert!(!acc.is_scanning().unwrap());
        assert!(acc.last_scanned_height().unwrap().is_none());
        assert_eq!(acc.name().unwrap(), "zero");
        assert!(matches!(acc.network(), Ok(SpNetwork::Regtest)));
        assert_eq!(acc.min_birthday_height().unwrap(), 1);
    }

    #[test]
    fn init_idempotent_guard() {
        // Verify that receiver() returns None on the second call (guard ensures single-init).
        // We test the inner account directly since StreamSink requires the FRB runtime.
        let dir = tempdir().unwrap();
        let acc = watch_only("guard", dir.path());

        let rx1 = acc.inner.lock().unwrap().receiver();
        assert!(rx1.is_some());
        let rx2 = acc.inner.lock().unwrap().receiver();
        assert!(rx2.is_none());
    }

    #[test]
    fn taproot_address_never_reissued() {
        // `new_taproot_address` must REVEAL a fresh, never-before-issued
        // address on every call (no reuse), and the receive tip must persist
        // across a reopen so it never collides with a previously issued index.
        let dir = tempdir().unwrap();
        let mut seen = std::collections::BTreeSet::new();
        {
            let acc = watch_only("sub-persist", dir.path());
            for i in 0..5 {
                let addr = acc
                    .new_taproot_address()
                    .unwrap_or_else(|e| panic!("reveal {i}: {e}"));
                assert!(!addr.is_empty(), "taproot address must be non-empty");
                assert!(
                    seen.insert(addr.clone()),
                    "reveal {i} reused address {addr}"
                );
            }
        }
        let reopened = watch_only("sub-persist", dir.path());
        let addr = reopened.new_taproot_address().unwrap();
        assert!(seen.insert(addr.clone()), "reopen reused address {addr}");
    }

    /// Revealed taproot addresses are BIP86 `m/86'/1'/0'/0/i` addresses,
    /// derived outside bwk, at increasing indexes.
    #[test]
    fn taproot_address_is_the_bip86_derivation() {
        let dir = tempdir().unwrap();
        let keys = derive(MNEMONIC);
        let acc = watch_only("bip86", dir.path());
        let secp = Secp256k1::new();
        let expected: Vec<String> = (0..50)
            .map(|index| {
                let sk = keys
                    .taproot_account_xprv
                    .derive_priv(
                        &secp,
                        &bitcoin::bip32::DerivationPath::from_str(&format!("m/0/{index}")).unwrap(),
                    )
                    .unwrap()
                    .private_key;
                let (internal, _) = sk.x_only_public_key(&secp);
                bitcoin::Address::p2tr(&secp, internal, None, Network::Regtest).to_string()
            })
            .collect();
        // BIP86's own test vector for this mnemonic, on a test network.
        assert_eq!(
            expected[0],
            "bcrt1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqjeprhg"
        );
        let index_of = |addr: &str| {
            expected
                .iter()
                .position(|e| e == addr)
                .unwrap_or_else(|| panic!("{addr} is not a BIP86 receive address"))
        };
        let first = index_of(&acc.new_taproot_address().unwrap());
        let second = index_of(&acc.new_taproot_address().unwrap());
        assert!(second > first, "{first} then {second}");
    }

    #[test]
    fn unified_views_zero_state() {
        let dir = tempdir().unwrap();
        let acc = watch_only("unified-zero", dir.path());

        let bal = acc.unified_balance().unwrap();
        assert_eq!(bal.confirmed_sat, 0);
        assert_eq!(bal.total_unified_sat, 0);
        assert!(bal.last_scanned_height.is_none());

        assert!(acc.unified_coins().unwrap().is_empty());
        assert!(acc.unified_history().unwrap().is_empty());

        assert_eq!(acc.sub_account_balance(SubAccountKind::Segwit).unwrap(), 0);
        assert_eq!(acc.sub_account_balance(SubAccountKind::Taproot).unwrap(), 0);
        assert!(!acc.new_taproot_address().unwrap().is_empty());
    }

    #[test]
    fn prepare_empty_account() {
        let dir = tempdir().unwrap();
        let acc = watch_only("prepare-empty", dir.path());

        // No coins → coin selection finds nothing.
        let sp_addr = acc.sp_address().expect("sp_address");
        let result = acc.prepare_psbt(
            vec![RecipientView::Sp {
                address: sp_addr,
                amount_sat: 10_000,
                label: None,
                is_max: false,
            }],
            1,
        );
        assert!(
            matches!(result, Err(SpError::Other { .. })),
            "expected a plain failure for an empty coin store: {result:?}"
        );
    }

    #[test]
    fn prepare_invalid_sp_address() {
        let dir = tempdir().unwrap();
        let acc = watch_only("prepare-invalid-sp", dir.path());

        let result = acc.prepare_psbt(
            vec![RecipientView::Sp {
                address: "not_a_valid_sp_address".to_string(),
                amount_sat: 10_000,
                label: None,
                is_max: false,
            }],
            1,
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid SP address"));
    }

    #[test]
    fn prepare_invalid_standard_address() {
        let dir = tempdir().unwrap();
        let acc = watch_only("prepare-invalid-std", dir.path());

        let result = acc.prepare_psbt(
            vec![RecipientView::Standard {
                address: "not_a_bitcoin_address".to_string(),
                amount_sat: 10_000,
                is_max: false,
            }],
            1,
        );
        assert!(result.unwrap_err().to_string().contains("invalid address"));
    }

    #[test]
    fn parse_electrum_url_variants() {
        // plain host:port → defaults to TCP
        let (h, p, s) = parse_electrum_url("electrum.example.com:50001").unwrap();
        assert_eq!(h.as_deref(), Some("electrum.example.com"));
        assert_eq!(p, Some(50001));
        assert_eq!(s, ElectrumScheme::Tcp);

        // tcp:// scheme is honoured and stripped
        let (h, p, s) = parse_electrum_url("tcp://electrum.example.com:50001").unwrap();
        assert_eq!(h.as_deref(), Some("electrum.example.com"));
        assert_eq!(p, Some(50001));
        assert_eq!(s, ElectrumScheme::Tcp);

        // ssl:// scheme is honoured and stripped.
        let (h, p, s) = parse_electrum_url("ssl://electrum.bullbitcoin.com:50002").unwrap();
        assert_eq!(h.as_deref(), Some("electrum.bullbitcoin.com"));
        assert_eq!(p, Some(50002));
        assert_eq!(s, ElectrumScheme::Ssl);

        // empty input → no host/port, defaults TCP
        let (h, p, _s) = parse_electrum_url("").unwrap();
        assert!(h.is_none());
        assert!(p.is_none());

        // unknown scheme is rejected
        assert!(parse_electrum_url("http://foo:80").is_err());
        assert!(parse_electrum_url("ws://foo:80").is_err());
    }

    #[test]
    fn parse_bwk_electrum_endpoint_preserves_bwk_ssl_prefix() {
        let (host, port) = parse_bwk_electrum_endpoint("ssl://electrum.example.com:50002")
            .expect("parse endpoint");
        assert_eq!(host.as_deref(), Some("ssl://electrum.example.com"));
        assert_eq!(port, Some(50002));
    }

    #[test]
    fn parse_bwk_electrum_endpoint_keeps_tcp_host_bare() {
        let (host, port) = parse_bwk_electrum_endpoint("tcp://electrum.example.com:50001")
            .expect("parse endpoint");
        assert_eq!(host.as_deref(), Some("electrum.example.com"));
        assert_eq!(port, Some(50001));
    }

    #[test]
    fn wipe_string_clears_the_buffer() {
        let mut secret = String::from("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
        let ptr = secret.as_ptr();
        let len = secret.len();
        wipe_string(&mut secret);
        assert!(secret.is_empty());
        // SAFETY: the allocation is still owned by `secret` (clear keeps the
        // capacity), so the old bytes are readable.
        let old = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(old.iter().all(|b| *b == 0));
    }

    /// Regression: dropping an SpAccount must terminate the
    /// notification thread instead of leaking it (and the inner sqlite
    /// handle) for the lifetime of the process.
    ///
    /// We can't call `init()` from a non-FRB test because `StreamSink`
    /// requires the FRB runtime, so we exercise the shutdown contract
    /// directly: inject a stand-in worker thread into `notif_handle`
    /// that watches the same `shutdown` flag, then assert the thread
    /// exits when `dispose()` runs (and again that `Drop` is a no-op
    /// the second time).
    #[test]
    fn dispose_joins_notification_thread() {
        let dir = tempdir().unwrap();
        let acc = watch_only("dispose-thread", dir.path());

        let observed = Arc::new(AtomicBool::new(false));
        let observed_clone = observed.clone();
        let shutdown = acc.shutdown.clone();
        let handle = std::thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
            }
            observed_clone.store(true, Ordering::Release);
        });
        *acc.notif_handle.lock().unwrap() = Some(handle);

        let baseline = notif_thread_exit_count();
        let res = futures_lite_block_on(acc.dispose());
        assert!(
            res.is_ok(),
            "dispose must succeed when lock is free: {res:?}"
        );
        assert!(
            observed.load(Ordering::Acquire),
            "thread did not observe shutdown"
        );

        // dispose() must be idempotent.
        let res2 = futures_lite_block_on(acc.dispose());
        assert!(res2.is_ok(), "second dispose must succeed: {res2:?}");

        // Dropping after dispose must be a clean no-op (no double-join panic).
        drop(acc);
        assert!(notif_thread_exit_count() >= baseline);
    }

    /// Regression: a poisoned inner-mutex must surface as a
    /// recoverable `Err` rather than panicking via `.unwrap()`.
    #[test]
    fn poisoned_mutex_returns_err_not_panic() {
        let dir = tempdir().unwrap();
        let acc = watch_only("poison", dir.path());

        let inner = acc.inner.clone();
        let _ = std::thread::spawn(move || {
            let _guard = inner.lock().unwrap();
            panic!("intentional poison");
        })
        .join();

        assert!(acc.sp_address().is_err());
        assert!(acc.confirmed_balance().is_err());
        assert!(acc.is_scanning().is_err());
        assert!(acc.name().is_err());
        assert!(acc.unified_balance().is_err());
        assert!(acc.unified_coins().is_err());
        assert!(acc.unified_history().is_err());
        assert!(acc.coins().is_err());
        assert!(acc.network().is_err());
        assert!(acc.last_scanned_height().is_err());
    }

    /// Regression: the scan-cancel signal must be wired through to the
    /// bwk_sp::Account's scanner_stop flag, and flipping it must NOT require
    /// taking the inner mutex. This pins the invariant that the Stop button
    /// cannot deadlock against an in-flight scan.
    #[test]
    fn scan_cancel_signal_aborts_in_progress_scan() {
        let dir = tempdir().unwrap();
        let acc = watch_only("scan-cancel", dir.path());

        let inner = acc.inner.clone();
        let stuck = std::thread::spawn(move || {
            let _guard = inner.lock().expect("lock");
            std::thread::sleep(Duration::from_millis(500));
        });

        let start = std::time::Instant::now();
        let res = futures_lite_block_on(acc.stop_scan());
        let elapsed = start.elapsed();
        assert!(res.is_ok(), "stop_scan must succeed: {res:?}");
        assert!(
            elapsed < Duration::from_millis(100),
            "stop_scan blocked for {elapsed:?}; must be non-blocking (deadlock regression)"
        );
        assert!(acc.scan_cancel.load(Ordering::Relaxed));

        stuck.join().expect("join");
        let inner_flag = acc.inner.lock().unwrap().cancel_flag();
        assert!(Arc::ptr_eq(&acc.scan_cancel, &inner_flag));
        assert!(inner_flag.load(Ordering::Relaxed));
    }

    /// Regression: `dispose()` must NOT block indefinitely while a scan
    /// holds the inner mutex, and an account reopened on the same data_dir
    /// afterwards must not race the sqlite handle.
    #[test]
    fn dispose_during_running_scan_releases_lock() {
        let dir = tempdir().unwrap();
        let acc = watch_only("dispose-scan", dir.path());

        let inner = acc.inner.clone();
        let scan_cancel = acc.scan_cancel.clone();
        let scanning = std::thread::spawn(move || {
            let _guard = inner.lock().expect("lock");
            while !scan_cancel.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let start = std::time::Instant::now();
        let res = futures_lite_block_on(acc.dispose());
        let elapsed = start.elapsed();
        scanning.join().expect("join");

        assert!(
            res.is_ok(),
            "dispose must succeed when scan cooperates: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "dispose took {elapsed:?}; expected <2s once scan cooperates"
        );
        assert!(acc.inner.try_lock().is_ok());
        drop(acc);

        let keys = derive(MNEMONIC);
        let acc2 = open(
            "dispose-scan",
            dir.path(),
            &keys.sp_descriptor,
            Some(&keys.taproot_descriptor),
        );
        assert!(acc2.is_ok(), "reopening after dispose must succeed");
    }

    /// Regression: `dispose()` MUST return [`SpError::DisposeTimedOut`] when
    /// the inner mutex is held past the 5-second budget.
    #[test]
    fn dispose_returns_err_when_lock_held_past_timeout() {
        let dir = tempdir().unwrap();
        let acc = watch_only("dispose-timeout", dir.path());

        let inner = acc.inner.clone();
        let holder = std::thread::spawn(move || {
            let _guard = inner.lock().expect("lock");
            std::thread::sleep(Duration::from_millis(6_000));
        });
        std::thread::sleep(Duration::from_millis(50));

        let start = std::time::Instant::now();
        let res = futures_lite_block_on(acc.dispose());
        let elapsed = start.elapsed();

        let err = res.expect_err("dispose must time out when lock is held past budget");
        assert!(
            matches!(err, SpError::DisposeTimedOut),
            "expected DisposeTimedOut, got: {err:?}"
        );
        assert!(
            acc.scan_cancel.load(Ordering::Relaxed),
            "scan_cancel must be set even when dispose times out"
        );
        assert!(
            elapsed < Duration::from_millis(5_500),
            "dispose budget breached: elapsed={elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(5),
            "dispose returned too early ({elapsed:?}); must wait full budget before timing out"
        );
        holder.join().expect("join");
    }

    #[test]
    fn too_many_coins_starts_past_the_selector_limit() {
        assert!(too_many_coins(MAX_AUTO_SELECTED_COINS).is_none());
        assert!(matches!(
            too_many_coins(MAX_AUTO_SELECTED_COINS + 1),
            Some(SpError::TooManyCoins { count: 21, max: 20 })
        ));
    }

    #[test]
    fn a_sub_dust_max_is_reported_from_the_warning() {
        use bwk_tx::transaction::Warning;
        assert_eq!(max_under_dust(&[Warning::MaxUnderDust(3_000)]), Some(3_000));
        assert_eq!(
            max_under_dust(&[Warning::MaxCreateDust(4_000)]),
            Some(4_000)
        );
        assert_eq!(max_under_dust(&[Warning::ChangeUnderDust(3_000)]), None);
    }

    // The spent SP coins are written into the account's sqlite coin store
    // before it is opened, exactly as a scan would have recorded them (output
    // key `B_spend + t·G`, tweak `t`), so prepare reads them through the
    // account's real coin source.

    /// Seed SP coins paying `keys`' spend key into the store `open` reads.
    fn seed_sp_coins(dir: &std::path::Path, name: &str, keys: &Derived, coins: &[(u8, u8, u64)]) {
        use bwk_sp::account::coin_store::{SpCoinStore, STORE_KEY};
        use bwk_sp::receiver::{OutputSpendStatus, OwnedOutput};
        let secp = Secp256k1::new();
        let backend = bwk::persist::build_backend(
            Some(bwk::persist::PersistenceKind::Sqlite),
            dir.join(name),
        )
        .unwrap();
        let mut store = SpCoinStore::load_from_backend(backend, STORE_KEY).unwrap();
        for &(tweak_byte, outpoint_byte, sats) in coins {
            let tweak = SecretKey::from_slice(&[tweak_byte; 32]).unwrap();
            let output_key = keys.spend_pk.add_exp_tweak(&secp, &tweak.into()).unwrap();
            let script = bitcoin::ScriptBuf::new_p2tr_tweaked(
                bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                    output_key.x_only_public_key().0,
                ),
            );
            store.insert(
                outpoint(outpoint_byte),
                OwnedOutput {
                    blockheight: bitcoin::absolute::Height::from_consensus(1).unwrap(),
                    tweak: tweak.secret_bytes(),
                    amount: bitcoin::Amount::from_sat(sats),
                    script,
                    label: None,
                    spend_status: OutputSpendStatus::Unspent,
                },
            );
        }
        store.persist();
    }

    fn outpoint(byte: u8) -> bitcoin::OutPoint {
        use bitcoin::hashes::Hash;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([byte; 32]),
            vout: 0,
        }
    }

    /// A watch-only account for [MNEMONIC] holding the given SP coins.
    fn funded(name: &str, dir: &std::path::Path, coins: &[(u8, u8, u64)]) -> SpAccount {
        seed_sp_coins(dir, name, &derive(MNEMONIC), coins);
        watch_only(name, dir)
    }

    #[test]
    fn a_sub_dust_max_send_is_nothing_to_send() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-dust", dir.path(), &[(9, 1, 5_100)]);
        let err = acc
            .prepare_psbt(
                vec![RecipientView::Standard {
                    address: test_bitcoin_address(Network::Regtest),
                    amount_sat: 0,
                    is_max: true,
                }],
                1,
            )
            .expect_err("nothing left after the fee");
        // bwk-tx refuses a max output under the dust limit, and also one that
        // could not have paid for a change output on top of the dust limit
        // (`MaxCreateDust`), so the remainder may sit slightly above it.
        assert!(
            matches!(err, SpError::NothingToSendAfterFee { remainder_sat } if remainder_sat < 5_100),
            "{err:?}"
        );
        // bwk #114 panics on this case (`unreachable!()`); the account must
        // come out of it usable, its lock not poisoned.
        assert!(acc.sp_address().is_ok());
        assert_eq!(acc.confirmed_balance().unwrap(), 5_100);
    }

    #[test]
    fn a_builder_panic_is_an_error_not_an_unwind() {
        let err = guard_builder(|| -> u32 { panic!("unreachable in bwk-tx") }).expect_err("caught");
        assert!(matches!(err, SpError::Other { .. }), "{err:?}");
        assert_eq!(guard_builder(|| 7).unwrap(), 7);
    }

    /// Pins the bwk #114 bug [guard_builder] and [max_send_shortfall] work
    /// around: a sub-dust max send panics inside `simulate`. If this starts
    /// failing, bwk fixed it and the workaround can go.
    #[test]
    fn bwk_tx_panics_on_a_sub_dust_max_send() {
        let dir = tempdir().unwrap();
        let acc = funded("bwk-dust-panic", dir.path(), &[(9, 1, 5_100)]);
        let inner = acc.inner.lock().unwrap();
        let (outputs, has_max) = build_outputs(
            Network::Regtest,
            &[RecipientView::Standard {
                address: test_bitcoin_address(Network::Regtest),
                amount_sat: 0,
                is_max: true,
            }],
        )
        .unwrap();
        let builder = build_tx_with_coin_selection(&inner, &outputs, has_max, 1);
        let panicked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.simulate()));
        assert!(
            panicked.is_err(),
            "bwk-tx no longer panics on a sub-dust max"
        );
    }

    // Offline send flow: prepare, sign with the lent keys, finalize. Nothing
    // is broadcast.

    fn recipient_sp_address() -> String {
        let other = derive(keys::OTHER_MNEMONIC);
        let secp = Secp256k1::new();
        bwk_sp::core::utils::common::SilentPaymentAddress::new(
            other.scan_sk.public_key(&secp),
            other.spend_pk,
            bwk_sp::core::utils::common::Network::Regtest,
            bwk_sp::core::SpVersion::V0,
        )
        .unwrap()
        .to_string()
    }

    fn pay_sp(address: String, amount_sat: u64) -> Vec<RecipientView> {
        vec![RecipientView::Sp {
            address,
            amount_sat,
            label: None,
            is_max: false,
        }]
    }

    fn sign(simulation: &TxSimulation) -> Vec<u8> {
        let keys = derive(MNEMONIC);
        crate::api::sp_signer::sign_silent_payment_psbt(
            simulation.psbt.clone(),
            keys.b_spend.secret_bytes().to_vec(),
            Some(keys.taproot_account_xprv.to_string()),
        )
        .expect("sign")
    }

    #[test]
    fn prepare_sign_finalize_offline() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e", dir.path(), &[(9, 1, 500_000)]);
        assert_eq!(acc.confirmed_balance().unwrap(), 500_000);
        let to = recipient_sp_address();

        let sim = acc
            .prepare_psbt(pay_sp(to.clone(), 100_000), 2)
            .expect("prepare");

        // What the user confirms, read from the unsigned PSBT it carries.
        assert_eq!(sim.inputs.len(), 1);
        assert_eq!(sim.inputs[0].outpoint, outpoint(1).to_string());
        assert!(matches!(sim.inputs[0].source, CoinSource::Sp));
        assert_eq!(sim.tx_outputs.len(), 2, "recipient + SP change");
        let paid: Vec<_> = sim.tx_outputs.iter().filter(|o| !o.is_change).collect();
        assert_eq!(paid.len(), 1);
        assert_eq!(paid[0].amount_sat, 100_000);
        assert!(
            matches!(&paid[0].destination, OutputDestination::SilentPayment { address, .. } if *address == to)
        );
        let change: Vec<_> = sim.tx_outputs.iter().filter(|o| o.is_change).collect();
        assert_eq!(change.len(), 1);
        assert_eq!(sim.change_sat, change[0].amount_sat);
        assert!(sim.fee_sat > 0);
        assert_eq!(sim.fee_sat + sim.change_sat + 100_000, 500_000);
        assert_eq!(sim.fee_rate_sat_vb, 2);
        assert!(matches!(
            &sim.outputs[..],
            [RecipientView::Sp {
                amount_sat: 100_000,
                ..
            }]
        ));
        let unsigned = bwk_psbt::PsbtV2::deserialize(&sim.psbt).expect("an unsigned PSBTv2");
        assert!(
            unsigned.outputs.iter().all(|o| o.script_pubkey.is_none()),
            "SP outputs are left for the signer to script"
        );

        let signed = sign(&sim);
        let raw = acc.finalize(sim.clone(), signed).expect("finalize");
        let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, outpoint(1));
        assert!(!tx.input[0].witness.is_empty());
        assert_eq!(tx.output.len(), 2);
        assert!(tx.output.iter().all(|o| o.script_pubkey.is_p2tr()));
        for (out, simulated) in tx.output.iter().zip(&sim.tx_outputs) {
            assert_eq!(out.value.to_sat(), simulated.amount_sat);
        }

        // Spending left no key on disk either.
        drop(acc);
        let keys = derive(MNEMONIC);
        let hits = keys::find_secrets(dir.path(), &keys::secret_needles(&keys, MNEMONIC));
        assert!(hits.is_empty(), "key material on disk: {hits:?}");
    }

    #[test]
    fn max_send_pays_everything_but_the_fee() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-max", dir.path(), &[(9, 1, 300_000), (8, 2, 200_000)]);
        let sim = acc
            .prepare_psbt(
                vec![RecipientView::Standard {
                    address: test_bitcoin_address(Network::Regtest),
                    amount_sat: 0,
                    is_max: true,
                }],
                1,
            )
            .expect("prepare");
        assert_eq!(sim.inputs.len(), 2);
        assert_eq!(sim.tx_outputs.len(), 1);
        assert!(!sim.tx_outputs[0].is_change);
        assert_eq!(sim.change_sat, 0);
        let [RecipientView::Standard { amount_sat, .. }] = &sim.outputs[..] else {
            panic!("{:?}", sim.outputs);
        };
        assert_eq!(*amount_sat + sim.fee_sat, 500_000);
        let signed = sign(&sim);
        acc.finalize(sim, signed).expect("finalize");
    }

    #[test]
    fn more_coins_than_selection_searches_is_too_many_coins() {
        let dir = tempdir().unwrap();
        let coins: Vec<(u8, u8, u64)> = (1..=21).map(|i| (i, i, 10_000)).collect();
        let acc = funded("e2e-many", dir.path(), &coins);
        let err = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 50_000), 1)
            .expect_err("selection gives up");
        assert!(
            matches!(err, SpError::TooManyCoins { count: 21, max: 20 }),
            "{err:?}"
        );
    }

    /// The core redirect attack: an SP output script swapped after signing.
    /// The pin cannot see it (the unsigned PSBT has no script there); the
    /// account's BIP375 verification does.
    #[test]
    fn finalize_refuses_a_redirected_sp_output() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-redirect", dir.path(), &[(9, 1, 500_000)]);
        let sim = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 100_000), 1)
            .unwrap();
        let mut tampered = bwk_psbt::PsbtV2::deserialize(&sign(&sim)).unwrap();
        let secp = Secp256k1::new();
        let (attacker, _) = SecretKey::from_slice(&[0x42; 32])
            .unwrap()
            .x_only_public_key(&secp);
        let index = sim.tx_outputs.iter().position(|o| !o.is_change).unwrap();
        tampered.outputs[index].script_pubkey = Some(bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(attacker),
        ));
        let err = acc
            .finalize(sim, tampered.serialize().unwrap())
            .expect_err("redirected output");
        assert!(matches!(err, SpError::Verification { .. }), "{err:?}");
    }

    #[test]
    fn finalize_refuses_a_signed_psbt_paying_other_amounts_or_keys() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-amount", dir.path(), &[(9, 1, 500_000)]);
        let sim = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 100_000), 1)
            .unwrap();
        let signed = sign(&sim);
        let paid = sim.tx_outputs.iter().position(|o| !o.is_change).unwrap();

        // A bigger fee: an output pays less.
        let mut tampered = bwk_psbt::PsbtV2::deserialize(&signed).unwrap();
        tampered.outputs[paid].amount =
            tampered.outputs[paid].amount - bitcoin::Amount::from_sat(1_000);
        let err = acc
            .finalize(sim.clone(), tampered.serialize().unwrap())
            .expect_err("amount changed");
        assert!(matches!(err, SpError::SignedPsbtMismatch { .. }), "{err:?}");

        // Another silent-payment recipient.
        let mut tampered = bwk_psbt::PsbtV2::deserialize(&signed).unwrap();
        let info = bwk_psbt::sp::sp_v0_output(&tampered.outputs[paid].psbt)
            .unwrap()
            .unwrap();
        let other = SecretKey::from_slice(&[0x43; 32])
            .unwrap()
            .public_key(&Secp256k1::new());
        bwk_psbt::sp::set_sp_v0_output(
            &mut tampered.outputs[paid].psbt,
            info.scan_key,
            other,
            None,
        );
        let err = acc
            .finalize(sim.clone(), tampered.serialize().unwrap())
            .expect_err("recipient changed");
        assert!(matches!(err, SpError::SignedPsbtMismatch { .. }), "{err:?}");

        // Not a PSBT at all.
        let err = acc
            .finalize(sim.clone(), b"garbage".to_vec())
            .expect_err("garbage");
        assert!(matches!(err, SpError::SignedPsbtMismatch { .. }), "{err:?}");

        // The untampered one still goes through.
        acc.finalize(sim, signed).expect("finalize");
    }

    /// A signed PSBT is only accepted with the simulation it was built
    /// from: signing another confirmed transaction does not substitute.
    #[test]
    fn finalize_refuses_the_signature_of_another_simulation() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-swap", dir.path(), &[(9, 1, 500_000)]);
        let confirmed = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 100_000), 1)
            .unwrap();
        let other = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 150_000), 1)
            .unwrap();
        let err = acc
            .finalize(confirmed, sign(&other))
            .expect_err("signed another transaction");
        assert!(matches!(err, SpError::SignedPsbtMismatch { .. }), "{err:?}");
    }

    /// The display fields travel back from Dart: a simulation edited to show
    /// another fee, recipient or input than its PSBT does is refused.
    #[test]
    fn finalize_refuses_a_simulation_that_no_longer_describes_its_psbt() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-edited", dir.path(), &[(9, 1, 500_000)]);
        let sim = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 100_000), 1)
            .unwrap();
        let signed = sign(&sim);
        let mut fee = sim.clone();
        fee.fee_sat -= 1;
        let mut output = sim.clone();
        output.tx_outputs[0].amount_sat += 1;
        let mut input = sim.clone();
        input.inputs[0].outpoint = outpoint(2).to_string();
        let mut psbt = sim.clone();
        psbt.psbt = b"garbage".to_vec();
        for (case, edited) in [
            ("fee", fee),
            ("output", output),
            ("input", input),
            ("psbt", psbt),
        ] {
            let err = acc
                .finalize(edited, signed.clone())
                .err()
                .unwrap_or_else(|| panic!("{case}: refused"));
            assert!(
                matches!(err, SpError::SignedPsbtMismatch { .. }),
                "{case}: {err:?}"
            );
        }
    }

    /// A coin that left the wallet between confirmation and finalize: the
    /// same PSBT, finalized by an account that no longer holds the coin.
    #[test]
    fn finalize_refuses_a_drifted_simulation() {
        let dir = tempdir().unwrap();
        let acc = funded("e2e-drift", dir.path(), &[(9, 1, 500_000)]);
        let sim = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 100_000), 1)
            .unwrap();
        let signed = sign(&sim);
        let empty_dir = tempdir().unwrap();
        let without_the_coin = watch_only("e2e-drift", empty_dir.path());
        let err = without_the_coin
            .finalize(sim, signed)
            .expect_err("coin gone");
        assert!(matches!(err, SpError::SimulationDrifted { .. }), "{err:?}");
    }

    #[test]
    fn owned_outputs_finds_the_payment_to_self_and_the_change() {
        let dir = tempdir().unwrap();
        let acc = funded("owned-self", dir.path(), &[(9, 1, 500_000)]);
        let own = acc.sp_address().unwrap();
        let sim = acc.prepare_psbt(pay_sp(own, 100_000), 1).unwrap();
        let raw = acc.finalize(sim.clone(), sign(&sim)).unwrap();

        let owned = acc.owned_outputs(raw).expect("owned outputs");
        assert_eq!(owned.len(), 2, "payment and change: {owned:?}");
        assert!(owned
            .iter()
            .any(|o| !o.is_change && o.amount_sat == 100_000));
        assert!(owned
            .iter()
            .any(|o| o.is_change && o.amount_sat == sim.change_sat));
        for o in &owned {
            assert_eq!(sim.tx_outputs[o.vout as usize].is_change, o.is_change);
        }
    }

    #[test]
    fn owned_outputs_finds_only_the_change_of_a_payment_out() {
        let dir = tempdir().unwrap();
        let acc = funded("owned-out", dir.path(), &[(9, 1, 500_000)]);
        let sim = acc
            .prepare_psbt(pay_sp(recipient_sp_address(), 100_000), 1)
            .unwrap();
        let raw = acc.finalize(sim.clone(), sign(&sim)).unwrap();
        let owned = acc.owned_outputs(raw).unwrap();
        assert_eq!(owned.len(), 1, "{owned:?}");
        assert!(owned[0].is_change);
        assert_eq!(owned[0].amount_sat, sim.change_sat);
    }

    #[test]
    fn owned_outputs_refuses_a_transaction_spending_foreign_coins() {
        let dir = tempdir().unwrap();
        let acc = watch_only("owned-foreign", dir.path());
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };
        let err = acc
            .owned_outputs(bitcoin::consensus::encode::serialize(&tx))
            .expect_err("unknown input");
        assert!(
            matches!(&err, SpError::Other { message } if message.contains("does not hold")),
            "got: {err:?}"
        );
        assert!(acc.owned_outputs(vec![0xff]).is_err());
    }

    /// Minimal hand-rolled block_on for the async dispose/stop_scan
    /// helpers above. Both functions are non-blocking (they just flip an
    /// atomic and poll `try_lock`), so a noop-waker poll loop is sufficient.
    pub(crate) fn futures_lite_block_on<F: std::future::Future>(mut fut: F) -> F::Output {
        use std::pin::Pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop_clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

        let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
        // SAFETY: VTABLE methods are all no-ops; the waker's data pointer
        // is never dereferenced. This is the canonical noop-waker pattern.
        let waker = unsafe { Waker::from_raw(raw_waker) };
        let mut cx = Context::from_waker(&waker);

        // SAFETY: fut is owned by this function and is not moved after
        // pinning; the loop only borrows it as &mut.
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}
