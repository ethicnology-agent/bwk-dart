use flutter_rust_bridge::frb;

#[frb(unignore)]
#[derive(Debug, Clone)]
pub enum SpNetwork {
    Bitcoin,
    Signet,
    Testnet,
    Regtest,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub enum SubAccountKind {
    Segwit,
    Taproot,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub enum CoinSource {
    Sp,
    Segwit,
    Taproot,
    Other,
}

#[frb(unignore)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedCoinStatus {
    Unconfirmed,
    Unspent,
    Spent,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub enum SpNotification {
    ScanStarted {
        from: u32,
        to: u32,
    },
    ScanReceiveProgress {
        current: u32,
        end: u32,
    },
    ScanCompleted,
    ScanStopped,
    ScanFailed {
        message: String,
    },
    NewOutput {
        outpoint: String,
        amount_sat: u64,
    },
    OutputSpent {
        outpoint: String,
    },
    Broadcasted {
        txid: String,
    },
    BroadcastFailed {
        message: String,
    },
    BackendOffline,
    ElectrumTx {
        kind: CoinSource,
        txid: String,
        amount_sat: u64,
        height: Option<u32>,
    },
    ScanSpendProgress {
        current: u32,
        end: u32,
    },
    HeaderProgressStarted {
        phase: HeaderProgressPhase,
        start: u32,
        end: u32,
    },
    HeaderProgress {
        phase: HeaderProgressPhase,
        current: u32,
        end: u32,
    },
    HeaderProgressCompleted {
        phase: HeaderProgressPhase,
    },
    HeaderProgressFailed {
        phase: HeaderProgressPhase,
    },
    PaymentHistoryUpdated,
}

#[frb(unignore)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProgressPhase {
    Replay,
    InitialSync,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub struct SpCoinView {
    pub outpoint: String,
    pub amount_sat: u64,
    pub height: u32,
    pub is_spendable: bool,
    pub label: Option<String>,
}

/// An output of a signed transaction that the account owns, as
/// [`crate::api::sp_account::SpAccount::owned_outputs`] finds it.
#[frb(unignore)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpOwnedOutput {
    pub vout: u32,
    pub amount_sat: u64,
    /// Paid to the account's SP change label (`m = 0`).
    pub is_change: bool,
}

/// Typed payment direction surfaced to Dart so consumers can `match` on
/// it exhaustively instead of string-comparing.
#[frb(unignore)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpPaymentDirection {
    Receive,
    Send,
    SelfSend,
}

#[frb(unignore)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpPaymentStatus {
    Unconfirmed,
    ConfirmedUnverified,
    Verified,
    VerifyFailed,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub struct SpPaymentView {
    pub txid: String,
    pub direction: SpPaymentDirection,
    pub status: SpPaymentStatus,
    pub amount_sat: u64,
    pub fee_sat: Option<u64>,
    pub height: Option<u32>,
    pub timestamp: Option<u64>,
    pub label: Option<String>,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub struct UnifiedCoinView {
    pub source: CoinSource,
    pub outpoint: String,
    pub amount_sat: u64,
    pub height: Option<u32>,
    pub status: UnifiedCoinStatus,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub enum RecipientView {
    Sp {
        address: String,
        amount_sat: u64,
        label: Option<u32>,
        /// Send-max: drain all spendable coins to this output (amount_sat is
        /// ignored on the way in; the computed amount is reported back).
        is_max: bool,
    },
    Standard {
        address: String,
        amount_sat: u64,
        is_max: bool,
    },
}

#[frb(unignore)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpRecipientAddressKind {
    Sp,
    Standard,
}

/// Where one output of a simulated transaction pays.
#[frb(unignore)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputDestination {
    /// A silent-payment output. Its script is derived by the signer, so the
    /// unsigned PSBT carries the recipient's keys instead: `address` is the SP
    /// address those keys (and `label`) form, `scan_key`/`spend_key` the
    /// 33-byte compressed public keys, in hex.
    SilentPayment {
        address: String,
        scan_key: String,
        spend_key: String,
        label: Option<u32>,
    },
    /// A standard output to a known address.
    Address { address: String },
    /// A script with no address form, in hex.
    Script { script_hex: String },
}

/// One output of a simulated transaction, in transaction order.
#[frb(unignore)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedOutput {
    pub vout: u32,
    pub amount_sat: u64,
    pub destination: OutputDestination,
    /// Pays the account's own SP change address.
    pub is_change: bool,
}

/// A transaction the user confirms before it is signed.
///
/// `psbt` is the unsigned PSBTv2 to hand to
/// [`crate::api::sp_signer::sign_silent_payment_psbt`]; every other field is
/// read from it, for display. [`crate::api::sp_account::SpAccount::finalize`]
/// takes the simulation back with the signed PSBT and refuses one whose
/// transaction differs from it.
#[frb(unignore)]
#[derive(Debug, Clone)]
pub struct TxSimulation {
    /// The coins spent, in transaction order.
    pub inputs: Vec<UnifiedCoinView>,
    /// The requested recipients, a max amount resolved to what it pays.
    pub outputs: Vec<RecipientView>,
    /// Every output of the transaction, change included.
    pub tx_outputs: Vec<SimulatedOutput>,
    pub fee_sat: u64,
    pub change_sat: u64,
    /// The fee rate the transaction was built at, in sat/vB.
    pub fee_rate_sat_vb: u64,
    /// The unsigned PSBTv2.
    pub psbt: Vec<u8>,
}

#[frb(unignore)]
#[derive(Debug, Clone)]
pub struct SpBalanceView {
    pub confirmed_sat: u64,
    pub total_unified_sat: u64,
    pub last_scanned_height: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RegtestDefaults {
    pub is_ok: bool,
    pub error: String,
    pub blindbit_url: String,
    pub p2p_node: String,
    pub electrum_url: String,
}

/// Errors a Silent Payments call can return that a caller must be able to tell
/// apart, rather than matching on message text.
///
/// Everything the Dart side needs to branch on gets its own variant; anything
/// it can only log or show generically stays in [SpError::Other]. Added because
/// consumers were sniffing substrings out of the previous `Result<_, String>`
/// surface, which broke silently whenever a message was reworded.
#[frb(unignore)]
#[derive(Debug, Clone)]
pub enum SpError {
    /// A scan is already running; start another only after it finishes or is
    /// cancelled.
    ScannerAlreadyRunning,
    /// `dispose()` gave up waiting for the inner lock. The session is kept, so
    /// the caller may retry rather than treat the account as gone.
    DisposeTimedOut,
    /// The coin set moved after the simulation the caller confirmed, so the
    /// pinned transaction can no longer be built. The caller must re-confirm.
    /// `detail` names the offending outpoint, for logs only.
    SimulationDrifted { detail: String },
    /// Automatic coin selection refused: the wallet holds `count` coins, more
    /// than the `max` it can search. A max send to an own address merges them.
    TooManyCoins { count: u32, max: u32 },
    /// A max send leaves only `remainder_sat` after the fee, below the dust
    /// limit, so there is nothing to send.
    NothingToSendAfterFee { remainder_sat: u64 },
    /// A descriptor given to open an account was refused: malformed, for
    /// another network, or carrying a key the account must not hold.
    /// `reason` never quotes the descriptor.
    InvalidDescriptor { reason: String },
    /// The signer refused the PSBT or the keys it was lent: an input neither
    /// key owns, an unsupported input, a PSBT already signed, a malformed key.
    /// Nothing was signed. `reason` carries no key material.
    Signing { reason: String },
    /// The signed PSBT handed to `finalize` does not spend and pay exactly
    /// what the simulation the user confirmed does (inputs, outputs, amounts,
    /// fee), or the simulation no longer matches its own PSBT. Nothing was
    /// finalized. `detail` is for logs.
    SignedPsbtMismatch { detail: String },
    /// The account's own check of the signed PSBT failed: a BIP375 share,
    /// proof or silent-payment output script does not verify, or the
    /// signatures do not finalize. The signer malfunctioned or lied about a
    /// destination. Nothing was finalized. `reason` is for logs.
    Verification { reason: String },
    /// Anything else. `message` is for logs, never for the user.
    Other { message: String },
}

impl std::fmt::Display for SpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScannerAlreadyRunning => write!(f, "scanner already running"),
            Self::DisposeTimedOut => {
                write!(
                    f,
                    "dispose timed out: inner lock still held; retry or restart"
                )
            }
            Self::SimulationDrifted { detail } => write!(
                f,
                "transaction inputs changed since confirmation: {detail}; please re-confirm"
            ),
            Self::TooManyCoins { count, max } => write!(
                f,
                "{count} coins exceed the {max} automatic coin selection supports"
            ),
            Self::NothingToSendAfterFee { remainder_sat } => write!(
                f,
                "nothing left to send after the fee: {remainder_sat} sats is below the dust limit"
            ),
            Self::InvalidDescriptor { reason } => write!(f, "invalid descriptor: {reason}"),
            Self::Signing { reason } => write!(f, "signing refused: {reason}"),
            Self::SignedPsbtMismatch { detail } => {
                write!(
                    f,
                    "signed PSBT does not match the confirmed transaction: {detail}"
                )
            }
            Self::Verification { reason } => write!(f, "signed PSBT failed verification: {reason}"),
            Self::Other { message } => write!(f, "{message}"),
        }
    }
}

impl From<String> for SpError {
    fn from(message: String) -> Self {
        Self::Other { message }
    }
}
