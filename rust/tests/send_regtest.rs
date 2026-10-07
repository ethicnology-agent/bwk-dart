//! Regtest end to end for a watch-only account that spends only with keys
//! lent to the stateless signer for one call: fund the taproot sub-account
//! from bitcoind, send from it to the account's own SP address, scan, then
//! send SP→SP and SP→external, broadcast each, and see each confirmed.
//!
//! Ignored by default; it needs a local regtest stack:
//!
//! ```sh
//! BWK_DART_REGTEST=1 \
//! BWK_DART_BITCOIND_URL=http://127.0.0.1:18443 \
//! BWK_DART_BITCOIND_COOKIE=/path/to/regtest/.cookie \
//! BWK_DART_BLINDBIT_URL=http://127.0.0.1:8000 \
//! BWK_DART_ELECTRUM_URL=tcp://127.0.0.1:60401 \
//! cargo test --features bull_sdk --test send_regtest -- --ignored --nocapture
//! ```
//!
//! - bitcoind (regtest, wallet support, `-txindex=1`), reachable over
//!   JSON-RPC; credentials from `BWK_DART_BITCOIND_COOKIE` or
//!   `BWK_DART_BITCOIND_USER` + `BWK_DART_BITCOIND_PASS`. The test creates
//!   or loads its own wallet, `bwk-dart-regtest`, and mines what it needs.
//! - a blindbit oracle indexing that bitcoind (`BWK_DART_BLINDBIT_URL`).
//! - an Electrum server on that bitcoind (`BWK_DART_ELECTRUM_URL`,
//!   `[tcp|ssl]://host:port`), for the taproot sub-account, the header store
//!   and broadcast.

mod common;

use std::time::{Duration, Instant};

use dart_bwk::api::sp_account::SpAccount;
use dart_bwk::api::sp_signer::sign_silent_payment_psbt;
use dart_bwk::api::types::{CoinSource, RecipientView, SubAccountKind, TxSimulation};
use serde_json::{json, Value};

const WALLET: &str = "bwk-dart-regtest";

fn should_run() -> bool {
    std::env::var("BWK_DART_REGTEST").as_deref() == Ok("1")
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

struct Bitcoind {
    client: reqwest::blocking::Client,
    url: String,
    user: String,
    pass: String,
}

impl Bitcoind {
    fn from_env() -> Self {
        let (user, pass) = match std::env::var("BWK_DART_BITCOIND_COOKIE") {
            Ok(path) => {
                let cookie = std::fs::read_to_string(&path).expect("read the cookie file");
                let (user, pass) = cookie.trim().split_once(':').expect("user:pass cookie");
                (user.to_string(), pass.to_string())
            }
            Err(_) => (env("BWK_DART_BITCOIND_USER"), env("BWK_DART_BITCOIND_PASS")),
        };
        let node = Self {
            client: reqwest::blocking::Client::new(),
            url: env("BWK_DART_BITCOIND_URL")
                .trim_end_matches('/')
                .to_string(),
            user,
            pass,
        };
        if node.call_at("", "createwallet", json!([WALLET])).is_err() {
            // Already created: load it, or it is loaded already.
            let _ = node.call_at("", "loadwallet", json!([WALLET]));
        }
        node
    }

    fn call_at(&self, path: &str, method: &str, params: Value) -> Result<Value, Value> {
        let response: Value = self
            .client
            .post(format!("{}{path}", self.url))
            .basic_auth(&self.user, Some(&self.pass))
            .json(&json!({"jsonrpc": "1.0", "id": "bwk-dart", "method": method, "params": params}))
            .send()
            .expect("bitcoind reachable")
            .json()
            .expect("JSON-RPC response");
        match &response["error"] {
            Value::Null => Ok(response["result"].clone()),
            error => Err(error.clone()),
        }
    }

    fn call(&self, method: &str, params: Value) -> Value {
        self.call_at(&format!("/wallet/{WALLET}"), method, params)
            .unwrap_or_else(|e| panic!("{method}: {e}"))
    }

    fn height(&self) -> u32 {
        self.call("getblockcount", json!([])).as_u64().unwrap() as u32
    }

    fn mine(&self, blocks: u32) {
        let address = self.call("getnewaddress", json!([]));
        self.call("generatetoaddress", json!([blocks, address]));
    }

    fn ensure_funds(&self) {
        let balance = self.call("getbalance", json!([])).as_f64().unwrap();
        if balance < 1.0 {
            self.mine(101);
        }
    }

    fn send(&self, address: &str, sats: u64) -> String {
        let btc = sats as f64 / 100_000_000.0;
        self.call("sendtoaddress", json!([address, btc]))
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Wait for `txid` to reach the mempool or a block (30 s at most).
    fn wait_for_tx(&self, txid: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self
            .call_at(
                &format!("/wallet/{WALLET}"),
                "getrawtransaction",
                json!([txid, true]),
            )
            .is_err()
        {
            assert!(Instant::now() < deadline, "{txid} never reached bitcoind");
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn confirmations(&self, txid: &str) -> u64 {
        self.call("getrawtransaction", json!([txid, true]))["confirmations"]
            .as_u64()
            .unwrap_or(0)
    }
}

fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Wait for blindbit to index up to bitcoind's tip, then scan.
fn scan_to_tip(account: &SpAccount, node: &Bitcoind) {
    let tip = node.height();
    wait_until(
        "blindbit to index the tip",
        Duration::from_secs(120),
        || account.block_height().is_ok_and(|h| h >= tip),
    );
    account.scan_once(None).expect("scan_once");
    common::wait_for_scan(account);
}

fn open(name: &str, dir: &std::path::Path, keys: &common::Derived) -> SpAccount {
    let electrum = env("BWK_DART_ELECTRUM_URL");
    let account = common::watch_only_account(
        name,
        dir,
        keys,
        env("BWK_DART_BLINDBIT_URL"),
        electrum.clone(),
    );
    account
        .set_electrum_url(electrum)
        .expect("set_electrum_url");
    account.start_electrum().expect("start_electrum");
    account
}

/// Sign with the lent keys, finalize, broadcast; returns the txid once
/// bitcoind has it.
fn sign_finalize_broadcast(
    account: &SpAccount,
    keys: &common::Derived,
    simulation: TxSimulation,
    node: &Bitcoind,
) -> String {
    let signed = sign_silent_payment_psbt(
        simulation.psbt.clone(),
        keys.b_spend.clone(),
        Some(keys.taproot_account_xprv.clone()),
    )
    .expect("sign");
    let raw = account.finalize(simulation, signed).expect("finalize");
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
    let txid = tx.compute_txid().to_string();
    account.broadcast(hex::encode(&raw)).expect("broadcast");
    node.wait_for_tx(&txid);
    txid
}

#[test]
#[ignore] // see the module docs for the command and what it needs
fn a_watch_only_account_funds_and_spends_on_regtest() {
    if !should_run() {
        eprintln!("[skip] set BWK_DART_REGTEST=1 and the endpoints, see the module docs");
        return;
    }
    let node = Bitcoind::from_env();
    node.ensure_funds();

    let dir = tempfile::tempdir().unwrap();
    let keys = common::derive(common::TEST_MNEMONIC);
    let account = open("regtest-sender", dir.path(), &keys);

    // 1. Fund the taproot sub-account from bitcoind.
    let taproot_address = account.new_taproot_address().expect("taproot address");
    let funding = node.send(&taproot_address, 300_000);
    node.mine(1);
    assert!(node.confirmations(&funding) >= 1);
    wait_until("the taproot coin", Duration::from_secs(90), || {
        account
            .sub_account_balance(SubAccountKind::Taproot)
            .is_ok_and(|b| b >= 300_000)
    });

    // 2. Taproot → the account's own SP address: a BIP86 input signed with
    //    the lent account xprv, an SP output, SP change.
    let own_sp = account.sp_address().unwrap();
    let simulation = account
        .prepare_psbt(
            vec![RecipientView::Sp {
                address: own_sp.clone(),
                amount_sat: 200_000,
                label: None,
                is_max: false,
            }],
            2,
        )
        .expect("prepare taproot → SP");
    assert!(simulation
        .inputs
        .iter()
        .all(|i| matches!(i.source, CoinSource::Taproot)));
    let txid = sign_finalize_broadcast(&account, &keys, simulation, &node);
    node.mine(1);
    assert!(node.confirmations(&txid) >= 1, "taproot → SP confirmed");

    // The scan key alone finds the payment and the change.
    scan_to_tip(&account, &node);
    let sp_balance = account.confirmed_balance().unwrap();
    assert!(sp_balance >= 200_000, "SP balance after scan: {sp_balance}");

    // 3. SP → another wallet's SP address.
    let other_keys = common::derive(common::OTHER_MNEMONIC);
    let other_dir = tempfile::tempdir().unwrap();
    let other = open("regtest-recipient", other_dir.path(), &other_keys);
    let simulation = account
        .prepare_psbt(
            vec![RecipientView::Sp {
                address: other.sp_address().unwrap(),
                amount_sat: 50_000,
                label: None,
                is_max: false,
            }],
            2,
        )
        .expect("prepare SP → SP");
    assert!(simulation
        .inputs
        .iter()
        .any(|i| matches!(i.source, CoinSource::Sp)));
    let txid = sign_finalize_broadcast(&account, &keys, simulation, &node);
    node.mine(1);
    assert!(node.confirmations(&txid) >= 1, "SP → SP confirmed");
    scan_to_tip(&other, &node);
    assert_eq!(
        other.confirmed_balance().unwrap(),
        50_000,
        "recipient found it"
    );

    // 4. SP → an external address.
    scan_to_tip(&account, &node);
    let external = node
        .call("getnewaddress", json!([]))
        .as_str()
        .unwrap()
        .to_string();
    let simulation = account
        .prepare_psbt(
            vec![RecipientView::Standard {
                address: external.clone(),
                amount_sat: 20_000,
                is_max: false,
            }],
            2,
        )
        .expect("prepare SP → external");
    let txid = sign_finalize_broadcast(&account, &keys, simulation, &node);
    node.mine(1);
    assert!(node.confirmations(&txid) >= 1, "SP → external confirmed");
    let received = node
        .call("getreceivedbyaddress", json!([external, 1]))
        .as_f64()
        .unwrap();
    assert_eq!((received * 100_000_000.0).round() as u64, 20_000);

    common::block_on(account.dispose()).expect("dispose");
    common::block_on(other.dispose()).expect("dispose");
}
