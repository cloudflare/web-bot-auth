//! Deterministic executable benchmark for `MessageVerifier::verify` against a
//! `KeyRing`.
//!
//! Run both modes with the default iteration count:
//!
//! ```text
//! cargo bench -p web-bot-auth --bench keyring_verify
//! ```
//!
//! Select one mode or override the iteration count after `--`:
//!
//! ```text
//! cargo bench -p web-bot-auth --bench keyring_verify -- verify-only 100000
//! ```
//!
//! `verify-only` parses the message once and measures verification only;
//! `end-to-end` parses and verifies on every iteration. Both modes build the
//! keyring once, outside the measured loop. `cargo test --all-targets` runs a
//! short smoke check instead of a full measurement.

use std::hint::black_box;
use std::time::Instant;

use web_bot_auth::components::{CoveredComponent, DerivedComponent, HTTPField};
use web_bot_auth::keyring::{Algorithm, KeyRing};
use web_bot_auth::message_signatures::{MessageVerifier, SignedMessage};

/// Fixed test vector shared with the crate's unit tests.
const KEY_ID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
const PUBLIC_KEY: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
    0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b, 0x23,
    0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43, 0xd1, 0xbb,
];

struct StandardTestVector;

impl SignedMessage for StandardTestVector {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::HTTP(HTTPField { name, .. }) => {
                if name == "signature" {
                    return vec!["sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned()];
                }
                if name == "signature-input" {
                    return vec![r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#.to_owned()];
                }
                vec![]
            }
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                vec!["example.com".to_string()]
            }
            _ => vec![],
        }
    }
}

fn main() {
    let mut invoked_by_cargo_bench = false;
    let mut mode = None;
    let mut iteration_arg = None;
    for arg in std::env::args().skip(1) {
        if arg == "--bench" {
            invoked_by_cargo_bench = true;
        } else if arg.starts_with("--") {
            continue;
        } else if mode.is_none() {
            mode = Some(arg);
        } else if iteration_arg.is_none() {
            iteration_arg = Some(arg);
        } else {
            eprintln!("unexpected argument: {arg}");
            std::process::exit(2);
        }
    }

    let iterations: u64 = iteration_arg
        .map(|value| value.parse().expect("iterations must be an integer"))
        .unwrap_or(if invoked_by_cargo_bench || mode.is_some() {
            30_000
        } else {
            100
        });
    assert!(iterations > 0, "iterations must be greater than zero");

    let modes: &[&str] = match mode.as_deref() {
        None => &["verify-only", "end-to-end"],
        Some("verify-only") => &["verify-only"],
        Some("end-to-end") => &["end-to-end"],
        Some(other) => {
            eprintln!("unknown mode: {other} (expected verify-only or end-to-end)");
            std::process::exit(2);
        }
    };

    // Key import and keyring construction happen once, before measurement.
    let mut keyring = KeyRing::default();
    keyring.import_raw(KEY_ID.to_string(), Algorithm::Ed25519, PUBLIC_KEY.to_vec());
    let message = StandardTestVector;

    for mode in modes {
        run(mode, iterations, &keyring, &message);
    }
}

fn run(mode: &str, iterations: u64, keyring: &KeyRing, message: &StandardTestVector) {
    let mut checksum: u64 = 0;
    let elapsed = match mode {
        "verify-only" => {
            let verifier = MessageVerifier::parse(message, |(_, _)| true).unwrap();
            let start = Instant::now();
            for _ in 0..iterations {
                // `verify` consumes the verifier, so clone the parsed message.
                let timing = black_box(verifier.clone())
                    .verify(black_box(keyring), None)
                    .unwrap();
                checksum = checksum
                    .wrapping_add(timing.generation.as_nanos() as u64)
                    .wrapping_add(timing.verification.as_nanos() as u64)
                    .wrapping_add(1);
            }
            start.elapsed()
        }
        "end-to-end" => {
            let start = Instant::now();
            for _ in 0..iterations {
                let verifier = MessageVerifier::parse(black_box(message), |(_, _)| true).unwrap();
                let timing = verifier.verify(black_box(keyring), None).unwrap();
                checksum = checksum
                    .wrapping_add(timing.generation.as_nanos() as u64)
                    .wrapping_add(timing.verification.as_nanos() as u64)
                    .wrapping_add(1);
            }
            start.elapsed()
        }
        _ => unreachable!("mode validated in main"),
    };

    // Every iteration contributes at least 1 to the checksum; assert so the
    // loop's work cannot be optimized away.
    black_box(checksum);
    assert!(checksum >= iterations);
    let nanos_per_iteration = elapsed.as_secs_f64() * 1_000_000_000.0 / iterations as f64;
    println!(
        "{mode}: {nanos_per_iteration:.1} ns/iteration ({iterations} iterations in {elapsed:?}, checksum={checksum})"
    );
}
