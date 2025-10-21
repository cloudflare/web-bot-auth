// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent, HTTPField},
    keyring::{Algorithm, KeyRing},
    message_signatures::{MessageVerifier, SignedMessage},
};

struct MySignedMsg;

impl SignedMessage for MySignedMsg {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                vec!["example.com".to_string()]
            }
            CoveredComponent::HTTP(HTTPField { name, .. }) => {
                if name == "signature" {
                    return vec!["sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned()];
                }

                if name == "signature-input" {
                    return vec![r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#.to_owned()];
                }
                vec![]
            }
            _ => vec![],
        }
    }
}

fn main() {
    // Verifying an arbitrary message signature, not necessarily `web-bot-auth`
    let public_key = [
        0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b,
        0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43,
        0xd1, 0xbb,
    ];
    let mut keyring = KeyRing::default();
    keyring.import_raw(
        "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
        Algorithm::Ed25519,
        public_key.to_vec(),
    );
    let test = MySignedMsg {};
    let verifier = MessageVerifier::parse(&test, |_| true).unwrap();
    let advisory = verifier
        .parsed
        .base
        .parameters
        .details
        .possibly_insecure(|_| false);
    // Since the expiry date is in the past.
    assert!(advisory.is_expired.unwrap_or(true));
    assert!(!advisory.nonce_is_invalid.unwrap_or(true));
    assert!(verifier.verify(&keyring, None).is_ok());
}
