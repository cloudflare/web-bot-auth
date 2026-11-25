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

use serde::Deserialize;
use web_bot_auth::{
    SignatureAgentLink, WebBotAuthVerifier,
    components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParameters},
    keyring::{Algorithm, KeyRing},
    message_signatures::SignedMessage,
};

#[derive(Deserialize)]
struct MySignedMsg {
    signature_agent: String,
    signature_input: String,
    signature: String,
}

impl SignedMessage for MySignedMsg {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                vec!["example.com".to_string()]
            }
            CoveredComponent::HTTP(HTTPField { name, parameters }) => {
                match (name.as_str(), parameters.0.as_slice()) {
                    ("signature-agent", []) => vec![self.signature_agent.clone()],
                    // E.2.1 contains one dictionary member. `key` selects its value.
                    ("signature-agent", [HTTPFieldParameters::Key(key)]) if key == "sig2" => self
                        .signature_agent
                        .strip_prefix("sig2=")
                        .map(str::to_owned)
                        .into_iter()
                        .collect(),
                    ("signature", []) => vec![self.signature.clone()],
                    ("signature-input", []) => vec![self.signature_input.clone()],
                    _ => vec![],
                }
            }
            _ => vec![],
        }
    }
}

fn main() {
    // Verifying a Web Bot Auth message
    let public_key = [
        0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b,
        0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43,
        0xd1, 0xbb,
    ];
    let mut keyring = KeyRing::default();
    // sample keyid pulled from https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/
    keyring.import_raw(
        "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
        Algorithm::Ed25519,
        public_key.to_vec(),
    );
    let [dictionary, _legacy]: [MySignedMsg; 2] = serde_json::from_str(include_str!(
        "../verification-workers/test/draft-ietf-webbotauth-httpsig-protocol-01.json"
    ))
    .unwrap();
    let verifier = WebBotAuthVerifier::parse(&dictionary).unwrap();
    assert_eq!(
        verifier.get_signature_agents().as_slice(),
        &[SignatureAgentLink::Directory(
            "https://signature-agent.test".into()
        )]
    );
    // Check the published fixture regardless of when the example runs.
    verifier.verify_ignore_expiry(&keyring, None).unwrap();
}
