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

use indexmap::IndexMap;
use std::{time::Duration, vec};
use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParametersSet},
    keyring::Algorithm,
    message_signatures::{MessageSigner, UnsignedMessage},
};

#[derive(Debug, Default)]
pub(crate) struct MyThing {
    signature_input: String,
    signature_header: String,
}

impl UnsignedMessage for MyThing {
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
        IndexMap::from_iter([
            (
                CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
                "example.com".to_string(),
            ),
            (
                CoveredComponent::HTTP(HTTPField {
                    name: "signature-agent".to_string(),
                    parameters: HTTPFieldParametersSet(vec![]),
                }),
                "\"https://myexample.com\"".to_string(),
            ),
        ])
    }

    fn register_header_contents(&mut self, signature_input: String, signature_header: String) {
        self.signature_input = format!("sig1={signature_input}");
        self.signature_header = format!("sig1={signature_header}");
    }
}

fn main() {
    // Signing a message
    let private_key = vec![
        0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c, 0x0e,
        0x84, 0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f, 0x6a, 0x7d,
        0x29, 0xc5,
    ];
    let signer = MessageSigner {
        keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into(),
        nonce: "ZO3/XMEZjrvSnLtAP9M7jK0WGQf3J+pbmQRUpKDhF9/jsNCWqUh2sq+TH4WTX3/GpNoSZUa8eNWMKqxWp2/c2g==".into(),
        tag: "web-bot-auth".into(),
    };
    let mut headers = MyThing::default();
    signer
        .generate_signature_headers_content(
            &mut headers,
            Duration::from_secs(10),
            Algorithm::Ed25519,
            &private_key,
        )
        .unwrap();

    assert!(!headers.signature_input.is_empty());
    assert!(!headers.signature_header.is_empty());

    println!("{:?}", headers);
}
