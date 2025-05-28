use indexmap::IndexMap;
use std::time::Duration;
use web_bot_auth::{
    Algorithm, MessageSigner, UnsignedMessage,
    components::{CoveredComponent, DerivedComponent},
};

#[derive(Default)]
pub(crate) struct MyThing {
    signature_input: String,
    signature_header: String,
}

impl UnsignedMessage for MyThing {
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
        IndexMap::from_iter([(
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
            "example.com".to_string(),
        )])
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
        algorithm: Algorithm::Ed25519,
        keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into(),
        nonce: "ZO3/XMEZjrvSnLtAP9M7jK0WGQf3J+pbmQRUpKDhF9/jsNCWqUh2sq+TH4WTX3/GpNoSZUa8eNWMKqxWp2/c2g==".into(),
        tag: "web-bot-auth".into(),
    };
    let mut headers = MyThing::default();
    signer
        .generate_signature_headers_content(&mut headers, Duration::from_secs(10), &private_key)
        .unwrap();

    assert!(!headers.signature_input.is_empty());
    assert!(!headers.signature_header.is_empty());
}
