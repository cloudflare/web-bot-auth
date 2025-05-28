use web_bot_auth::{
    KeyRing, MessageVerifier, SignedMessage,
    components::{CoveredComponent, DerivedComponent},
};

struct MySignedMsg;

impl SignedMessage for MySignedMsg {
    fn fetch_signature_header(&self) -> Option<String> {
        Some("sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned())
    }
    fn fetch_signature_input(&self) -> Option<String> {
        Some(r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#.to_owned())
    }
    fn lookup_component(&self, name: &CoveredComponent) -> Option<String> {
        match *name {
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                Some("example.com".to_string())
            }
            _ => None,
        }
    }
}

fn main() {
    // Verifying an arbitrary message signature, not necessarily `web-bot-auth`
    let public_key = vec![
        0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b,
        0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43,
        0xd1, 0xbb,
    ];
    let keyring = KeyRing::from_iter([(
        "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
        public_key,
    )]);
    let test = MySignedMsg {};
    let verifier = MessageVerifier::parse(&test, None, |_| true).unwrap();
    assert!(verifier.verify(&keyring, None).is_ok());
}
