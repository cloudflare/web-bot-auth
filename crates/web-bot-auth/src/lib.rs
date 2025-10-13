#![deny(missing_docs)]
// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

//! # web-bot-auth library
//!
//! `web-bot-auth` is a library provides a Rust implementation of HTTP Message Signatures as defined in
//! [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421), with additional support
//! for verifying a web bot auth signed message.
//!
//! ## Features
//!
//! - **Message Signing**: Generate HTTP message signatures using Ed25519 cryptography
//! - **Message Verification**: Verify signed HTTP messages against public keys
//! - **Web Bot Auth**: Specialized verification for automated agents with additional security requirements
/// HTTP message components that can be present in a given signed / unsigned message, and all the logic
/// to parse it from an incoming message.
pub mod components;

/// Implementation of a JSON Web Key manager suitable for use with `web-bot-auth`. Can be used for arbitrary
/// HTTP message signatures as well.
pub mod keyring;

/// Implementation of HTTP Message Signatures
pub mod message_signatures;

use components::CoveredComponent;
use message_signatures::{MessageVerifier, ParsedLabel, SignatureTiming, SignedMessage};

use data_url::DataUrl;
use keyring::{Algorithm, JSONWebKeySet, KeyRing};
use std::time::SystemTimeError;

/// Errors that may be thrown by this module.
#[derive(Debug)]
pub enum ImplementationError {
    /// Errors that arise from invalid conversions from
    /// parsed structs back into structured field values,
    /// nominally "impossible" because the structs are already
    /// in a valid state.
    ImpossibleSfvError(sfv::Error),
    /// Errors that arise from conversions of structured field
    /// values into parsed structs, with an explanation of what
    /// wrong.
    ParsingError(String),
    /// Errors raised when trying to get the value of a covered
    /// component fails from a `SignedMessage` or `UnsignedMessage`,
    /// likely because the message did not contain the value.
    LookupError(CoveredComponent),
    /// Errors raised when an incoming message references an algorithm
    /// that isn't currently supported by this implementation. The subset
    /// of [registered IANA signature algorithms](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml)
    /// implemented here is provided by `Algorithms` struct.
    UnsupportedAlgorithm(Algorithm),
    /// An attempt to resolve key identifier to a valid public key failed.
    /// This prevents message verification.
    NoSuchKey,
    /// The resolved key ID did not have the sufficient length to be parsed as
    /// a valid key for the algorithm chosen.
    InvalidKeyLength,
    /// The signature provided in `Signature` header was not long enough to be
    /// a valid signature for the algorithm chosen.
    InvalidSignatureLength,
    /// Verification of a parsed signature against a resolved key failed, indicating
    /// the signature was invalid.
    FailedToVerify(ed25519_dalek::SignatureError),
    /// A valid signature base must contain only ASCII characters; this error is thrown
    /// if that's not the case. This may be thrown if some of the headers included in
    /// covered components contained non-ASCII characters, for example. This will be thrown
    /// during both signing and verification, as both steps require constructing the signature
    /// base.
    NonAsciiContentFound,
    /// When normalizing path, query, or authority to percent-decoded forms as mandated by RFC 9421,
    /// an invalid UTF-8 sequence was found. This will be thrown during signing, and indicates malformed
    /// UTF-8 input.
    InvalidUTF8Found,
    /// Signature bases are terminated with a line beginning with `@signature-params`. This error
    /// is thrown if the value of that line could not be converted into a structured field value.
    /// This is considered "impossible" as invalid values should not be present in the structure
    /// containing those values.
    SignatureParamsSerialization,
    /// Verification of `created` or `expires` component parameter requires use of a system clock.
    /// This error is thrown if the system clock is configured in ways that prevent adequate time
    /// resolution, such as the clock believes the start of Unix time is in the future.
    TimeError(SystemTimeError),
    /// A wrapper around `WebBotAuthError`
    WebBotAuth(WebBotAuthError),
}

/// Errors thrown when verifying a Web Bot Auth-signed message specifically.
#[derive(Debug)]
pub enum WebBotAuthError {
    /// Thrown when the signature is detected to be expired, using the `expires`
    /// and `creates` method.
    SignatureIsExpired,
}
/// A trait that messages wishing to be verified as a `web-bot-auth` method specifically
/// must implement.
pub trait WebBotAuthSignedMessage: SignedMessage {
    /// Obtain every `Signature-Agent` header in the message. Despite the name, you can omit
    /// `Signature-Agents` that are known to be invalid ahead of time. However, each `Signature-Agent`
    /// header must be unparsed and a be a valid sfv::Item::String value (meaning it should be encased
    /// in double quotes). You should separately implement looking this up in `SignedMessage::lookup_component`
    /// as an HTTP header with multiple values.
    fn fetch_all_signature_agents(&self) -> Vec<String>;
}

/// A verifier for Web Bot Auth messages specifically.
#[derive(Clone, Debug)]
pub struct WebBotAuthVerifier {
    message_verifier: MessageVerifier,
    /// List of valid `Signature-Agent` headers to try, if present.
    parsed_directories: Vec<SignatureAgentLink>,
}

/// The different types of URLs a `Signature-Agent` can have.
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum SignatureAgentLink {
    /// A data URL that was parsed into a JSON Web Key Set ahead of time.
    Inline(JSONWebKeySet),
    /// An external https:// or http:// URL that requires resolution into a JSON Web Key Set
    External(String),
}

impl WebBotAuthVerifier {
    /// Parse a message into a structure that is ready for verification against an
    /// external key with a suitable algorithm. If `alg` is not set, a default will
    /// be chosen from the `alg` parameter.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn parse(message: &impl WebBotAuthSignedMessage) -> Result<Self, ImplementationError> {
        let signature_agents = message.fetch_all_signature_agents();
        let web_bot_auth_verifier = Self {
            message_verifier: MessageVerifier::parse(message, |(_, innerlist)| {
                innerlist.params.contains_key("keyid")
                    && innerlist.params.contains_key("tag")
                    && innerlist.params.contains_key("expires")
                    && innerlist.params.contains_key("created")
                    && innerlist
                        .params
                        .get("tag")
                        .and_then(|tag| tag.as_string())
                        .is_some_and(|tag| tag.as_str() == "web-bot-auth")
                    && innerlist
                        .items
                        .iter()
                        .any(|item| *item == sfv::Item::new(sfv::StringRef::constant("@authority")))
                    && (if !signature_agents.is_empty() {
                        innerlist.items.iter().any(|item| {
                            *item == sfv::Item::new(sfv::StringRef::constant("signature-agent"))
                        })
                    } else {
                        true
                    })
            })?,
            parsed_directories: signature_agents
                .iter()
                .map(|header| {
                    sfv::Parser::new(header).parse_item().map_err(|e| {
                        ImplementationError::ParsingError(format!(
                            "Failed to parse `Signature-Agent` into valid sfv::Item: {e}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .flat_map(|item| {
                    let as_string = item.bare_item.as_string();
                    as_string.and_then(|link| {
                        let link_str = link.as_str();
                        if link_str.starts_with("https://") || link_str.starts_with("http://") {
                            return Some(SignatureAgentLink::External(String::from(link_str)));
                        }

                        if let Ok(url) = DataUrl::process(link_str) {
                            let mediatype = url.mime_type();
                            if mediatype.type_ == "application"
                                && mediatype.subtype == "http-message-signatures-directory"
                            {
                                if let Ok((body, _)) = url.decode_to_vec() {
                                    if let Ok(jwks) = serde_json::from_slice::<JSONWebKeySet>(&body)
                                    {
                                        return Some(SignatureAgentLink::Inline(jwks));
                                    }
                                }
                            }
                        }

                        None
                    })
                })
                .collect(),
        };

        Ok(web_bot_auth_verifier)
    }

    /// Obtain list of Signature-Agents parsed and ready. This method is ideal for populating
    /// a keyring ahead of time at your discretion.
    pub fn get_signature_agents(&self) -> &Vec<SignatureAgentLink> {
        &self.parsed_directories
    }

    /// Verify the messsage, consuming the verifier in the process.
    /// If `key_id` is not supplied, a key ID to fetch the public key
    /// from `keyring` will be sourced from the `keyid` parameter
    /// within the message.
    pub fn verify(
        self,
        keyring: &KeyRing,
        key_id: Option<String>,
    ) -> Result<SignatureTiming, ImplementationError> {
        self.message_verifier.verify(keyring, key_id)
    }

    /// Retrieve the contents of the chosen signature and signature input label for
    /// verification.
    pub fn get_parsed_label(&self) -> &ParsedLabel {
        &self.message_verifier.parsed
    }
}

#[cfg(test)]
mod tests {

    use components::DerivedComponent;
    use indexmap::IndexMap;

    use super::*;

    struct StandardTestVector {}

    impl SignedMessage for StandardTestVector {
        fn fetch_all_signature_headers(&self) -> Vec<String> {
            vec!["sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned()]
        }
        fn fetch_all_signature_inputs(&self) -> Vec<String> {
            vec![r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#.to_owned()]
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

    impl WebBotAuthSignedMessage for StandardTestVector {
        fn fetch_all_signature_agents(&self) -> Vec<String> {
            vec![]
        }
    }

    #[test]
    fn test_verifying_as_web_bot_auth() {
        let test = StandardTestVector {};
        let public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
            0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58,
            0x2b, 0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd,
            0xce, 0x43, 0xd1, 0xbb,
        ];
        let mut keyring = KeyRing::default();
        keyring.import_raw(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            Algorithm::Ed25519,
            public_key.to_vec(),
        );
        let verifier = WebBotAuthVerifier::parse(&test).unwrap();
        let advisory = verifier
            .get_parsed_label()
            .base
            .parameters
            .details
            .possibly_insecure(|_| false);
        // Since the expiry date is in the past.
        assert!(advisory.is_expired.unwrap_or(true));
        assert!(!advisory.nonce_is_invalid.unwrap_or(true));
        let timing = verifier.verify(&keyring, None).unwrap();
        assert!(timing.generation.as_nanos() > 0);
        assert!(timing.verification.as_nanos() > 0);
    }

    #[test]
    fn test_signing_then_verifying() {
        struct MyTest {
            signature_input: String,
            signature_header: String,
        }

        impl message_signatures::UnsignedMessage for MyTest {
            fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
                IndexMap::from_iter([(
                    CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
                    "example.com".to_string(),
                )])
            }

            fn register_header_contents(
                &mut self,
                signature_input: String,
                signature_header: String,
            ) {
                self.signature_input = format!("sig1={signature_input}");
                self.signature_header = format!("sig1={signature_header}");
            }
        }

        impl SignedMessage for MyTest {
            fn fetch_all_signature_headers(&self) -> Vec<String> {
                vec![self.signature_header.clone()]
            }
            fn fetch_all_signature_inputs(&self) -> Vec<String> {
                vec![self.signature_input.clone()]
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

        impl WebBotAuthSignedMessage for MyTest {
            fn fetch_all_signature_agents(&self) -> Vec<String> {
                vec![]
            }
        }

        let public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
            0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58,
            0x2b, 0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd,
            0xce, 0x43, 0xd1, 0xbb,
        ];

        let private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = [
            0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c,
            0x0e, 0x84, 0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f,
            0x6a, 0x7d, 0x29, 0xc5,
        ];

        let mut keyring = KeyRing::default();
        keyring.import_raw(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            Algorithm::Ed25519,
            public_key.to_vec(),
        );

        let signer = message_signatures::MessageSigner {
            keyid: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".into(),
            nonce: "end-to-end-test".into(),
            tag: "web-bot-auth".into(),
        };

        let mut mytest = MyTest {
            signature_input: String::new(),
            signature_header: String::new(),
        };

        signer
            .generate_signature_headers_content(
                &mut mytest,
                std::time::Duration::from_secs(10),
                Algorithm::Ed25519,
                &private_key.to_vec(),
            )
            .unwrap();

        let verifier = WebBotAuthVerifier::parse(&mytest).unwrap();
        let advisory = verifier
            .get_parsed_label()
            .base
            .parameters
            .details
            .possibly_insecure(|_| false);
        assert!(!advisory.is_expired.unwrap_or(true));
        assert!(!advisory.nonce_is_invalid.unwrap_or(true));

        let timing = verifier.verify(&keyring, None).unwrap();
        assert!(timing.generation.as_nanos() > 0);
        assert!(timing.verification.as_nanos() > 0);
    }

    #[test]
    fn test_missing_tags_break_web_bot_auth() {
        struct MissingParametersTestVector {}

        impl SignedMessage for MissingParametersTestVector {
            fn fetch_all_signature_headers(&self) -> Vec<String> {
                vec![
                    "sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned()
                ]
            }
            fn fetch_all_signature_inputs(&self) -> Vec<String> {
                vec![r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="not-web-bot-auth""#.to_owned()]
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

        impl WebBotAuthSignedMessage for MissingParametersTestVector {
            fn fetch_all_signature_agents(&self) -> Vec<String> {
                vec![]
            }
        }

        let test = MissingParametersTestVector {};
        WebBotAuthVerifier::parse(&test).expect_err("This should not have parsed");
    }

    #[test]
    fn test_signature_agents_are_required_in_signature_input() {
        struct MissingParametersTestVector {}

        impl SignedMessage for MissingParametersTestVector {
            fn fetch_all_signature_headers(&self) -> Vec<String> {
                vec!["sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned()]
            }
            fn fetch_all_signature_inputs(&self) -> Vec<String> {
                vec![r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="web-bot-auth""#.to_owned()]
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

        impl WebBotAuthSignedMessage for MissingParametersTestVector {
            fn fetch_all_signature_agents(&self) -> Vec<String> {
                vec![String::from("\"https://myexample.com\"")]
            }
        }

        let test = MissingParametersTestVector {};
        WebBotAuthVerifier::parse(&test).expect_err("This should not have parsed");
    }

    #[test]
    fn test_signature_agents_are_parsed_correctly() {
        struct StandardTestVector {}

        impl SignedMessage for StandardTestVector {
            fn fetch_all_signature_headers(&self) -> Vec<String> {
                vec!["sig1=:3q7S1TtbrFhQhpcZ1gZwHPCFHTvdKXNY1xngkp6lyaqqqv3QZupwpu/wQG5a7qybnrj2vZYMeVKuWepm+rNkDw==:".to_owned()]
            }
            fn fetch_all_signature_inputs(&self) -> Vec<String> {
                vec![r#"sig1=("@authority" "signature-agent");alg="ed25519";keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";nonce="ZO3/XMEZjrvSnLtAP9M7jK0WGQf3J+pbmQRUpKDhF9/jsNCWqUh2sq+TH4WTX3/GpNoSZUa8eNWMKqxWp2/c2g==";tag="web-bot-auth";created=1749331474;expires=1749331484"#.to_owned()]
            }
            fn lookup_component(&self, name: &CoveredComponent) -> Option<String> {
                match name {
                    CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                        Some("example.com".to_string())
                    }
                    CoveredComponent::HTTP(components::HTTPField { name, .. }) => {
                        if name == "signature-agent" {
                            return Some(String::from("\"https://myexample.com\""));
                        }
                        None
                    }
                    _ => None,
                }
            }
        }

        impl WebBotAuthSignedMessage for StandardTestVector {
            fn fetch_all_signature_agents(&self) -> Vec<String> {
                vec![String::from("\"https://myexample.com\"")]
            }
        }

        let public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
            0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58,
            0x2b, 0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd,
            0xce, 0x43, 0xd1, 0xbb,
        ];
        let mut keyring = KeyRing::default();
        keyring.import_raw(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            Algorithm::Ed25519,
            public_key.to_vec(),
        );

        let test = StandardTestVector {};
        let verifier = WebBotAuthVerifier::parse(&test).unwrap();
        let timing = verifier.verify(&keyring, None).unwrap();
        assert!(timing.generation.as_nanos() > 0);
        assert!(timing.verification.as_nanos() > 0);
    }
}
