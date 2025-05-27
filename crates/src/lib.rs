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
pub mod components;

use components::CoveredComponent;
use indexmap::IndexMap;
use sfv::SerializeValue;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

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
    UnsupportedAlgorithm,
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
    FailedToVerify,
    /// A valid signature base must contain only ASCII characters; this error is thrown
    /// if that's not the case. This may be thrown if some of the headers included in
    /// covered components contained non-ASCII characters, for example. This will be thrown
    /// during both signing and verification, as both steps require constructing the signature
    /// base.
    NonAsciiContentFound,
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
    /// Thrown today only if a Signature-Agent header is provided and following
    /// the link in that is enabled. In a future release, we may support fetching
    /// and ingesting the key.
    NotImplemented,
}

#[derive(Debug)]
struct SignatureParams {
    raw: sfv::Parameters,
    details: ParameterDetails,
}

/// Parsed values from `Signature-Input` header.
#[derive(Debug, Clone)]
pub struct ParameterDetails {
    pub algorithm: Option<Algorithm>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub keyid: Option<String>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
}

impl From<sfv::Parameters> for SignatureParams {
    fn from(value: sfv::Parameters) -> Self {
        let mut parameter_details = ParameterDetails {
            algorithm: None,
            created: None,
            expires: None,
            keyid: None,
            nonce: None,
            tag: None,
        };

        for (key, val) in &value {
            match key.as_str() {
                "alg" => {
                    parameter_details.algorithm = val.as_string().and_then(|algorithm_string| {
                        match algorithm_string.as_str() {
                            "ed25519" => Some(Algorithm::Ed25519),
                            _ => None,
                        }
                    });
                }
                "keyid" => {
                    parameter_details.keyid = val.as_string().map(|s| s.as_str().to_string());
                }
                "tag" => parameter_details.tag = val.as_string().map(|s| s.as_str().to_string()),
                "nonce" => {
                    parameter_details.nonce = val.as_string().map(|s| s.as_str().to_string());
                }
                "created" => {
                    parameter_details.created = val.as_integer().map(std::convert::Into::into);
                }
                "expires" => {
                    parameter_details.expires = val.as_integer().map(std::convert::Into::into);
                }
                _ => {}
            }
        }

        Self {
            raw: value,
            details: parameter_details,
        }
    }
}

struct SignatureBaseBuilder {
    components: Vec<CoveredComponent>,
    parameters: SignatureParams,
}

impl TryFrom<sfv::InnerList> for SignatureBaseBuilder {
    type Error = ImplementationError;

    fn try_from(value: sfv::InnerList) -> Result<Self, Self::Error> {
        Ok(SignatureBaseBuilder {
            components: value
                .items
                .iter()
                .map(|item| (*item).clone().try_into())
                .collect::<Result<Vec<CoveredComponent>, ImplementationError>>()?,
            // Note: it is the responsibility of higher layers to check whether the message is
            // expired, down here we just parse.
            parameters: value.params.into(),
        })
    }
}

impl SignatureBaseBuilder {
    fn into_signature_base(
        self,
        message: &impl SignedMessage,
    ) -> Result<SignatureBase, ImplementationError> {
        Ok(SignatureBase {
            components: IndexMap::from_iter(
                self.components
                    .into_iter()
                    .map(|component| match message.lookup_component(&component) {
                        Some(serialized_value) => Ok((component, serialized_value)),
                        None => Err(ImplementationError::LookupError(component)),
                    })
                    .collect::<Result<Vec<(CoveredComponent, String)>, ImplementationError>>()?,
            ),
            parameters: self.parameters,
        })
    }
}

/// A representation of the signature base to be generated during verification and signing.
#[derive(Debug)]
struct SignatureBase {
    components: IndexMap<CoveredComponent, String>,
    parameters: SignatureParams,
}

impl SignatureBase {
    // Convert `SignatureBase` into its ASCII representation as well as the portion of
    // itself that corresponds to `@signature-params` line.
    fn into_ascii(self) -> Result<(String, String), ImplementationError> {
        let mut output = String::new();

        let mut signature_params_line_items: Vec<sfv::Item> = vec![];

        for (component, serialized_value) in self.components {
            let sfv_item = match component {
                CoveredComponent::HTTP(http) => sfv::Item::try_from(http)?,
                CoveredComponent::Derived(derived) => sfv::Item::try_from(derived)?,
            };

            let _ = writeln!(
                output,
                "{}: {}",
                sfv_item.serialize_value(),
                serialized_value
            );
            signature_params_line_items.push(sfv_item);
        }

        let signature_params_line = vec![sfv::ListEntry::InnerList(sfv::InnerList::with_params(
            signature_params_line_items,
            self.parameters.raw,
        ))]
        .serialize_value()
        .ok_or(ImplementationError::SignatureParamsSerialization)?;

        let _ = write!(output, "\"@signature-params\": {signature_params_line}");

        if output.is_ascii() {
            Ok((output, signature_params_line))
        } else {
            Err(ImplementationError::NonAsciiContentFound)
        }
    }

    fn get_details(&self) -> ParameterDetails {
        self.parameters.details.clone()
    }

    fn is_expired(&self) -> Option<bool> {
        self.parameters.details.expires.map(|expires| {
            if expires <= 0 {
                return true;
            }

            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => i64::try_from(duration.as_secs())
                    .map(|dur| dur >= expires)
                    .unwrap_or(true),
                Err(_) => true,
            }
        })
    }
}

/// Subset of [HTTP signature algorithm](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml)
/// implemented in this module. In the future, we may support more.
#[derive(Debug, Clone)]
pub enum Algorithm {
    Ed25519,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Algorithm::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// Represents a public key to be consumed during the verification.
pub type PublicKey = Vec<u8>;
/// Represents a JSON Web Key base64-encoded thumpprint as implemented
/// per [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)
pub type Thumbprint = String;
/// A map from a thumbprint to the public key, to be used to map `keyid`s
/// to public keys.
pub type KeyRing = HashMap<Thumbprint, PublicKey>;

/// Trait that messages seeking verification should implement to facilitate looking up
/// raw values from the underlying message.
pub trait SignedMessage {
    /// Obtain the parsed version of `Signature` HTTP header
    fn fetch_signature_header(&self) -> Option<String>;
    /// Obtain the parsed version of `Signature-Input` HTTP header
    fn fetch_signature_input(&self) -> Option<String>;
    /// Obtain the serialized value of a covered component. Implementations should
    /// respect any parameter values set on the covered component per the message
    /// signature spec. Component values that cannot be found must return None.
    /// `CoveredComponent::HTTP` fields are guaranteed to have lowercase ASCII names, so
    /// care should be taken to ensure HTTP field names in the message are checked in a
    /// case-insensitive way.
    fn lookup_component(&self, name: &CoveredComponent) -> Option<String>;
}

/// Trait that messages seeking signing should implement to generate `Signature-Input`
/// and `Signature` header contents.
pub trait UnsignedMessage {
    /// Obtain a list of covered components to be included
    fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String>;
    /// Store the contents of a generated `Signature-Input` and `Signature` header value.
    /// It is the responsibility of the application to generate a consistent label for both.
    /// `signature_header` is guaranteed to be a `sfv` byte sequence element. `signature_input`
    /// is guaranteed to be `sfv` inner list of strings.
    fn register_header_contents(&mut self, signature_input: String, signature_header: String);
}

/// A struct that implements signing. The struct fields here are serialized into the `Signature-Input`
/// header.
pub struct MessageSigner {
    /// Algorith mto use for signing
    pub algorithm: Algorithm,
    /// Name to use for `keyid` parameter
    pub keyid: String,
    /// A random nonce to be provided for additional security
    pub nonce: String,
    /// Value to be used for `tag` parameter
    pub tag: String,
}

impl MessageSigner {
    /// Sign the provided method with `signing_key`, setting an expiration value of
    /// length `expires` from now (the time of signing).
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to signing and parsing.
    pub fn generate_signature_headers_content(
        &self,
        message: &mut impl UnsignedMessage,
        expires: Duration,
        signing_key: &PublicKey,
    ) -> Result<(), ImplementationError> {
        let components_to_cover = message.fetch_components_to_cover();
        let mut sfv_parameters = sfv::Parameters::new();

        sfv_parameters.insert(
            sfv::KeyRef::constant("alg").to_owned(),
            sfv::BareItem::String(sfv::StringRef::constant(&self.algorithm.to_string()).to_owned()),
        );

        sfv_parameters.insert(
            sfv::KeyRef::constant("keyid").to_owned(),
            sfv::BareItem::String(
                sfv::StringRef::from_str(&self.keyid)
                    .map_err(|_| {
                        ImplementationError::ParsingError(
                            "keyid contains non-printable ASCII characters".into(),
                        )
                    })?
                    .to_owned(),
            ),
        );

        sfv_parameters.insert(
            sfv::KeyRef::constant("nonce").to_owned(),
            sfv::BareItem::String(
                sfv::StringRef::from_str(&self.nonce)
                    .map_err(|_| {
                        ImplementationError::ParsingError(
                            "nonce contains non-printable ASCII characters".into(),
                        )
                    })?
                    .to_owned(),
            ),
        );

        sfv_parameters.insert(
            sfv::KeyRef::constant("tag").to_owned(),
            sfv::BareItem::String(
                sfv::StringRef::from_str(&self.tag)
                    .map_err(|_| {
                        ImplementationError::ParsingError(
                            "tag contains non-printable ASCII characters".into(),
                        )
                    })?
                    .to_owned(),
            ),
        );

        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(ImplementationError::TimeError)?;
        let expiry = created + expires;

        let created_as_i64 = i64::try_from(created.as_secs()).map_err(|_| {
            ImplementationError::ParsingError(
                "Clock time does not fit in i64, verfy your clock is set correctly".into(),
            )
        })?;
        let expires_as_i64 = i64::try_from(expiry.as_secs()).map_err(|_| {
            ImplementationError::ParsingError(
                "Clcok time + `expires` value does not fit in i64, verfy your duration is valid"
                    .into(),
            )
        })?;

        sfv_parameters.insert(
            sfv::KeyRef::constant("created").to_owned(),
            sfv::BareItem::Integer(sfv::Integer::constant(created_as_i64)),
        );

        sfv_parameters.insert(
            sfv::KeyRef::constant("expires").to_owned(),
            sfv::BareItem::Integer(sfv::Integer::constant(expires_as_i64)),
        );

        let (signature_base, signature_params_content) = SignatureBase {
            components: components_to_cover,
            parameters: sfv_parameters.into(),
        }
        .into_ascii()?;

        let signature = match self.algorithm {
            Algorithm::Ed25519 => {
                use ed25519_dalek::{Signer, SigningKey};
                let signing_key_dalek = SigningKey::try_from(signing_key.as_slice())
                    .map_err(|_| ImplementationError::InvalidKeyLength)?;

                sfv::Item {
                    bare_item: sfv::BareItem::ByteSequence(
                        signing_key_dalek.sign(signature_base.as_bytes()).to_vec(),
                    ),
                    params: sfv::Parameters::new(),
                }
                .serialize_value()
            }
        };

        message.register_header_contents(signature_params_content, signature);

        Ok(())
    }
}

#[derive(Debug)]
struct ParsedLabel {
    signature: Vec<u8>,
    base: SignatureBase,
}

/// A `MessageVerifier` performs the verifications needed for a signed message.
#[derive(Debug)]
pub struct MessageVerifier {
    parsed: ParsedLabel,
    algorithm: Algorithm,
}

impl MessageVerifier {
    /// Parse a message into a structure that is ready for verification against an
    /// external key with a suitable algorithm. If `alg` is not set, a default will
    /// be chosen from the `alg` parameter. `pick` is a predicate
    /// enabling you to choose which message label should be considered as the message to
    /// verify - if it is known only one signature is in the message, simply return true.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn parse<P>(
        message: &impl SignedMessage,
        alg: Option<Algorithm>,
        pick: P,
    ) -> Result<Self, ImplementationError>
    where
        P: Fn(&(sfv::Key, sfv::InnerList)) -> bool,
    {
        let unparsed_signature_header =
            message
                .fetch_signature_header()
                .ok_or(ImplementationError::ParsingError(
                    "No `Signature` header value ".into(),
                ))?;

        let unparsed_signature_input =
            message
                .fetch_signature_input()
                .ok_or(ImplementationError::ParsingError(
                    "No `Signature-Input` value ".into(),
                ))?;

        let signature_input = sfv::Parser::new(&unparsed_signature_input)
            .parse_dictionary()
            .map_err(|e| {
                ImplementationError::ParsingError(format!(
                    "Failed to parse `Signature-Input` header into sfv::Dictionary: {e}"
                ))
            })?;

        let mut signature_header = sfv::Parser::new(&unparsed_signature_header)
            .parse_dictionary()
            .map_err(|e| {
                ImplementationError::ParsingError(format!(
                    "Failed to parse `Signature` header into sfv::Dictionary: {e}"
                ))
            })?;

        let (label, innerlist) = signature_input
            .into_iter()
            .filter_map(|(label, listentry)| match listentry {
                sfv::ListEntry::InnerList(inner_list) => Some((label, inner_list)),
                sfv::ListEntry::Item(_) => None,
            })
            .find(pick)
            .ok_or(ImplementationError::ParsingError(
                "No matching label and signature base found".into(),
            ))?;

        let signature = match signature_header.shift_remove(&label).ok_or(
            ImplementationError::ParsingError("No matching signature found from label".into()),
        )? {
            sfv::ListEntry::Item(sfv::Item {
                bare_item,
                params: _,
            }) => match bare_item {
                sfv::GenericBareItem::ByteSequence(sequence) => sequence,
                other_type => {
                    return Err(ImplementationError::ParsingError(format!(
                        "Invalid type for signature found, expected byte sequence: {other_type:?}"
                    )));
                }
            },
            other_type @ sfv::ListEntry::InnerList(_) => {
                return Err(ImplementationError::ParsingError(format!(
                    "Invalid type for signature found, expected byte sequence: {other_type:?}"
                )));
            }
        };

        let builder = SignatureBaseBuilder::try_from(innerlist)?;
        let base = builder.into_signature_base(message)?;

        let algorithm = match alg {
            Some(algorithm) => algorithm,
            None => base
                .get_details()
                .algorithm
                .clone()
                .ok_or(ImplementationError::UnsupportedAlgorithm)?,
        };

        Ok(MessageVerifier {
            parsed: ParsedLabel { signature, base },
            algorithm,
        })
    }

    /// Retrieve the parsed `ParameterDetails` from the message. Useful for logging
    /// information about the message.
    pub fn get_details(&self) -> ParameterDetails {
        self.parsed.base.parameters.details.clone()
    }

    /// Verify the messsage, consuming the verifier in the process.
    /// If `key_id` is not supplied, a key ID to fetch the public key
    /// from `keyring` will be sourced from the `keyid` parameter
    /// within the message.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn verify(
        self,
        keyring: &KeyRing,
        key_id: Option<Thumbprint>,
    ) -> Result<(), ImplementationError> {
        let keying_material = (match key_id {
            Some(key) => keyring.get(&key),
            None => self
                .parsed
                .base
                .parameters
                .details
                .keyid
                .as_ref()
                .and_then(|key| keyring.get(key)),
        })
        .ok_or(ImplementationError::NoSuchKey)?;
        let (base_representation, _) = self.parsed.base.into_ascii()?;
        match self.algorithm {
            Algorithm::Ed25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let verifying_key = VerifyingKey::try_from(keying_material.as_slice())
                    .map_err(|_| ImplementationError::InvalidKeyLength)?;

                let sig = Signature::try_from(self.parsed.signature.as_slice())
                    .map_err(|_| ImplementationError::InvalidSignatureLength)?;

                verifying_key
                    .verify(base_representation.as_bytes(), &sig)
                    .map_err(|_| ImplementationError::FailedToVerify)
            }
        }
    }

    /// Whether or not this message is expired, based on its `expires` value.
    pub fn is_expired(&self) -> Option<bool> {
        self.parsed.base.is_expired()
    }
}

/// A trait that messages wishing to be verified as a `web-bot-auth` method specifically
/// must implement.
pub trait WebBotAuthSignedMessage: SignedMessage {
    /// Obtain the parsed version of `Signature-Agent` HTTP header
    fn fetch_signature_agent(&self) -> Option<String>;
}

/// A verifier for Web Bot Auth messages specifically.
#[derive(Debug)]
pub struct WebBotAuthVerifier {
    message_verifier: MessageVerifier,
    /// The value of `Signature-Agent` header, if resolved to a link
    key_directory: Option<String>,
}

impl WebBotAuthVerifier {
    /// Parse a message into a structure that is ready for verification against an
    /// external key with a suitable algorithm. If `alg` is not set, a default will
    /// be chosen from the `alg` parameter.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn parse(
        message: &impl WebBotAuthSignedMessage,
        algorithm: Option<Algorithm>,
    ) -> Result<Self, ImplementationError> {
        let signature_agent = match message.fetch_signature_agent() {
            Some(agent) => Some(sfv::Parser::new(&agent).parse_item().map_err(|e| {
                ImplementationError::ParsingError(format!(
                    "Failed to parse `Signature-Agent` into valid sfv::Item: {e}"
                ))
            })?),
            None => None,
        };

        let key_directory = signature_agent.and_then(|item| {
            item.bare_item
                .as_string()
                .filter(|link| {
                    link.as_str().starts_with("https") || link.as_str().starts_with("data")
                })
                .map(std::string::ToString::to_string)
        });

        let web_bot_auth_verifier = Self {
            message_verifier: MessageVerifier::parse(message, algorithm, |(_, innerlist)| {
                innerlist.params.contains_key("keyid")
                    && innerlist.params.contains_key("tag")
                    && innerlist.params.contains_key("expires")
                    && innerlist.params.contains_key("created")
                    && innerlist
                        .params
                        .get("tag")
                        .and_then(|tag| tag.as_string())
                        .is_some_and(|tag| tag.as_str() == "web-bot-auth")
                    && innerlist.items.iter().any(|item| {
                        *item == sfv::Item::new(sfv::StringRef::constant("@authority"))
                            || (key_directory.is_some()
                                && *item
                                    == sfv::Item::new(sfv::StringRef::constant("signature-agent")))
                    })
            })?,
            key_directory,
        };

        Ok(web_bot_auth_verifier)
    }

    /// Verify the messsage, consuming the verifier in the process.
    /// If `key_id` is not supplied, a key ID to fetch the public key
    /// from `keyring` will be sourced from the `keyid` parameter
    /// within the message. If `enforce_key_directory_lookup` is set,
    /// verification will attempt to follow the `Signature-Agent` header
    /// to ingest the JWK from an external directory. Note: we currently
    /// do not implement ingesting JWKs from an external directory.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn verify(
        self,
        keyring: &KeyRing,
        key_id: Option<Thumbprint>,
        enforce_key_directory_lookup: bool,
    ) -> Result<(), ImplementationError> {
        if (!enforce_key_directory_lookup && self.key_directory.is_some())
            || self.key_directory.is_none()
        {
            return self.message_verifier.verify(keyring, key_id);
        }

        Err(ImplementationError::WebBotAuth(
            WebBotAuthError::NotImplemented,
        ))
    }

    // Return details + whether or not a Signature Agent header was present
    pub fn get_details(&self) -> ParameterDetails {
        self.message_verifier.get_details()
    }

    /// Indicates whether or not the message has semantic errors
    /// that pose a security risk, such as whether or not the message
    /// is expired, the nonce is invalid, etc.
    pub fn possibly_insecure(&self) -> bool {
        self.message_verifier.is_expired().unwrap_or(false)

        // TODO: Validate nonce somehow
    }
}

#[cfg(test)]
mod tests {

    use components::{DerivedComponent, HTTPField, HTTPFieldParametersSet};
    use indexmap::IndexMap;

    use super::*;

    struct StandardTestVector {}

    impl SignedMessage for StandardTestVector {
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

    impl WebBotAuthSignedMessage for StandardTestVector {
        fn fetch_signature_agent(&self) -> Option<String> {
            None
        }
    }

    #[test]
    fn test_parsing_as_http_signature() {
        let test = StandardTestVector {};
        let verifier = MessageVerifier::parse(&test, None, |(_, _)| true).unwrap();
        let expected_signature_params = "(\"@authority\");created=1735689600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1735693200;nonce=\"gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==\";tag=\"web-bot-auth\"";
        let expected_base = format!(
            "\"@authority\": example.com\n\"@signature-params\": {expected_signature_params}"
        );
        let (base, signature_params) = verifier.parsed.base.into_ascii().unwrap();
        assert_eq!(base, expected_base.as_str());
        assert_eq!(signature_params, expected_signature_params);
    }

    #[test]
    fn test_verifying_as_http_signature() {
        let test = StandardTestVector {};
        let public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
            0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58,
            0x2b, 0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd,
            0xce, 0x43, 0xd1, 0xbb,
        ];
        let keyring: KeyRing = HashMap::from_iter([(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            public_key.to_vec(),
        )]);
        let verifier = MessageVerifier::parse(&test, None, |(_, _)| true).unwrap();
        assert!(verifier.verify(&keyring, None).is_ok());
    }

    #[test]
    fn test_verifying_as_web_bot_auth() {
        let test = StandardTestVector {};
        let public_key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
            0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58,
            0x2b, 0x23, 0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd,
            0xce, 0x43, 0xd1, 0xbb,
        ];
        let keyring: KeyRing = HashMap::from_iter([(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            public_key.to_vec(),
        )]);
        let verifier = WebBotAuthVerifier::parse(&test, None).unwrap();
        // Since the expiry date is in the past.
        assert!(verifier.possibly_insecure());
        assert!(verifier.verify(&keyring, None, false).is_ok());
    }

    #[test]
    fn test_signing_then_verifying() {
        struct MyTest {
            signature_input: String,
            signature_header: String,
        }

        impl UnsignedMessage for MyTest {
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
            fn fetch_signature_header(&self) -> Option<String> {
                Some(self.signature_header.clone())
            }
            fn fetch_signature_input(&self) -> Option<String> {
                Some(self.signature_input.clone())
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
            fn fetch_signature_agent(&self) -> Option<String> {
                None
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

        let keyring: KeyRing = HashMap::from_iter([(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            public_key.to_vec(),
        )]);

        let signer = MessageSigner {
            algorithm: Algorithm::Ed25519,
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
                Duration::from_secs(10),
                &private_key.to_vec(),
            )
            .unwrap();

        let verifier = WebBotAuthVerifier::parse(&mytest, None).unwrap();
        assert!(!verifier.possibly_insecure());
        assert!(verifier.verify(&keyring, None, false).is_ok());
    }

    #[test]
    fn test_missing_tags_break_web_bot_auth() {
        struct MissingParametersTestVector {}

        impl SignedMessage for MissingParametersTestVector {
            fn fetch_signature_header(&self) -> Option<String> {
                Some("sig1=:uz2SAv+VIemw+Oo890bhYh6Xf5qZdLUgv6/PbiQfCFXcX/vt1A8Pf7OcgL2yUDUYXFtffNpkEr5W6dldqFrkDg==:".to_owned())
            }
            fn fetch_signature_input(&self) -> Option<String> {
                Some(r#"sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="gubxywVx7hzbYKatLgzuKDllDAIXAkz41PydU7aOY7vT+Mb3GJNxW0qD4zJ+IOQ1NVtg+BNbTCRUMt1Ojr5BgA==";tag="not-web-bot-auth""#.to_owned())
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
            fn fetch_signature_agent(&self) -> Option<String> {
                None
            }
        }

        let test = MissingParametersTestVector {};
        WebBotAuthVerifier::parse(&test, None).expect_err("This should not have parsed");
    }

    #[test]
    fn test_signing() {
        struct SigningTest {}
        impl UnsignedMessage for SigningTest {
            fn fetch_components_to_cover(&self) -> IndexMap<CoveredComponent, String> {
                IndexMap::from_iter([
                    (
                        CoveredComponent::Derived(DerivedComponent::Method { req: false }),
                        "POST".to_string(),
                    ),
                    (
                        CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
                        "example.com".to_string(),
                    ),
                    (
                        CoveredComponent::HTTP(HTTPField {
                            name: "content-length".to_string(),
                            parameters: HTTPFieldParametersSet(vec![]),
                        }),
                        "18".to_string(),
                    ),
                ])
            }

            fn register_header_contents(
                &mut self,
                _signature_input: String,
                _signature_header: String,
            ) {
            }
        }

        let signer = MessageSigner {
            algorithm: Algorithm::Ed25519,
            keyid: "test".into(),
            nonce: "another-test".into(),
            tag: "web-bot-auth".into(),
        };

        let private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH] = [
            0x9f, 0x83, 0x62, 0xf8, 0x7a, 0x48, 0x4a, 0x95, 0x4e, 0x6e, 0x74, 0x0c, 0x5b, 0x4c,
            0x0e, 0x84, 0x22, 0x91, 0x39, 0xa2, 0x0a, 0xa8, 0xab, 0x56, 0xff, 0x66, 0x58, 0x6f,
            0x6a, 0x7d, 0x29, 0xc5,
        ];

        let mut test = SigningTest {};

        assert!(
            signer
                .generate_signature_headers_content(
                    &mut test,
                    Duration::from_secs(10),
                    &private_key.to_vec()
                )
                .is_ok()
        );
    }

    #[test]
    fn signature_base_generates_the_expected_representation() {
        let sigbase = SignatureBase {
            components: IndexMap::from_iter([
                (
                    CoveredComponent::Derived(DerivedComponent::Method { req: false }),
                    "POST".to_string(),
                ),
                (
                    CoveredComponent::Derived(DerivedComponent::Authority { req: false }),
                    "example.com".to_string(),
                ),
                (
                    CoveredComponent::HTTP(HTTPField {
                        name: "content-length".to_string(),
                        parameters: HTTPFieldParametersSet(vec![]),
                    }),
                    "18".to_string(),
                ),
            ]),
            parameters: IndexMap::from_iter([
                (
                    sfv::Key::from_string("keyid".into()).unwrap(),
                    sfv::BareItem::String(sfv::String::from_string("test".to_string()).unwrap()),
                ),
                (
                    sfv::Key::from_string("created".into()).unwrap(),
                    sfv::BareItem::Integer(sfv::Integer::constant(1_618_884_473_i64)),
                ),
            ])
            .into(),
        };

        let expected_base = "\"@method\": POST\n\"@authority\": example.com\n\"content-length\": 18\n\"@signature-params\": (\"@method\" \"@authority\" \"content-length\");keyid=\"test\";created=1618884473";
        let (base, _) = sigbase.into_ascii().unwrap();
        assert_eq!(base, expected_base);
    }
}
