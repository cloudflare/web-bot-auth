use super::ImplementationError;
use crate::components::{self, CoveredComponent, HTTPField};
use crate::keyring::{Algorithm, KeyRing};
use indexmap::IndexMap;
use regex::bytes::Regex;
use sfv::SerializeValue;
use std::fmt::Write as _;
use std::sync::LazyLock;
use time::{Duration, UtcDateTime};
static OBSOLETE_LINE_FOLDING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s*\r\n\s+").unwrap());

/// The component parameters associated with the signature in `Signature-Input`
#[derive(Clone, Debug)]
pub struct SignatureParams {
    /// The raw signature parameters associated with this request.
    pub raw: sfv::Parameters,
    /// Standard values obtained from the component parameters, such as created, etc.
    pub details: ParameterDetails,
}

/// Parsed values from `Signature-Input` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterDetails {
    /// The value of the `alg` parameter, if present and resolves to a known algorithm.
    pub algorithm: Option<Algorithm>,
    /// The value of the `created` parameter, if present.
    pub created: Option<i64>,
    /// The value of the `expires` parameter, if present.
    pub expires: Option<i64>,
    /// The value of the `keyid` parameter, if present.
    pub keyid: Option<String>,
    /// The value of the `nonce` parameter, if present.
    pub nonce: Option<String>,
    /// The value of the `tag` parameter,if present.
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
                            "rsa-pss-sha512" => Some(Algorithm::RsaPssSha512),
                            "rsa-v1_5-sha256" => Some(Algorithm::RsaV1_5Sha256),
                            "hmac-sha256" => Some(Algorithm::HmacSha256),
                            "ecdsa-p256-sha256" => Some(Algorithm::EcdsaP256Sha256),
                            "ecdsa-p384-sha384" => Some(Algorithm::EcdsaP384Sha384),
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

/// Advises whether or not to accept the message as valid prior to
/// verification, based on a cursory examination of the message parameters.
pub struct SecurityAdvisory {
    /// If the `expires` tag was present on the message, whether or not
    /// the message expired in the past.
    pub is_expired: Option<bool>,
    /// If the `nonce` tag was present on the message, whether or not
    /// the nonce was valid, as judged py a suitable nonce validator.
    pub nonce_is_invalid: Option<bool>,
}

impl ParameterDetails {
    /// Indicates whether or not the message has semantic errors
    /// that suggest the message should not be verified on account of posing
    /// a security risk. `nonce_validator` should return `true` if the nonce is
    /// invalid, and `false` otherwise.
    pub fn possibly_insecure<F>(&self, nonce_validator: F) -> SecurityAdvisory
    where
        F: FnOnce(&String) -> bool,
    {
        SecurityAdvisory {
            is_expired: self.expires.map(|expires| {
                if let Ok(expiry) = UtcDateTime::from_unix_timestamp(expires) {
                    let now = UtcDateTime::now();
                    return now >= expiry;
                }

                true
            }),
            nonce_is_invalid: self.nonce.as_ref().map(nonce_validator),
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
                        v if v.len() == 1 => Ok((component, v[0].to_owned())),
                        v if v.len() > 1 && matches!(component, CoveredComponent::HTTP(_)) => {
                            let mut register: Vec<String> = vec![];

                            for header_value in v.into_iter() {
                                register.push(
                                    // replace leading / trailing whitespace and obsolete line folding,
                                    // per HTTP message signature spec
                                    String::from_utf8(
                                        OBSOLETE_LINE_FOLDING
                                            .replace_all(header_value.as_bytes().trim_ascii(), b" ")
                                            .into_owned(),
                                    )
                                    .map_err(|_| ImplementationError::NonAsciiContentFound)?,
                                );
                            }

                            Ok((component, register.join(", ")))
                        }
                        _ => Err(ImplementationError::LookupError(component)),
                    })
                    .collect::<Result<Vec<(CoveredComponent, String)>, ImplementationError>>()?,
            ),
            parameters: self.parameters,
        })
    }
}

/// A representation of the signature base to be generated during verification and signing.
#[derive(Clone, Debug)]
pub struct SignatureBase {
    /// The components that have been covered and their found values
    pub components: IndexMap<CoveredComponent, String>,
    /// The component parameters associated with this message.
    pub parameters: SignatureParams,
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
}

/// Trait that messages seeking verification should implement to facilitate looking up
/// raw values from the underlying message.
pub trait SignedMessage {
    /// Retrieve the raw value(s) of a covered component. Implementations should
    /// respect any parameter values set on the covered component per the message
    /// signature spec. Component values that cannot be found must return an empty vector.
    /// `CoveredComponent::HTTP` fields are guaranteed to have lowercase ASCII names, so
    /// care should be taken to ensure HTTP field names in the message are checked in a
    /// case-insensitive way. Only `CoveredComponent::Http` should return a vector with
    /// more than one element.
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String>;
}

/// Trait that messages seeking signing should implement to generate `Signature-Input`
/// and `Signature` header contents.
pub trait UnsignedMessage {
    /// Obtain a list of covered components to be included. HTTP fields must be lowercased before
    /// emitting. It is NOT RECOMMENDED to include `signature` and `signature-input` fields here.
    /// If signing a Web Bot Auth message, and `Signature-Agent` header is intended present, you MUST
    /// include it as a component here for successful verification.
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
    /// Returns an error if the algorithm chosen is not supported by this library.
    pub fn generate_signature_headers_content(
        &self,
        message: &mut impl UnsignedMessage,
        expires: Duration,
        algorithm: Algorithm,
        signing_key: &Vec<u8>,
    ) -> Result<(), ImplementationError> {
        let components_to_cover = message.fetch_components_to_cover();
        let mut sfv_parameters = sfv::Parameters::new();

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

        let created = UtcDateTime::now();
        let expiry = created + expires;

        sfv_parameters.insert(
            sfv::KeyRef::constant("created").to_owned(),
            sfv::BareItem::Integer(sfv::Integer::constant(created.unix_timestamp())),
        );

        sfv_parameters.insert(
            sfv::KeyRef::constant("expires").to_owned(),
            sfv::BareItem::Integer(sfv::Integer::constant(expiry.unix_timestamp())),
        );

        let (signature_base, signature_params_content) = SignatureBase {
            components: components_to_cover,
            parameters: sfv_parameters.into(),
        }
        .into_ascii()?;

        let signature = match algorithm {
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
            other => return Err(ImplementationError::UnsupportedAlgorithm(other)),
        };

        message.register_header_contents(signature_params_content, signature);

        Ok(())
    }
}

/// A parsed representation of the signature and the components chosen to cover that
/// signature, once `MessageVerifier` has parsed the message. This allows inspection
/// of the chosen labl and its components.
#[derive(Clone, Debug)]
pub struct ParsedLabel {
    /// The label that was chosen.
    pub label: sfv::Key,
    /// The signature obtained from the message that verifiers will verify
    pub signature: Vec<u8>,
    /// The signature base obtained from the message, containining both the chosen
    /// components to cover as well as any interesting parameters of the same.
    pub base: SignatureBase,
}

/// A `MessageVerifier` performs the verifications needed for a signed message.
#[derive(Clone, Debug)]
pub struct MessageVerifier {
    /// Parsed version of the signature label chosen for this message.
    pub parsed: ParsedLabel,
}

/// Micro-measurements of different parts of the process in a call to `verify()`.
/// Useful for measuring overhead.
#[derive(Clone, Debug)]
pub struct SignatureTiming {
    /// Time taken to generate a signature base,
    pub generation: Duration,
    /// Time taken to execute cryptographic verification.
    pub verification: Duration,
}

impl MessageVerifier {
    /// Parse a message into a structure that is ready for verification against an
    /// external key with a suitable algorithm. `pick` is a predicate
    /// enabling you to choose which message label should be considered as the message to
    /// verify - if it is known only one signature is in the message, simply return true.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn parse<P>(message: &impl SignedMessage, pick: P) -> Result<Self, ImplementationError>
    where
        P: Fn(&(sfv::Key, sfv::InnerList)) -> bool,
    {
        let signature_input = message
            .lookup_component(&CoveredComponent::HTTP(HTTPField {
                name: "signature-input".to_string(),
                parameters: components::HTTPFieldParametersSet(vec![]),
            }))
            .into_iter()
            .filter_map(|sig_input| sfv::Parser::new(&sig_input).parse_dictionary().ok())
            .reduce(|mut acc, sig_input| {
                acc.extend(sig_input);
                acc
            })
            .ok_or(ImplementationError::ParsingError(
                "No validly-formatted `Signature-Input` headers found".to_string(),
            ))?;

        let mut signature_header = message
            .lookup_component(&CoveredComponent::HTTP(HTTPField {
                name: "signature".to_string(),
                parameters: components::HTTPFieldParametersSet(vec![]),
            }))
            .into_iter()
            .filter_map(|sig_input| sfv::Parser::new(&sig_input).parse_dictionary().ok())
            .reduce(|mut acc, sig_input| {
                acc.extend(sig_input);
                acc
            })
            .ok_or(ImplementationError::ParsingError(
                "No validly-formatted `Signature` headers found".to_string(),
            ))?;

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

        Ok(MessageVerifier {
            parsed: ParsedLabel {
                label,
                signature,
                base,
            },
        })
    }

    /// Verify the messsage, consuming the verifier in the process.
    /// If `key_id` is not supplied, a key ID to fetch the public key
    /// from `keyring` will be sourced from the `keyid` parameter
    /// within the message. Returns information about how long verification
    /// took if successful.
    ///
    /// # Errors
    ///
    /// Returns `ImplementationErrors` relevant to verifying and parsing.
    pub fn verify(
        self,
        keyring: &KeyRing,
        key_id: Option<String>,
    ) -> Result<SignatureTiming, ImplementationError> {
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
        let generation = UtcDateTime::now();
        let (base_representation, _) = self.parsed.base.into_ascii()?;
        let generation = UtcDateTime::now() - generation;
        match &keying_material.0 {
            Algorithm::Ed25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let verifying_key = VerifyingKey::try_from(keying_material.1.as_slice())
                    .map_err(|_| ImplementationError::InvalidKeyLength)?;

                let sig = Signature::try_from(self.parsed.signature.as_slice())
                    .map_err(|_| ImplementationError::InvalidSignatureLength)?;

                let verification = UtcDateTime::now();
                verifying_key
                    .verify(base_representation.as_bytes(), &sig)
                    .map_err(ImplementationError::FailedToVerify)
                    .map(|()| SignatureTiming {
                        generation,
                        verification: UtcDateTime::now() - verification,
                    })
            }
            other => Err(ImplementationError::UnsupportedAlgorithm(other.clone())),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::components::{DerivedComponent, HTTPField, HTTPFieldParametersSet};
    use indexmap::IndexMap;

    use super::*;

    struct StandardTestVector {}

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

    #[test]
    fn test_parsing_as_http_signature() {
        let test = StandardTestVector {};
        let verifier = MessageVerifier::parse(&test, |(_, _)| true).unwrap();
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
        let mut keyring = KeyRing::default();
        keyring.import_raw(
            "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            Algorithm::Ed25519,
            public_key.to_vec(),
        );
        let verifier = MessageVerifier::parse(&test, |(_, _)| true).unwrap();
        let timing = verifier.verify(&keyring, None).unwrap();
        assert!(timing.generation.whole_nanoseconds() > 0);
        assert!(timing.verification.whole_nanoseconds() > 0);
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
                    Duration::seconds(10),
                    Algorithm::Ed25519,
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
