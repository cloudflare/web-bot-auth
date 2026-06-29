use serde::{Deserialize, Serialize};

use crate::keyring::JSONWebKeySet;

/// Errors returned while parsing registry-related documents and headers.
#[derive(Debug)]
pub enum RegistryError {
    /// Structured Fields parsing failed.
    StructuredFields(sfv::Error),
    /// JSON parsing failed.
    Json(serde_json::Error),
    /// A field had an unsupported value.
    Invalid(String),
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegistryError::StructuredFields(error) => write!(f, "structured fields: {error}"),
            RegistryError::Json(error) => write!(f, "json: {error}"),
            RegistryError::Invalid(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            RegistryError::StructuredFields(error) => Some(error),
            RegistryError::Json(error) => Some(error),
            RegistryError::Invalid(_) => None,
        }
    }
}

/// Signature-Agent discovery type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAgentDiscoveryType {
    /// Resolve the well-known HTTP Message Signatures Directory.
    Directory,
    /// Resolve the member value as a direct JWK Set URI.
    JwksUri,
    /// Resolve the member value as a Client ID Metadata Document.
    Cimd,
}

/// One parsed `Signature-Agent` member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureAgentEntry {
    /// Dictionary member label. Empty only for legacy item syntax.
    pub label: String,
    /// Discovery URI.
    pub uri: String,
    /// Discovery type.
    #[serde(rename = "type")]
    pub discovery_type: SignatureAgentDiscoveryType,
}

/// Parsed `Signature-Agent` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureAgentHeader {
    /// Current sf-dictionary syntax.
    Current {
        /// Parsed entries.
        entries: Vec<SignatureAgentEntry>,
    },
    /// Legacy sf-item syntax.
    Legacy {
        /// Parsed entries.
        entries: Vec<SignatureAgentEntry>,
    },
}

impl SignatureAgentHeader {
    /// Returns parsed entries.
    #[must_use]
    pub fn entries(&self) -> &[SignatureAgentEntry] {
        match self {
            SignatureAgentHeader::Current { entries, .. }
            | SignatureAgentHeader::Legacy { entries, .. } => entries,
        }
    }
}

impl IntoIterator for SignatureAgentHeader {
    type Item = SignatureAgentEntry;
    type IntoIter = std::vec::IntoIter<SignatureAgentEntry>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SignatureAgentHeader::Current { entries }
            | SignatureAgentHeader::Legacy { entries } => entries.into_iter(),
        }
    }
}

/// Web Bot Auth-specific card metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct WebBotAuthMetadata {
    /// Expected User-Agent value or pattern.
    #[serde(
        rename = "expected-user-agent",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_user_agent: Option<String>,
    /// robots.txt product token.
    #[serde(
        rename = "rfc9309-product-token",
        skip_serializing_if = "Option::is_none"
    )]
    pub rfc9309_product_token: Option<String>,
    /// robots.txt directives supported by the agent.
    #[serde(rename = "rfc9309-compliance", skip_serializing_if = "Option::is_none")]
    pub rfc9309_compliance: Option<Vec<String>>,
    /// Agent trigger mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    /// Agent purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Content the agent targets.
    #[serde(rename = "targeted-content", skip_serializing_if = "Option::is_none")]
    pub targeted_content: Option<String>,
    /// Rate-control mechanism.
    #[serde(rename = "rate-control", skip_serializing_if = "Option::is_none")]
    pub rate_control: Option<String>,
    /// Expected request rate.
    #[serde(rename = "rate-expectation", skip_serializing_if = "Option::is_none")]
    pub rate_expectation: Option<String>,
    /// Known URLs the agent accesses.
    #[serde(rename = "known-urls", skip_serializing_if = "Option::is_none")]
    pub known_urls: Option<Vec<String>>,
    /// JAFAR IP list URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips_uri: Option<String>,
}

/// Signature Agent Card.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureAgentCard {
    /// Resolvable Signature Agent identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Human-readable client name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Client information URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    /// Client logo URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// Contact URIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    /// Remote JWK Set URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Inline JWK Set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JSONWebKeySet>,
    /// Web Bot Auth metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_bot_auth: Option<WebBotAuthMetadata>,
}

fn has_scheme(uri: &str, scheme: &str) -> bool {
    uri.strip_prefix(scheme)
        .is_some_and(|rest| !rest.is_empty())
}

fn valid_special_uri(uri: &str, scheme: &str) -> bool {
    has_scheme(uri, scheme) && !uri.chars().any(char::is_whitespace)
}

fn valid_http_uri(uri: &str, scheme: &str) -> bool {
    let Some(rest) = uri.strip_prefix(scheme) else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && !authority.chars().any(char::is_whitespace)
}

fn valid_uri_with_scheme(uri: &str, scheme: &str) -> bool {
    match scheme {
        "http://" | "https://" => valid_http_uri(uri, scheme),
        "data:" => valid_special_uri(uri, scheme),
        _ => false,
    }
}

fn has_any_scheme(uri: &str) -> bool {
    uri.split_once(':').is_some_and(|(scheme, rest)| {
        !scheme.is_empty() && !rest.is_empty() && !uri.chars().any(char::is_whitespace)
    })
}

fn validate_discovery_uri(
    uri: &str,
    discovery_type: &SignatureAgentDiscoveryType,
) -> Result<(), RegistryError> {
    match discovery_type {
        SignatureAgentDiscoveryType::Directory => {
            if valid_uri_with_scheme(uri, "https://") || valid_uri_with_scheme(uri, "http://") {
                Ok(())
            } else {
                Err(RegistryError::Invalid(
                    "directory Signature-Agent must use http or https".into(),
                ))
            }
        }
        SignatureAgentDiscoveryType::JwksUri | SignatureAgentDiscoveryType::Cimd => {
            if valid_uri_with_scheme(uri, "https://") {
                Ok(())
            } else {
                Err(RegistryError::Invalid(format!(
                    "{} Signature-Agent must use https",
                    discovery_type_name(discovery_type)
                )))
            }
        }
    }
}

fn discovery_type_name(discovery_type: &SignatureAgentDiscoveryType) -> &'static str {
    match discovery_type {
        SignatureAgentDiscoveryType::Directory => "directory",
        SignatureAgentDiscoveryType::JwksUri => "jwks_uri",
        SignatureAgentDiscoveryType::Cimd => "cimd",
    }
}

fn parse_discovery_type(
    value: Option<&sfv::BareItem>,
) -> Result<SignatureAgentDiscoveryType, RegistryError> {
    match value {
        None => Ok(SignatureAgentDiscoveryType::Directory),
        Some(item) => {
            let token = item.as_token().ok_or_else(|| {
                RegistryError::Invalid("Signature-Agent type must be a token".into())
            })?;
            match token.as_str() {
                "directory" => Ok(SignatureAgentDiscoveryType::Directory),
                "jwks_uri" => Ok(SignatureAgentDiscoveryType::JwksUri),
                "cimd" => Ok(SignatureAgentDiscoveryType::Cimd),
                other => Err(RegistryError::Invalid(format!(
                    "unsupported Signature-Agent type {other}"
                ))),
            }
        }
    }
}

/// Parses a `Signature-Agent` header value.
///
/// Legacy sf-string syntax is accepted and reported with a warning.
///
/// # Errors
///
/// Returns an error when both current and legacy parsing fail, or when a member
/// has an unsupported URI scheme or discovery type.
pub fn parse_signature_agent_header(header: &str) -> Result<SignatureAgentHeader, RegistryError> {
    match parse_signature_agent_dictionary(header) {
        Ok(entries) => Ok(SignatureAgentHeader::Current { entries }),
        Err(dictionary_error) => match parse_signature_agent_legacy(header) {
            Ok(entries) => Ok(SignatureAgentHeader::Legacy { entries }),
            Err(legacy_error) => Err(RegistryError::Invalid(format!(
                "failed to parse Signature-Agent header: {dictionary_error}; {legacy_error}"
            ))),
        },
    }
}

fn parse_signature_agent_dictionary(
    header: &str,
) -> Result<Vec<SignatureAgentEntry>, RegistryError> {
    let dictionary = sfv::Parser::new(header)
        .parse_dictionary::<sfv::Dictionary>()
        .map_err(RegistryError::StructuredFields)?;
    if dictionary.is_empty() {
        return Err(RegistryError::Invalid(
            "Signature-Agent header must not be empty".into(),
        ));
    }
    let mut entries = Vec::new();
    for (label, list_entry) in dictionary {
        let sfv::ListEntry::Item(item) = list_entry else {
            return Err(RegistryError::Invalid(
                "Signature-Agent entries must be items".into(),
            ));
        };
        let uri = item
            .bare_item
            .as_string()
            .ok_or_else(|| RegistryError::Invalid("Signature-Agent values must be strings".into()))?
            .as_str()
            .to_string();
        let discovery_type = parse_discovery_type(item.params.get("type"))?;
        validate_discovery_uri(&uri, &discovery_type)?;
        entries.push(SignatureAgentEntry {
            label: label.as_str().to_string(),
            uri,
            discovery_type,
        });
    }
    Ok(entries)
}

fn parse_signature_agent_legacy(header: &str) -> Result<Vec<SignatureAgentEntry>, RegistryError> {
    let item = sfv::Parser::new(header)
        .parse_item::<sfv::Item>()
        .map_err(RegistryError::StructuredFields)?;
    let uri = item
        .bare_item
        .as_string()
        .ok_or_else(|| RegistryError::Invalid("legacy Signature-Agent must be a string".into()))?
        .as_str()
        .to_string();
    validate_discovery_uri(&uri, &SignatureAgentDiscoveryType::Directory)?;
    Ok(vec![SignatureAgentEntry {
        label: String::new(),
        uri,
        discovery_type: SignatureAgentDiscoveryType::Directory,
    }])
}

fn strip_registry_comment(line: &str) -> &str {
    for (index, character) in line.char_indices() {
        if character == '#'
            && (index == 0
                || line[..index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace))
        {
            return line[..index].trim();
        }
    }
    line.trim()
}

/// Parses a registry body into Signature Agent Card URLs.
///
/// Inline cards are intentionally rejected.
///
/// # Errors
///
/// Returns an error when any non-empty registry line is not an HTTPS card URL.
pub fn parse_registry(registry: &str) -> Result<Vec<String>, RegistryError> {
    let mut entries = Vec::new();
    for (index, raw_line) in registry.lines().enumerate() {
        let line = strip_registry_comment(raw_line);
        if line.is_empty() {
            continue;
        }
        if has_scheme(line, "data:") {
            return Err(RegistryError::Invalid(
                "inline signature agent cards are not supported".into(),
            ));
        }
        if !valid_uri_with_scheme(line, "https://") {
            return Err(RegistryError::Invalid(format!(
                "registry line {}: registry entries must use https",
                index + 1
            )));
        }
        entries.push(line.to_string());
    }
    Ok(entries)
}

fn validate_optional_uri(
    value: Option<&String>,
    field: &str,
    schemes: &[&str],
) -> Result<(), RegistryError> {
    if let Some(uri) = value {
        if schemes
            .iter()
            .any(|scheme| valid_uri_with_scheme(uri, scheme))
        {
            return Ok(());
        }
        return Err(RegistryError::Invalid(format!(
            "{field} must use one of: {}",
            schemes.join(", ")
        )));
    }
    Ok(())
}

fn validate_contacts(contacts: Option<&Vec<String>>) -> Result<(), RegistryError> {
    if let Some(contacts) = contacts {
        for contact in contacts {
            if !has_any_scheme(contact) {
                return Err(RegistryError::Invalid("contacts must be URIs".into()));
            }
        }
    }
    Ok(())
}

fn validate_web_bot_auth(metadata: Option<&WebBotAuthMetadata>) -> Result<(), RegistryError> {
    if let Some(metadata) = metadata {
        if let Some(trigger) = &metadata.trigger
            && trigger != "fetcher"
            && trigger != "crawler"
        {
            return Err(RegistryError::Invalid(
                "trigger must be fetcher or crawler".into(),
            ));
        }
        validate_optional_uri(metadata.ips_uri.as_ref(), "ips_uri", &["https://"])?;
    }
    Ok(())
}

/// Parses and validates a Signature Agent Card JSON value.
///
/// # Errors
///
/// Returns an error if the card is malformed or violates draft constraints.
pub fn parse_signature_agent_card_value(
    value: serde_json::Value,
    card_url: Option<&str>,
) -> Result<SignatureAgentCard, RegistryError> {
    let card: SignatureAgentCard = serde_json::from_value(value).map_err(RegistryError::Json)?;
    validate_signature_agent_card(&card, card_url)?;
    Ok(card)
}

/// Parses and validates a Signature Agent Card JSON string.
///
/// # Errors
///
/// Returns an error if the card is malformed or violates draft constraints.
pub fn parse_signature_agent_card(
    json: &str,
    card_url: Option<&str>,
) -> Result<SignatureAgentCard, RegistryError> {
    let card: SignatureAgentCard = serde_json::from_str(json).map_err(RegistryError::Json)?;
    validate_signature_agent_card(&card, card_url)?;
    Ok(card)
}

fn validate_signature_agent_card(
    card: &SignatureAgentCard,
    card_url: Option<&str>,
) -> Result<(), RegistryError> {
    if card.client_id.is_none()
        && card.client_name.is_none()
        && card.client_uri.is_none()
        && card.logo_uri.is_none()
        && card.contacts.is_none()
        && card.jwks_uri.is_none()
        && card.jwks.is_none()
        && card.web_bot_auth.is_none()
    {
        return Err(RegistryError::Invalid(
            "signature agent card must contain at least one parameter".into(),
        ));
    }
    if card.jwks_uri.is_some() && card.jwks.is_some() {
        return Err(RegistryError::Invalid(
            "card must not contain both jwks and jwks_uri".into(),
        ));
    }
    if let (Some(expected), Some(actual)) = (card_url, &card.client_id)
        && expected != actual
    {
        return Err(RegistryError::Invalid(
            "client_id must match the card URL".into(),
        ));
    }

    validate_optional_uri(card.client_id.as_ref(), "client_id", &["https://"])?;
    validate_optional_uri(
        card.client_uri.as_ref(),
        "client_uri",
        &["http://", "https://"],
    )?;
    validate_optional_uri(
        card.logo_uri.as_ref(),
        "logo_uri",
        &["http://", "https://", "data:"],
    )?;
    validate_contacts(card.contacts.as_ref())?;
    validate_optional_uri(card.jwks_uri.as_ref(), "jwks_uri", &["https://"])?;
    validate_web_bot_auth(card.web_bot_auth.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct SignatureAgentVector {
        header: String,
        entries: Vec<SignatureAgentVectorEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct SignatureAgentVectorEntry {
        label: String,
        uri: String,
        #[serde(rename = "type")]
        discovery_type: SignatureAgentDiscoveryType,
    }

    #[derive(Debug, Deserialize)]
    struct RegistryVector {
        registry_txt: String,
        signature_agent_cards: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct CardVector {
        url: String,
        card: serde_json::Value,
        valid: bool,
        error: Option<String>,
    }

    #[test]
    fn parses_signature_agent_vectors() {
        let vectors: Vec<SignatureAgentVector> = serde_json::from_str(include_str!(
            "../../../packages/web-bot-auth/test/test_data/web_bot_auth_signature_agent_v1.json"
        ))
        .unwrap();

        for vector in vectors {
            let parsed = parse_signature_agent_header(&vector.header).unwrap();
            assert!(matches!(parsed, SignatureAgentHeader::Current { .. }));
            assert_eq!(parsed.entries().len(), vector.entries.len());
            for (actual, expected) in parsed.entries().iter().zip(vector.entries.iter()) {
                assert_eq!(actual.label, expected.label);
                assert_eq!(actual.uri, expected.uri);
                assert_eq!(actual.discovery_type, expected.discovery_type);
            }
        }
    }

    #[test]
    fn rejects_empty_signature_agent() {
        let error = parse_signature_agent_header("").unwrap_err().to_string();
        assert!(error.contains("must not be empty"));
    }

    #[test]
    fn accepts_legacy_signature_agent() {
        let parsed = parse_signature_agent_header("\"https://signature-agent.test\"").unwrap();
        assert!(matches!(parsed, SignatureAgentHeader::Legacy { .. }));
        assert_eq!(parsed.entries().len(), 1);
        assert_eq!(parsed.entries()[0].label, "");
        assert_eq!(parsed.entries()[0].uri, "https://signature-agent.test");
        assert_eq!(
            parsed.entries()[0].discovery_type,
            SignatureAgentDiscoveryType::Directory
        );
    }

    #[test]
    fn parses_registry_vectors() {
        let vectors: Vec<RegistryVector> = serde_json::from_str(include_str!(
            "../../../packages/web-bot-auth/test/test_data/web_bot_auth_registry_v1.json"
        ))
        .unwrap();

        for vector in vectors {
            assert_eq!(
                parse_registry(&vector.registry_txt).unwrap(),
                vector.signature_agent_cards
            );
        }
    }

    #[test]
    fn rejects_invalid_registry_vectors() {
        for (registry, expected_error) in [
            (
                "http://example.com/bot\n",
                "registry entries must use https",
            ),
            (
                "data:application/json,{\"client_name\":\"Inline Bot\"}\n",
                "inline signature agent cards are not supported",
            ),
        ] {
            let error = parse_registry(registry).unwrap_err().to_string();
            assert!(error.contains(expected_error));
        }
    }

    #[test]
    fn rejects_invalid_https_url() {
        let error = parse_registry("https://\n").unwrap_err().to_string();
        assert!(error.contains("registry entries must use https"));
    }

    #[test]
    fn validates_card_vectors() {
        let vectors: Vec<CardVector> = serde_json::from_str(include_str!(
            "../../../packages/web-bot-auth/test/test_data/web_bot_auth_signature_agent_card_v1.json"
        ))
        .unwrap();

        for vector in vectors {
            let parsed = parse_signature_agent_card_value(vector.card, Some(&vector.url));
            if vector.valid {
                parsed.unwrap();
            } else {
                let error = parsed.unwrap_err().to_string();
                assert!(error.contains(&vector.error.unwrap()));
            }
        }
    }
}
