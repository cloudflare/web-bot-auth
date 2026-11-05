// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use std::io::Read;
use std::time::Duration;

use clap::Parser;
use log::{debug, error, info};
use reqwest::{
    Url,
    blocking::Client,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent, HTTPField},
    keyring::{JSONWebKeySet, KeyRing, Thumbprintable},
    message_signatures::{MessageVerifier, SignedMessage},
};

const MIME_TYPE: &str = "application/http-message-signatures-directory+json";
const WELL_KNOWN_PATH: &str = "/.well-known/http-message-signatures-directory";
const DEFAULT_USERAGENT: &str = "http-signature-directory-test-script/0.1.0";

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// URL pointing to your HTTP Message Signature JSON Web Key Set e.g. `https://example.com/.well-known/http-message-signatures-directory`
    url: String,
    /// Optional useragent that can be used to customize the useragent being sent to the server.
    #[arg (default_value_t = String::from(DEFAULT_USERAGENT))]
    user_agent: String,
}

#[derive(Serialize, Deserialize)]
struct ValidationResult {
    success: bool,
    message: String,
    details: ValidationDetails,
}

#[derive(Serialize, Deserialize)]
struct ValidationDetails {
    url: String,
    keys_count: usize,
    validated_keys: Vec<KeyValidationInfo>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct KeyValidationInfo {
    thumbprint: String,
    valid: bool, // Checks if the key structure is valid (correct key type, curve is Ed25519, import succeeds)
    signature_verified: bool, // Checks if the HTTP signature on the directory response is cryptographically valid using this key
    raw_key_data: Option<RawKeyData>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RawKeyData {
    kty: String,
    crv: String,
    x: String,
}

struct SignedDirectory<'a> {
    headers: &'a reqwest::header::HeaderMap,
    authority: String,
}

impl SignedMessage for SignedDirectory<'_> {
    fn lookup_component(&self, name: &CoveredComponent) -> Vec<String> {
        match name {
            CoveredComponent::Derived(DerivedComponent::Authority { req: true }) => {
                debug!(
                    "Resolved {} for derived component {:?}",
                    self.authority, name
                );

                vec![self.authority.clone()]
            }
            CoveredComponent::Derived(DerivedComponent::Authority { req: false }) => {
                error!(
                    "You are signing a plain `@authority` without the `req` component parameter. Fix by signing with `req` so that Signature-Input uses `\"@authority\";req` instead",
                );
                vec![]
            }
            CoveredComponent::HTTP(HTTPField { name, .. }) => {
                if let Some(header) = self.headers.get(name)
                    && let Ok(value) = header.to_str()
                {
                    debug!("Found {} for header {}", value, name);
                    return vec![String::from(value)];
                }

                debug!("No value for header {:?} found", name);
                vec![]
            }
            _ => vec![],
        }
    }
}

fn fetch_directory(
    client: &Client,
    url: &Url,
    user_agent: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let get = |url: Url| {
        client
            .get(url)
            .header(ACCEPT, MIME_TYPE)
            .header(USER_AGENT, user_agent)
            .send()
    };
    if url.path() == "/" {
        let mut directory = url.clone();
        directory.set_path(WELL_KNOWN_PATH);
        directory.set_query(None);
        let response = get(directory)?;
        if response.status() != reqwest::StatusCode::NOT_FOUND
            && response.status() != reqwest::StatusCode::GONE
        {
            return Ok(response);
        }
    }
    get(url.clone())
}

fn parse_jwks(body: &[u8], well_known: bool) -> Result<JSONWebKeySet, String> {
    if body.len() > 64_000 {
        return Err("directory response is too large".into());
    }
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let jwks: JSONWebKeySet = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if jwks.keys.len() > 100 {
        return Err("directory contains too many keys".into());
    }
    if well_known && let Some(keys) = value.get("keys").and_then(serde_json::Value::as_array) {
        for (raw, key) in keys.iter().zip(&jwks.keys) {
            if let Some(kid) = raw.get("kid")
                && kid.as_str() != Some(key.b64_thumbprint().as_str())
            {
                return Err("well-known JWK kid must match its thumbprint".into());
            }
        }
    }
    Ok(jwks)
}

impl SignedDirectory<'_> {
    fn verify(&self, body: &[u8], keyid: &str, keyring: &KeyRing) -> Result<(), String> {
        let digests = self
            .headers
            .get("content-digest")
            .ok_or("missing Content-Digest")?
            .to_str()
            .map_err(|e| e.to_string())?;
        let dictionary = sfv::Parser::new(digests)
            .parse_dictionary::<sfv::Dictionary>()
            .map_err(|e| e.to_string())?;
        let Some(sfv::ListEntry::Item(sfv::Item {
            bare_item: sfv::BareItem::ByteSequence(digest),
            ..
        })) = dictionary.get("sha-256")
        else {
            return Err("missing SHA-256 Content-Digest".into());
        };
        if digest.as_slice() != Sha256::digest(body).as_slice() {
            return Err("directory Content-Digest mismatch".into());
        }
        let verifier = MessageVerifier::parse(self, |(_, input)| {
            input
                .params
                .get("keyid")
                .and_then(sfv::BareItem::as_string)
                .is_some_and(|id| id.as_str() == keyid)
                && input
                    .params
                    .get("tag")
                    .and_then(sfv::BareItem::as_string)
                    .is_some_and(|tag| tag.as_str() == "http-message-signatures-directory")
                && input.items.iter().any(|item| {
                    item.bare_item
                        .as_string()
                        .is_some_and(|s| s.as_str() == "@authority")
                        && item.params.len() == 1
                        && item.params.get("req") == Some(&sfv::BareItem::Boolean(true))
                })
                && input.items.iter().any(|item| {
                    item.bare_item
                        .as_string()
                        .is_some_and(|s| s.as_str() == "content-digest")
                        && item.params.is_empty()
                })
        })
        .map_err(|e| e.to_string())?;
        let advisory = verifier
            .parsed
            .base
            .parameters
            .details
            .possibly_insecure(|_| false);
        if advisory.is_expired.unwrap_or(true) || advisory.is_created_in_future.unwrap_or(true) {
            return Err("directory proof is outside its validity window".into());
        }
        verifier.verify(keyring, None).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn report_failure(url: &str, warnings: &[String], message: String) -> String {
    let result = ValidationResult {
        success: false,
        message: message.clone(),
        details: ValidationDetails {
            url: url.to_string(),
            keys_count: 0,
            validated_keys: vec![],
            errors: vec![message.clone()],
            warnings: warnings.to_vec(),
        },
    };
    eprintln!("{}", serde_json::to_string_pretty(&result).unwrap());
    message
}

fn main() -> Result<(), String> {
    env_logger::init();
    let cli = Cli::parse();

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut validated_keys = Vec::new();

    // Parse and validate URL
    let url = match Url::parse(cli.url.as_str()) {
        Ok(url) => url,
        Err(error) => {
            let error_msg = format!("URL parsing error: {:?}", error);
            report_failure(&cli.url, &warnings, error_msg);
            return Err("URL parsing failed".to_string());
        }
    };

    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(report_failure(
            &cli.url,
            &warnings,
            "URL must use HTTPS without credentials or a fragment".to_string(),
        ));
    }

    let authority = url.authority();
    debug!(
        "Assumed the following @authority component: {:?}",
        authority
    );

    // Fetch the directory
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| report_failure(&cli.url, &warnings, e.to_string()))?;
    let response = match fetch_directory(&client, &url, &cli.user_agent) {
        Ok(response) => response,
        Err(error) => {
            let error_msg = format!("Fetch error: {:?}", error);
            report_failure(&cli.url, &warnings, error_msg);
            return Err("Fetch failed".to_string());
        }
    };

    if response.status() != reqwest::StatusCode::OK {
        return Err(report_failure(
            &cli.url,
            &warnings,
            format!("discovery returned HTTP {}", response.status()),
        ));
    }
    let resolved_url = response.url().clone();
    let well_known = resolved_url.path() == WELL_KNOWN_PATH;
    if !well_known {
        warnings.push(format!(
            "JWK Set is not served at '{WELL_KNOWN_PATH}'; key possession proofs were not checked"
        ));
    }
    if well_known
        && !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(MIME_TYPE))
    {
        return Err(report_failure(
            resolved_url.as_str(),
            &warnings,
            "invalid well-known directory media type".into(),
        ));
    }

    let headers = response.headers().clone();

    // Extract signature headers
    let signature_headers: Vec<String> = headers
        .get_all("Signature")
        .iter()
        .filter_map(|header| header.to_str().map(String::from).ok())
        .collect();

    debug!(
        "Found the following Signature headers: {:?}",
        signature_headers
    );

    let signature_inputs: Vec<String> = headers
        .get_all("Signature-Input")
        .iter()
        .filter_map(|header| header.to_str().map(String::from).ok())
        .collect();

    debug!(
        "Found the following Signature-Input headers: {:?}",
        signature_inputs
    );

    let mut body = Vec::new();
    let body_text = match response.take(64_001).read_to_end(&mut body) {
        Ok(_) => String::from_utf8(body)
            .map_err(|e| report_failure(resolved_url.as_str(), &warnings, e.to_string()))?,
        Err(err) => {
            let error_msg = format!("Failed to read response body: {:?}", err);
            report_failure(&cli.url, &warnings, error_msg);
            return Err("Body read failed".to_string());
        }
    };

    // Parse JSON Web Key Set
    let json_web_key_set = match parse_jwks(body_text.as_bytes(), well_known) {
        Ok(jwks) => jwks,
        Err(error) => {
            let error_msg = format!("Failed to parse content as JSON web key set: {:?}", error);
            report_failure(&cli.url, &warnings, error_msg);
            eprintln!("This was the data the server sent back:");
            eprintln!("--- RAW RESPONSE BODY START ---");
            println!("{}", body_text);
            eprintln!("--- RAW RESPONSE BODY END ---");
            return Err("JSON parsing failed".to_string());
        }
    };

    if json_web_key_set.keys.is_empty() {
        errors.push("Empty JSON web key set".to_string());
    }

    // Import keys and validate
    let mut keyring = KeyRing::default();
    let import_errors = keyring.import_jwks(json_web_key_set.clone());

    for (index, key) in json_web_key_set.keys.iter().enumerate() {
        let thumbprint = key.b64_thumbprint();
        info!("Analyzing key with thumbprint {}", thumbprint);

        let mut key_info = KeyValidationInfo {
            thumbprint: thumbprint.clone(),
            valid: false,
            signature_verified: false,
            raw_key_data: None,
            error: None,
        };

        if let Thumbprintable::OKP { crv, x } = key {
            if *crv == "Ed25519" {
                info!("Key was identified as an Ed25519 key");
                key_info.valid = true;

                let import_error = import_errors.get(index).and_then(|opt| opt.as_ref());
                match import_error {
                    Some(err) => {
                        key_info.error = Some(format!(
                            "Could not import key with encoded public key {}, encountered error {:?}",
                            x, err
                        ));
                        key_info.valid = false;
                    }
                    None => {
                        // Key imported successfully, now verify signature
                        let directory = SignedDirectory {
                            headers: &headers,
                            authority: String::from(authority),
                        };

                        let proof = if well_known {
                            directory.verify(body_text.as_bytes(), &thumbprint, &keyring)
                        } else {
                            Ok(())
                        };
                        match proof {
                            Ok(()) => {
                                key_info.signature_verified = well_known;
                                key_info.raw_key_data = Some(RawKeyData {
                                    kty: "OKP".into(),
                                    crv: crv.clone(),
                                    x: x.clone(),
                                });
                            }
                            Err(error) => key_info.error = Some(error.to_string()),
                        }
                    }
                }
            } else {
                key_info.error = Some(format!("Unsupported curve: {}", crv));
            }
        } else {
            key_info.error = Some("Unsupported key type".to_string());
        }

        validated_keys.push(key_info);
    }

    // Collect validation errors
    for key in &validated_keys {
        if let Some(ref error) = key.error {
            errors.push(format!("Key {}: {}", key.thumbprint, error));
        }
    }

    let success =
        errors.is_empty() && !validated_keys.is_empty() && validated_keys.iter().all(|k| k.valid);
    let message = if success {
        "HTTP signature directory is valid!".to_string()
    } else {
        format!("Validation failed with {} errors", errors.len())
    };

    // Output result
    let result = ValidationResult {
        success,
        message,
        details: ValidationDetails {
            url: resolved_url.to_string(),
            keys_count: json_web_key_set.keys.len(),
            validated_keys,
            errors,
            warnings,
        },
    };

    let output = serde_json::to_string_pretty(&result).unwrap();
    if success {
        println!("{}", output);
    } else {
        eprintln!("{}", output);
    }

    if success {
        Ok(())
    } else {
        Err("Validation failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn server(statuses: Vec<u16>) -> (Url, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for status in statuses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                requests.push(first);
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                )
                .unwrap();
            }
            requests
        });
        (url, handle)
    }

    #[test]
    fn discovery_falls_back_only_for_absent_origin_directories() {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for (path, status, expected) in [
            ("/?version=1", 200, vec![WELL_KNOWN_PATH]),
            ("/?version=1", 404, vec![WELL_KNOWN_PATH, "/?version=1"]),
            ("/", 410, vec![WELL_KNOWN_PATH, "/"]),
            ("/", 302, vec![WELL_KNOWN_PATH]),
            ("/", 503, vec![WELL_KNOWN_PATH]),
            ("/jwks.json?v=1", 404, vec!["/jwks.json?v=1"]),
        ] {
            let statuses = if expected.len() == 2 {
                vec![status, 200]
            } else {
                vec![status]
            };
            let (url, server) = server(statuses);
            let url = url.join(path).unwrap();
            let response = fetch_directory(&client, &url, DEFAULT_USERAGENT).unwrap();
            assert_eq!(
                response.status().as_u16(),
                if expected.len() == 2 { 200 } else { status }
            );
            let requests = server.join().unwrap();
            assert_eq!(
                requests,
                expected
                    .iter()
                    .map(|path| format!("GET {path} HTTP/1.1\r\n"))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn validates_well_known_proofs_and_allows_ordinary_jwks_labels() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/web-bot-auth/test/test_data/web_bot_auth_directory_response_v1.json"
        ))
        .unwrap();
        let response = &vectors[0]["response"];
        let body = response["body"].as_str().unwrap().as_bytes();
        let keys = parse_jwks(body, true).unwrap();
        let keyid = keys.keys[0].b64_thumbprint();
        let mut keyring = KeyRing::default();
        keyring.import_jwks(keys);
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in response["headers"].as_object().unwrap() {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.as_str().unwrap().parse().unwrap(),
            );
        }
        let directory = SignedDirectory {
            headers: &headers,
            authority: "signature-agent.test".into(),
        };
        directory.verify(body, &keyid, &keyring).unwrap();
        assert!(directory.verify(b"altered body", &keyid, &keyring).is_err());
        headers.remove("Signature");
        assert!(
            SignedDirectory {
                headers: &headers,
                authority: "signature-agent.test".into()
            }
            .verify(body, &keyid, &keyring)
            .is_err()
        );
        let mut value: serde_json::Value = serde_json::from_slice(body).unwrap();
        value["keys"][0]["kid"] = serde_json::json!("operator-label");
        let body = serde_json::to_vec(&value).unwrap();
        assert!(parse_jwks(&body, false).is_ok());
        assert!(parse_jwks(&body, true).is_err());
    }
}
