// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use clap::Parser;
use log::{debug, error, info};
use reqwest::{
    Url,
    blocking::Client,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent, HTTPField},
    keyring::{JSONWebKeySet, KeyRing, Thumbprintable},
    message_signatures::{MessageVerifier, SignedMessage},
};

const MIME_TYPE: &str = "application/http-message-signatures-directory+json";
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
            let result = ValidationResult {
                success: false,
                message: error_msg.clone(),
                details: ValidationDetails {
                    url: cli.url.clone(),
                    keys_count: 0,
                    validated_keys: vec![],
                    errors: vec![error_msg.clone()],
                    warnings: vec![],
                },
            };
            eprintln!("{}", serde_json::to_string_pretty(&result).unwrap());
            return Err("URL parsing failed".to_string());
        }
    };

    if url.scheme() != "https" {
        errors.push("URL must be an HTTPS URL".to_string());
    }

    if url.path() != "/.well-known/http-message-signatures-directory" {
        warnings.push(
            "JSON web key set should be hosted on '/.well-known/http-message-signatures-directory'"
                .to_string(),
        );
    }

    let authority = url.authority();
    debug!(
        "Assumed the following @authority component: {:?}",
        authority
    );

    // Fetch the directory
    let response = match Client::new()
        .get(cli.url.clone())
        .header(ACCEPT, MIME_TYPE)
        .header(USER_AGENT, cli.user_agent)
        .send()
    {
        Ok(response) => response,
        Err(error) => {
            let error_msg = format!("Fetch error: {:?}", error);
            errors.push(error_msg.clone());
            let result = ValidationResult {
                success: false,
                message: error_msg,
                details: ValidationDetails {
                    url: cli.url.clone(),
                    keys_count: 0,
                    validated_keys: vec![],
                    errors,
                    warnings,
                },
            };
            eprintln!("{}", serde_json::to_string_pretty(&result).unwrap());
            return Err("Fetch failed".to_string());
        }
    };

    // Check content type
    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if content_type.as_bytes() != MIME_TYPE.as_bytes() {
            warnings.push(format!(
                "URL did not contain correct Content-Type of value `{}`, found: {:?}",
                MIME_TYPE, content_type
            ));
        }
    } else {
        warnings.push("No Content Type header found".to_string());
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

    let body_text = match response.text() {
        Ok(text) => text,
        Err(err) => {
            let error_msg = format!("Failed to read response body: {:?}", err);
            errors.push(error_msg.clone());
            let result = ValidationResult {
                success: false,
                message: error_msg.clone(),
                details: ValidationDetails {
                    url: cli.url.clone(),
                    keys_count: 0,
                    validated_keys: vec![],
                    errors,
                    warnings,
                },
            };
            eprintln!("{}", serde_json::to_string_pretty(&result).unwrap());
            return Err("Body read failed".to_string());
        }
    };

    // Parse JSON Web Key Set
    let json_web_key_set: JSONWebKeySet = match serde_json::from_str(&body_text) {
        Ok(jwks) => jwks,
        Err(error) => {
            let error_msg = format!("Failed to parse content as JSON web key set: {:?}", error);
            errors.push(error_msg.clone());
            let result = ValidationResult {
                success: false,
                message: error_msg,
                details: ValidationDetails {
                    url: cli.url.clone(),
                    keys_count: 0,
                    validated_keys: vec![],
                    errors,
                    warnings,
                },
            };
            eprintln!("{}", serde_json::to_string_pretty(&result).unwrap());
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

                        match MessageVerifier::parse(&directory, |(_, innerlist)| {
                            innerlist.params.contains_key("expires")
                                && innerlist.params.contains_key("created")
                                && innerlist
                                    .params
                                    .get("tag")
                                    .and_then(|tag| tag.as_string())
                                    .is_some_and(|tag| {
                                        tag.as_str() == "http-message-signatures-directory"
                                    })
                                && innerlist
                                    .params
                                    .get("keyid")
                                    .and_then(|tag| tag.as_string())
                                    .is_some_and(|tag| tag.as_str() == thumbprint)
                                && innerlist.items.iter().any(|item| {
                                    item.bare_item
                                        .as_string()
                                        .is_some_and(|s| (*s).as_str() == "@authority")
                                })
                        }) {
                            Ok(verifier) => {
                                let advisory = verifier
                                    .parsed
                                    .base
                                    .parameters
                                    .details
                                    .possibly_insecure(|_| false);

                                if advisory.is_expired.unwrap_or(true) {
                                    key_info.error = Some("Signature is expired".to_string());
                                }

                                match verifier.verify(&keyring, None) {
                                    Ok(_) => {
                                        key_info.signature_verified = true;
                                        key_info.raw_key_data = Some(RawKeyData {
                                            kty: "OKP".to_string(),
                                            crv: crv.to_string(),
                                            x: x.to_string(),
                                        });
                                    }
                                    Err(err) => {
                                        key_info.error = Some(format!(
                                            "Generated signature was incorrect, leading to verification failure, because: {:?}",
                                            err
                                        ));
                                    }
                                }
                            }
                            Err(err) => {
                                key_info.error =
                                    Some(format!("Failed to parse signature: {:?}", err));
                            }
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
            url: cli.url.clone(),
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
