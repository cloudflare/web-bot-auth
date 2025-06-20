// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use clap::Parser;
use log::{debug, info};
use reqwest::{
    Url,
    blocking::Client,
    header::{ACCEPT, CONTENT_TYPE},
};
use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent},
    keyring::{JSONWebKeySet, KeyRing, Thumbprintable},
    message_signatures::{MessageVerifier, SignedMessage},
};

const MIME_TYPE: &str = "application/http-message-signatures-directory+json";

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// URL pointing to your HTTP Message Signature JSON Web Key Set e.g. `https://example.com/.well-known/http-message-signatures-directory`
    url: String,
}

struct SignedDirectory {
    signature: Vec<String>,
    input: Vec<String>,
    authority: String,
}

impl SignedMessage for SignedDirectory {
    fn fetch_all_signature_headers(&self) -> Vec<String> {
        self.signature.clone()
    }
    fn fetch_all_signature_inputs(&self) -> Vec<String> {
        self.input.clone()
    }
    fn lookup_component(&self, name: &CoveredComponent) -> Option<String> {
        match *name {
            CoveredComponent::Derived(DerivedComponent::Authority { .. }) => {
                Some(self.authority.clone())
            }
            _ => None,
        }
    }
}

fn main() -> Result<(), String> {
    env_logger::init();
    let cli = Cli::parse();
    let url =
        Url::parse(cli.url.as_str()).map_err(|error| format!("URL parsing error: {:?}", error))?;

    if url.scheme() != "https" {
        return Err(String::from("URL must be an HTTPS URL"));
    }

    if url.path() != "/.well-known/http-message-signatures-directory" {
        return Err(String::from(
            "JSON web key set must be hosted on '/.well-known/http-message-signatures-directory'",
        ));
    }

    let authority = url.authority();

    debug!(
        "Extracted the following @authority component: {:?}",
        authority
    );

    let response = Client::new()
        .get(cli.url)
        .header(ACCEPT, MIME_TYPE)
        .send()
        .map_err(|error| format!("Fetch error: {:?}", error))?;

    if response
        .headers()
        .get(CONTENT_TYPE)
        .ok_or("No Content Type header found")?
        .as_bytes()
        != MIME_TYPE.as_bytes()
    {
        return Err(format!(
            "URL did not contain correct Content-Type of value `{}`",
            MIME_TYPE
        ));
    }

    let signature_headers: Vec<String> = response
        .headers()
        .get_all("Signature")
        .iter()
        .filter_map(|header| header.to_str().map(String::from).ok())
        .collect();

    debug!(
        "Found the following Signature headers: {:?}",
        signature_headers
    );

    let signature_inputs: Vec<String> = response
        .headers()
        .get_all("Signature-Input")
        .iter()
        .filter_map(|header| header.to_str().map(String::from).ok())
        .collect();

    debug!(
        "Found the following Signature-Input headers: {:?}",
        signature_inputs
    );

    let json_web_key_set: JSONWebKeySet = response
        .json()
        .map_err(|error| format!("Failed to parse content as JSON web key set: {:?}", error))?;

    if json_web_key_set.keys.is_empty() {
        return Err(String::from("Empty JSON web key set"));
    }

    let mut keyring = KeyRing::default();
    let import_errors = keyring.import_jwks(json_web_key_set.clone());

    for (index, key) in json_web_key_set.keys.iter().enumerate() {
        let thumbprint = key.b64_thumbprint();
        info!("Analyzing key with thumbprint {}", thumbprint);
        if let Thumbprintable::OKP { crv, x } = key {
            if *crv == "Ed25519" {
                info!("Key was identified as an Ed25519 key");
                let import_error = import_errors.get(index).ok_or(format!(
                    "Could not import key with encoded public key {}",
                    x
                ))?;
                if let Some(err) = import_error {
                    return Err(format!(
                        "Could not import key with encoded public key {}, encountered error {:?}",
                        x, err
                    ));
                }
                let directory = SignedDirectory {
                    signature: signature_headers.clone(),
                    input: signature_inputs.clone(),
                    authority: String::from(authority),
                };

                let verifier = MessageVerifier::parse(
                    &directory,
                    |(_, innerlist)| {
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
                                *item == sfv::Item::new(sfv::StringRef::constant("@authority"))
                            })
                    },
                )
                .map_err(|error| {
                    format!(
                        "Failed to match a valid signature / signature-input for thumbprint {} and public key {}: {:?}",
                        thumbprint, x, error
                    )
                })?;

                let advisory = verifier.get_details().possibly_insecure(|_| false);
                // Since the expiry date is in the past.
                if advisory.is_expired.unwrap_or(true) {
                    return Err(String::from(
                        "Signature for key with public key {} is expired",
                    ));
                }
                if let Err(err) = verifier.verify(&keyring, None) {
                    return Err(format!("Failed to verify: {:?}", err));
                }
            }
        }
    }

    println!("HTTP signature directory is valid!");

    Ok(())
}
