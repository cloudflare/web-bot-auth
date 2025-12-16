use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use indexmap::map::IndexMap;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::Duration;
use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParametersSet},
    keyring::{Algorithm, Thumbprintable},
    message_signatures::{MessageSigner, UnsignedMessage},
};
use worker::*;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct SignatureAgentCard {
    client_name: String,
    contacts: Vec<String>,
    keys: Vec<Thumbprintable>,
}

struct SignatureHeaderGenerator<'a> {
    req: &'a HttpRequest,
    digest_header: String,
    outputs: (String, String),
}

impl UnsignedMessage for SignatureHeaderGenerator<'_> {
    fn fetch_components_to_cover(
        &self,
    ) -> IndexMap<web_bot_auth::components::CoveredComponent, String> {
        IndexMap::from_iter([
            (
                CoveredComponent::Derived(DerivedComponent::Authority { req: true }),
                self.req.uri().host().unwrap().to_string(),
            ),
            (
                CoveredComponent::HTTP(HTTPField {
                    name: "content-digest".to_string(),
                    parameters: HTTPFieldParametersSet(vec![]),
                }),
                self.digest_header.clone(),
            ),
        ])
    }

    fn register_header_contents(&mut self, signature_input: String, signature_header: String) {
        self.outputs = (
            format!("sig1={}", signature_input),
            format!("sig1={}", signature_header),
        )
    }
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<Response> {
    let kv = env.kv("signed-agent-registry-hostnames")?;
    let host = req.uri().host().ok_or(worker::Error::RouteNoDataError)?;

    match req.uri().path() {
        "/" => {
            println!("got here");
            let list = kv.list().limit(1000).execute().await?;
            Response::ok(
                list.keys
                    .into_iter()
                    .map(|key| format!("https://{}", key.name.clone()))
                    .collect::<Vec<String>>()
                    .join("\n"),
            )
        }
        "/.well-known/http-message-signatures-directory" => {
            // Safe to use `seed_from_u64` even though it is marked not for crypto use -
            // we don't care about generated keypairs or nonces - we will literally never use them
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1234_u64);

            let vectorized_keypair: Vec<u8> = match kv.get(host).bytes().await? {
                Some(pair) => pair,
                None => {
                    let signing_key: SigningKey = SigningKey::generate(&mut rng);
                    let keypair = signing_key.to_keypair_bytes().to_vec();
                    kv.put_bytes(host, &keypair)?.execute().await?;
                    keypair
                }
            };

            let keypair_bytes: [u8; 64_usize] = vectorized_keypair
                .try_into()
                .expect("Vec length must match array length");

            let signing_key = SigningKey::from_keypair_bytes(&keypair_bytes)
                .map_err(|e| worker::Error::RustError(e.to_string()))?;

            let verifying_key = signing_key.verifying_key();
            let thumbprintable = Thumbprintable::OKP {
                crv: "Ed25519".to_string(),
                x: general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
            };
            let thumbprint = thumbprintable.b64_thumbprint();

            let card = SignatureAgentCard {
                client_name: host.to_string(),
                contacts: vec!["test@example.com".to_string()],
                keys: vec![thumbprintable],
            };

            let body = serde_json::to_string(&card)
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
            let mut hasher = Sha256::new();
            hasher.update(&body);
            let digest_header = format!(
                "sha-256=:{}=",
                general_purpose::STANDARD.encode(hasher.finalize())
            );

            let mut generator = SignatureHeaderGenerator {
                req: &req,
                digest_header: digest_header.clone(),
                outputs: (String::new(), String::new()),
            };

            let mut nonce: [u8; 64] = [0; 64];
            rng.fill_bytes(&mut nonce);

            let signer = MessageSigner {
                keyid: thumbprint.into(),
                nonce: general_purpose::STANDARD.encode(nonce).into(),
                tag: "http-message-signatures-directory".into(),
            };

            println!("I got here");

            signer
                .generate_signature_headers_content(
                    &mut generator,
                    Duration::seconds(10),
                    Algorithm::Ed25519,
                    &(signing_key.as_bytes().to_vec()),
                )
                .unwrap();

            let (signature_input, signature_header) = generator.outputs.clone();

            let mut response = Response::from_body(ResponseBody::Body(body.into_bytes()))?;
            let headers = response.headers_mut();
            headers.set("content-digest", &digest_header)?;
            headers.set(
                "content-type",
                "application/http-message-signatures-directory+json",
            )?;
            headers.set("signature-input", &signature_input)?;
            headers.set("signature", &signature_header)?;
            Ok(response)
        }
        _ => Ok(Response::empty()?),
    }
}
