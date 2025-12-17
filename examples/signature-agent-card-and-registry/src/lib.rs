use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;
use indexmap::map::IndexMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::Duration;
use web_bot_auth::{
    components::{CoveredComponent, DerivedComponent, HTTPField, HTTPFieldParametersSet},
    keyring::{Algorithm, Thumbprintable},
    message_signatures::{MessageSigner, UnsignedMessage},
};
use worker::*;

const README: &str = r#"
<h1>Example Signature Agent Card and Registry on Cloudflare Workers</h1>
<p>This deploys a <a href="https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/">registry and a signature agent card</a> 
on the same host: a Cloudflare worker.
<h2>Instructions</h2>
<ol>
    <li>Navigate to <a href="/.well-known/http-message-signatures-directory"><code>/.well-known/http-message-signatures-directory</code></a> to view a generated Signature Agent card on demand.</li>
    <li>Navigate to <a href="/registry.txt"><code>/registry.txt</code></a> to view a generated registry linking to that Signature Agent card.</li>
</ol>
<h3>Customize</h3>
You can add a worker binding and multiple custom routes, and visit <a href="/.well-known/http-message-signatures-directory"><code>/.well-known/http-message-signatures-directory</code></a> on each custom route. 
This will automatically populate your registry with multiple, unique entries.
"#;

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
        "/registry.txt" => {
            let scheme = req
                .uri()
                .scheme_str()
                .ok_or(worker::Error::RouteNoDataError)?
                .to_string();
            let list = kv.list().limit(1000).execute().await?;
            Response::ok(
                list.keys
                    .into_iter()
                    .map(|key| {
                        format!(
                            "{}://{}/.well-known/http-message-signatures-directory",
                            scheme.clone(),
                            key.name.clone()
                        )
                    })
                    .collect::<Vec<String>>()
                    .join("\n"),
            )
        }
        "/.well-known/http-message-signatures-directory" => {
            let mut rng = rand::rngs::OsRng;

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
                keyid: thumbprint,
                nonce: general_purpose::STANDARD.encode(nonce),
                tag: "http-message-signatures-directory".to_string(),
            };

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
        _ => Response::from_html(README),
    }
}
