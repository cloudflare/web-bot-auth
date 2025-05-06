/// This script generates test vectors for https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/
/// The vectors are generated in JSON format
///
/// It takes one positional argument: [path] which is where the vectors should be written in JSON

const { generateNonce, helpers, jwkToKeyID, signatureHeaders } = await import(
  "../src/index.ts"
);

const fs = await import("fs");
const jwk = JSON.parse(
  await fs.promises.readFile("../../examples/rfc9421-keys/ed25519.json", "utf8")
);

const SIGNATURE_AGENT_DOMAIN = "signature-agent.test";
const ORIGIN_URL = "https://example.com/path/to/resource";

class Ed25519Signer {
  public alg: Algorithm = "ed25519";
  public keyid: string;
  private privateKey: CryptoKey;

  constructor(keyid: string, privateKey: CryptoKey) {
    this.keyid = keyid;
    this.privateKey = privateKey;
  }

  static async fromJWK(jwk: JsonWebKey): Promise<Ed25519Signer> {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "Ed25519" },
      true,
      ["sign"]
    );
    const keyid = await jwkToKeyID(
      jwk,
      helpers.WEBCRYPTO_SHA256,
      helpers.BASE64URL_DECODE
    );
    return new Ed25519Signer(keyid, key);
  }

  async sign(data: string): Promise<Uint8Array> {
    const message = new TextEncoder().encode(data);
    const signature = await crypto.subtle.sign(
      "ed25519",
      this.privateKey,
      message
    );
    return new Uint8Array(signature);
  }
}

interface TestVector {
  key: JsonWebKey;
  target_url: string;
  created_ms: number;
  expires_ms: number;
  nonce: string;
  label: string;
  signature: string;
  signature_input: string;
  signature_agent?: string;
}

async function generateTestVectors(): Promise<TestVector[]> {
  const now = new Date("2025-01-01T00:00:00Z");
  const created = now;
  const expires = new Date(now.getTime() + 3_600_000);
  const signer = await Ed25519Signer.fromJWK(jwk);

  const nonce = generateNonce();
  const label = "sig1";
  let request = new Request(ORIGIN_URL);
  const signedHeaders = await signatureHeaders(request, signer, {
    created,
    expires,
    nonce,
    key: label,
  });

  const nonceWithAgent = generateNonce();
  const labelWithAgent = "sig2";
  request = new Request(ORIGIN_URL, {
    headers: { "Signature-Agent": SIGNATURE_AGENT_DOMAIN },
  });
  const signedHeadersWithAgent = await signatureHeaders(request, signer, {
    created,
    expires,
    nonce: nonceWithAgent,
    key: labelWithAgent,
  });

  return [
    {
      key: jwk,
      target_url: ORIGIN_URL,
      created_ms: created.getTime(),
      expires_ms: expires.getTime(),
      nonce,
      label,
      signature: signedHeaders["Signature"],
      signature_input: signedHeaders["Signature-Input"],
    },
    {
      key: jwk,
      target_url: ORIGIN_URL,
      created_ms: created.getTime(),
      expires_ms: expires.getTime(),
      nonce: nonceWithAgent,
      label: labelWithAgent,
      signature: signedHeadersWithAgent["Signature"],
      signature_input: signedHeadersWithAgent["Signature-Input"],
      signature_agent: SIGNATURE_AGENT_DOMAIN,
    },
  ];
}

const outputPath = process.argv[2];

if (!outputPath) {
  console.error("Please provide a file path as the first argument.");
  process.exit(1);
}

const vectors = await generateTestVectors();

for (const vector of vectors) {
  console.log(`Signature base

NOTE: '\\' line wrapping per RFC 8792
`);
  console.log(`"@authority": ${new URL(vector.target_url).host}`);
  if (vector.signature_agent) {
    console.log(`"signature-agent": ${vector.signature_agent}`);
  }
  console.log(
    `"@signature-params": ${vector.signature_input.slice(`${vector.label}=`.length).replaceAll(";", "\\\n ;")}`
  );
  console.log("");

  console.log(`Signature headers

NOTE: '\\' line wrapping per RFC 8792
`);
  if (vector.signature_agent) {
    console.log(`Signature-Agent: ${vector.signature_agent}`);
  }
  console.log(
    `Signature-Input: ${vector.signature_input.replaceAll(";", "\\\n ;")}`
  );
  console.log(`Signature: ${vector.signature}`);
  console.log("");
}

fs.writeFileSync(outputPath, JSON.stringify(vectors, null, 2), "utf-8");
