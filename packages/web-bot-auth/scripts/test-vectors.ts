/// This script generates test vectors for https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/
/// The vectors are generated in JSON format
///
/// It takes one positional argument: [path] which is where the vectors should be written in JSON

const { generateNonce, recommendedComponents, signatureHeaders } = await import(
  "../dist/index.mjs"
);

const { signerFromJWK } = await import("../dist/crypto.mjs");

const fs = await import("fs");

const SIGNATURE_AGENT_HEADER = "https://signature-agent.test";
const ORIGIN_URL = "https://example.com/path/to/resource";

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
  signature_agent_key?: string;
}

async function generateTestVectors(jwk: JsonWebKey): Promise<TestVector[]> {
  const now = new Date("2025-01-01T00:00:00Z");
  const created = now;
  const expires = new Date(now.getTime() + 3_153_600_000_000);
  const signer = await signerFromJWK(jwk);

  const nonce = generateNonce();
  const label = "sig1";
  let request = new Request(ORIGIN_URL);
  const signedHeaders = await signatureHeaders(request, signer, {
    components: recommendedComponents(),
    created,
    expires,
    nonce,
    key: label,
  });

  const nonceWithAgent = generateNonce();
  const labelWithAgent = "sig2";
  const signatureAgentKey = "agent2";
  request = new Request(ORIGIN_URL, {
    headers: {
      "Signature-Agent": `${signatureAgentKey}="${SIGNATURE_AGENT_HEADER}"`,
    },
  });
  const signedHeadersWithAgent = await signatureHeaders(request, signer, {
    components: recommendedComponents(signatureAgentKey),
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
      signature_agent: request.headers.get("Signature-Agent"),
      signature_agent_key: signatureAgentKey,
    },
  ];
}

const outputPath = process.argv[2];

if (!outputPath) {
  console.error("Please provide a file path as the first argument.");
  process.exit(1);
}

const jwks = {
  ed25519: JSON.parse(
    await fs.promises.readFile(
      "../../examples/rfc9421-keys/ed25519.json",
      "utf8"
    )
  ),
  rsapss: JSON.parse(
    await fs.promises.readFile(
      "../../examples/rfc9421-keys/rsapss.json",
      "utf8"
    )
  ),
};
const vectors = [
  ...(await generateTestVectors(jwks.rsapss)),
  ...(await generateTestVectors(jwks.ed25519)),
];

for (const vector of vectors) {
  console.log(`Signature base

NOTE: '\\' line wrapping per RFC 8792
`);
  console.log(`"@authority": ${new URL(vector.target_url).host}`);
  if (vector.signature_agent) {
    const split = vector.signature_agent.split("=");
    console.log(`"signature-agent";key="${split[0]}": ${split[1]}`);
  }
  console.log(
    `"@signature-params": ${vector.signature_input.slice(`${vector.label}=`.length).replaceAll(";", "\\\n ;").replaceAll("\\\n ;key=", ";key=")}`
  );
  console.log("");

  console.log(`Signature headers

NOTE: '\\' line wrapping per RFC 8792
`);
  if (vector.signature_agent) {
    console.log(`Signature-Agent: ${vector.signature_agent}`);
  }
  console.log(
    `Signature-Input: ${vector.signature_input.replaceAll(";", "\\\n ;").replaceAll("\\\n ;key=", ";key=")}`
  );
  console.log(`Signature: ${vector.signature}`);
  console.log("");
}

fs.writeFileSync(outputPath, JSON.stringify(vectors, null, 2), "utf-8");
