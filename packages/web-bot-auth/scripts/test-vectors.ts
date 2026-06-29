/// This script generates test vectors for https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-directory/
/// and https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/
/// The vectors are generated in JSON format
///
/// It takes one positional argument: [directory] which is where the vectors should be written in JSON

const { recommendedComponents, signatureHeaders } =
  await import("../dist/index.mjs");

const { signerFromJWK } = await import("../dist/crypto.mjs");

const crypto = await import("crypto");
const fs = await import("fs");
const path = await import("path");

const SIGNATURE_AGENT_HEADER = "https://signature-agent.test";
const ORIGIN_URL = "https://example.com/path/to/resource";

// Nonces are deterministic so vector updates are reproducible. The public seed
// is drand round 29865500 from:
// https://drand.cloudflare.com/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/29865500
// Each nonce is base64(sha512(<round>:<randomness>:<jwk.kty>:<signature label>)).
const DRAND_ROUND = 29865500;
const DRAND_RANDOMNESS =
  "4901231f69a4e411e699f96485790415e83c56d1a8ef81acdf1bbdd75f6a2332";

function nonceFor(jwk: JsonWebKey, label: string): string {
  return crypto
    .createHash("sha512")
    .update(`${DRAND_ROUND}:${DRAND_RANDOMNESS}:${jwk.kty}:${label}`)
    .digest("base64");
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
  signature_agent_key?: string;
}

interface SignatureAgentVector {
  name: string;
  header: string;
  entries: {
    label: string;
    uri: string;
    type: "directory" | "jwks_uri" | "cimd";
  }[];
}

interface RegistryVector {
  name: string;
  registry_txt: string;
  signature_agent_cards: string[];
}

interface SignatureAgentCardVector {
  name: string;
  url: string;
  card: unknown;
  valid: boolean;
  error?: string;
}

async function generateTestVectors(jwk: JsonWebKey): Promise<TestVector[]> {
  const now = new Date("2025-01-01T00:00:00Z");
  const created = now;
  // Use a far-future expiry so test vectors never expire during conformance testing.
  const expires = new Date(now.getTime() + 3_153_600_000_000);
  const signer = await signerFromJWK(jwk);

  const label = "sig1";
  const nonce = nonceFor(jwk, label);
  let request = new Request(ORIGIN_URL);
  const signedHeaders = await signatureHeaders(request, signer, {
    components: recommendedComponents(),
    created,
    expires,
    nonce,
    key: label,
  });

  const labelWithAgent = "sig2";
  const nonceWithAgent = nonceFor(jwk, labelWithAgent);
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

const signatureAgentVectors: SignatureAgentVector[] = [
  {
    name: "directory-default",
    header: 'sig1="https://signature-agent.test"',
    entries: [
      {
        label: "sig1",
        uri: "https://signature-agent.test",
        type: "directory",
      },
    ],
  },
  {
    name: "jwks-uri",
    header: 'sig1="https://signature-agent.test/jwks.json";type=jwks_uri',
    entries: [
      {
        label: "sig1",
        uri: "https://signature-agent.test/jwks.json",
        type: "jwks_uri",
      },
    ],
  },
  {
    name: "cimd",
    header: 'sig1="https://signature-agent.test/card";type=cimd',
    entries: [
      {
        label: "sig1",
        uri: "https://signature-agent.test/card",
        type: "cimd",
      },
    ],
  },
];

const registryVectors: RegistryVector[] = [
  {
    name: "single-card",
    registry_txt: "https://example.com/bot\n",
    signature_agent_cards: ["https://example.com/bot"],
  },
  {
    name: "comments-and-blank-lines",
    registry_txt:
      "# bots\nhttps://bot1.example.com/card # primary\n\nhttps://bot2.example.com/card\n",
    signature_agent_cards: [
      "https://bot1.example.com/card",
      "https://bot2.example.com/card",
    ],
  },
];

const cardVectors: SignatureAgentCardVector[] = [
  {
    name: "jwks-uri-card",
    url: "https://example.com/bot",
    valid: true,
    card: {
      client_id: "https://example.com/bot",
      client_name: "Example Bot",
      contacts: ["mailto:bot-support@example.com"],
      jwks_uri:
        "https://example.com/.well-known/http-message-signatures-directory",
      web_bot_auth: {
        "expected-user-agent": "Mozilla/5.0 ExampleBot",
        "rfc9309-product-token": "ExampleBot",
        trigger: "fetcher",
        purpose: "tdm",
        ips_uri: "https://example.com/ips.json",
      },
    },
  },
  {
    name: "jwks-card",
    url: "https://example.com/bot",
    valid: true,
    card: {
      client_id: "https://example.com/bot",
      client_name: "Example Bot",
      jwks: {
        keys: [
          {
            kty: "OKP",
            crv: "Ed25519",
            x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
          },
        ],
      },
    },
  },
  {
    name: "jwks-and-jwks-uri",
    url: "https://example.com/bot",
    valid: false,
    error: "card must not contain both jwks and jwks_uri",
    card: {
      client_id: "https://example.com/bot",
      jwks_uri: "https://example.com/jwks.json",
      jwks: { keys: [] },
    },
  },
  {
    name: "client-id-mismatch",
    url: "https://example.com/bot",
    valid: false,
    error: "client_id must match the card URL",
    card: {
      client_id: "https://example.com/other",
      jwks_uri: "https://example.com/jwks.json",
    },
  },
];

const outputDirectory = process.argv[2];

if (!outputDirectory) {
  console.error("Please provide an output directory as the first argument.");
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

await fs.promises.mkdir(outputDirectory, { recursive: true });

const writeVectors = (fileName: string, value: unknown) => {
  fs.writeFileSync(
    path.join(outputDirectory, fileName),
    `${JSON.stringify(value, null, 2)}\n`,
    "utf-8"
  );
};

writeVectors("web_bot_auth_architecture_v2.json", vectors);
writeVectors("web_bot_auth_signature_agent_v1.json", signatureAgentVectors);
writeVectors("web_bot_auth_registry_v1.json", registryVectors);
writeVectors("web_bot_auth_signature_agent_card_v1.json", cardVectors);
