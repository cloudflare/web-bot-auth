import { readFile } from "node:fs/promises";
import { createSignatureSync, verifySignature } from "http-message-sig";
import { sign, verify } from "web-bot-auth";
import { signerFromJWK, verifierFromJWK } from "web-bot-auth/crypto";

const key = JSON.parse(
  await readFile(
    new URL("../examples/rfc9421-keys/ed25519.json", import.meta.url),
    "utf8"
  )
);

const request = {
  kind: "request",
  method: "POST",
  targetUri: "https://example.com/foo?param=Value&Pet=dog",
  requestTarget: "/foo?param=Value&Pet=dog",
  fields: [
    { name: "Host", value: "example.com" },
    { name: "Date", value: "Tue, 20 Apr 2021 02:07:55 GMT" },
    { name: "Content-Type", value: "application/json" },
    { name: "Content-Digest", value: "sha-256=:YWJjZA==:" },
    { name: "Content-Length", value: "18" },
  ],
};
const components = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
  "content-length",
  "content-type",
];
const coreSignature = new Uint8Array([1, 2, 3]);
const coreSigner = {
  algorithm: "test-alg",
  sign() {
    return coreSignature;
  },
};
const coreVerifier = {
  algorithm: "test-alg",
  verify() {
    return true;
  },
};
const coreOptions = {
  components,
  parameters: { created: 1_618_884_475, alg: "test-alg", keyid: "key" },
  signer: coreSigner,
};
const coreFields = createSignatureSync(request, coreOptions);
const signedDescriptor = {
  ...request,
  fields: [
    ...request.fields,
    { name: "Signature", value: coreFields.signature },
    { name: "Signature-Input", value: coreFields.signatureInput },
  ],
};
const coreVerifyOptions = {
  policy: {
    algorithms: ["test-alg"],
    requiredComponents: components,
    requiredParameters: ["created", "keyid"],
    now: 1_618_884_500,
  },
  resolveVerifier: () => coreVerifier,
};

const signer = await signerFromJWK(key);
const verifier = await verifierFromJWK(key);
const created = new Date("2025-01-01T00:00:00Z");
const expires = new Date("2025-01-01T01:00:00Z");
const now = new Date("2025-01-01T00:30:00Z");
const webRequest = new Request("https://example.com/resource", {
  headers: {
    "content-type": "application/json",
    "signature-agent": 'sig1="https://example.com/agent";type=directory',
  },
});
const webOptions = {
  signer,
  created,
  expires,
  signatureAgentKey: "sig1",
  additionalComponents: ["content-type"],
};
const webFields = await sign(webRequest, webOptions);
const webHeaders = new Headers(webRequest.headers);
webHeaders.set("signature", webFields.signature);
webHeaders.set("signature-input", webFields.signatureInput);
const signedWebRequest = new Request(webRequest, { headers: webHeaders });
const webVerifyOptions = { now, resolver: () => verifier };

export const operations = Object.freeze({
  coreSign: () => createSignatureSync(request, coreOptions),
  coreVerify: () => verifySignature(signedDescriptor, coreVerifyOptions),
  sign: () => sign(webRequest, webOptions),
  verify: () => verify(signedWebRequest, webVerifyOptions),
  signerFromJWK: () => signerFromJWK(key),
  verifierFromJWK: () => verifierFromJWK(key),
});
