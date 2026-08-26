# web-bot-auth

![License](https://img.shields.io/npm/l/web-bot-auth.svg)
[![crates.io](https://img.shields.io/npm/v/web-bot-auth.svg)][npm]

[npm]: https://www.npmjs.com/package/web-bot-auth

TypeScript helpers for Web Bot Auth, as described in [draft-meunier-webbotauth-httpsig-protocol-00](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/00/).

## Table of Contents

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- Web Bot Auth request signing and verification policy
- Ed25519 and RSA-PSS/SHA-512 JWK signers and verifiers
- `Signature-Agent`, registry, and Signature Agent Card parsers
- TypeScript types

## Usage

This section shows basic signing and verification.
More concrete examples are provided on [cloudflareresearch/web-bot-auth/examples](https://github.com/cloudflareresearch/web-bot-auth#examples).

### Research server for debug purposes

To help debug `web-both-auth` HTTPS requests, Cloudflare Research provides a test endpoint on `https://http-message-signatures-example.research.cloudflare.com/debug`. You may also run this [research server's code on GitHub](https://github.com/cloudflare/web-bot-auth/tree/main/examples/verification-workers) on a local endpoint.

### Signing

```typescript
import { generateNonce, sign } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";

const signatureAgent = 'sig1="https://signature-agent.test";type=directory';
const request = new Request("https://example.com", {
  headers: { "Signature-Agent": signatureAgent },
});

// This is a testing-only private key/public key pair described in RFC 9421 Appendix B.1.4
// Also available at https://github.com/cloudflareresearch/web-bot-auth/blob/main/examples/rfc9421-keys/ed25519.json
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  alg: "EdDSA",
  kid: "test-key-ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

const now = new Date();
const fields = await sign(request, {
  signer: await signerFromJWK(RFC_9421_ED25519_TEST_KEY),
  created: now,
  expires: new Date(now.getTime() + 300_000),
  nonce: generateNonce(),
});

// Et voila! Here is our signed request.
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: fields.signature,
    "Signature-Agent": signatureAgent,
    "Signature-Input": fields.signatureInput,
  },
});
```

### Verifying

```typescript
import { verify } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";

// available at https://github.com/cloudflareresearch/web-bot-auth/blob/main/examples/rfc9421-keys/ed25519.json
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  alg: "EdDSA",
  kid: "test-key-ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

// Reusing the incoming request signed in the above section
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: fields.signature,
    "Signature-Agent": signatureAgent,
    "Signature-Input": fields.signatureInput,
  },
});

const verifier = await verifierFromJWK(RFC_9421_ED25519_TEST_KEY);
const authenticated = await verify(signedRequest, {
  // Resolve only from trusted local configuration. The candidate is untrusted.
  resolver: (candidate) => {
    if (candidate.keyid !== verifier.keyid) throw new Error("unknown key");
    return verifier;
  },
  validate: ({ nonce }) => {
    // Atomically reject a nonce already present in your replay cache.
  },
});
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
