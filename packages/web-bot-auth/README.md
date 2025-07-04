# web-bot-auth

![License](https://img.shields.io/npm/l/web-bot-auth.svg)
[![crates.io](https://img.shields.io/npm/v/web-bot-auth.svg)][npm]

[npm]: https://www.npmjs.com/package/web-bot-auth

Web Bot Authentication defined by [draft-meunier-web-bot-auth-architecture](https://thibmeu.github.io/http-message-signatures-directory/draft-meunier-web-bot-auth-architecture.html).

## Tables of Content

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- JWK Thumbprint pre-compute
- JWK Thumbprint when passing a hash and encoding function
- TypeScript types

## Usage

This section provides examples usage for signing and verifying web-bot-auth material.
More concrete examples are provided on [cloudflareresearch/web-bot-auth/examples](https://github.com/cloudflareresearch/web-bot-auth#examples).

### Research server for debug purposes

To help debug `web-both-auth` HTTPS requests, Cloudflare Research provides a test endpoint on `https://http-message-signatures-example.research.cloudflare.com/debug`. You may also run this [research server's code on GitHub](https://github.com/cloudflare/web-bot-auth/tree/main/examples/verification-workers) on a local endpoint.

### Signing

```typescript
import { signatureHeaders } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";

// The following simple request is going to be signed
const request = new Request("https://example.com");

// This is a testing-only private key/public key pair described in RFC 9421 Appendix B.1.4
// Also available at https://github.com/cloudflareresearch/web-bot-auth/blob/main/examples/rfc9421-keys/ed25519.json
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  kid: "test-key-ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

const now = new Date();
const headers = await signatureHeaders(
  request,
  await signerFromJWK(RFC_9421_ED25519_TEST_KEY),
  {
    created: now,
    expires: new Date(now.getTime() + 300_000), // now + 5 min
  }
);

// Et voila! Here is our signed request.
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: headers["Signature"],
    "Signature-Input": headers["Signature-Input"],
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
  kid: "test-key-ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

// Reusing the incoming request signed in the above section
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: headers["Signature"],
    "Signature-Input": headers["Signature-Input"],
  },
});

await verify(signedRequest, await verifierFromJWK(RFC_9421_ED25519_TEST_KEY));
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
