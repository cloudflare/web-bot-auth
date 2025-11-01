# jsonwebkey-thumbprint

![License](https://img.shields.io/npm/l/jsonwebkey-thumbprint.svg)
[![crates.io](https://img.shields.io/npm/v/jsonwebkey-thumbprint.svg)][npm]

[npm]: https://www.npmjs.com/package/jsonwebkey-thumbprint

Variable-Length Integer Encoding defined by [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html).

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

```typescript
import { jwkThumbprint } from "jsonwebkey-thumbprint";

// A public key exported as a JWK
const keypair = await crypto.subtle.generateKey("Ed25519", true, [
  "sign",
  "verify",
]);
const jwk = await crypto.subtle.exportKey("jwk", keypair.publicKey);

// Using sha-256 as a hash function and base64url as encoding
const hash = (b: BufferSource) => crypto.subtle.digest("SHA-256", b);
const decode = (u: ArrayBuffer) =>
  b64ToB64URL(b64ToB64NoPadding(u8ToB64(new Uint8Array(u))));

// Compute the JWK Thumbprint for the public key
console.log(await jwkThumbprint(jwk, hash, decode));

// Helper functions
const u8ToB64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));

const b64ToB64URL = (s: string) => s.replace(/\+/g, "-").replace(/\//g, "_");

const b64ToB64NoPadding = (s: string) => s.replace(/=/g, "");
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
