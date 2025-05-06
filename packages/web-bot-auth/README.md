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

### Signing

```typescript
import { Algorithm, signatureHeaders } from "web-bot-auth";

// The following simple request ios going to be signed
const request = new Request("https://example.com");

// available at https://github.com/cloudflareresearch/web-bot-auth/blob/main/examples/rfc9421-keys/ed25519.json
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  kid: "test-key-ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

// Declare a signer for HTTP Message Signature
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

const headers = signatureHeaders(
  request,
  Ed25519Signer.fromJWK(RFC_9421_ED25519_TEST_KEY),
  {
    created: now,
    expires: new Date(now.getTime() + 300_000), // now + 5 min
  }
);

// Et voila! Here is our signed request
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: headers["Signature"],
    "Signature-Input": headers["Signature-Input"],
  },
});
```

### Verifying

```typescript
import { Directory, VerificationParams, verify } from "web-bot-auth";

// Reusing the incoming request signed in the above section
const signedRequest = new Request("https://example.com", {
  headers: {
    Signature: headers["Signature"],
    "Signature-Input": headers["Signature-Input"],
  },
});

async function verifyEd25519(
  data: string,
  signature: Uint8Array,
  params: VerificationParams
) {
  // note that here we use getDirectory, but this is as simple as a fetch
  const directory = await getDirectory();

  const key = await crypto.subtle.importKey(
    "jwk",
    RFC_9421_ED25519_TEST_KEY,
    { name: "Ed25519" },
    true,
    ["verify"]
  );

  const message = new TextEncoder().encode(data);

  const isValid = await crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature,
    message
  );

  if (!isValid) {
    throw new Error("invalid signature");
  }
}

await verify(signedRequest, verifyEd25519);
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache-2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
