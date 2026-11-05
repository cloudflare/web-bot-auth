# http-signature-directory

![License](https://img.shields.io/crates/l/web-bot-auth.svg)
[![crates.io](https://img.shields.io/crates/v/http-signature-directory.svg)][crates.io]

[crates.io]: https://crates.io/crates/http-signature-directory

A command-line tool to validate an HTTP message signatures directory per [draft-meunier-webbotauth-httpsig-directory-00](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-directory/00/).

This is an opinionated validator:

1. URLs must use HTTPS without credentials or a fragment. Redirects are not followed.
2. For an origin URL, it tries `/.well-known/http-message-signatures-directory` first, falling back to the original URL only on HTTP 404 or 410. The final response must be HTTP 200.
3. Well-known directories must use `application/http-message-signatures-directory+json`. Each key must have a valid proof covering `"@authority";req` and `"content-digest"`, with a matching SHA-256 body digest, key ID, directory tag, and validity window. A JWK's `kid`, when present, must match its thumbprint.
4. Ordinary JWK Set URLs are checked for key validity without possession proofs, with a warning. Only Ed25519 keys are supported. Responses are limited to 64,000 bytes and 100 keys.

## Tables of Content

- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Usage

```
$ cargo install http-signature-directory

$ http-signature-directory --help
Validate if your JWKS directories meet web-bot-auth standards

Usage: http-signature-directory <URL> [USER_AGENT]

Arguments:
  <URL>         URL pointing to your HTTP Message Signature JSON Web Key Set e.g. `https://example.com/.well-known/http-message-signatures-directory`
  [USER_AGENT]  Optional useragent that can be used to customize the useragent being sent to the server. [default: http-signature-directory-test-script/0.1.0]

Options:
  -h, --help     Print help
  -V, --version  Print version
```

The [passing Ed25519 test vector](../../packages/web-bot-auth/test/test_data/web_bot_auth_directory_response_v1.json) uses the following proof headers for `signature-agent.test` (a test hostname, not a live endpoint):

```http
Content-Digest: sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:
Signature: binding0=:yiHq0TXrbpzbmlttAQMpYoAufitFJUWuNsakB7QQMoN0EHbo5o51bZRVR8az/ptTWCwllix9clrKXfGKwdPzBg==:
Signature-Input: binding0=("@authority";req "content-digest");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="http-message-signatures-directory"
```

For that response, successful validation produces:

```json
{
  "success": true,
  "message": "HTTP signature directory is valid!",
  "details": {
    "url": "https://signature-agent.test/.well-known/http-message-signatures-directory",
    "keys_count": 1,
    "validated_keys": [
      {
        "thumbprint": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
        "valid": true,
        "signature_verified": true,
        "raw_key_data": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        },
        "error": null
      }
    ],
    "errors": [],
    "warnings": []
  }
}
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the [Apache-2.0 license](./LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
