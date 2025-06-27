# http-signature-directory

![License](https://img.shields.io/crates/l/web-bot-auth.svg)
[![crates.io](https://img.shields.io/crates/v/http-signature-directory.svg)][crates.io]

[crates.io]: https://crates.io/crates/http-signature-directory

A command-line tool to validate an HTTP message signatures directory per [the HTTP Message Signatures directory draft](https://www.ietf.org/archive/id/draft-meunier-http-message-signatures-directory-00.html).

This is an opinionated validator:

1. It does not support validating non-HTTPS URL scheme
2. It does not support validating components other than `@authority`. Support for more thorough validation is welcome.

## Tables of Content

- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)


## Usage

```
$ cargo install http-signature-directory

$ http-signature-directory --help
Validate if your JWKS directories meet web-bot-auth standards

Usage: http-signature-directory <URL>

Arguments:
  <URL>  URL pointing to your HTTP Message Signature JSON Web Key Set e.g. `https://example.com/.well-known/http-message-signatures-directory`

Options:
  -h, --help     Print help
  -V, --version  Print version


$ RUST_LOG=debug http-signature-directory https://http-message-signatures-example.research.cloudflare.com/.well-known/http-message-signatures-directory
[2025-06-27T16:10:36Z DEBUG http_signature_directory] Extracted the following @authority component: "http-message-signatures-example.research.cloudflare.com"
[2025-06-27T16:10:36Z DEBUG reqwest::connect] starting new connection: https://http-message-signatures-example.research.cloudflare.com/
[2025-06-27T16:10:36Z DEBUG http_signature_directory] Found the following Signature headers: ["binding0=:kgzhyjU+BoBv/I0xF5vGipUbYL4CqNA5G1fxPk61bC3ZBxjM3PnwcySgHzFCSbX5d5DU8Mjd8l/O3Nl4yV0gCw==:"]
[2025-06-27T16:10:36Z DEBUG http_signature_directory] Found the following Signature-Input headers: ["binding0=(\"@authority\");created=1751040636;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1751040936;tag=\"http-message-signatures-directory\""]
[2025-06-27T16:10:36Z INFO  http_signature_directory] Analyzing key with thumbprint poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U
[2025-06-27T16:10:36Z INFO  http_signature_directory] Key was identified as an Ed25519 key
{
  "success": true,
  "message": "HTTP signature directory is valid!",
  "details": {
    "url": "https://http-message-signatures-example.research.cloudflare.com/.well-known/http-message-signatures-directory",
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
