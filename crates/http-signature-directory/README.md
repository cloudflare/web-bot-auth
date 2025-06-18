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


$ http-signature-directory https://http-message-signatures-example.research.cloudflare.com/.well-known/http-message-signatures-directory
HTTP signature directory is valid!

# debug logging enabled
$ RUST_LOG=debug http-signature-directory https://http-message-signatures-example.research.cloudflare.com/.well-known/http-message-signatures-directory
[2025-06-18T13:23:57Z DEBUG http_signature_directory] Extracted the following @authority component: "http-message-signatures-example.research.cloudflare.com"
[2025-06-18T13:23:57Z DEBUG reqwest::connect] starting new connection: https://http-message-signatures-example.research.cloudflare.com/
[2025-06-18T13:23:58Z DEBUG http_signature_directory] Found the following Signature headers: ["binding0=:phQjWRDPBioZR672wQCWGSEChJUXk9zUiWNQlqLw1HVRjGw+n0xefZA0nqk4GbHUSpEKntvpGqfJSn0iqdGfCw==:"]
[2025-06-18T13:23:58Z DEBUG http_signature_directory] Found the following Signature-Input headers: ["binding0=(\"@authority\");created=1750253037;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1750253337;tag=\"http-message-signatures-directory\""]
[2025-06-18T13:23:58Z INFO  http_signature_directory] Analyzing key with thumbprint poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U
[2025-06-18T13:23:58Z INFO  http_signature_directory] Key was identified as an Ed25519 key
HTTP signature directory is valid!
```

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the [Apache-2.0 license](./LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
