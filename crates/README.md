# web-bot-auth

![License](https://img.shields.io/crates/l/web-bot-auth.svg)
[![crates.io](https://img.shields.io/crates/v/web-bot-auth.svg)][crates.io]

[crates.io]: https://crates.io/crates/web-bot-auth

A pure Rust implementation of [web-bot-auth](https://github.com/cloudflareresearch/web-bot-auth) as defined by [draft-meunier-web-bot-auth-architecture](https://thibmeu.github.io/http-message-signatures-directory/draft-meunier-web-bot-auth-architecture.html).

## Tables of Content

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- Plug-and-play HTTP message signature support: generate and verify signatures for any arbitrary HTTP message, independent of framework or library, by implementing the traits `UnsignedMessage` / `SignedMessage`.
- Out-of-the-box support for verifying and generating secure `web-bot-auth` signatures specifically.

## Usage

- Signing a message:  See [./examples/signing.rs](./examples/signing.rs) to generate the contents of `Signature` and `Signature-Input` header for the tag `web-bot-auth`.
- Verifying a Web Bot Auth message: See [./examples/verify.rs](./examples/verify.rs).
- Verifying an arbitrary message signature, not necessarily `web-bot-auth`: See [./examples/verify_arbitrary.rs](./examples/verify_arbitrary.rs).

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the [Apache-2.0 license](./LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache-2.0 licensed as above, without any additional terms or conditions.
