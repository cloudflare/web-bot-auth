# Web Bot Auth

![GitHub License](https://img.shields.io/github/license/cloudflareresearch/web-bot-auth)

Repository presenting authentication for orchestrated agents navigating the web.
It implements all components required by Web Bot Authentication defined by [draft-meunier-web-bot-auth-architecture](https://thibmeu.github.io/http-message-signatures-directory/draft-meunier-web-bot-auth-architecture.html), and presents [examples](#examples).

## Tables of Content

- [Examples](#examples)
- [Development](#development)
- [Security Considerations](#security-considerations)
- [License](#license)

## Examples

### Live deployment

Cloudflare Research provides a live environment at [http-message-signatures-example.research.cloudflare.com](https://http-message-signatures-example.research.cloudflare.com/).

This deployment allows to test your implementation.

1. It validates the presence of a `Signature` header signed [RFC9421 ed25519 test key](./examples/rfc9421-keys/ed25519.pem),
2. It exposes a bot directory on [/.well-known/http-message-signatures-directory](https://http-message-signatures-example.research.cloudflare.com/.well-known/http-message-signatures-directory),
3. It provides explanation about the protocol.

### Signing

| Example                                            | Description                                  |
| :------------------------------------------------- | :------------------------------------------- |
| [Browser extension](./examples/browser-extension/) | Adds a `Signature` on every outgoing request |
| [Rust](./examples/rust/)                           | Signs a hardcoded test request               |

### Verifying

| Example                                                | Description                                            |
| :----------------------------------------------------- | :----------------------------------------------------- |
| [Cloudflare Workers](./examples/verification-workers/) | Verify RFC 9421 `Signature` for every incoming request |
| [Caddy Plugin](./examples/caddy-plugin/)               | Verify RFC 9421 `Signature` for every incoming request |
| [Rust](./examples/rust/)                               | Verify a sample test request                           |

## Development

This repository uses [npm](https://docs.npmjs.com/cli/v11/using-npm/workspaces) and [cargo](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) workspaces. There are several packages which it provides:

| Package                                                        | Language   | Description                                                                            |
| :------------------------------------------------------------- | :--------- | :------------------------------------------------------------------------------------- |
| [http-message-sig](./packages/http-message-sig/)               | TypeScript | HTTP Message Signatures as defined in RFC 9421                                         |
| [jsonwebkey-thumbprint](./packages/jsonwebkey-thumbprint/)     | TypeScript | JWK Thumbprint as defined in RFC 7638                                                  |
| [web-bot-auth](./packages/web-bot-auth/)                       | TypeScript | HTTP Message Signatures for Bots as defined in draft-meunier-web-bot-auth-architecture |
| [web-bot-auth](./crates/web-bot-auth/)                         | Rust       | HTTP Message Signatures for Bots as defined in draft-meunier-web-bot-auth-architecture |
| [http-signature-directory](./crates/http-signature-directory/) | Rust       | Validates whether an HTTP message signature directory is correctly signed and valid    |

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache 2.0 licensed as above, without any additional terms or conditions.
