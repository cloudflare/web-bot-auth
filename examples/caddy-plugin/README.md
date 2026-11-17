# web-bot-auth Caddy Plugin

![GitHub License](https://img.shields.io/github/license/cloudflareresearch/web-bot-auth)
![GitHub Release](https://img.shields.io/github/v/release/cloudflareresearch/web-bot-auth)

[Caddy plugin](https://caddyserver.com/docs/extending-caddy) extending Caddy configuration to allow for validation of web-bot-auth as defined in [draft-meunier-webbotauth-httpsig-protocol](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/).

## Table of Contents

- [Features](#features)
- [Usage](#usage)
- [Known Limitations](#known-limitations)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

This is an example plugin and only supports Ed25519. You can find a test key in [Appendix B.1.4 of RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421#name-example-ed25519-test-key).

- `httpsig` configuration hook
- Load keys from a direct HTTP Message Signatures directory with `directory_base`
- Load keys from registry signature-agent cards with `registry`
- Load multiple inline keys, or multiple keys from `jwks_uri`
- Load IP allowlists from `ips_uri` as defined in [draft-illyes-webbotauth-jafar-00](https://datatracker.ietf.org/doc/html/draft-illyes-webbotauth-jafar-00)
- Block request without a valid signature

## Usage

First, you need to install [xcaddy](https://github.com/caddyserver/xcaddy)

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Then you build caddy

```bash
xcaddy build latest --with github.com/cloudflareresearch/web-bot-auth/examples/caddy-plugin=./
```

And finally, you run caddy

```bash
./caddy run --config Caddyfile
```

To generate a signed request, you can use the sibling [browser extension](../browser-extension).

`directory_base` is the direct directory mode. `registry` is experimental registry draft support and can be repeated. Keys are loaded during provisioning, so changes require a Caddy reload. `fail_on_load_error` defaults to `false`, returning 503 when no validator was loaded; set it to `true` to fail provisioning instead.

## Known Limitations

When a request carries `Signature-Agent` as a Dictionary, the plugin requires the signature to cover the member keyed to its label, for example `"signature-agent";key="sig1"`, as Section 5.2.1 of [draft-ietf-webbotauth-httpsig-protocol](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) requires. httpsig-go v1.2.2 computes the wrong signature base for the `key` parameter, so these requests get `401` even when they are signed correctly. Requests without `Signature-Agent`, or with a legacy String `Signature-Agent`, are not affected. The fix is in [remitly-oss/httpsig-go#39](https://github.com/remitly-oss/httpsig-go/pull/39). Until a release includes it, the plugin rejects Dictionary-form requests.

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache 2.0 licensed as above, without any additional terms or conditions.
