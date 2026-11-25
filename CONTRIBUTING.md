# Rust Developer's guide to web-bot-auth

Welcome to web-bot-auth's contributor guidelines. Please take a look.
This should help you get ready to contribute to this repo.

## How to contribute

Discuss substantial or breaking changes in an issue before opening a PR. Small fixes can go straight to a PR. If an issue already exists, use it.

Use the issue templates for bugs, feature requests, and questions. Report suspected vulnerabilities [privately](https://github.com/cloudflare/web-bot-auth/security/advisories/new), not in public issues or PRs.

For Rust and TypeScript interoperability issues, open one issue describing the desired behavior in both libraries. Split follow-up work only if it needs separate tracking.

## Principles for contributions

- Use the current [Web Bot Auth protocol](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) and [registry and Signature Agent Card](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/) drafts as conformance references.
- If a signing or verification change affects compatibility with deployed peers, describe how users should roll it out. If security or spec compliance requires an immediate break, explain why and what users need to change.
- Keep deprecated public APIs for at least two minor releases before 1.0 and at least one major version from 1.0 onward.
- AI-assisted PRs are welcome. Explain the problem and your plan briefly, in your own words.

## Testing

Crates in this repo provide Rust tests.
You can run these manually using:

```bash
cargo +stable test --workspace --all-features --all-targets
```

For Rust changes affecting WASM, run the same build as [CI](./.github/workflows/pullrequest.yml):

```bash
cargo +stable build --workspace --exclude http-signature-directory --all-features --tests --target wasm32-unknown-unknown
```

We also target Cloudflare's worker environment. A [basic example](./examples/signature-agent-card-and-registry/)
exists to confirm our crates work in said environment.
Depending on your changes you might need to expand this example or create your own.
Incompatibilities can surface only at runtime, so please exercise the example when
your change touches the Workers path (such as adding new dependencies).
For more information see [comment on #74](https://github.com/cloudflare/web-bot-auth/issues/74#issuecomment-4269847139)

## Code Formatting

Our CI runs `rustfmt` to check code formatting and `clippy` to lint.
You can run the same yourself before submitting a PR by running:

```bash
cargo +stable fmt --workspace -- --check
cargo +stable clippy --workspace --all-features --all-targets -- -D warnings
```

### Style

Additionally, we settled on a three-block use declaration format.
This means, use declarations (imports, in other languages) are split into
three blocks. The first one is reserved for items provided by Rust's standard library
(either `std`, `alloc`, or `core`). The second one is used for adding items from
external crates (for example `serde` or `time`). The last one is used for internal
items (`crate`, `super`, or a module).

```rust
use std::collections::HashMap;
use std::time::Duration;

use serde::Serialize;

use message_signatures::MessageVerifier;
```

rather than a single ordered block:

```rust
use message_signatures::MessageVerifier;
use serde::Serialize;
use std::time::Duration;
use std::collections::HashMap;
```

## Releases

Releases are currently on an ad-hoc basis. To request a release, please ping either @AkshatM or @thibmeu.
