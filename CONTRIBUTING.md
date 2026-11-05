# Rust Developer's guide to web-bot-auth

Welcome to web-bot-auth's contributor guidelines. Please take a look.
This should help you get ready to contribute to this repo.

## How to contribute

Before opening a PR, please raise an issue on the main repository and
confirm the change is one we'll accept.

We accept the following forms of issues:

1. _Bug report_: The libraries provided here do not implement the specification faithfully, provided examples do not work, or a vulnerability is present.
2. _Feature request_: A new feature to support against any library. New API methods, convenience features, or new behaviour belongs here.
3. _Questions_: Clarification on operations or best path forward.

For interop issues - where the Rust and Typescript libraries differ in their behaviour, but do not violate the Web Bot Auth specification -
please open a feature request separately for each library, stating the final goal.

## Principles for contributions

0. For bug reports, we aim to support the most recent specifications of:

   - The [Web Bot Auth protocol](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)
   - The [registry and signature agent card](https://www.ietf.org/archive/id/draft-meunier-webbotauth-registry-04.html)

1. Verifiers require paths for graceful migration, while signers don't. Changes in verification logic, such as what is considered a valid
   signed message, should use feature gates, deperecation warnings, or similar and outline a stable deprecation path. A method may be removed
   if it has been deprecated for at least two minor versions before 1.0, and one major version after 1.0.
2. We support WASM as a compilation target for Rust. Your changes should be tested to work on `wasm32-unknown-unknown` in addiion to local environments.
3. AI-generated pull requests are accepted, but, where possible, use your own voice to describe the issue and your plan.

## Testing

Crates in this repo provide Rust tests.
You can run these manually using:

```bash
cargo +stable test --workspace --all-features --all-targets
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
