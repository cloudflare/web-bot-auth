---
name: Bug report
about: >-
  The libraries do not implement the specification faithfully, provided
  examples do not work, or a vulnerability is present.
title: "[bug]: "
labels: ["bug"]
---

## Summary

A clear and concise description of the bug.

## Issue type

Which of the accepted bug forms does this fall under? (See [CONTRIBUTING.md](https://github.com/cloudflare/web-bot-auth/blob/main/CONTRIBUTING.md))

- [ ] A library does not implement the Web Bot Auth specification faithfully
- [ ] A provided example does not work
- [ ] A vulnerability is present

## Affected library

- [ ] Rust crate `web-bot-auth`
- [ ] Rust crate `http-signature-directory`
- [ ] TypeScript package `web-bot-auth`
- [ ] TypeScript package `http-message-sig`
- [ ] TypeScript package `jsonwebkey-thumbprint`
- [ ] An example under [`examples/`](https://github.com/cloudflare/web-bot-auth/tree/main/examples)
- [ ] Not sure

## Environment

- Crate/package version:
- Toolchain (e.g. output of `rustc --version`, Node.js version):
- Runtime: native / Cloudflare Workers / other (please specify):
- Link to affected code or repository:

## Reproduction

Minimal steps to reproduce the behaviour. A failing test or a small code snippet is best.

1.
2.
3.

**Expected behaviour:** what should happen according to the specification?

**Actual behaviour:** what happens instead?

If a vulnerability is present, please include a proof of concept, but avoid posting exploitable details beyond what is needed to reproduce the issue.

## Test output

For Rust crates, please paste the output of:

```bash
cargo +stable test --workspace --all-features --all-targets
```

If the bug involves the Cloudflare Workers runtime (for example, new dependencies), please note whether it reproduces when running the [signature-agent-card-and-registry example](https://github.com/cloudflare/web-bot-auth/tree/main/examples/signature-agent-card-and-registry), as incompatibilities can surface only at runtime.

## Checklist

- [ ] I have read [CONTRIBUTING.md](https://github.com/cloudflare/web-bot-auth/blob/main/CONTRIBUTING.md) and confirmed this is an accepted issue form.
- [ ] This is not an interop issue. (Interop issues - where the Rust and TypeScript libraries differ in their behaviour, but do not violate the Web Bot Auth specification - are filed as feature requests separately for each library, stating the final goal.)
