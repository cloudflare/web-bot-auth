---
name: Feature request
about: >-
  A new feature to support against any library. New API methods, convenience
  features, or new algorithms belong here.
title: "[feature]: "
labels: ["enhancement"]
---

## Problem to solve

What are you trying to achieve? A clear description of the problem or gap this feature addresses.

## Affected library

Feature requests target one library at a time. This includes interop issues - where the Rust and TypeScript libraries differ in their behaviour, but do not violate the Web Bot Auth specification - which are filed as one feature request per library, each stating the final goal.

- [ ] Rust crate `web-bot-auth`
- [ ] Rust crate `http-signature-directory`
- [ ] TypeScript package `web-bot-auth`
- [ ] TypeScript package `http-message-sig`
- [ ] TypeScript package `jsonwebkey-thumbprint`

## Proposed solution

Describe the feature: new API methods (a sketch of the proposed signature is helpful), convenience features, or new algorithms.

```rust
// Proposed API sketch (Rust or TypeScript)
```

## Relation to the specification

- [ ] This feature is covered by an existing specification (please link the relevant section).
- [ ] This feature extends beyond the Web Bot Auth / HTTP Message Signatures specifications.
- [ ] This feature would require a specification change.

## Alternatives considered

Any alternative solutions or workarounds you have considered.

## Additional context

Links to related issues, upstream discussions, or prior art.

## Checklist

- [ ] I have read [CONTRIBUTING.md](https://github.com/cloudflare/web-bot-auth/blob/main/CONTRIBUTING.md) and confirmed this is an accepted issue form.
- [ ] If this is an interop issue (the Rust and TypeScript libraries differ in their behaviour, but do not violate the Web Bot Auth specification), I understand a separate feature request must be opened for each library, each stating the final goal.
