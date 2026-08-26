# http-message-sig

Core [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP Message
Signatures for TypeScript.

## Capabilities

| Capability                                 | Support                                                                                            |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| Native `Request` and `Response`            | Yes, using Fetch-observable values                                                                 |
| Final request/response descriptors         | Yes, with ordered field occurrences and optional trailers                                          |
| Related request components (`req`)         | Yes, on response descriptors                                                                       |
| Ordinary field components                  | Yes                                                                                                |
| Structured Field dictionary member (`key`) | Yes, strict RFC 8941 parsing                                                                       |
| Derived components                         | `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`, `@status` |
| Multiple signatures                        | Yes                                                                                                |
| Async signing and verification             | Yes                                                                                                |
| Synchronous signing                        | Yes                                                                                                |
| Explicit verification policy               | Required                                                                                           |
| WebCrypto providers                        | Ed25519 and RSA-PSS with SHA-512                                                                   |

## Signing

```typescript
import { appendSignature, createSignature } from "http-message-sig";

const fields = await createSignature(request, {
  label: "sig1",
  components: ["@method", "@authority", "@path", "content-digest"],
  parameters: { created: 1_700_000_000, alg: signer.algorithm, keyid: "key-1" },
  signer,
});

const headers = appendSignature(request.headers, fields);
```

Signers consume UTF-8 signature-base bytes and expose `readonly algorithm`.
`appendSignature` accepts `Headers` only, returns a clone, and atomically parses
and merges both signature dictionaries.

Use `component("example-dict", { key: "member" })` for parameterized
components. `componentIdentity` returns the exact serialized component
identifier.

## Verification

```typescript
import { verifySignature } from "http-message-sig";

const verified = await verifySignature(request, {
  policy: {
    algorithms: ["ed25519"],
    requiredComponents: ["@method", "@authority", "@path"],
    requiredParameters: ["created", "keyid"],
    maxAge: 300,
    clockSkew: 5,
  },
  resolveVerifier(untrustedCandidate, context) {
    return lookupVerifier(untrustedCandidate.parameters.keyid, context);
  },
});
```

The resolver candidate is untrusted until cryptographic verification succeeds.
The optional policy `validate` callback receives authenticated data and runs
only after successful cryptographic verification.

## Limitations

- `sf`, `bs`, `tr`, `@query-param`, and unknown derived components are rejected
  with `UnsupportedFeature`.
- RFC 9651 dates and display strings are rejected in signature fields. Signature
  metadata is limited to RFC 8941 bare items.
- Fetch does not expose raw field occurrences or trailers. Use descriptors when
  those values matter.
- `Response` has no related request. Use a response descriptor for `req`.
- Cryptographic algorithms and key discovery are supplied by the caller.
- The former directory helpers and draft-era `signatureHeaders`, `verify`, and
  `RequestLike` APIs were removed. Directory behavior belongs in the consuming
  package and must migrate to `createSignature` plus `appendSignature`.

## Errors

Library validation failures use `SignatureError`, stable `SignatureErrorCode`
values, and `isSignatureError`.

## Security

This software has not been audited. Applications must define policy appropriate
to their protocol, including algorithm, component, parameter, and freshness
requirements.

## License

Apache-2.0.
