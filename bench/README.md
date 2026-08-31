# TypeScript benchmarks

The harness separates signature processing, WebCrypto, and key setup.

| Command               | Purpose                                      |
| --------------------- | -------------------------------------------- |
| `npm run bench`       | Compare signature and JWK thumbprint latency |
| `npm run bench:trace` | Export CPU, heap, and WebCrypto profiles     |

Tracing defaults to Web Bot Auth verification. Select another operation and
iteration count with environment variables:

```sh
OP=coreSign ITERS=10000 npm run bench:trace
```

Operations are `coreSign`, `coreVerify`, `sign`, `verify`, `signerFromJWK`, and
`verifierFromJWK`.

Trace artifacts are written under `bench/.trace/`:

- `.cpuprofile`: open in speedscope or Chrome DevTools Performance
- `.heapprofile`: open in Chrome DevTools Memory to find allocation sites
- `.trace.json`: open in Perfetto to inspect WebCrypto call duration

CPU, heap, and WebCrypto data are collected in separate passes so tracing does
not distort the profiles.
