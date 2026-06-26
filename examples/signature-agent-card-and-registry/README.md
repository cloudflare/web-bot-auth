# Example Signature Agent Card and Registry on Cloudflare Workers

This deploys three endpoints on one Cloudflare Worker: a registry, a Signature Agent Card, and a signed key directory.

Instructions:

- `npx wrangler dev`
- Visit `http://localhost:8787/signature-agent-card` to view the card.
- Visit `http://localhost:8787/.well-known/http-message-signatures-directory` to view the signed JWKS directory.
- Visit `http://localhost:8787/registry.txt` to view the registry. The registry entry appears after the directory endpoint has generated a key for the host.

The `http://localhost:8787` output is for development only. Registry entries, `client_id`, and `jwks_uri` are expected to use HTTPS. For local parser tests, put the Worker behind a local HTTPS proxy, for example with `mkcert`-generated certificates.

Attach more routes to the Worker to generate one card per host. The registry lists each host once it has key material.

## Warning

The JSON web keys produced by this worker are _not cryptographically secure_. You should not use any of the private or public keys generated for message signing or verifying outside of this host. This example is only suitable for insecure use.
