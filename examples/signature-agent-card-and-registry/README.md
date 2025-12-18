# Example Signature Agent Card and Registry on Cloudflare Workers

This deploys a registry and a signature agent card on the same host: a Cloudflare worker.

Instructions:

- `npx wrangler dev`
- Navigate to `http://localhost:8787/.well-known/http-message-signatures-directory` to view a generated signature agent card with an example directory.
- Navigate to `http://localhost:8787` to view a registry containing this host. Note: this will not be generated until after you've visited `/.well-known/http-message-signatures-directory`, since the card will not exist until then.

This configuration allows you to attach multiple routes and generate an SAC for each one, all viewable in the registry.

## Warning

The JSON web keys produced by this worker are _not cryptographically secure_. You should not use any of the private or public keys generated for message signing or verifying outside of this host. This example is only suitable for insecure use.
