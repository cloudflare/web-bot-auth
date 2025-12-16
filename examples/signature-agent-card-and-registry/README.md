# Example Signature Agent Card and Registry on Cloudflare Workers 

This deploys a registry and a signature agent card on the same host: a Cloudflare worker.

Instructions:

- `npx wrangler dev`
- Navigate to `http://localhost:8787/.well-known/http-message-signatures-directory` to view a generated signature agent card with an example directory.
- Navigate to `http://localhost:8787` to view a registry containing this host. Note: this will not be generated until after you've visited `/.well-known/http-message-signatures-directory`, since the card will not exist until then.

This configuration allows you to attach multiple routes and generate an SAC for each one, all viewable in the registry. 