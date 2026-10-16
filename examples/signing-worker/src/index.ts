import { sign, SIGNATURE_AGENT_HEADER } from "web-bot-auth";
import { signerFromJWK } from "web-bot-auth/crypto";

interface Env {
  TARGET: string;
  SIGNATURE_AGENT: string;
  // Set with `wrangler secret put JWK`. Defaults to the published RFC 9421 test key.
  JWK?: string;
}

// Published RFC 9421 test key. Never use it in production.
const RFC_9421_ED25519_TEST_KEY = {
  kty: "OKP",
  crv: "Ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const signer = await signerFromJWK(
      env.JWK ? JSON.parse(env.JWK) : RFC_9421_ED25519_TEST_KEY
    );
    const outgoing = new Request(env.TARGET, request);
    outgoing.headers.set(
      SIGNATURE_AGENT_HEADER,
      `sig1="${env.SIGNATURE_AGENT}";type=directory`
    );
    const now = new Date();
    const fields = await sign(outgoing, {
      signer,
      created: now,
      expires: new Date(now.getTime() + 300_000),
    });
    outgoing.headers.set("Signature", fields.signature);
    outgoing.headers.set("Signature-Input", fields.signatureInput);
    return fetch(outgoing);
  },
};
