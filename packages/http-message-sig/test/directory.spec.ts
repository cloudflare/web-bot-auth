import { describe, expect, it } from "vitest";

import { directoryResponseHeaders, Signer } from "../src";

describe("directoryResponseHeaders", () => {
  it("binds the response body to the request authority", async () => {
    const created = new Date(1735689600000);
    const expires = new Date(4889289600000);
    const signature = new Uint8Array([1, 2, 3]);
    const signer: Signer = {
      keyid: "test-key",
      alg: "ed25519",
      async sign(data) {
        expect(data).toBe(
          [
            '"@authority";req: signature-agent.test',
            '"content-digest": sha-256=:test-digest:',
            '"@signature-params": ("@authority";req "content-digest");created=1735689600;keyid="test-key";alg="ed25519";expires=4889289600;tag="http-message-signatures-directory"',
          ].join("\n")
        );
        return signature;
      },
    };

    const headers = await directoryResponseHeaders(
      {
        request: {
          method: "GET",
          url: "https://signature-agent.test/.well-known/http-message-signatures-directory",
          headers: {},
        },
        response: {
          status: 200,
          headers: { "content-digest": "sha-256=:test-digest:" },
        },
      },
      [signer],
      { created, expires }
    );

    expect(headers["Signature-Input"]).toBe(
      'binding0=("@authority";req "content-digest");created=1735689600;keyid="test-key";alg="ed25519";expires=4889289600;tag="http-message-signatures-directory"'
    );
    expect(headers.Signature).toBe("binding0=:AQID:");
  });
});
