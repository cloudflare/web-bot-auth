import { component, verifySignature } from "http-message-sig";
import { describe, expect, it } from "vitest";
import { u8ToB64 } from "../src/base64";
import { verifierFromJWK } from "../src/crypto";
import vectors from "./test_data/web_bot_auth_directory_response_v1.json";

describe.each(vectors)("directory response vector: $name", (vector) => {
  it("has a valid content digest and core signature", async () => {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(vector.response.body)
    );
    expect(vector.response.headers["content-digest"]).toBe(
      `sha-256=:${u8ToB64(new Uint8Array(digest))}:`
    );

    const request = {
      kind: "request",
      method: vector.request.method,
      targetUri: vector.request.target_url,
      fields: Object.entries(vector.request.headers).map(([name, value]) => ({
        name,
        value,
      })),
    } satisfies import("http-message-sig").RequestDescriptor;
    const response = {
      kind: "response",
      status: vector.response.status,
      fields: Object.entries(vector.response.headers).map(([name, value]) => ({
        name,
        value,
      })),
      request,
    } satisfies import("http-message-sig").ResponseDescriptor;
    const verifier = await verifierFromJWK(vector.public_key);
    await expect(
      verifySignature(response, {
        label: "binding0",
        policy: {
          algorithms: ["ed25519"],
          requiredComponents: [
            component("@authority", { req: true }),
            "content-digest",
          ],
          requiredParameters: ["created", "expires", "keyid", "alg", "tag"],
          now: 1_735_689_600,
        },
        resolveVerifier: () => verifier,
      })
    ).resolves.toMatchObject({ verifier, label: "binding0" });
  });
});
