import { describe, expect, it } from "vitest";
import { verify } from "http-message-sig";

import { u8ToB64 } from "../src/base64";
import { verifierFromJWK } from "../src/crypto";
import vectors from "./test_data/web_bot_auth_directory_response_v1.json";

describe.each(vectors)("directory response vector: $name", (vector) => {
  it("has a valid content digest and signature", async () => {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(vector.response.body)
    );
    expect(vector.response.headers["content-digest"]).toBe(
      `sha-256=:${u8ToB64(new Uint8Array(digest))}:`
    );

    const request = {
      method: vector.request.method,
      url: vector.request.target_url,
      headers: new Headers(vector.request.headers),
    };
    const response = {
      status: vector.response.status,
      headers: new Headers(vector.response.headers),
    };

    await expect(
      verify({ request, response }, await verifierFromJWK(vector.public_key))
    ).resolves.toBeUndefined();
  });
});
