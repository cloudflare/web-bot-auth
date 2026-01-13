import { describe, expect, it } from "vitest";

import { signatureHeaders, Signer, RequestLike, ResponseLike } from "../src";
import { encode as base64Encode } from "../src/base64";

const sampleRequest: RequestLike = {
  method: "POST",
  url: "https://example.com/path?query=string",
  headers: {
    "Content-Type": "application/json",
    Digest: "SHA-256=abcdef",
  },
};
const sampleResponse: ResponseLike = {
  status: 200,
  headers: {
    "Content-Type": "text/plain",
    Digest: "SHA-256=abcdef",
    "X-Total": "200",
  },
};
const created = new Date(1681004344000);

describe("sign", () => {
  const expectedHash = new Uint8Array([
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36,
    39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
  ]);
  const expectedHashBase64 = base64Encode(expectedHash);

  describe("request", () => {
    it("should apply default components", async () => {
      const expectedData = [
        '"@method": POST',
        '"@path": /path',
        '"@query": ?query=string',
        '"@authority": example.com',
        '"content-type": application/json',
        '"digest": SHA-256=abcdef',
        '"@signature-params": ("@method" "@path" "@query" "@authority" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      ].join("\n");

      const signer: Signer = {
        keyid: "test-key",
        alg: "hmac-sha256",
        async sign(data) {
          expect(data).to.equal(expectedData);
          return expectedHash;
        },
      };

      const signedRequest = await signatureHeaders(sampleRequest, {
        signer,
        created,
      });
      expect(signedRequest).to.deep.equal({
        Signature: `sig1=:${expectedHashBase64}:`,
        "Signature-Input":
          'sig1=("@method" "@path" "@query" "@authority" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      });
    });

    it("should apply custom components", async () => {
      const components = ["@authority", "@method", "@path", "digest"];
      const expectedData = [
        '"@authority": example.com',
        '"@method": POST',
        '"@path": /path',
        '"digest": SHA-256=abcdef',
        '"@signature-params": ("@authority" "@method" "@path" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      ].join("\n");

      const signer: Signer = {
        keyid: "test-key",
        alg: "hmac-sha256",
        async sign(data) {
          expect(data).to.equal(expectedData);
          return expectedHash;
        },
      };

      const signedRequest = await signatureHeaders(sampleRequest, {
        signer,
        components,
        created,
      });
      expect(signedRequest).to.deep.equal({
        Signature: `sig1=:${expectedHashBase64}:`,
        "Signature-Input":
          'sig1=("@authority" "@method" "@path" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      });
    });

    it("should apply the key name", async () => {
      const components = ["@authority"];
      const expectedData = [
        '"@authority": example.com',
        '"@signature-params": ("@authority");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      ].join("\n");

      const signer: Signer = {
        keyid: "test-key",
        alg: "hmac-sha256",
        async sign(data) {
          expect(data).to.equal(expectedData);
          return expectedHash;
        },
      };

      const signedRequest = await signatureHeaders(sampleRequest, {
        components,
        signer,
        created,
        key: "foo",
      });
      expect(signedRequest).to.deep.equal({
        Signature: `foo=:${expectedHashBase64}:`,
        "Signature-Input":
          'foo=("@authority");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      });
    });
  });

  describe("response", () => {
    it("should apply default components", async () => {
      const expectedData = [
        '"@status": 200',
        '"content-type": text/plain',
        '"digest": SHA-256=abcdef',
        '"@signature-params": ("@status" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      ].join("\n");

      const signer: Signer = {
        keyid: "test-key",
        alg: "hmac-sha256",
        async sign(data) {
          expect(data).to.equal(expectedData);
          return expectedHash;
        },
      };

      const signedResponse = await signatureHeaders(sampleResponse, {
        signer,
        created,
      });
      expect(signedResponse).to.deep.equal({
        Signature: `sig1=:${expectedHashBase64}:`,
        "Signature-Input":
          'sig1=("@status" "content-type" "digest");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      });
    });

    it("should apply custom components", async () => {
      const components = ["@status", "digest", "x-total"];
      const expectedData = [
        '"@status": 200',
        '"digest": SHA-256=abcdef',
        '"x-total": 200',
        '"@signature-params": ("@status" "digest" "x-total");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      ].join("\n");

      const signer: Signer = {
        keyid: "test-key",
        alg: "hmac-sha256",
        async sign(data) {
          expect(data).to.equal(expectedData);
          return expectedHash;
        },
      };

      const signedResponse = await signatureHeaders(sampleResponse, {
        signer,
        components,
        created,
      });
      expect(signedResponse).to.deep.equal({
        Signature: `sig1=:${expectedHashBase64}:`,
        "Signature-Input":
          'sig1=("@status" "digest" "x-total");created=1681004344;keyid="test-key";alg="hmac-sha256"',
      });
    });

    it("should honor the `req` parameter", async () => {
      const components = [
        "@status",
        "digest",
        "x-total",
        {
          name: "@authority",
          parameters: new Map([["req", true]]),
        },
      ];
      const expectedData = [
        '"@status": 200',
        '"digest": SHA-256=abcdef',
        '"x-total": 200',
        '"@authority";req: example.com',
        '"@signature-params": ("@status" "digest" "x-total" "@authority";req);created=1681004344;keyid="test-key";alg="hmac-sha256"',
      ].join("\n");

      const signer: Signer = {
        keyid: "test-key",
        alg: "hmac-sha256",
        async sign(data) {
          expect(data).to.equal(expectedData);
          return expectedHash;
        },
      };

      const signedResponse = await signatureHeaders(
        {
          response: sampleResponse,
          request: sampleRequest,
        },
        {
          signer,
          components,
          created,
        }
      );
      expect(signedResponse).to.deep.equal({
        Signature: `sig1=:${expectedHashBase64}:`,
        "Signature-Input":
          'sig1=("@status" "digest" "x-total" "@authority";req);created=1681004344;keyid="test-key";alg="hmac-sha256"',
      });
    });
  });
});
