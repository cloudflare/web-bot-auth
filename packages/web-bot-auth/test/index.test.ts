import { vi, describe, it, expect } from "vitest";
import {
  generateNonce,
  signatureHeaders,
  validateNonce,
  NONCE_LENGTH_IN_BYTES,
  SIGNATURE_AGENT_HEADER,
  verify,
} from "../src/index";
import { signerFromJWK, verifierFromJWK } from "../src/crypto";
import { b64Tou8, u8ToB64 } from "../src/base64";

import vectors from "./test_data/web_bot_auth_architecture_v1.json";
type Vectors = (typeof vectors)[number];

describe.each(vectors)("Web-bot-auth-ed25519-Vector-%#", (v: Vectors) => {
  it("should pass IETF draft test vectors", async () => {
    const signer = await signerFromJWK(v.key);

    const headers = new Headers();
    if (v.signature_agent) {
      headers.append(SIGNATURE_AGENT_HEADER, v.signature_agent);
    }
    const request = new Request(v.target_url, { headers });
    const signedHeaders = await signatureHeaders(request, signer, {
      created: new Date(v.created_ms),
      expires: new Date(v.expires_ms),
      nonce: v.nonce,
      key: v.label,
    });

    expect(signedHeaders["Signature-Input"]).toBe(v.signature_input);

    // Appending signed header to the request, given that's what the origin receives
    headers.append("Signature", signedHeaders["Signature"]);
    headers.append("Signature-Input", signedHeaders["Signature-Input"]);
    const signedRequest = new Request(request.url, {
      headers,
    });

    vi.setSystemTime(new Date(v.created_ms));
    expect(
      await verify(signedRequest, await verifierFromJWK(v.key))
    ).toBeUndefined();
    vi.useRealTimers();
  });
});

describe("nonce", () => {
  describe("generateNonce", () => {
    it("should generate a base64 string", () => {
      const nonce = generateNonce();
      expect(typeof nonce).toBe("string");
      // Base64 regex pattern
      expect(() => b64Tou8(nonce)).not.toThrowError();
    });

    it("should generate nonce with correct length when decoded", () => {
      const nonce = generateNonce();
      const decoded = b64Tou8(nonce);
      expect(decoded.length).toBe(NONCE_LENGTH_IN_BYTES);
    });

    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      const nonce3 = generateNonce();
      expect(nonce1).not.toBe(nonce2);
      expect(nonce2).not.toBe(nonce3);
      expect(nonce1).not.toBe(nonce3);
    });
  });

  describe("validateNonce", () => {
    it("should validate correctly generated nonces", () => {
      const nonce = generateNonce();
      expect(validateNonce(nonce)).toBe(true);
    });

    it("should reject invalid base64 strings", () => {
      expect(validateNonce("not-base64!@#$")).toBe(false);
    });

    it("should reject empty string", () => {
      expect(validateNonce("")).toBe(false);
    });

    it("should reject nonces of incorrect length", () => {
      // Create a small base64 string
      const shortNonce = btoa("too short");
      expect(validateNonce(shortNonce)).toBe(false);

      // Create a long base64 string
      const longArray = new Uint8Array(NONCE_LENGTH_IN_BYTES + 10);
      crypto.getRandomValues(longArray);
      const longNonce = u8ToB64(longArray);
      expect(validateNonce(longNonce)).toBe(false);
    });

    it.each([[null], [undefined], [123], [{}], [[]], [true]])(
      "should handle invalid input type: %s",
      (invalidInput: unknown) => {
        expect(validateNonce(invalidInput as string)).toBe(false);
      }
    );

    it("should validate multiple generated nonces", () => {
      for (let i = 0; i < 10; i++) {
        const nonce = generateNonce();
        expect(validateNonce(nonce)).toBe(true);
      }
    });
  });
});
