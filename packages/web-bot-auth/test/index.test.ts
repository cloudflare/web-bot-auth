import { createSignature, component } from "http-message-sig";
import { describe, expect, it, vi } from "vitest";
import {
  generateNonce,
  sign,
  signSync,
  validateNonce,
  verify,
  type SignatureFields,
  type WebBotSigner,
  type WebBotSignerSync,
  type WebBotVerifier,
} from "../src/index";
import { signerFromJWK, verifierFromJWK } from "../src/crypto";
import vectors from "./test_data/web_bot_auth_architecture_v2.json";

const created = new Date("2025-01-01T00:00:00Z");
const expires = new Date("2025-01-01T01:00:00Z");
const now = new Date("2025-01-01T00:30:00Z");
const ed25519Vector = vectors.find((vector) => vector.key.kty === "OKP");
if (ed25519Vector === undefined) throw new Error("missing Ed25519 vector");
const ed25519Jwk: JsonWebKey = ed25519Vector.key;

function withSignature(request: Request, fields: SignatureFields): Request {
  const headers = new Headers(request.headers);
  headers.set("signature", fields.signature);
  headers.set("signature-input", fields.signatureInput);
  return new Request(request, { headers });
}

async function signedRequest(
  request: Request,
  signer: WebBotSigner,
  overrides: Partial<{
    readonly created: Date;
    readonly expires: Date;
    readonly nonce: string;
    readonly label: string;
  }> = {}
): Promise<Request> {
  return withSignature(
    request,
    await sign(request, {
      signer,
      created: overrides.created ?? created,
      expires: overrides.expires ?? expires,
      nonce: overrides.nonce,
      label: overrides.label,
    })
  );
}

describe.each(vectors)("architecture vector: $label/$key.kty", (vector) => {
  it("signs and verifies", async () => {
    const signer = await signerFromJWK(vector.key);
    const headers = new Headers();
    if (vector.signature_agent !== undefined) {
      headers.set("signature-agent", vector.signature_agent);
    }
    const request = new Request(vector.target_url, { headers });
    const fields = await sign(request, {
      signer,
      created: new Date(vector.created_ms),
      expires: new Date(vector.expires_ms),
      nonce: vector.nonce,
      label: vector.label,
    });
    expect(fields.signatureInput).toBe(vector.signature_input);

    const verifier = await verifierFromJWK(vector.key);
    const result = await verify(withSignature(request, fields), {
      now: new Date(vector.created_ms),
      resolver: () => verifier,
    });
    expect(result.keyid).toBe(signer.keyid);
    expect(result.signatureAgent?.label).toBe(vector.signature_agent_key);

    const vectorFields: SignatureFields = {
      signature: vector.signature,
      signatureInput: vector.signature_input,
    };
    await expect(
      verify(withSignature(request, vectorFields), {
        now: new Date(vector.created_ms),
        resolver: () => verifier,
      })
    ).resolves.toMatchObject({ keyid: signer.keyid });
  });
});

describe("nonce", () => {
  it("is absent when omitted", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const fields = await sign(new Request("https://example.com"), {
      signer,
      created,
      expires,
    });
    expect(fields.signatureInput).not.toContain(";nonce=");
  });

  it("generates canonical unpadded base64url", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(validateNonce(nonce)).toBe(true);
  });

  it.each([
    "",
    "abc",
    "A".repeat(85),
    "A".repeat(85) + "=",
    "A".repeat(85) + "+",
  ])("rejects malformed nonce %s", async (nonce) => {
    const signer = await signerFromJWK(ed25519Jwk);
    await expect(
      sign(new Request("https://example.com"), {
        signer,
        created,
        expires,
        nonce,
      })
    ).rejects.toThrow("canonical unpadded base64url");
  });
});

describe("synchronous signing", () => {
  it("applies the same profile as asynchronous signing", () => {
    const signer: WebBotSignerSync = {
      algorithm: "ed25519",
      keyid: "test-key",
      sign: () => new Uint8Array(64),
    };
    const request = new Request("https://example.com", {
      headers: {
        "signature-agent": 'sig1="https://bot.example";type=directory',
      },
    });
    const fields = signSync(request, { signer, created, expires });
    expect(fields.signatureInput).toContain(
      '("@authority" "signature-agent";key="sig1")'
    );
    expect(fields.signatureInput).toContain(';alg="ed25519"');
    expect(fields.signature).toMatch(/^sig1=:/);
  });
});

describe("Signature-Agent coverage", () => {
  it("signs and authenticates the exact signature label member", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: {
        "signature-agent": 'sig1="https://bot.example/card";type=cimd',
      },
    });
    const fields = await sign(request, { signer, created, expires });
    expect(fields.signatureInput).toContain('"signature-agent";key="sig1"');
    const resolver = vi.fn(() => verifier);
    const result = await verify(withSignature(request, fields), {
      resolver,
      now,
    });
    expect(resolver).toHaveBeenCalledWith({
      keyid: signer.keyid,
      algorithm: "ed25519",
      signatureAgent: {
        label: "sig1",
        uri: "https://bot.example/card",
        type: "cimd",
      },
    });
    expect(result.signatureAgent?.uri).toBe("https://bot.example/card");
  });

  it("rejects a missing matching header member while signing", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: { "signature-agent": 'other="https://bot.example"' },
    });
    await expect(sign(request, { signer, created, expires })).rejects.toThrow(
      "Signature-Agent has no member sig1"
    );
  });

  it("rejects whole-field-only coverage before resolution", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: { "signature-agent": 'sig1="https://bot.example"' },
    });
    const fields = await createSignature(request, {
      signer,
      components: ["@authority", "signature-agent"],
      parameters: {
        created: Math.floor(created.getTime() / 1000),
        expires: Math.floor(expires.getTime() / 1000),
        keyid: signer.keyid,
        alg: signer.algorithm,
        tag: "web-bot-auth",
      },
    });
    const resolver = vi.fn(() => verifierFromJWK(ed25519Jwk));
    await expect(
      verify(withSignature(request, fields), { resolver, now })
    ).rejects.toMatchObject({
      message: "Verifier resolution failed",
      cause: { message: "signature must cover signature-agent member sig1" },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it("rejects coverage of the wrong dictionary member", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: {
        "signature-agent":
          'sig1="https://one.example", sig2="https://two.example"',
      },
    });
    const fields = await createSignature(request, {
      signer,
      components: ["@authority", component("signature-agent", { key: "sig2" })],
      parameters: {
        created: Math.floor(created.getTime() / 1000),
        expires: Math.floor(expires.getTime() / 1000),
        keyid: signer.keyid,
        alg: signer.algorithm,
        tag: "web-bot-auth",
      },
    });
    const resolver = vi.fn(() => verifierFromJWK(ed25519Jwk));
    await expect(
      verify(withSignature(request, fields), { resolver, now })
    ).rejects.toMatchObject({
      message: "Verifier resolution failed",
      cause: { message: "signature must cover signature-agent member sig1" },
    });
    expect(resolver).not.toHaveBeenCalled();
  });

  it("rejects req component confusion", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: { "signature-agent": 'sig1="https://bot.example"' },
    });
    const requestDescriptor = {
      kind: "request",
      method: "GET",
      targetUri: request.url,
      fields: [
        { name: "signature-agent", value: 'sig1="https://bot.example"' },
      ],
    } satisfies import("http-message-sig").RequestDescriptor;
    const response = {
      kind: "response",
      status: 200,
      fields: [],
      request: requestDescriptor,
    } satisfies import("http-message-sig").ResponseDescriptor;
    const fields = await createSignature(response, {
      signer,
      components: [
        component("@authority", { req: true }),
        component("signature-agent", { req: true, key: "sig1" }),
      ],
      parameters: {
        created: Math.floor(created.getTime() / 1000),
        expires: Math.floor(expires.getTime() / 1000),
        keyid: signer.keyid,
        alg: signer.algorithm,
        tag: "web-bot-auth",
      },
    });
    const resolver = vi.fn(() => verifierFromJWK(ed25519Jwk));
    await expect(
      verify(withSignature(request, fields), { resolver, now })
    ).rejects.toThrow("req requires a response");
    expect(resolver).not.toHaveBeenCalled();
  });

  it("rejects legacy form", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = new Request("https://example.com", {
      headers: { "signature-agent": '"https://bot.example"' },
    });
    await expect(sign(request, { signer, created, expires })).rejects.toThrow(
      "legacy Signature-Agent"
    );
  });
});

describe("verification policy", () => {
  it("rejects algorithm mismatch", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = await signedRequest(
      new Request("https://example.com"),
      signer
    );
    const mismatched: WebBotVerifier = {
      algorithm: "rsa-pss-sha512",
      keyid: signer.keyid,
      verify: () => true,
    };
    await expect(
      verify(request, { resolver: () => mismatched, now })
    ).rejects.toThrow("does not match");
  });

  it("rejects resolved keyid mismatch before crypto", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const request = await signedRequest(
      new Request("https://example.com"),
      signer
    );
    const verifier: WebBotVerifier = {
      algorithm: "ed25519",
      keyid: "wrong-key",
      verify: vi.fn(() => true),
    };
    await expect(
      verify(request, { resolver: () => verifier, now })
    ).rejects.toMatchObject({
      message: "Verifier resolution failed",
      cause: { message: "resolved verifier keyid does not match signed keyid" },
    });
    expect(verifier.verify).not.toHaveBeenCalled();
  });

  it.each([
    {
      name: "future",
      signedCreated: new Date("2025-01-01T00:31:00Z"),
      signedExpires: expires,
      maxAge: 3600,
      error: "future",
    },
    {
      name: "expired",
      signedCreated: created,
      signedExpires: new Date("2025-01-01T00:29:59Z"),
      maxAge: 3600,
      error: "expired",
    },
    {
      name: "too old",
      signedCreated: created,
      signedExpires: expires,
      maxAge: 60,
      error: "too old",
    },
  ])(
    "rejects $name signatures",
    async ({ signedCreated, signedExpires, maxAge, error }) => {
      const signer = await signerFromJWK(ed25519Jwk);
      const verifier = await verifierFromJWK(ed25519Jwk);
      const request = await signedRequest(
        new Request("https://example.com"),
        signer,
        {
          created: signedCreated,
          expires: signedExpires,
        }
      );
      await expect(
        verify(request, { resolver: () => verifier, now, maxAge })
      ).rejects.toThrow(error);
    }
  );

  it("runs replay validation after authentication", async () => {
    const signer = await signerFromJWK(ed25519Jwk);
    const verifier = await verifierFromJWK(ed25519Jwk);
    const nonce = generateNonce();
    const request = await signedRequest(
      new Request("https://example.com"),
      signer,
      { nonce }
    );
    const validate = vi.fn(() => false);
    await expect(
      verify(request, { resolver: () => verifier, now, validate })
    ).rejects.toThrow("profile validation");
    expect(validate).toHaveBeenCalledWith(
      expect.objectContaining({ nonce, verifier })
    );
  });
});

describe("JWK binding", () => {
  it("rejects conflicting JWK alg", async () => {
    await expect(
      signerFromJWK({ ...ed25519Jwk, alg: "PS512" })
    ).rejects.toThrow("Ed25519 JWK alg");
  });
});
