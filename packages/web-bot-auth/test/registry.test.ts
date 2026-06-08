import { describe, it, expect } from "vitest";
import { parseRegistry, parseSignatureAgentCard } from "../src/index";

import vectors from "./test_data/web_bot_auth_registry_v1.json";

type Vectors = (typeof vectors)[number];

describe.each(vectors)("Web-bot-auth-registry-Vector-%#", (v: Vectors) => {
  it("should pass IETF draft registry test vectors", () => {
    expect(parseRegistry(v.registry_txt).map((entry) => entry.href)).toEqual(
      v.signature_agent_cards
    );
  });
});

describe("parseRegistry", () => {
  it("ignores blank lines and comments", () => {
    expect(
      parseRegistry(`
        # bots
        https://bot.example/card # local comment

		http://localhost:8787/card
		`).map((entry) => entry.href)
    ).toEqual(["https://bot.example/card", "http://localhost:8787/card"]);
  });

  it("rejects unsupported schemes", () => {
    expect(() => parseRegistry("ftp://example.com/card")).toThrow(
      "unsupported scheme"
    );
  });

  it("does not support inline data cards", () => {
    expect(() =>
      parseRegistry('data:application/json,{"client_name":"Inline Bot"}')
    ).toThrow("unsupported scheme");
  });
});

describe("parseSignatureAgentCard", () => {
  it("validates known card parameters", () => {
    expect(
      parseSignatureAgentCard({
        client_name: "Example Bot",
        trigger: "fetcher",
        jwks_uri:
          "https://example.com/.well-known/http-message-signatures-directory",
        ips_uri: "https://example.com/ips.json",
      })
    ).toMatchObject({
      client_name: "Example Bot",
      trigger: "fetcher",
    });
  });

  it("rejects invalid card parameters", () => {
    expect(() =>
      parseSignatureAgentCard({ jwks_uri: "http://example.com/jwks" })
    ).toThrow("jwks_uri must use one of: https");
  });

  it("ignores unknown parameters", () => {
    expect(parseSignatureAgentCard({ unknown: true })).toEqual({});
  });

  it("rejects empty cards", () => {
    expect(() => parseSignatureAgentCard({})).toThrow("at least one parameter");
  });

  it("requires client_uri data URLs to be text/plain", () => {
    expect(() =>
      parseSignatureAgentCard({ client_uri: "data:image/png,abc" })
    ).toThrow("text/plain");
  });

  it("requires contacts to be URIs", () => {
    expect(() =>
      parseSignatureAgentCard({ contacts: ["not a uri"] })
    ).toThrow();
  });
});
