import { describe, expect, it } from "vitest";
import {
  parseRegistry,
  parseSignatureAgentCard,
  parseSignatureAgentHeader,
} from "../src/index";

import cardVectors from "./test_data/web_bot_auth_signature_agent_card_v1.json";
import registryVectors from "./test_data/web_bot_auth_registry_v1.json";
import signatureAgentVectors from "./test_data/web_bot_auth_signature_agent_v1.json";

describe.each(signatureAgentVectors)("Signature-Agent $name", (vector) => {
  it("parses the header", () => {
    const result = parseSignatureAgentHeader(vector.header);

    expect(result.kind).toBe("current");
    expect(result.entries).toEqual(vector.entries);
  });
});

describe("Signature-Agent invalid syntax", () => {
  it("rejects an empty header", () => {
    expect(() => parseSignatureAgentHeader("")).toThrow("must not be empty");
  });

  it("accepts legacy string syntax with a warning", () => {
    expect(parseSignatureAgentHeader('"https://signature-agent.test"')).toEqual(
      {
        kind: "legacy",
        entries: [
          {
            label: "",
            uri: "https://signature-agent.test",
            type: "directory",
          },
        ],
      }
    );
  });
});

describe.each(registryVectors)("registry $name", (vector) => {
  it("parses the registry", () => {
    expect(
      parseRegistry(vector.registry_txt).map((entry) => entry.href)
    ).toEqual(vector.signature_agent_cards);
  });
});

describe("invalid registry", () => {
  it.each([
    ["http://example.com/bot\n", "registry entries must use https"],
    [
      'data:application/json,{"client_name":"Inline Bot"}\n',
      "inline signature agent cards are not supported",
    ],
  ])("rejects %s", (registry, error) => {
    expect(() => parseRegistry(registry)).toThrow(error);
  });
});

describe.each(cardVectors)("signature agent card $name", (vector) => {
  it("validates the card", () => {
    if (vector.valid) {
      expect(parseSignatureAgentCard(vector.card, vector.url)).toMatchObject(
        vector.card
      );
    } else {
      expect(() => parseSignatureAgentCard(vector.card, vector.url)).toThrow(
        vector.error
      );
    }
  });
});

describe("signature agent card key material", () => {
  it("requires key material", () => {
    expect(() =>
      parseSignatureAgentCard(
        { client_id: "https://example.com/bot" },
        "https://example.com/bot"
      )
    ).toThrow("either jwks or jwks_uri");
  });

  it("requires client_id when card URL is known", () => {
    expect(() =>
      parseSignatureAgentCard(
        { jwks_uri: "https://example.com/jwks.json" },
        "https://example.com/bot"
      )
    ).toThrow("client_id is required");
  });
});
