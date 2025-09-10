import { describe, it, expect } from "vitest";
import { registryToURLs } from "../src/index";

import vectors from "./test_data/web_bot_auth_registry_v1.json";
type Vectors = (typeof vectors)[number];

describe.each(vectors)("Web-bot-auth-registry-Vector-%#", (v: Vectors) => {
  it("should pass IETF draft registry test vectors", async () => {
    const urls = registryToURLs(v.registry_txt);
    expect(urls).toEqual(v.signature_agent_cards);
  });
});
