import { describe, test } from "vitest";
import { operations } from "./fixtures.mjs";

const options = {
  time: 2_000,
  warmupTime: 1_000,
};

describe("HTTP message signatures", () => {
  test("core without crypto", async ({ bench }) => {
    await bench.compare(
      bench("core sign without crypto", operations.coreSign),
      bench("core verify without crypto", operations.coreVerify),
      options
    );
  });
});

describe("Web Bot Auth", () => {
  test("Ed25519", async ({ bench }) => {
    await bench.compare(
      bench("sign Ed25519", operations.sign),
      bench("verify Ed25519", operations.verify),
      bench("create Ed25519 signer", operations.signerFromJWK),
      bench("create Ed25519 verifier", operations.verifierFromJWK),
      options
    );
  });
});
