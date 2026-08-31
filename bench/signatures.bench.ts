import { bench, describe } from "vitest";
import { operations } from "./fixtures.mjs";

const options = {
  time: 2_000,
  warmupTime: 1_000,
};

describe("HTTP message signatures", () => {
  bench("core sign without crypto", operations.coreSign, options);
  bench("core verify without crypto", operations.coreVerify, options);
});

describe("Web Bot Auth", () => {
  bench("sign Ed25519", operations.sign, options);
  bench("verify Ed25519", operations.verify, options);
  bench("create Ed25519 signer", operations.signerFromJWK, options);
  bench("create Ed25519 verifier", operations.verifierFromJWK, options);
});
