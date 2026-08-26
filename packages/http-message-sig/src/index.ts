export { Token } from "structured-headers";
import { createWebCryptoSigner, createWebCryptoVerifier } from "./webcrypto";

export const webcrypto = Object.freeze({
  signer: createWebCryptoSigner,
  verifier: createWebCryptoVerifier,
});

export * from "./core";
export * from "./errors";
export * from "./types";
