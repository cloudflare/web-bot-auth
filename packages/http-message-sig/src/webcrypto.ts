import { SignatureError, SignatureErrorCode } from "./errors";
import type { Signer, Verifier } from "./types";

function rsaHashName(algorithm: KeyAlgorithm): string | undefined {
  if (!("hash" in algorithm)) return undefined;
  const hash = algorithm.hash;
  if (typeof hash !== "object" || hash === null || !("name" in hash)) {
    return undefined;
  }
  return typeof hash.name === "string" ? hash.name : undefined;
}

function signatureAlgorithm(key: CryptoKey): string {
  if (key.algorithm.name === "Ed25519") return "ed25519";
  if (
    key.algorithm.name === "RSA-PSS" &&
    rsaHashName(key.algorithm) === "SHA-512"
  ) {
    return "rsa-pss-sha512";
  }
  throw new SignatureError(
    SignatureErrorCode.UnsupportedFeature,
    `Unsupported WebCrypto algorithm ${key.algorithm.name}`
  );
}

function cryptoParameters(key: CryptoKey): AlgorithmIdentifier | RsaPssParams {
  return key.algorithm.name === "RSA-PSS"
    ? { name: "RSA-PSS", saltLength: 64 }
    : { name: key.algorithm.name };
}

export function createWebCryptoSigner(key: CryptoKey): Signer {
  if (key.type !== "private" || !key.usages.includes("sign")) {
    throw new SignatureError(
      SignatureErrorCode.PolicyViolation,
      "Signing requires a private key with sign usage"
    );
  }
  const algorithm = signatureAlgorithm(key);
  const parameters = cryptoParameters(key);
  return Object.freeze({
    algorithm,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(await crypto.subtle.sign(parameters, key, data));
    },
  });
}

export function createWebCryptoVerifier(key: CryptoKey): Verifier {
  if (key.type !== "public" || !key.usages.includes("verify")) {
    throw new SignatureError(
      SignatureErrorCode.PolicyViolation,
      "Verification requires a public key with verify usage"
    );
  }
  const algorithm = signatureAlgorithm(key);
  const parameters = cryptoParameters(key);
  return Object.freeze({
    algorithm,
    verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
      return crypto.subtle.verify(parameters, key, signature, data);
    },
  });
}
