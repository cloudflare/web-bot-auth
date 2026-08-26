import { webcrypto } from "http-message-sig";
import { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";
import type { WebBotAlgorithm, WebBotSigner, WebBotVerifier } from "./index";

function base64Url(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function keyid(jwk: JsonWebKey): Promise<string> {
  return jwkToKeyID(
    jwk,
    (value) => crypto.subtle.digest("SHA-256", value),
    base64Url
  );
}

function jwkAlgorithm(jwk: JsonWebKey): WebBotAlgorithm {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    if (jwk.alg !== undefined && jwk.alg !== "EdDSA") {
      throw new Error("Ed25519 JWK alg must be EdDSA when present");
    }
    return "ed25519";
  }
  if (jwk.kty === "RSA" && jwk.alg === "PS512") {
    return "rsa-pss-sha512";
  }
  throw new Error("JWK must be Ed25519 or RSA-PSS/SHA-512");
}

function importAlgorithm(
  algorithm: WebBotAlgorithm
): AlgorithmIdentifier | RsaHashedImportParams {
  return algorithm === "ed25519"
    ? { name: "Ed25519" }
    : { name: "RSA-PSS", hash: "SHA-512" };
}

function publicJwk(jwk: JsonWebKey, algorithm: WebBotAlgorithm): JsonWebKey {
  if (algorithm === "ed25519") {
    return { kty: "OKP", crv: "Ed25519", alg: "EdDSA", x: jwk.x };
  }
  return { kty: "RSA", alg: "PS512", e: jwk.e, n: jwk.n };
}

export async function signerFromJWK(jwk: JsonWebKey): Promise<WebBotSigner> {
  const algorithm = jwkAlgorithm(jwk);
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    importAlgorithm(algorithm),
    false,
    ["sign"]
  );
  const signer = webcrypto.signer(key);
  if (signer.algorithm !== algorithm) {
    throw new Error("imported CryptoKey algorithm does not match JWK");
  }
  return Object.freeze({
    algorithm,
    keyid: await keyid(jwk),
    sign(data: Uint8Array) {
      return signer.sign(data);
    },
  });
}

export async function verifierFromJWK(
  jwk: JsonWebKey
): Promise<WebBotVerifier> {
  const algorithm = jwkAlgorithm(jwk);
  const key = await crypto.subtle.importKey(
    "jwk",
    publicJwk(jwk, algorithm),
    importAlgorithm(algorithm),
    false,
    ["verify"]
  );
  const verifier = webcrypto.verifier(key);
  if (verifier.algorithm !== algorithm) {
    throw new Error("imported CryptoKey algorithm does not match JWK");
  }
  return Object.freeze({
    algorithm,
    keyid: await keyid(jwk),
    verify(data: Uint8Array, signature: Uint8Array) {
      return verifier.verify(data, signature);
    },
  });
}
