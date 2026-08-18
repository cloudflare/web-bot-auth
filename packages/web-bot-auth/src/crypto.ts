import * as FetchSig from "fetch-message-signatures";
import { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";
import { b64ToB64NoPadding, b64ToB64URL, u8ToB64 } from "./base64";

export const helpers = {
  WEBCRYPTO_SHA256: (b: BufferSource) => crypto.subtle.digest("SHA-256", b),
  BASE64URL_DECODE: (u: ArrayBuffer) =>
    b64ToB64URL(b64ToB64NoPadding(u8ToB64(new Uint8Array(u)))),
};

/** A signer paired with the key identifier its signatures carry. */
export interface KeyedSigner {
  readonly alg: string;
  readonly keyid: string;
  readonly signer: FetchSig.SignerFactory;
}

async function keyIdFor(jwk: JsonWebKey): Promise<string> {
  return jwkToKeyID(jwk, helpers.WEBCRYPTO_SHA256, helpers.BASE64URL_DECODE);
}

export async function Ed25519Signer(
  keyid: string,
  privateKey: CryptoKey
): Promise<KeyedSigner> {
  return { alg: "ed25519", keyid, signer: FetchSig.ed25519Signer(privateKey) };
}

export async function RSAPSSSHA512Signer(
  keyid: string,
  privateKey: CryptoKey
): Promise<KeyedSigner> {
  return {
    alg: "rsa-pss-sha512",
    keyid,
    signer: FetchSig.rsaPssSha512Signer(privateKey),
  };
}

export async function signerFromJWK(jwk: JsonWebKey): Promise<KeyedSigner> {
  switch (jwk.kty) {
    case "OKP": {
      if (jwk.crv !== "Ed25519") {
        throw new Error(`Unsupported curve: ${jwk.crv}`);
      }
      const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "Ed25519" },
        true,
        ["sign"]
      );
      return Ed25519Signer(await keyIdFor(jwk), key);
    }
    case "RSA": {
      if (jwk.alg !== "PS512") {
        throw new Error(`Unsupported algorithm: ${jwk.alg}`);
      }
      const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSA-PSS", hash: { name: "SHA-512" } },
        true,
        ["sign"]
      );
      return RSAPSSSHA512Signer(await keyIdFor(jwk), key);
    }
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
}

/**
 * Builds a verifier factory bound to one already-trusted key.
 *
 * Synchronous, so it can be composed inside a caller's own factory without an await.
 */
export function verifier(key: CryptoKey): FetchSig.SynchronousVerifierFactory {
  switch (key.algorithm.name) {
    case "Ed25519":
      return FetchSig.ed25519Verifier(key);
    case "RSA-PSS":
      return FetchSig.rsaPssSha512Verifier(key);
    default:
      throw new Error(`Unsupported algorithm: ${key.algorithm.name}`);
  }
}

export async function verifierFromJWK(
  jwk: JsonWebKey
): Promise<FetchSig.SynchronousVerifierFactory> {
  switch (jwk.kty) {
    case "OKP": {
      if (jwk.crv !== "Ed25519") {
        throw new Error(`Unsupported curve: ${jwk.crv}`);
      }
      // Only the public members, because the vectors carry private keys.
      return verifier(
        await crypto.subtle.importKey(
          "jwk",
          { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
          { name: "Ed25519" },
          true,
          ["verify"]
        )
      );
    }
    case "RSA": {
      if (jwk.alg !== "PS512") {
        throw new Error(`Unsupported algorithm: ${jwk.alg}`);
      }
      return verifier(
        await crypto.subtle.importKey(
          "jwk",
          { kty: jwk.kty, e: jwk.e, n: jwk.n },
          { name: "RSA-PSS", hash: { name: "SHA-512" } },
          true,
          ["verify"]
        )
      );
    }
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
}
