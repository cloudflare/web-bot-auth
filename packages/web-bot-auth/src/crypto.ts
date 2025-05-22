import { type Algorithm, type Signer } from "http-message-sig";
import { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";
import { b64ToB64NoPadding, b64ToB64URL, u8ToB64 } from "./base64";
import type { VerificationParams, Verify } from "./index";

export const helpers = {
  WEBCRYPTO_SHA256: (b: BufferSource) => crypto.subtle.digest("SHA-256", b),
  BASE64URL_DECODE: (u: ArrayBuffer) =>
    b64ToB64URL(b64ToB64NoPadding(u8ToB64(new Uint8Array(u)))),
};

export class Ed25519Signer implements Signer {
  public alg: Algorithm = "ed25519";
  public keyid: string;
  private privateKey: CryptoKey;

  constructor(keyid: string, privateKey: CryptoKey) {
    this.keyid = keyid;
    this.privateKey = privateKey;
  }

  static async fromJWK(jwk: JsonWebKey): Promise<Ed25519Signer> {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "Ed25519" },
      true,
      ["sign"]
    );
    const keyid = await jwkToKeyID(
      jwk,
      helpers.WEBCRYPTO_SHA256,
      helpers.BASE64URL_DECODE
    );
    return new Ed25519Signer(keyid, key);
  }

  async sign(data: string): Promise<Uint8Array> {
    const message = new TextEncoder().encode(data);
    const signature = await crypto.subtle.sign(
      "ed25519",
      this.privateKey,
      message
    );
    return new Uint8Array(signature);
  }
}

export class RSAPSSSHA512Signer implements Signer {
  public alg: Algorithm = "rsa-pss-sha512";
  public keyid: string;
  private privateKey: CryptoKey;

  constructor(keyid: string, privateKey: CryptoKey) {
    this.keyid = keyid;
    this.privateKey = privateKey;
  }

  static async fromJWK(jwk: JsonWebKey): Promise<RSAPSSSHA512Signer> {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      // restricting to RSA-PSS with SHA-512 as other SHA- algorithms are not registered
      { name: "RSA-PSS", hash: { name: "SHA-512" } },
      true,
      ["sign"]
    );
    const keyid = await jwkToKeyID(
      jwk,
      helpers.WEBCRYPTO_SHA256,
      helpers.BASE64URL_DECODE
    );
    return new RSAPSSSHA512Signer(keyid, key);
  }

  async sign(data: string): Promise<Uint8Array> {
    const message = new TextEncoder().encode(data);
    const signature = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 64 },
      this.privateKey,
      message
    );
    return new Uint8Array(signature);
  }
}

export function signerFromJWK(jwk: JsonWebKey): Promise<Signer> {
  switch (jwk.kty) {
    case "OKP":
      if (jwk.crv === "Ed25519") {
        return Ed25519Signer.fromJWK(jwk);
      }
      throw new Error(`Unsupported curve: ${jwk.crv}`);
    case "RSA":
      // Per RFC7517, the alg field is optional for RSA keys
      // However, it's safer to check and mandate it
      // https://www.rfc-editor.org/rfc/rfc7517#section-4.4
      if (jwk.alg === "PS512") {
        return RSAPSSSHA512Signer.fromJWK(jwk);
      }
      throw new Error(`Unsupported algorithm: ${jwk.alg}`);
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
}

export function verifier(
  key: CryptoKey
): (
  data: string,
  signature: Uint8Array,
  params: VerificationParams
) => Promise<void> {
  return async (
    data: string,
    signature: Uint8Array,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    params: VerificationParams
  ) => {
    const encodedData = new TextEncoder().encode(data);

    const cryptoParams: Parameters<typeof crypto.subtle.verify>[0] =
      key.algorithm;
    switch (key.algorithm.name) {
      case "Ed25519":
        break;
      case "RSA-PSS":
        cryptoParams["saltLength"] = 64;
        break;
      default:
        throw new Error(`Unsupported algorithm: ${key.algorithm.name}`);
    }

    const isValid = await crypto.subtle.verify(
      cryptoParams,
      key,
      signature,
      encodedData
    );

    if (!isValid) {
      throw new Error("invalid signature");
    }
  };
}

export async function verifierFromJWK(jwk: JsonWebKey): Promise<Verify<void>> {
  let key: CryptoKey;
  switch (jwk.kty) {
    case "OKP":
      if (jwk.crv === "Ed25519") {
        key = await crypto.subtle.importKey(
          "jwk",
          { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
          { name: "Ed25519" },
          true,
          ["verify"]
        );
        break;
      }
      throw new Error(`Unsupported curve: ${jwk.crv}`);
    case "RSA":
      // Per RFC7517, the alg field is optional for RSA keys
      // However, it's safer to check and mandate it
      // https://www.rfc-editor.org/rfc/rfc7517#section-4.4
      if (jwk.alg === "PS512") {
        key = await crypto.subtle.importKey(
          "jwk",
          { kty: jwk.kty, e: jwk.e, n: jwk.n },
          // restricting to RSA-PSS with SHA-512 as other SHA- algorithms are not registered
          { name: "RSA-PSS", hash: { name: "SHA-512" } },
          true,
          ["verify"]
        );
        break;
      }
      throw new Error(`Unsupported algorithm: ${jwk.alg}`);
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
  return verifier(key);
}
