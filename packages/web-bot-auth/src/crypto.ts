import { type Algorithm, type Signer } from "http-message-sig";
import { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";
import { b64ToB64NoPadding, b64ToB64URL, u8ToB64 } from "./base64";

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
      { name: "RSA-PSS", saltLength: 32 },
      this.privateKey,
      message
    );
    return new Uint8Array(signature);
  }
}
