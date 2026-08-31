import { describe, bench } from "vitest";
import { jwkThumbprintPreCompute, jwkThumbprint } from "../src";

const u8ToB64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));

const b64ToB64URL = (s: string) => s.replace(/\+/g, "-").replace(/\//g, "_");

const b64ToB64NoPadding = (s: string) => s.replace(/=/g, "");

const tests = [{ name: "EC" }, { name: "OKP" }, { name: "RSA" }];

const randomKeys = async (num: number, alg: string) => {
  const values = new Array<JsonWebKey>();
  for (let i = 0; i < num; i++) {
    let keypair: CryptoKeyPair;
    switch (alg) {
      case "EC":
        keypair = await crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"]
        );
        break;
      case "OKP":
        keypair = await crypto.subtle.generateKey("Ed25519", true, [
          "sign",
          "verify",
        ]);
        break;
      case "RSA":
        keypair = await crypto.subtle.generateKey(
          {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" },
          },
          true,
          ["sign", "verify"]
        );
        break;
      default:
        throw new Error("Unsupported key type");
    }
    const jwk = (await crypto.subtle.exportKey(
      "jwk",
      keypair.publicKey
    )) as JsonWebKey;
    values.push(jwk);
  }
  return values;
};

async function setupBenchmarks() {
  for (const { name } of tests) {
    // use just one random key for the benchmark
    const inputs = await randomKeys(1, name);

    describe(`Benchmark for ${name}`, () => {
      bench(
        `${name} jwkThumbprintPreCompute`,
        () => {
          for (const input of inputs) {
            jwkThumbprintPreCompute(input);
          }
        },
        { iterations: 1000 }
      );
    });

    describe(`Benchmark for ${name}`, () => {
      const hash = (b: BufferSource) => crypto.subtle.digest("SHA-256", b);
      const decode = (u: ArrayBuffer) =>
        b64ToB64URL(b64ToB64NoPadding(u8ToB64(new Uint8Array(u))));
      bench(
        `${name} jwkThumbprint`,
        async () => {
          for (const input of inputs) {
            await jwkThumbprint(input, hash, decode);
          }
        },
        { iterations: 1000 }
      );
    });
  }
}

await setupBenchmarks();
