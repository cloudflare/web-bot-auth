import { jwkToKeyID, signSync, type WebBotSignerSync } from "web-bot-auth";
import _sodium from "libsodium-wrappers";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

function base64Url(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

await _sodium.ready;
const KEY_ID = await jwkToKeyID(
  jwk,
  (value) => crypto.subtle.digest("SHA-256", value),
  base64Url
);

const MAX_AGE_IN_MS = 1000 * 60 * 60; // 1 hour
const SIGNATURE_AGENT =
  "https://http-message-signatures-example.research.cloudflare.com";

class Ed25519Signer implements WebBotSignerSync {
  public readonly algorithm = "ed25519";
  public readonly keyid = KEY_ID;
  private privateKey: Uint8Array<ArrayBuffer>;

  constructor(jwk: JsonWebKey) {
    const sodium = _sodium;
    if (jwk.d === undefined || jwk.x === undefined) {
      throw new Error("Ed25519 JWK must contain d and x");
    }

    // Base64URL decode helper
    const base64urlDecode = (str: string) =>
      sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);

    // Decode keys
    const privateKey = base64urlDecode(jwk.d); // 32 bytes
    const publicKey = base64urlDecode(jwk.x); // 32 bytes

    // Build the full 64-byte secret key: privateKey || publicKey
    const fullSecretKey = new Uint8Array(64);
    fullSecretKey.set(privateKey);
    fullSecretKey.set(publicKey, 32);

    this.privateKey = fullSecretKey;
  }

  sign(data: Uint8Array): Uint8Array {
    const sodium = _sodium;
    const signedMessage = sodium.crypto_sign(data, this.privateKey);
    return signedMessage.slice(0, sodium.crypto_sign_BYTES);
  }
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    details.requestHeaders?.push({
      name: "Signature-Agent",
      value: `sig1="${SIGNATURE_AGENT}";type=directory`,
    });

    const headers = new Headers();
    for (const header of details.requestHeaders ?? []) {
      if (header.value !== undefined) headers.append(header.name, header.value);
    }
    const request = new Request(details.url, {
      method: details.method,
      headers,
    });
    const now = new Date();
    const signature = signSync(request, {
      signer: new Ed25519Signer(jwk),
      created: now,
      expires: new Date(now.getTime() + MAX_AGE_IN_MS),
    });

    details.requestHeaders?.push({
      name: "Signature",
      value: signature.signature,
    });
    details.requestHeaders?.push({
      name: "Signature-Input",
      value: signature.signatureInput,
    });

    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

chrome.runtime.onStartup.addListener(() => {
  console.log(`onStartup()`);
});
