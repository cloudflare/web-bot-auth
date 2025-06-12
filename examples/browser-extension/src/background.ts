import {
  Algorithm,
  signatureHeadersSync,
  helpers,
  jwkToKeyID,
} from "web-bot-auth";
import _sodium from "libsodium-wrappers";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

// THIS IS DETERMINISTIC AND BASED ON THE KEY MATERIAL
let KEY_ID = "not-set-yet";
jwkToKeyID(jwk, helpers.WEBCRYPTO_SHA256, helpers.BASE64URL_DECODE).then(
  (kid) => (KEY_ID = kid)
);

const MAX_AGE_IN_MS = 1000 * 60 * 60; // 1 hour

class Ed25519Signer {
  public alg: Algorithm = "ed25519";
  public keyid: string;
  private privateKey: Uint8Array<ArrayBuffer>;

  constructor(public jwk: JsonWebKey) {
    const sodium = _sodium;

    // Base64URL decode helper
    const base64urlDecode = (str) =>
      sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);

    // Decode keys
    const privateKey = base64urlDecode(jwk.d); // 32 bytes
    const publicKey = base64urlDecode(jwk.x); // 32 bytes

    // Build the full 64-byte secret key: privateKey || publicKey
    const fullSecretKey = new Uint8Array(64);
    fullSecretKey.set(privateKey);
    fullSecretKey.set(publicKey, 32);

    this.privateKey = fullSecretKey;

    // NOTE: this MUST be computed from the public key bytes. It just so happen Chrome does not easily allow to perform a sha256 synchronously
    this.keyid = KEY_ID;
  }

  signSync(data: string): Uint8Array {
    const sodium = _sodium;
    const message = sodium.from_string(data);
    const signedMessage = sodium.crypto_sign(message, this.privateKey);
    return signedMessage.slice(0, sodium.crypto_sign_BYTES);
  }
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    const request = new Request(details.url, {
      method: details.method,
      // eslint-disable-next-line @typescript-eslint/no-non-null-asserted-optional-chain
      headers: details.requestHeaders?.map((h) => [h.name, h.value!])!,
    });
    const now = new Date();
    const headers = signatureHeadersSync(request, new Ed25519Signer(jwk), {
      created: now,
      expires: new Date(now.getTime() + MAX_AGE_IN_MS),
    });

    details.requestHeaders?.push({
      name: "Signature",
      value: headers["Signature"],
    });
    details.requestHeaders?.push({
      name: "Signature-Input",
      value: headers["Signature-Input"],
    });

    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

chrome.runtime.onStartup.addListener(() => {
  console.log(`onStartup()`);
});
