import * as httpsig from "http-message-sig";
export {
  HTTP_MESSAGE_SIGNATURES_DIRECTORY,
  type Algorithm,
  MediaType,
  type SignatureHeaders,
  type Signer,
  type SignerSync,
  Tag,
  directoryResponseHeaders,
} from "http-message-sig";
export { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";

import { b64Tou8, u8ToB64 } from "./base64";
export { helpers } from "./crypto";

export const HTTP_MESSAGE_SIGNAGURE_TAG = "web-bot-auth";
export const SIGNATURE_AGENT_HEADER = "signature-agent";
export const REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT: httpsig.Component[] = [
  "@authority",
];
export const REQUEST_COMPONENTS: httpsig.Component[] = [
  "@authority",
  SIGNATURE_AGENT_HEADER,
];
export const NONCE_LENGTH_IN_BYTES = 64;

export interface SignatureParams {
  created: Date;
  expires: Date;
  nonce?: string;
  key?: string;
}

export interface VerificationParams {
  keyid: string;
  created: Date;
  expires: Date;
  tag: typeof HTTP_MESSAGE_SIGNAGURE_TAG;
  nonce?: string;
}

export function generateNonce(): string {
  const nonceBytes = new Uint8Array(NONCE_LENGTH_IN_BYTES);
  crypto.getRandomValues(nonceBytes);
  return u8ToB64(nonceBytes);
}

export function validateNonce(nonce: string): boolean {
  try {
    return b64Tou8(nonce).length === NONCE_LENGTH_IN_BYTES;
  } catch {
    return false;
  }
}

export function signatureHeaders<
  T extends httpsig.RequestLike | httpsig.ResponseLike,
>(
  message: T,
  signer: httpsig.Signer,
  params: SignatureParams
): Promise<httpsig.SignatureHeaders> {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }
  // Nonce should be a base64 encoded 64-byte array. We should check it
  let nonce = params.nonce;
  if (!nonce) {
    nonce = generateNonce();
  } else {
    if (!validateNonce(nonce)) {
      throw new Error("nonce is not a valid uint32");
    }
  }
  const signatureAgent = httpsig.extractHeader(message, SIGNATURE_AGENT_HEADER);
  let components: string[] = REQUEST_COMPONENTS;
  // not the ideal check, but extractHeader returns "" instead of throwing or null when the header does not exist
  if (!signatureAgent) {
    components = REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT;
  }
  return httpsig.signatureHeaders(message, {
    signer,
    components,
    created: params.created,
    expires: params.expires,
    nonce,
    keyid: signer.keyid,
    key: params.key,
    tag: HTTP_MESSAGE_SIGNAGURE_TAG,
  });
}

export function signatureHeadersSync<
  T extends httpsig.RequestLike | httpsig.ResponseLike,
>(
  message: T,
  signer: httpsig.SignerSync,
  params: SignatureParams
): httpsig.SignatureHeaders {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }
  let nonce = params.nonce;
  if (!nonce) {
    nonce = generateNonce();
  } else {
    if (!validateNonce(nonce)) {
      throw new Error("nonce is not a valid uint32");
    }
  }
  const signatureAgent = httpsig.extractHeader(message, SIGNATURE_AGENT_HEADER);
  let components: string[] = REQUEST_COMPONENTS;
  // not the ideal check, but extractHeader returns "" instead of throwing or null when the header does not exist
  if (!signatureAgent) {
    components = REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT;
  }
  return httpsig.signatureHeadersSync(message, {
    signer,
    components,
    created: params.created,
    expires: params.expires,
    nonce,
    keyid: signer.keyid,
    tag: HTTP_MESSAGE_SIGNAGURE_TAG,
  });
}

export type Verify<T> = (
  data: string,
  signature: Uint8Array,
  params: VerificationParams
) => T | Promise<T>;

export function verify<T>(
  message: httpsig.RequestLike | httpsig.ResponseLike,
  verifier: Verify<T>
): Promise<T> {
  const v = (
    data: string,
    signature: Uint8Array,
    params: httpsig.Parameters
  ): T | Promise<T> => {
    if (params.tag !== HTTP_MESSAGE_SIGNAGURE_TAG) {
      throw new Error(`tag must be '${HTTP_MESSAGE_SIGNAGURE_TAG}'`);
    }
    if (params.created.getTime() > Date.now()) {
      throw new Error("created in the future");
    }
    if (params.expires.getTime() < Date.now()) {
      throw new Error("signature has expired");
    }
    if (params.keyid === undefined) {
      throw new Error("keyid MUST be defined");
    }
    const vparams: VerificationParams = {
      keyid: params.keyid,
      created: params.created,
      expires: params.expires,
      tag: params.tag,
      nonce: params.nonce,
    };
    return verifier(data, signature, vparams);
  };
  return httpsig.verify(message, v);
}

export interface Directory extends httpsig.Directory {
  purpose: string;
}
