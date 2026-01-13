import { Tag } from "./consts";
import { signatureHeaders } from "./sign";
import {
  Component,
  ResponseRequestPair,
  SignatureHeaders,
  Signer,
} from "./types";

export const RESPONSE_COMPONENTS: Component[] = [
  {
    name: "@authority",
    parameters: new Map([["req", true]]),
  },
];

export interface SignatureParams {
  created: Date;
  expires: Date;
}

export async function directoryResponseHeaders(
  message: ResponseRequestPair,
  signers: Signer[],
  params: SignatureParams
): Promise<SignatureHeaders> {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }

  // TODO: consider validating the directory structure, and confirm we have one signer per key
  const headers = new Map<string, SignatureHeaders>();

  for (let i = 0; i < signers.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection
    const signer = signers[i];
    if (headers.has(signer.keyid)) {
      throw new Error(`Duplicated signer with keyid ${signer.keyid}`);
    }

    headers.set(
      signer.keyid,
      await signatureHeaders(message, {
        signer,
        components: RESPONSE_COMPONENTS,
        created: params.created,
        expires: params.expires,
        keyid: signer.keyid,
        key: `binding${i}`,
        tag: Tag.HTTP_MESSAGE_SIGNAGURES_DIRECTORY,
      })
    );
  }

  const SF_SEPARATOR = ", ";
  // Providing multiple signature as described in Section 4.3 of RFC 9421
  // https://datatracker.ietf.org/doc/html/rfc9421#name-multiple-signatures
  return {
    Signature: Array.from(headers.values())
      .map((h) => h.Signature)
      .join(SF_SEPARATOR),
    "Signature-Input": Array.from(headers.values())
      .map((h) => h["Signature-Input"])
      .join(SF_SEPARATOR),
  };
}
