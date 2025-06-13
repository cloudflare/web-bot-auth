import { Tag } from "./consts";
import { signatureHeaders } from "./sign";
import { Component, RequestLike, SignatureHeaders, Signer } from "./types";

export const RESPONSE_COMPONENTS: Component[] = ["@authority"];

export interface SignatureParams {
  created: Date;
  expires: Date;
}

export async function directoryResponseHeaders<T1 extends RequestLike>(
  request: T1, // request is used to derive @authority for the response
  signers: Signer[],
  params: SignatureParams
): Promise<SignatureHeaders> {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }

  // TODO: consider validating the directory structure, and confirm we have one signer per key

  const components: string[] = RESPONSE_COMPONENTS;

  const headers = new Map<string, SignatureHeaders>();

  for (let i = 0; i < signers.length; i += 1) {
    // eslint-disable-next-line security/detect-object-injection
    const signer = signers[i];
    if (headers.has(signer.keyid)) {
      throw new Error(`Duplicated signer with keyid ${signer.keyid}`);
    }

    headers.set(
      signer.keyid,
      await signatureHeaders(request, {
        signer,
        components,
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
