import * as FetchSig from "fetch-message-signatures";

import { Tag } from "./consts";
import type { KeyedSigner } from "./crypto";
import type { SignatureHeaders } from "./index";

/**
 * A directory response is signed over the authority of the request that asked for it, so `;req`
 * binds the covered value to the related request rather than the response.
 */
export const RESPONSE_COMPONENTS: FetchSig.ComponentIdentifier[] = [
  FetchSig.component("@authority", { req: true }),
];

export interface SignatureParams {
  created: Date;
  expires: Date;
}

/**
 * Signs a directory response once per key and returns the combined fields.
 *
 * Each signature is appended under its own label, which is how RFC 9421 Section 4.3 carries more
 * than one signature on a message.
 */
export async function directoryResponseHeaders(
  message: { request: Request; response: Response },
  signers: KeyedSigner[],
  params: SignatureParams
): Promise<SignatureHeaders> {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }

  const seen = new Set<string>();
  let headers = new Headers();

  for (const [index, signer] of signers.entries()) {
    if (seen.has(signer.keyid)) {
      throw new Error(`Duplicated signer with keyid ${signer.keyid}`);
    }
    seen.add(signer.keyid);

    const fields = await FetchSig.createSignature(message.response, {
      request: message.request,
      signer: signer.signer,
      components: RESPONSE_COMPONENTS,
      parameters: [
        ["created", params.created],
        ["keyid", signer.keyid],
        ["alg", signer.alg],
        ["expires", params.expires],
        ["tag", Tag.HTTP_MESSAGE_SIGNAGURES_DIRECTORY],
      ],
      label: `binding${index}`,
    });
    headers = FetchSig.appendSignature(headers, fields);
  }

  return {
    "Signature-Input": headers.get("signature-input") ?? "",
    Signature: headers.get("signature") ?? "",
  };
}
