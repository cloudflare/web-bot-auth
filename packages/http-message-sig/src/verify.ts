import {
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
  Verify,
} from "./types";
import { parseSignatureHeader, parseSignatureInputHeader } from "./parse";
import { buildSignedData, extractHeader, resolveMessageKind } from "./build";

export async function verify<T>(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  verifier: Verify<T>
): Promise<T> {
  const signatureInputHeader = extractHeader(
    resolveMessageKind(message),
    "signature-input"
  );
  if (!signatureInputHeader)
    throw new Error("Message does not contain Signature-Input header");
  const { key, components, parameters } =
    parseSignatureInputHeader(signatureInputHeader);

  if (parameters.expires && parameters.expires < new Date())
    throw new Error("Signature expired");

  const signatureHeader = extractHeader(
    resolveMessageKind(message),
    "signature"
  );
  if (!signatureHeader)
    throw new Error("Message does not contain Signature header");
  const signature = parseSignatureHeader(key, signatureHeader);

  const signatureInputString = signatureInputHeader
    .toString()
    .replace(/^[^=]+=/, "");
  const signedData = buildSignedData(message, components, signatureInputString);

  return verifier(signedData, signature, parameters);
}
