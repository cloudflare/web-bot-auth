import {
  Component,
  Parameters,
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
  SignatureHeaders,
  SignOptions,
  SignSyncOptions,
} from "./types";
import {
  buildSignatureInputString,
  buildSignedData,
  resolveMessageKind,
} from "./build";
import { encode as base64Encode } from "./base64";

const defaultRequestComponents: Component[] = [
  "@method",
  "@path",
  "@query",
  "@authority",
  "content-type",
  "digest",
];

const defaultResponseComponents: Component[] = [
  "@status",
  "content-type",
  "digest",
];

export async function signatureHeaders<
  T extends RequestLike | ResponseLike | ResponseRequestPair,
>(message: T, opts: SignOptions): Promise<SignatureHeaders> {
  const { signer, components: _components, key: _key, ...params } = opts;

  const components =
    _components ??
    ("status" in resolveMessageKind(message)
      ? defaultResponseComponents
      : defaultRequestComponents);
  const key = _key ?? "sig1";

  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
    ...(params as Parameters),
  };

  const signatureInputString = buildSignatureInputString(
    components,
    signParams
  );
  const dataToSign = buildSignedData(message, components, signatureInputString);

  const signature = await signer.sign(dataToSign);
  const sigBase64 = base64Encode(signature);

  return {
    Signature: `${key}=:${sigBase64}:`,
    "Signature-Input": `${key}=${signatureInputString}`,
  };
}

export function signatureHeadersSync<
  T extends RequestLike | ResponseLike | ResponseRequestPair,
>(message: T, opts: SignSyncOptions): SignatureHeaders {
  const { signer, components: _components, key: _key, ...params } = opts;

  const components =
    _components ??
    ("status" in resolveMessageKind(message)
      ? defaultResponseComponents
      : defaultRequestComponents);
  const key = _key ?? "sig1";

  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
    ...(params as Parameters),
  };

  const signatureInputString = buildSignatureInputString(
    components,
    signParams
  );
  const dataToSign = buildSignedData(message, components, signatureInputString);

  const signature = signer.signSync(dataToSign);
  const sigBase64 = base64Encode(signature);

  return {
    Signature: `${key}=:${sigBase64}:`,
    "Signature-Input": `${key}=${signatureInputString}`,
  };
}
