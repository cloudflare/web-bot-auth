import {
  component,
  createSignature,
  createSignatureSync,
  SignatureError,
  SignatureErrorCode,
  verifySignature,
  type ComponentDescriptor,
  type RequestDescriptor,
  type SignatureComponent,
  type SignatureFields,
  type Signer,
  type SignerSync,
  type UntrustedSignatureCandidate,
  type VerifiedSignature,
  type Verifier,
} from "http-message-sig";
import { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";
import {
  parseRegistry,
  parseSignatureAgentCard,
  parseSignatureAgentHeader,
  type JSONWebKeySet,
  type SignatureAgentCard,
  type SignatureAgentDiscoveryType,
  type SignatureAgentEntry,
  type SignatureAgentHeader,
  type WebBotAuthMetadata,
} from "./registry";

export { jwkToKeyID };
export {
  parseRegistry,
  parseSignatureAgentCard,
  parseSignatureAgentHeader,
  type JSONWebKeySet,
  type SignatureAgentCard,
  type SignatureAgentDiscoveryType,
  type SignatureAgentEntry,
  type SignatureAgentHeader,
  type WebBotAuthMetadata,
};
export type { RequestDescriptor, SignatureFields } from "http-message-sig";

export const HTTP_MESSAGE_SIGNATURE_TAG = "web-bot-auth";
export const SIGNATURE_AGENT_HEADER = "signature-agent";
export const HTTP_MESSAGE_SIGNATURES_DIRECTORY =
  "/.well-known/http-message-signatures-directory";
export const NONCE_LENGTH_IN_BYTES = 64;

export type WebBotAlgorithm = "ed25519" | "rsa-pss-sha512";

export interface WebBotSigner extends Signer {
  readonly algorithm: WebBotAlgorithm;
  readonly keyid: string;
}

export interface WebBotSignerSync extends SignerSync {
  readonly algorithm: WebBotAlgorithm;
  readonly keyid: string;
}

export interface WebBotVerifier extends Verifier {
  readonly algorithm: WebBotAlgorithm;
  readonly keyid: string;
}

export interface SignOptions {
  readonly signer: WebBotSigner;
  readonly expires: Date;
  readonly created?: Date;
  readonly nonce?: string;
  readonly label?: string;
  readonly target?: "@authority" | "@target-uri";
  readonly additionalComponents?: readonly SignatureComponent[];
}

export interface SignSyncOptions extends Omit<SignOptions, "signer"> {
  readonly signer: WebBotSignerSync;
}

export interface UntrustedWebBotSignatureCandidate {
  readonly keyid: string;
  readonly algorithm: WebBotAlgorithm;
  readonly signatureAgent?: SignatureAgentEntry;
}

export interface VerifiedWebBotSignature<
  V extends WebBotVerifier = WebBotVerifier,
> extends VerifiedSignature<V> {
  readonly keyid: string;
  readonly created: Date;
  readonly expires: Date;
  readonly tag: typeof HTTP_MESSAGE_SIGNATURE_TAG;
  readonly nonce?: string;
  readonly signatureAgent?: SignatureAgentEntry;
}

export interface VerifyOptions<V extends WebBotVerifier = WebBotVerifier> {
  readonly resolver: (
    candidate: UntrustedWebBotSignatureCandidate
  ) => V | Promise<V>;
  readonly algorithms?: readonly WebBotAlgorithm[];
  readonly label?: string;
  readonly maxAge?: number;
  readonly clockSkew?: number;
  readonly now?: Date;
  readonly validate?: (
    signature: VerifiedWebBotSignature<V>
  ) => boolean | void | Promise<boolean | void>;
}

function policyError(message: string): never {
  throw new SignatureError(SignatureErrorCode.PolicyViolation, message);
}

function seconds(date: Date, name: string): number {
  const milliseconds = date.getTime();
  if (!Number.isFinite(milliseconds)) {
    return policyError(`${name} must be a valid date`);
  }
  return Math.floor(milliseconds / 1000);
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  const remainder = value.length % 4;
  if (remainder === 1) return undefined;
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - remainder) % 4);
  try {
    return Uint8Array.from(atob(padded), (character) =>
      character.charCodeAt(0)
    );
  } catch {
    return undefined;
  }
}

export function generateNonce(): string {
  const nonce = new Uint8Array(NONCE_LENGTH_IN_BYTES);
  crypto.getRandomValues(nonce);
  return base64Url(nonce);
}

export function validateNonce(nonce: unknown): nonce is string {
  if (typeof nonce !== "string") return false;
  const decoded = decodeBase64Url(nonce);
  return (
    decoded !== undefined &&
    decoded.length === NONCE_LENGTH_IN_BYTES &&
    base64Url(decoded) === nonce
  );
}

function requestHeader(
  request: Request | RequestDescriptor,
  name: string
): string | undefined {
  if ("kind" in request) {
    const values = request.fields
      .filter((field) => field.name.toLowerCase() === name)
      .map((field) => field.value.trim());
    return values.length === 0 ? undefined : values.join(", ");
  }
  return request.headers.get(name) ?? undefined;
}

function signatureAgent(
  request: Request | RequestDescriptor,
  label: string
): SignatureAgentEntry | undefined {
  const header = requestHeader(request, SIGNATURE_AGENT_HEADER);
  if (header === undefined) return undefined;
  const parsed = parseSignatureAgentHeader(header);
  if (parsed.kind !== "current") {
    return policyError(
      "legacy Signature-Agent cannot be covered by dictionary member"
    );
  }
  const entry = parsed.entries.find((candidate) => candidate.label === label);
  if (entry === undefined) {
    return policyError(`Signature-Agent has no member ${label}`);
  }
  return Object.freeze({ ...entry });
}

function hasExactBareTarget(
  components: readonly ComponentDescriptor[]
): boolean {
  return components.some(
    ({ name, parameters }) =>
      (name === "@authority" || name === "@target-uri") &&
      Object.keys(parameters).length === 0
  );
}

function hasExactAgentComponent(
  components: readonly ComponentDescriptor[],
  label: string
): boolean {
  return components.some(({ name, parameters }) => {
    const entries = Object.entries(parameters);
    return (
      name === SIGNATURE_AGENT_HEADER &&
      entries.length === 1 &&
      parameters.key === label
    );
  });
}

function signingOptions(
  request: Request | RequestDescriptor,
  options: Omit<SignOptions, "signer"> & {
    readonly signer: Pick<WebBotSigner, "algorithm" | "keyid">;
  }
) {
  if (
    options.signer.algorithm !== "ed25519" &&
    options.signer.algorithm !== "rsa-pss-sha512"
  ) {
    return policyError("signer algorithm is unsupported");
  }
  if (options.signer.keyid === "") {
    return policyError("signer keyid must not be empty");
  }
  const label = options.label ?? "sig1";
  const created = seconds(options.created ?? new Date(), "created");
  const expires = seconds(options.expires, "expires");
  if (created > expires)
    return policyError("created must not be after expires");
  if (options.nonce !== undefined && !validateNonce(options.nonce)) {
    return policyError(
      "nonce must be canonical unpadded base64url encoding of 64 bytes"
    );
  }
  const agent = signatureAgent(request, label);
  const components: SignatureComponent[] = [options.target ?? "@authority"];
  if (agent !== undefined) {
    components.push(component(SIGNATURE_AGENT_HEADER, { key: label }));
  }
  components.push(...(options.additionalComponents ?? []));
  return {
    label,
    components,
    parameters: {
      created,
      expires,
      keyid: options.signer.keyid,
      alg: options.signer.algorithm,
      tag: HTTP_MESSAGE_SIGNATURE_TAG,
      nonce: options.nonce,
    },
  };
}

export async function sign(
  request: Request | RequestDescriptor,
  options: SignOptions
): Promise<SignatureFields> {
  return createSignature(request, {
    ...signingOptions(request, options),
    signer: options.signer,
  });
}

export function signSync(
  request: Request | RequestDescriptor,
  options: SignSyncOptions
): SignatureFields {
  return createSignatureSync(request, {
    ...signingOptions(request, options),
    signer: options.signer,
  });
}

function profileCandidate(
  request: Request | RequestDescriptor,
  candidate: UntrustedSignatureCandidate
): UntrustedWebBotSignatureCandidate {
  const { algorithm, parameters, components, label } = candidate;
  if (algorithm !== "ed25519" && algorithm !== "rsa-pss-sha512") {
    return policyError("signed algorithm is missing or unsupported");
  }
  const keyid = parameters.keyid;
  if (typeof keyid !== "string" || keyid === "") {
    return policyError("keyid must be a non-empty string");
  }
  if (parameters.tag !== HTTP_MESSAGE_SIGNATURE_TAG) {
    return policyError(`tag must be '${HTTP_MESSAGE_SIGNATURE_TAG}'`);
  }
  const created = parameters.created;
  const expires = parameters.expires;
  if (typeof created !== "number" || typeof expires !== "number") {
    return policyError("created and expires must be integers");
  }
  if (created > expires)
    return policyError("created must not be after expires");
  if (parameters.nonce !== undefined && !validateNonce(parameters.nonce)) {
    return policyError(
      "nonce must be canonical unpadded base64url encoding of 64 bytes"
    );
  }
  if (!hasExactBareTarget(components)) {
    return policyError(
      "signature must cover bare @authority or bare @target-uri"
    );
  }
  const agent = signatureAgent(request, label);
  if (agent !== undefined && !hasExactAgentComponent(components, label)) {
    return policyError(
      `signature must cover ${SIGNATURE_AGENT_HEADER} member ${label}`
    );
  }
  return Object.freeze({ keyid, algorithm, signatureAgent: agent });
}

export async function verify<V extends WebBotVerifier>(
  request: Request | RequestDescriptor,
  options: VerifyOptions<V>
): Promise<VerifiedWebBotSignature<V>> {
  const algorithms = options.algorithms ?? ["ed25519", "rsa-pss-sha512"];
  const now = seconds(options.now ?? new Date(), "now");
  let selected: UntrustedWebBotSignatureCandidate | undefined;
  const verified = await verifySignature(request, {
    label: options.label,
    policy: {
      algorithms,
      requiredComponents: [],
      requiredParameters: ["created", "expires", "keyid", "alg", "tag"],
      maxAge: options.maxAge ?? 86_400,
      clockSkew: options.clockSkew ?? 0,
      now,
    },
    async resolveVerifier(candidate) {
      const profile = profileCandidate(request, candidate);
      selected = profile;
      const verifier = await options.resolver(profile);
      if (verifier.keyid !== profile.keyid) {
        return policyError(
          "resolved verifier keyid does not match signed keyid"
        );
      }
      return verifier;
    },
  });
  if (selected === undefined) {
    return policyError("signature candidate was not resolved");
  }
  const authenticatedCreated = verified.parameters.created;
  const authenticatedExpires = verified.parameters.expires;
  if (
    typeof authenticatedCreated !== "number" ||
    typeof authenticatedExpires !== "number"
  ) {
    return policyError("authenticated signature lacks timestamps");
  }
  const result: VerifiedWebBotSignature<V> = Object.freeze({
    ...verified,
    keyid: selected.keyid,
    created: new Date(authenticatedCreated * 1000),
    expires: new Date(authenticatedExpires * 1000),
    tag: HTTP_MESSAGE_SIGNATURE_TAG,
    nonce: verified.parameters.nonce,
    signatureAgent: selected.signatureAgent,
  });
  if (
    options.validate !== undefined &&
    (await options.validate(result)) === false
  ) {
    return policyError("signature rejected by profile validation");
  }
  return result;
}
