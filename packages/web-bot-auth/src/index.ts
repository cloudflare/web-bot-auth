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
  readonly signatureAgentKey?: string;
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

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64Url(bytes: Uint8Array): string {
  return base64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64(value: string): Uint8Array | undefined {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  if (remainder === 1) return undefined;
  const padded = normalized + "=".repeat((4 - remainder) % 4);
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
  return base64(nonce);
}

export function validateNonce(nonce: unknown): nonce is string {
  if (typeof nonce !== "string") return false;
  const decoded = decodeBase64(nonce);
  return (
    decoded !== undefined &&
    decoded.length === NONCE_LENGTH_IN_BYTES &&
    (base64(decoded) === nonce || base64Url(decoded) === nonce)
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

interface SignatureAgentSelection {
  readonly component: SignatureComponent;
}

function signingSignatureAgent(
  request: Request | RequestDescriptor,
  key: string
): SignatureAgentSelection | undefined {
  const header = requestHeader(request, SIGNATURE_AGENT_HEADER);
  if (header === undefined) return undefined;
  const parsed = parseSignatureAgentHeader(header);
  if (parsed.kind === "legacy") {
    const entry = parsed.entries[0];
    if (entry === undefined) return policyError("Signature-Agent is empty");
    return Object.freeze({ component: SIGNATURE_AGENT_HEADER });
  }
  const entry = parsed.entries.find((candidate) => candidate.label === key);
  if (entry === undefined) {
    return policyError(`Signature-Agent has no member ${key}`);
  }
  return Object.freeze({
    component: component(SIGNATURE_AGENT_HEADER, { key }),
  });
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

function verifiedSignatureAgent(
  request: Request | RequestDescriptor,
  components: readonly ComponentDescriptor[]
): SignatureAgentEntry | undefined {
  const header = requestHeader(request, SIGNATURE_AGENT_HEADER);
  if (header === undefined) return undefined;
  const parsed = parseSignatureAgentHeader(header);
  if (parsed.kind === "legacy") {
    const covered = components.some(
      ({ name, parameters }) =>
        name === SIGNATURE_AGENT_HEADER && Object.keys(parameters).length === 0
    );
    if (!covered) {
      return policyError(`signature must cover ${SIGNATURE_AGENT_HEADER}`);
    }
    const entry = parsed.entries[0];
    if (entry === undefined) return policyError("Signature-Agent is empty");
    return Object.freeze({ ...entry });
  }
  const keys = components.flatMap(({ name, parameters }) => {
    const entries = Object.entries(parameters);
    return name === SIGNATURE_AGENT_HEADER &&
      entries.length === 1 &&
      typeof parameters.key === "string"
      ? [parameters.key]
      : [];
  });
  if (keys.length !== 1) {
    return policyError(
      `signature must cover exactly one ${SIGNATURE_AGENT_HEADER} member`
    );
  }
  const entry = parsed.entries.find((candidate) => candidate.label === keys[0]);
  if (entry === undefined) {
    return policyError(`Signature-Agent has no member ${keys[0]}`);
  }
  return Object.freeze({ ...entry });
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
      "nonce must be canonical base64 or unpadded base64url encoding of 64 bytes"
    );
  }
  const agent = signingSignatureAgent(
    request,
    options.signatureAgentKey ?? label
  );
  const components: SignatureComponent[] = [options.target ?? "@authority"];
  if (agent !== undefined) {
    components.push(agent.component);
  }
  components.push(...(options.additionalComponents ?? []));
  return {
    label,
    components,
    parameters: {
      created,
      keyid: options.signer.keyid,
      alg: options.signer.algorithm,
      expires,
      nonce: options.nonce,
      tag: HTTP_MESSAGE_SIGNATURE_TAG,
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
  const { algorithm, parameters, components } = candidate;
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
      "nonce must be canonical base64 or unpadded base64url encoding of 64 bytes"
    );
  }
  if (!hasExactBareTarget(components)) {
    return policyError(
      "signature must cover bare @authority or bare @target-uri"
    );
  }
  const agent = verifiedSignatureAgent(request, components);
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
