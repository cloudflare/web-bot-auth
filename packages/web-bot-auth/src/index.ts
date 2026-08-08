import * as FetchSig from "fetch-message-signatures";
export { jwkThumbprint as jwkToKeyID } from "jsonwebkey-thumbprint";

import { b64Tou8, u8ToB64 } from "./base64";
import type { KeyedSigner } from "./crypto";
export { helpers } from "./crypto";
export { HTTP_MESSAGE_SIGNATURES_DIRECTORY, MediaType, Tag } from "./consts";
export { directoryResponseHeaders, RESPONSE_COMPONENTS } from "./directory";

// The registry these identifiers come from is extensible, so this covers the initial entries only.
export type Algorithm =
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256"
  | "hmac-sha256"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ed25519";

export type { KeyedSigner, KeyedSigner as Signer } from "./crypto";

// The recipient contract callers have to satisfy, re-exported so that a consumer of verify() does
// not have to depend on fetch-message-signatures directly.
export type {
  MessageSignature,
  SynchronousVerifierFactory,
  VerifierFactory,
} from "fetch-message-signatures";

export const HTTP_MESSAGE_SIGNATURE_TAG = "web-bot-auth";
export const SIGNATURE_AGENT_HEADER = "signature-agent";
export const REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT: FetchSig.ComponentIdentifier[] =
  ["@authority"];
export const REQUEST_COMPONENTS: FetchSig.ComponentIdentifier[] = [
  "@authority",
  SIGNATURE_AGENT_HEADER,
];
export const NONCE_LENGTH_IN_BYTES = 64;

export interface SignatureHeaders {
  "Signature-Input": string;
  Signature: string;
}

export interface SignatureParams {
  created: Date;
  expires: Date;
  nonce?: string;
  key?: string;
  components?: FetchSig.ComponentIdentifier[];
}

export interface VerificationParams {
  keyid: string;
  created: Date;
  expires: Date;
  tag: string;
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

export function recommendedComponents(
  signatureAgentKey?: string
): FetchSig.ComponentIdentifier[] {
  if (signatureAgentKey) {
    return [
      "@authority",
      FetchSig.component(SIGNATURE_AGENT_HEADER, { key: signatureAgentKey }),
    ];
  }
  return ["@authority"];
}

function signatureAgentOf(message: Request | Response): string | null {
  return message.headers.get(SIGNATURE_AGENT_HEADER);
}

function signingComponents(
  message: Request | Response,
  params: SignatureParams
): FetchSig.ComponentIdentifier[] {
  const signatureAgent = signatureAgentOf(message);
  if (!params.components) {
    return signatureAgent
      ? REQUEST_COMPONENTS
      : REQUEST_COMPONENTS_WITHOUT_SIGNATURE_AGENT;
  }
  // findComponents rather than includesComponent: recommendedComponents() produces
  // `"signature-agent";key="sig1"`, and the rule is about the field being bound at all.
  if (
    signatureAgent &&
    FetchSig.findComponents(params.components, SIGNATURE_AGENT_HEADER)
      .length === 0
  ) {
    throw new Error(
      `${SIGNATURE_AGENT_HEADER} is required in params.components when included as a header param`
    );
  }
  return params.components;
}

interface ResolvedParams {
  components: FetchSig.ComponentIdentifier[];
  label: string;
  parameters: FetchSig.SignatureParameters;
}

function resolveParams(
  message: Request | Response,
  signer: KeyedSigner,
  params: SignatureParams
): ResolvedParams {
  if (params.created.getTime() > params.expires.getTime()) {
    throw new Error("created should happen before expires");
  }
  let nonce = params.nonce;
  if (!nonce) {
    nonce = generateNonce();
  } else if (!validateNonce(nonce)) {
    throw new Error("nonce is not a valid uint32");
  }

  return {
    components: signingComponents(message, params),
    label: params.key ?? "sig1",
    // Ordered, because RFC 9421 covers parameter order in the signature base.
    parameters: [
      ["created", params.created],
      ["keyid", signer.keyid],
      ["alg", signer.alg],
      ["expires", params.expires],
      ["nonce", nonce],
      ["tag", HTTP_MESSAGE_SIGNATURE_TAG],
    ],
  };
}

export function signatureHeaders(
  message: Request | Response,
  signer: KeyedSigner,
  params: SignatureParams
): Promise<SignatureHeaders> {
  // Resolved here so invalid arguments throw rather than rejecting.
  const resolved = resolveParams(message, signer, params);

  return createFields(message, signer, resolved);
}

/**
 * The synchronous counterpart of {@link signatureHeaders}, for callers that cannot await.
 *
 * A blocking `chrome.webRequest.onBeforeSendHeaders` listener is the motivating case: it has to
 * return the modified headers synchronously. createSignatureBase() and createSignatureFields() are
 * the two halves of createSignature(), neither of which returns a Promise, so the same components
 * and parameters go to both.
 *
 * The signer must be synchronous. Web Cryptography is not, so this needs a signer backed by a
 * synchronous library.
 */
export function signatureHeadersSync(
  message: Request | Response,
  signer: KeyedSigner,
  params: SignatureParams
): SignatureHeaders {
  const { components, label, parameters } = resolveParams(
    message,
    signer,
    params
  );

  const base = FetchSig.createSignatureBase(message, {
    components,
    parameters,
  });
  const signature = signer.signer().sign(new TextEncoder().encode(base));
  if (!(signature instanceof Uint8Array)) {
    throw new Error("signer is not synchronous");
  }

  const fields = FetchSig.createSignatureFields({
    signature,
    components,
    parameters,
    label,
  });

  return {
    "Signature-Input": fields.signatureInput,
    Signature: fields.signatureField,
  };
}

async function createFields(
  message: Request | Response,
  signer: KeyedSigner,
  resolved: ResolvedParams
): Promise<SignatureHeaders> {
  const fields = await FetchSig.createSignature(message, {
    signer: signer.signer,
    components: resolved.components,
    parameters: resolved.parameters,
    label: resolved.label,
  });

  return {
    "Signature-Input": fields.signatureInput,
    Signature: fields.signatureField,
  };
}

export async function verify(
  message: Request | Response,
  verifier: FetchSig.VerifierFactory,
  request?: Request
): Promise<void> {
  const signatureAgent = signatureAgentOf(message);

  await FetchSig.verify(message, {
    verifier,
    request,
    policy: {
      requiredComponents: [],
      requiredParameters: ["keyid", "created", "expires", "tag"],
      algorithms: ["ed25519", "rsa-pss-sha512"],
      validate(signature) {
        if (
          FetchSig.getSignatureParameter(signature, "tag") !==
          HTTP_MESSAGE_SIGNATURE_TAG
        ) {
          throw new Error(`tag must be '${HTTP_MESSAGE_SIGNATURE_TAG}'`);
        }
        // A signature that covers no request target can be replayed against any
        // endpoint. Require @authority or @target-uri, and signature-agent
        // whenever the header is present.
        //
        // findComponents rather than includesComponent, because a response
        // signature binds the request target as `"@authority";req`, which is a
        // different identifier but the same rule.
        const covered = signature.components;
        if (
          FetchSig.findComponents(covered, "@authority").length === 0 &&
          FetchSig.findComponents(covered, "@target-uri").length === 0
        ) {
          throw new Error("signature must cover @authority or @target-uri");
        }
        if (
          signatureAgent &&
          FetchSig.findComponents(covered, SIGNATURE_AGENT_HEADER).length === 0
        ) {
          throw new Error(
            `signature with ${SIGNATURE_AGENT_HEADER} header must cover ${SIGNATURE_AGENT_HEADER}`
          );
        }
      },
    },
  });
}

export interface Directory {
  keys: JsonWebKey[];
  purpose: string;
  schema?: string;
}

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
} from "./registry";
