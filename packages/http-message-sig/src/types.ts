// HTTP Message Signatures Algorithms Registry at IANA
// https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-algorithms
export type Algorithm =
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256"
  | "hmac-sha256"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ed25519";

export interface Signer {
  sign: (data: string) => Uint8Array | Promise<Uint8Array>;
  keyid: string;
  alg: Algorithm;
}

export interface SignerSync {
  signSync: (data: string) => Uint8Array;
  keyid: string;
  alg: Algorithm;
}

export type Verify<T> = (
  data: string,
  signature: Uint8Array,
  params: Parameters
) => T | Promise<T>;

interface HeadersMap {
  get(name: string): string | null;
  set(name: string, value: string): void;
}

type Headers = Record<string, HeaderValue> | HeadersMap;

export type HeaderValue = { toString(): string } | string | string[];

export interface RequestLike {
  method: string;
  url: string;
  protocol?: string;
  headers: Headers;
}

export interface ResponseLike {
  status: number;
  headers: Headers;
}

// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-06#section-2.3.1
export type Parameter =
  | "created"
  | "expires"
  | "nonce"
  | "alg"
  | "keyid"
  | string;

export interface StructuredFieldComponent {
  header: string;
  key: string;
}

export type Component =
  | "@method"
  | "@target-uri"
  | "@authority"
  | "@scheme"
  | "@request-target"
  | "@path"
  | "@query"
  | "@query-param"
  | "@status"
  | "@request-response"
  | string
  | StructuredFieldComponent;

interface StandardParameters {
  expires?: Date;
  created?: Date;
  nonce?: string;
  alg?: string;
  keyid?: string;
  tag?: string;
}

export type Parameters = StandardParameters &
  Record<
    Parameter,
    string | number | true | Date | { [Symbol.toStringTag]: () => string }
  >;

export type SignOptions = StandardParameters & {
  components?: Component[];
  key?: string;
  signer: Signer;
  [name: Parameter]:
    | Component[]
    | Signer
    | string
    | number
    | true
    | Date
    | { [Symbol.toStringTag]: () => string }
    | undefined;
};

export type SignSyncOptions = StandardParameters & {
  components?: Component[];
  key?: string;
  signer: SignerSync;
  [name: Parameter]:
    | Component[]
    | SignerSync
    | string
    | number
    | true
    | Date
    | { [Symbol.toStringTag]: () => string }
    | undefined;
};

export interface SignatureHeaders {
  Signature: string;
  "Signature-Input": string;
}

export interface Directory {
  keys: JsonWebKey[];
}
