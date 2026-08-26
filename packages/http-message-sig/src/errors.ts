export const SignatureErrorCode = Object.freeze({
  MissingField: "MissingField",
  MalformedField: "MalformedField",
  LabelRequired: "LabelRequired",
  LabelMismatch: "LabelMismatch",
  DuplicateLabel: "DuplicateLabel",
  InvalidComponent: "InvalidComponent",
  DuplicateComponent: "DuplicateComponent",
  UnsupportedFeature: "UnsupportedFeature",
  AlgorithmMismatch: "AlgorithmMismatch",
  PolicyViolation: "PolicyViolation",
  VerificationFailed: "VerificationFailed",
  ResolverFailed: "ResolverFailed",
});

export type SignatureErrorCode =
  (typeof SignatureErrorCode)[keyof typeof SignatureErrorCode];

export class SignatureError extends Error {
  readonly code: SignatureErrorCode;
  readonly cause?: unknown;

  constructor(code: SignatureErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "SignatureError";
    this.code = code;
    this.cause = cause;
  }
}

export function isSignatureError(error: unknown): error is SignatureError {
  return error instanceof SignatureError;
}
