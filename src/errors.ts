export type FederationErrorCode =
  | "authentication-failed"
  | "downgrade-detected"
  | "expired"
  | "invalid-input"
  | "policy-rejected"
  | "replay"
  | "unsupported";

export class FederationError extends Error {
  readonly code: FederationErrorCode;

  constructor(code: FederationErrorCode, message: string) {
    super(message);
    this.name = "FederationError";
    this.code = code;
  }
}
