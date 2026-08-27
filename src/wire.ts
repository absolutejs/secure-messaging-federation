import { FederationError } from "./errors";
import {
  FEDERATION_CONTRACT,
  type FederationEnvelope,
  type FederationSignature,
  type SignedFederationEnvelope,
} from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const ENVELOPE_KEYS = [
  "contract",
  "createdAt",
  "destinationDomain",
  "expiresAt",
  "id",
  "kind",
  "originDomain",
  "payload",
  "routeId",
  "sessionId",
  "transcriptHash",
] as const;
const SIGNATURE_KEYS = ["algorithm", "keyId", "signature"] as const;
const ROOT_KEYS = ["envelope", "signature"] as const;
const kinds = new Set(["application", "commit", "proposal", "welcome"]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const hasExactKeys = (
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean =>
  Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");

const requireString = (value: Record<string, unknown>, key: string): string => {
  const result = value[key];
  if (typeof result !== "string" || result.length === 0)
    throw new FederationError(
      "invalid-input",
      `${key} must be a non-empty string.`,
    );
  return result;
};

const requireInteger = (
  value: Record<string, unknown>,
  key: string,
): number => {
  const result = value[key];
  if (typeof result !== "number" || !Number.isSafeInteger(result))
    throw new FederationError(
      "invalid-input",
      `${key} must be a safe integer.`,
    );
  return result;
};

const toBase64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

const fromBase64Url = (value: string, maximumBytes: number): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value))
    throw new FederationError(
      "invalid-input",
      "Binary value is not base64url.",
    );
  const maximumEncodedLength = Math.ceil(maximumBytes / 3) * 4;
  if (value.length > maximumEncodedLength)
    throw new FederationError(
      "policy-rejected",
      "Binary value exceeds its limit.",
    );
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  let decoded: Uint8Array;
  try {
    const binary = atob(
      value.replaceAll("-", "+").replaceAll("_", "/") + padding,
    );
    decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new FederationError(
      "invalid-input",
      "Binary value is not base64url.",
    );
  }
  if (
    decoded.length === 0 ||
    decoded.length > maximumBytes ||
    toBase64Url(decoded) !== value
  )
    throw new FederationError(
      "invalid-input",
      "Binary value is empty or non-canonical.",
    );
  return decoded;
};

export const encodeSignedFederationEnvelope = (
  signed: SignedFederationEnvelope,
): Uint8Array =>
  encoder.encode(
    JSON.stringify({
      envelope: {
        ...signed.envelope,
        payload: toBase64Url(signed.envelope.payload),
      },
      signature: {
        ...signed.signature,
        signature: toBase64Url(signed.signature.signature),
      },
    }),
  );

export const decodeSignedFederationEnvelope = (
  bytes: Uint8Array,
  limits: {
    readonly maximumEnvelopeBytes: number;
    readonly maximumPayloadBytes: number;
    readonly maximumSignatureBytes: number;
  },
): SignedFederationEnvelope => {
  if (
    !Number.isSafeInteger(limits.maximumEnvelopeBytes) ||
    !Number.isSafeInteger(limits.maximumPayloadBytes) ||
    !Number.isSafeInteger(limits.maximumSignatureBytes) ||
    limits.maximumEnvelopeBytes < 1 ||
    limits.maximumPayloadBytes < 1 ||
    limits.maximumSignatureBytes < 1 ||
    bytes.length === 0 ||
    bytes.length > limits.maximumEnvelopeBytes
  )
    throw new FederationError(
      "policy-rejected",
      "Federation wire envelope exceeds policy.",
    );
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new FederationError(
      "invalid-input",
      "Federation wire envelope is not valid JSON.",
    );
  }
  if (!isRecord(parsed) || !hasExactKeys(parsed, ROOT_KEYS))
    throw new FederationError(
      "invalid-input",
      "Federation wire envelope has unknown fields.",
    );
  const rawEnvelope = parsed.envelope;
  const rawSignature = parsed.signature;
  if (
    !isRecord(rawEnvelope) ||
    !hasExactKeys(rawEnvelope, ENVELOPE_KEYS) ||
    !isRecord(rawSignature) ||
    !hasExactKeys(rawSignature, SIGNATURE_KEYS)
  )
    throw new FederationError(
      "invalid-input",
      "Federation wire fields are invalid.",
    );
  const contract = requireInteger(rawEnvelope, "contract");
  const kind = requireString(rawEnvelope, "kind");
  if (contract !== FEDERATION_CONTRACT || !kinds.has(kind))
    throw new FederationError(
      "unsupported",
      "Federation wire contract or kind is unsupported.",
    );
  const envelope: FederationEnvelope = {
    contract: FEDERATION_CONTRACT,
    createdAt: requireInteger(rawEnvelope, "createdAt"),
    destinationDomain: requireString(rawEnvelope, "destinationDomain"),
    expiresAt: requireInteger(rawEnvelope, "expiresAt"),
    id: requireString(rawEnvelope, "id"),
    kind: kind as FederationEnvelope["kind"],
    originDomain: requireString(rawEnvelope, "originDomain"),
    payload: fromBase64Url(
      requireString(rawEnvelope, "payload"),
      limits.maximumPayloadBytes,
    ),
    routeId: requireString(rawEnvelope, "routeId"),
    sessionId: requireString(rawEnvelope, "sessionId"),
    transcriptHash: requireString(rawEnvelope, "transcriptHash"),
  };
  const signature: FederationSignature = {
    algorithm: requireString(rawSignature, "algorithm"),
    keyId: requireString(rawSignature, "keyId"),
    signature: fromBase64Url(
      requireString(rawSignature, "signature"),
      limits.maximumSignatureBytes,
    ),
  };
  return Object.freeze({
    envelope: Object.freeze(envelope),
    signature: Object.freeze(signature),
  });
};
