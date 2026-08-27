import { FederationError } from "./errors";

const encoder = new TextEncoder();

const canonicalize = (value: unknown): unknown => {
  if (value instanceof Uint8Array) return { $bytes: toBase64Url(value) };
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, canonicalize(entry)]),
    );
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value))
  )
    return value;
  throw new FederationError(
    "invalid-input",
    "Value cannot be canonically encoded.",
  );
};

export const toBase64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

export const canonicalBytes = (value: unknown): Uint8Array =>
  encoder.encode(JSON.stringify(canonicalize(value)));

export const digestCanonical = async (value: unknown): Promise<string> =>
  toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        Uint8Array.from(canonicalBytes(value)),
      ),
    ),
  );
