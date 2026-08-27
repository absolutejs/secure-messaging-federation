import { FederationError } from "./errors";
import {
  FEDERATION_CONTRACT,
  type FederationAbuseAuthorization,
  type FederationAbuseEvidenceProvider,
  type FederationAbuseReason,
  type FederationAbuseReport,
} from "./types";
import { requireToken } from "./validation";

const reasons = new Set<FederationAbuseReason>([
  "child-safety",
  "fraud",
  "harassment",
  "impersonation",
  "malware",
  "spam",
  "threat",
]);

const validateAuthorization = (
  authorization: FederationAbuseAuthorization,
): void => {
  if (authorization.method === "user-approved")
    requireToken(authorization.approvalId, "Approval ID");
  else requireToken(authorization.mandateId, "Mandate ID");
};

export const createFederationAbuseReport = async (input: {
  readonly allegedSender: string;
  readonly authorization: FederationAbuseAuthorization;
  readonly createdAt: number;
  readonly evidence: Uint8Array;
  readonly evidenceProvider: FederationAbuseEvidenceProvider;
  readonly expiresAt: number;
  readonly maximumEvidenceBytes: number;
  readonly maximumSealedEvidenceBytes: number;
  readonly maximumTtlMs: number;
  readonly messageIds: readonly string[];
  readonly reason: FederationAbuseReason;
  readonly recipientKeyId: string;
  readonly reportId: string;
  readonly roomId: string;
}): Promise<FederationAbuseReport> => {
  validateAuthorization(input.authorization);
  requireToken(input.reportId, "Report ID");
  requireToken(input.roomId, "Room ID");
  requireToken(input.recipientKeyId, "Evidence recipient key ID");
  requireToken(input.allegedSender, "Alleged sender");
  if (!reasons.has(input.reason))
    throw new FederationError("invalid-input", "Abuse reason is invalid.");
  if (
    input.messageIds.length === 0 ||
    new Set(input.messageIds).size !== input.messageIds.length
  )
    throw new FederationError(
      "invalid-input",
      "Message IDs must be non-empty and unique.",
    );
  for (const messageId of input.messageIds)
    requireToken(messageId, "Message ID");
  if (
    input.evidence.length === 0 ||
    input.evidence.length > input.maximumEvidenceBytes
  )
    throw new FederationError(
      "policy-rejected",
      "Evidence exceeds local policy.",
    );
  if (
    !Number.isSafeInteger(input.createdAt) ||
    !Number.isSafeInteger(input.expiresAt) ||
    input.expiresAt <= input.createdAt ||
    input.expiresAt - input.createdAt > input.maximumTtlMs
  )
    throw new FederationError("expired", "Abuse report violates time policy.");
  const evidence = await input.evidenceProvider.seal({
    allegedSender: input.allegedSender,
    authorization: input.authorization,
    evidence: input.evidence,
    messageIds: input.messageIds,
    recipientKeyId: input.recipientKeyId,
    reportId: input.reportId,
  });
  if (
    evidence.bytes.length === 0 ||
    evidence.bytes.length > input.maximumSealedEvidenceBytes ||
    evidence.providerId !== input.evidenceProvider.id ||
    evidence.recipientKeyId !== input.recipientKeyId
  )
    throw new FederationError(
      "authentication-failed",
      "Evidence provider returned invalid or oversized binding.",
    );
  return Object.freeze({
    allegedSender: input.allegedSender,
    authorization: input.authorization,
    contract: FEDERATION_CONTRACT,
    createdAt: input.createdAt,
    evidence,
    expiresAt: input.expiresAt,
    messageIds: Object.freeze([...input.messageIds]),
    reason: input.reason,
    reportId: input.reportId,
    roomId: input.roomId,
  });
};
