import { canonicalBytes } from "./canonical";
import { FederationError } from "./errors";
import {
  FEDERATION_CONTRACT,
  type FederationEnvelope,
  type FederationLimits,
  type FederationReplayStore,
  type FederationSession,
  type FederationSignatureProvider,
  type SignedFederationEnvelope,
} from "./types";
import { requireDomain, requireToken } from "./validation";

const validateEnvelope = (input: {
  readonly envelope: FederationEnvelope;
  readonly expectedDestinationDomain: string;
  readonly expectedOriginDomain: string;
  readonly limits: FederationLimits;
  readonly now: number;
  readonly session: FederationSession;
}): void => {
  const {
    envelope,
    expectedDestinationDomain,
    expectedOriginDomain,
    limits,
    now,
    session,
  } = input;
  if (envelope.contract !== FEDERATION_CONTRACT)
    throw new FederationError(
      "unsupported",
      "Envelope contract is unsupported.",
    );
  requireDomain(envelope.originDomain, "Origin domain");
  requireDomain(envelope.destinationDomain, "Destination domain");
  requireToken(envelope.id, "Envelope ID");
  requireToken(envelope.routeId, "Route ID");
  if (
    envelope.destinationDomain !== expectedDestinationDomain ||
    envelope.originDomain !== expectedOriginDomain ||
    envelope.sessionId !== session.sessionId ||
    envelope.transcriptHash !== session.transcriptHash ||
    ![session.initiatorDomain, session.responderDomain].includes(
      envelope.originDomain,
    ) ||
    envelope.originDomain === envelope.destinationDomain
  )
    throw new FederationError(
      "authentication-failed",
      "Envelope routing or session binding is invalid.",
    );
  if (
    envelope.payload.length === 0 ||
    envelope.payload.length > limits.maximumFrameBytes ||
    envelope.payload.length > session.profile.maximumFrameBytes
  )
    throw new FederationError(
      "policy-rejected",
      "Envelope exceeds frame policy.",
    );
  if (
    !Number.isSafeInteger(envelope.createdAt) ||
    !Number.isSafeInteger(envelope.expiresAt) ||
    envelope.createdAt > now + limits.maximumClockSkewMs ||
    envelope.expiresAt <= now ||
    envelope.expiresAt > session.expiresAt ||
    envelope.expiresAt - envelope.createdAt > limits.maximumTtlMs
  )
    throw new FederationError("expired", "Envelope violates time policy.");
};

export const signFederationEnvelope = async (input: {
  readonly envelope: FederationEnvelope;
  readonly limits: FederationLimits;
  readonly localDomain: string;
  readonly now: number;
  readonly session: FederationSession;
  readonly signatureProvider: FederationSignatureProvider;
}): Promise<SignedFederationEnvelope> => {
  const destinationDomain =
    input.session.initiatorDomain === input.localDomain
      ? input.session.responderDomain
      : input.session.initiatorDomain;
  validateEnvelope({
    envelope: input.envelope,
    expectedDestinationDomain: destinationDomain,
    expectedOriginDomain: input.localDomain,
    limits: input.limits,
    now: input.now,
    session: input.session,
  });
  return Object.freeze({
    envelope: input.envelope,
    signature: await input.signatureProvider.sign({
      destinationDomain: input.envelope.destinationDomain,
      payload: canonicalBytes(input.envelope),
      purpose: "federation-envelope",
    }),
  });
};

export const verifyFederationEnvelope = async (input: {
  readonly limits: FederationLimits;
  readonly localDomain: string;
  readonly now: number;
  readonly replayStore: FederationReplayStore;
  readonly session: FederationSession;
  readonly signatureProvider: FederationSignatureProvider;
  readonly signed: SignedFederationEnvelope;
}): Promise<FederationEnvelope> => {
  const envelope = input.signed.envelope;
  const originDomain =
    input.session.initiatorDomain === input.localDomain
      ? input.session.responderDomain
      : input.session.initiatorDomain;
  validateEnvelope({
    envelope,
    expectedDestinationDomain: input.localDomain,
    expectedOriginDomain: originDomain,
    limits: input.limits,
    now: input.now,
    session: input.session,
  });
  if (
    !(await input.signatureProvider.verify({
      expectedDomain: envelope.originDomain,
      payload: canonicalBytes(envelope),
      purpose: "federation-envelope",
      signature: input.signed.signature,
    }))
  )
    throw new FederationError(
      "authentication-failed",
      "Envelope signature is invalid.",
    );
  if (
    (await input.replayStore.claim({
      expiresAt: envelope.expiresAt,
      id: envelope.id,
      originDomain: envelope.originDomain,
      sessionId: envelope.sessionId,
    })) !== "claimed"
  )
    throw new FederationError(
      "replay",
      "Federation envelope was already processed.",
    );
  return envelope;
};
