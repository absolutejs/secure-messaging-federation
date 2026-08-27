import { canonicalBytes, digestCanonical, toBase64Url } from "./canonical";
import { FederationError } from "./errors";
import {
  FEDERATION_CONTRACT,
  type FederationConfirmation,
  type FederationLimits,
  type FederationOffer,
  type FederationProfile,
  type FederationSession,
  type FederationSignatureProvider,
  type FederationTranscript,
} from "./types";
import { requireToken, validateOffer } from "./validation";

const sameProfile = (
  left: FederationProfile,
  right: FederationProfile,
): boolean =>
  toBase64Url(canonicalBytes(left)) === toBase64Url(canonicalBytes(right));

export const negotiateFederation = async (input: {
  readonly initiatorOffer: FederationOffer;
  readonly limits: FederationLimits;
  readonly now: number;
  readonly preferredProfileIds: readonly string[];
  readonly responderOffer: FederationOffer;
  readonly sessionId: string;
}): Promise<FederationTranscript> => {
  validateOffer(input.initiatorOffer, input.now, input.limits);
  validateOffer(input.responderOffer, input.now, input.limits);
  requireToken(input.sessionId, "Session ID");
  const initiator = input.initiatorOffer;
  const responder = input.responderOffer;
  if (
    initiator.role !== "initiator" ||
    responder.role !== "responder" ||
    initiator.originDomain !== responder.destinationDomain ||
    initiator.destinationDomain !== responder.originDomain
  )
    throw new FederationError(
      "authentication-failed",
      "Offer roles or domains do not match.",
    );
  const preference = new Map(
    input.preferredProfileIds.map((id, index) => [id, index]),
  );
  const shared = initiator.profiles
    .filter((profile) =>
      responder.profiles.some(
        (candidate) =>
          candidate.id === profile.id && sameProfile(candidate, profile),
      ),
    )
    .filter(({ id }) => preference.has(id))
    .sort(
      (left, right) =>
        (preference.get(left.id) ?? Number.MAX_SAFE_INTEGER) -
        (preference.get(right.id) ?? Number.MAX_SAFE_INTEGER),
    );
  const profile = shared[0];
  if (profile === undefined)
    throw new FederationError(
      "unsupported",
      "No exactly matching, locally preferred federation profile exists.",
    );
  return Object.freeze({
    contract: FEDERATION_CONTRACT,
    initiatorOfferHash: await digestCanonical(initiator),
    profile,
    responderOfferHash: await digestCanonical(responder),
    sessionId: input.sessionId,
  });
};

export const confirmFederationTranscript = async (input: {
  readonly destinationDomain: string;
  readonly domain: string;
  readonly signatureProvider: FederationSignatureProvider;
  readonly transcript: FederationTranscript;
}): Promise<FederationConfirmation> => {
  const transcriptHash = await digestCanonical(input.transcript);
  return Object.freeze({
    domain: input.domain,
    signature: await input.signatureProvider.sign({
      destinationDomain: input.destinationDomain,
      payload: canonicalBytes(input.transcript),
      purpose: "federation-transcript",
    }),
    transcriptHash,
  });
};

export const activateFederationSession = async (input: {
  readonly initiatorConfirmation: FederationConfirmation;
  readonly initiatorOffer: FederationOffer;
  readonly now: number;
  readonly responderConfirmation: FederationConfirmation;
  readonly responderOffer: FederationOffer;
  readonly signatureProvider: FederationSignatureProvider;
  readonly transcript: FederationTranscript;
}): Promise<FederationSession> => {
  const transcriptHash = await digestCanonical(input.transcript);
  const [initiatorOfferHash, responderOfferHash] = await Promise.all([
    digestCanonical(input.initiatorOffer),
    digestCanonical(input.responderOffer),
  ]);
  const payload = canonicalBytes(input.transcript);
  const initiatorDomain = input.initiatorOffer.originDomain;
  const responderDomain = input.responderOffer.originDomain;
  if (
    input.initiatorOffer.role !== "initiator" ||
    input.responderOffer.role !== "responder" ||
    input.initiatorOffer.destinationDomain !== responderDomain ||
    input.responderOffer.destinationDomain !== initiatorDomain ||
    input.transcript.contract !== FEDERATION_CONTRACT ||
    input.transcript.initiatorOfferHash !== initiatorOfferHash ||
    input.transcript.responderOfferHash !== responderOfferHash ||
    !input.initiatorOffer.profiles.some((profile) =>
      sameProfile(profile, input.transcript.profile),
    ) ||
    !input.responderOffer.profiles.some((profile) =>
      sameProfile(profile, input.transcript.profile),
    ) ||
    input.initiatorConfirmation.domain !== initiatorDomain ||
    input.responderConfirmation.domain !== responderDomain ||
    input.initiatorConfirmation.transcriptHash !== transcriptHash ||
    input.responderConfirmation.transcriptHash !== transcriptHash
  )
    throw new FederationError(
      "downgrade-detected",
      "Transcript confirmation or bound offer does not match.",
    );
  const [initiatorValid, responderValid] = await Promise.all([
    input.signatureProvider.verify({
      expectedDomain: initiatorDomain,
      payload,
      purpose: "federation-transcript",
      signature: input.initiatorConfirmation.signature,
    }),
    input.signatureProvider.verify({
      expectedDomain: responderDomain,
      payload,
      purpose: "federation-transcript",
      signature: input.responderConfirmation.signature,
    }),
  ]);
  if (!initiatorValid || !responderValid)
    throw new FederationError(
      "authentication-failed",
      "Transcript signature is invalid.",
    );
  const expiresAt = Math.min(
    input.initiatorOffer.expiresAt,
    input.responderOffer.expiresAt,
  );
  if (expiresAt <= input.now)
    throw new FederationError(
      "expired",
      "Federation session negotiation expired.",
    );
  return Object.freeze({
    expiresAt,
    initiatorDomain,
    profile: input.transcript.profile,
    responderDomain,
    sessionId: input.transcript.sessionId,
    transcriptHash,
  });
};
