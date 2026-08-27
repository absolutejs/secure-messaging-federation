import { FederationError } from "./errors";
import {
  FEDERATION_CONTRACT,
  type FederationLimits,
  type FederationOffer,
  type FederationProfile,
} from "./types";

const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}$/u;
const DOMAIN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

export const requireToken = (value: string, label: string): void => {
  if (!TOKEN.test(value))
    throw new FederationError("invalid-input", `${label} is invalid.`);
};

export const requireDomain = (value: string, label: string): void => {
  if (value !== value.toLowerCase() || !DOMAIN.test(value))
    throw new FederationError(
      "invalid-input",
      `${label} must be a canonical DNS domain.`,
    );
};

const requireUniqueTokens = (
  values: readonly string[],
  label: string,
): void => {
  if (values.length === 0 || new Set(values).size !== values.length)
    throw new FederationError(
      "invalid-input",
      `${label} must be non-empty and unique.`,
    );
  for (const value of values) requireToken(value, label);
};

export const validateProfile = (
  profile: FederationProfile,
  limits?: Pick<FederationLimits, "maximumFrameBytes">,
): void => {
  requireToken(profile.id, "Profile ID");
  requireToken(profile.e2eeProtocol, "E2EE protocol");
  requireToken(profile.federationProtocol, "Federation protocol");
  requireToken(profile.revision, "Protocol revision");
  requireUniqueTokens(profile.contentTypes, "Content types");
  if (new Set(profile.features).size !== profile.features.length)
    throw new FederationError("invalid-input", "Features must be unique.");
  for (const feature of profile.features) requireToken(feature, "Feature");
  if (
    !Number.isSafeInteger(profile.maximumFrameBytes) ||
    profile.maximumFrameBytes < 1 ||
    (limits !== undefined &&
      profile.maximumFrameBytes > limits.maximumFrameBytes)
  )
    throw new FederationError(
      "policy-rejected",
      "Profile frame limit is invalid.",
    );
  if (profile.security.mode === "managed-recovery")
    requireToken(profile.security.recoveryAuthority, "Recovery authority");
};

export const validateOffer = (
  offer: FederationOffer,
  now: number,
  limits: FederationLimits,
): void => {
  if (offer.contract !== FEDERATION_CONTRACT)
    throw new FederationError(
      "unsupported",
      "Federation contract is unsupported.",
    );
  requireDomain(offer.originDomain, "Origin domain");
  requireDomain(offer.destinationDomain, "Destination domain");
  requireToken(offer.offerId, "Offer ID");
  if (
    !Number.isSafeInteger(offer.createdAt) ||
    !Number.isSafeInteger(offer.expiresAt) ||
    offer.createdAt > now + limits.maximumClockSkewMs ||
    offer.expiresAt <= now ||
    offer.expiresAt - offer.createdAt > limits.maximumOfferTtlMs
  )
    throw new FederationError(
      "expired",
      "Federation offer violates time policy.",
    );
  if (
    offer.profiles.length === 0 ||
    new Set(offer.profiles.map(({ id }) => id)).size !== offer.profiles.length
  )
    throw new FederationError(
      "invalid-input",
      "Offer profiles must be non-empty and unique.",
    );
  for (const profile of offer.profiles) validateProfile(profile, limits);
};
