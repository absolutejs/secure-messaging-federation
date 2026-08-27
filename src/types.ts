export const FEDERATION_CONTRACT = 1 as const;

export type FederationSecurityMode =
  | { readonly mode: "strict-e2ee" }
  | {
      readonly mode: "managed-recovery";
      readonly recoveryAuthority: string;
    };

export type FederationProfile = {
  readonly contentTypes: readonly string[];
  readonly e2eeProtocol: string;
  readonly features: readonly string[];
  readonly federationProtocol: string;
  readonly id: string;
  readonly maximumFrameBytes: number;
  readonly revision: string;
  readonly security: FederationSecurityMode;
};

export type FederationOffer = {
  readonly contract: typeof FEDERATION_CONTRACT;
  readonly createdAt: number;
  readonly destinationDomain: string;
  readonly expiresAt: number;
  readonly offerId: string;
  readonly originDomain: string;
  readonly profiles: readonly FederationProfile[];
  readonly role: "initiator" | "responder";
};

export type FederationTranscript = {
  readonly contract: typeof FEDERATION_CONTRACT;
  readonly initiatorOfferHash: string;
  readonly profile: FederationProfile;
  readonly responderOfferHash: string;
  readonly sessionId: string;
};

export type FederationSignature = {
  readonly algorithm: string;
  readonly keyId: string;
  readonly signature: Uint8Array;
};

export type FederationConfirmation = {
  readonly domain: string;
  readonly signature: FederationSignature;
  readonly transcriptHash: string;
};

export type FederationSignatureProvider = {
  readonly id: string;
  readonly sign: (input: {
    readonly destinationDomain: string;
    readonly payload: Uint8Array;
    readonly purpose: "federation-envelope" | "federation-transcript";
  }) => Promise<FederationSignature>;
  readonly verify: (input: {
    readonly destinationDomain: string;
    readonly expectedDomain: string;
    readonly payload: Uint8Array;
    readonly purpose: "federation-envelope" | "federation-transcript";
    readonly signature: FederationSignature;
  }) => Promise<boolean>;
};

export type FederationSession = {
  readonly expiresAt: number;
  readonly initiatorDomain: string;
  readonly profile: FederationProfile;
  readonly responderDomain: string;
  readonly sessionId: string;
  readonly transcriptHash: string;
};

export type FederationEnvelope = {
  readonly contract: typeof FEDERATION_CONTRACT;
  readonly createdAt: number;
  readonly destinationDomain: string;
  readonly expiresAt: number;
  readonly id: string;
  readonly kind: "application" | "commit" | "proposal" | "welcome";
  /** Opaque provider-local route. Do not put a user identifier here. */
  readonly routeId: string;
  readonly originDomain: string;
  readonly payload: Uint8Array;
  readonly sessionId: string;
  readonly transcriptHash: string;
};

export type SignedFederationEnvelope = {
  readonly envelope: FederationEnvelope;
  readonly signature: FederationSignature;
};

export type FederationTransportAdapter = {
  readonly id: string;
  readonly acknowledge: (input: {
    readonly cursor: string;
    readonly localDomain: string;
  }) => Promise<void>;
  readonly receive: (input: {
    readonly cursor?: string;
    readonly localDomain: string;
    readonly maximumMessages: number;
  }) => Promise<{
    readonly cursor?: string;
    readonly messages: readonly SignedFederationEnvelope[];
  }>;
  readonly send: (
    messages: readonly SignedFederationEnvelope[],
  ) => Promise<void>;
};

export type FederationReplayStore = {
  readonly claim: (input: {
    readonly expiresAt: number;
    readonly id: string;
    readonly originDomain: string;
    readonly sessionId: string;
  }) => Promise<"claimed" | "duplicate">;
};

export type FederationLimits = {
  readonly maximumClockSkewMs: number;
  readonly maximumFrameBytes: number;
  readonly maximumMessagesPerBatch: number;
  readonly maximumOfferTtlMs: number;
  readonly maximumTtlMs: number;
};

export type FederationAbuseReason =
  | "child-safety"
  | "fraud"
  | "harassment"
  | "impersonation"
  | "malware"
  | "spam"
  | "threat";

export type FederationAbuseAuthorization =
  | { readonly approvalId: string; readonly method: "user-approved" }
  | { readonly mandateId: string; readonly method: "standing-policy" };

export type SealedFederationAbuseEvidence = {
  readonly bytes: Uint8Array;
  readonly evidenceId: string;
  readonly providerId: string;
  readonly protocol: string;
  readonly recipientKeyId: string;
  readonly senderAuthenticity: "franked" | "receiver-asserted";
};

export type FederationAbuseEvidenceProvider = {
  readonly id: string;
  readonly seal: (input: {
    readonly allegedSender: string;
    readonly authorization: FederationAbuseAuthorization;
    readonly evidence: Uint8Array;
    readonly messageIds: readonly string[];
    readonly recipientKeyId: string;
    readonly reportId: string;
  }) => Promise<SealedFederationAbuseEvidence>;
};

export type FederationAbuseReport = {
  readonly allegedSender: string;
  readonly authorization: FederationAbuseAuthorization;
  readonly contract: typeof FEDERATION_CONTRACT;
  readonly createdAt: number;
  readonly evidence: SealedFederationAbuseEvidence;
  readonly expiresAt: number;
  readonly messageIds: readonly string[];
  readonly reason: FederationAbuseReason;
  readonly reportId: string;
  readonly roomId: string;
};
