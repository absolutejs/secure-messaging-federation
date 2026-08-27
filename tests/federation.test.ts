import { describe, expect, test } from "bun:test";
import {
  FEDERATION_CONTRACT,
  FederationError,
  activateFederationSession,
  confirmFederationTranscript,
  createFederationAbuseReport,
  negotiateFederation,
  signFederationEnvelope,
  verifyFederationEnvelope,
  type FederationLimits,
  type FederationOffer,
  type FederationProfile,
  type FederationSignatureProvider,
} from "../src";

const text = new TextEncoder();
const limits: FederationLimits = {
  maximumClockSkewMs: 100,
  maximumFrameBytes: 4_096,
  maximumMessagesPerBatch: 25,
  maximumOfferTtlMs: 1_000,
  maximumTtlMs: 500,
};
const profile: FederationProfile = {
  contentTypes: ["application/absolute-secure-message"],
  e2eeProtocol: "MLS-1.0",
  features: ["opaque-route-v1"],
  federationProtocol: "ABS-FED-1",
  id: "abs.mls.strict.v1",
  maximumFrameBytes: 2_048,
  revision: "1",
  security: { mode: "strict-e2ee" },
};
const offer = (
  role: "initiator" | "responder",
  originDomain: string,
  destinationDomain: string,
  offered: FederationProfile = profile,
): FederationOffer => ({
  contract: FEDERATION_CONTRACT,
  createdAt: 1_000,
  destinationDomain,
  expiresAt: 1_900,
  offerId: `${role}-offer`,
  originDomain,
  profiles: [offered],
  role,
});

const signatureProvider = (
  localDomain?: string,
): FederationSignatureProvider => ({
  id: "test-signatures",
  sign: async ({ payload, purpose }) => {
    if (localDomain === undefined) throw new Error("Verifier cannot sign.");
    return {
      algorithm: "TEST-SHA-256",
      keyId: localDomain,
      signature: new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          text.encode(`${localDomain}:${purpose}:${payload.length}`),
        ),
      ),
    };
  },
  verify: async ({ expectedDomain, payload, purpose, signature }) => {
    if (signature.keyId !== expectedDomain) return false;
    const expected = await signatureProvider(expectedDomain).sign({
      destinationDomain: "unused.example",
      payload,
      purpose,
    });
    return Buffer.from(signature.signature).equals(
      Buffer.from(expected.signature),
    );
  },
});

const activate = async () => {
  const initiatorOffer = offer("initiator", "alice.example", "bob.example");
  const responderOffer = offer("responder", "bob.example", "alice.example");
  const transcript = await negotiateFederation({
    initiatorOffer,
    limits,
    now: 1_001,
    preferredProfileIds: [profile.id],
    responderOffer,
    sessionId: "session-1",
  });
  const initiatorConfirmation = await confirmFederationTranscript({
    destinationDomain: "bob.example",
    domain: "alice.example",
    signatureProvider: signatureProvider("alice.example"),
    transcript,
  });
  const responderConfirmation = await confirmFederationTranscript({
    destinationDomain: "alice.example",
    domain: "bob.example",
    signatureProvider: signatureProvider("bob.example"),
    transcript,
  });
  const session = await activateFederationSession({
    initiatorConfirmation,
    initiatorOffer,
    now: 1_002,
    responderConfirmation,
    responderOffer,
    signatureProvider: signatureProvider(),
    transcript,
  });
  return {
    initiatorConfirmation,
    initiatorOffer,
    responderConfirmation,
    responderOffer,
    session,
    transcript,
  };
};

describe("secure messaging federation", () => {
  test("binds exact bilateral offers into a mutually authenticated session", async () => {
    const { session } = await activate();
    expect(session).toMatchObject({
      initiatorDomain: "alice.example",
      profile,
      responderDomain: "bob.example",
      sessionId: "session-1",
    });
    expect(session.transcriptHash).toHaveLength(43);
  });

  test("does not negotiate a weaker or differently configured profile", async () => {
    const weaker: FederationProfile = {
      ...profile,
      id: "abs.mls.managed.v1",
      security: {
        mode: "managed-recovery",
        recoveryAuthority: "bob-recovery",
      },
    };
    await expect(
      negotiateFederation({
        initiatorOffer: offer("initiator", "alice.example", "bob.example"),
        limits,
        now: 1_001,
        preferredProfileIds: [profile.id, weaker.id],
        responderOffer: offer(
          "responder",
          "bob.example",
          "alice.example",
          weaker,
        ),
        sessionId: "session-1",
      }),
    ).rejects.toMatchObject({
      code: "unsupported",
    } satisfies Partial<FederationError>);
  });

  test("rejects offer substitution after both domains confirm", async () => {
    const negotiated = await activate();
    await expect(
      activateFederationSession({
        initiatorConfirmation: negotiated.initiatorConfirmation,
        initiatorOffer: {
          ...negotiated.initiatorOffer,
          offerId: "substituted-offer",
        },
        now: 1_002,
        responderConfirmation: negotiated.responderConfirmation,
        responderOffer: negotiated.responderOffer,
        signatureProvider: signatureProvider(),
        transcript: negotiated.transcript,
      }),
    ).rejects.toMatchObject({
      code: "downgrade-detected",
    } satisfies Partial<FederationError>);
  });

  test("authenticates minimal envelopes and claims replay only after signature verification", async () => {
    const { session } = await activate();
    let claims = 0;
    const signed = await signFederationEnvelope({
      envelope: {
        contract: FEDERATION_CONTRACT,
        createdAt: 1_100,
        destinationDomain: "bob.example",
        expiresAt: 1_500,
        id: "message-1",
        kind: "application",
        originDomain: "alice.example",
        payload: Uint8Array.of(1, 2, 3),
        routeId: "opaque-route-1",
        sessionId: session.sessionId,
        transcriptHash: session.transcriptHash,
      },
      limits,
      localDomain: "alice.example",
      now: 1_100,
      session,
      signatureProvider: signatureProvider("alice.example"),
    });
    const replayStore = {
      claim: async (): Promise<"claimed" | "duplicate"> =>
        ++claims === 1 ? "claimed" : "duplicate",
    };
    await expect(
      verifyFederationEnvelope({
        limits,
        localDomain: "bob.example",
        now: 1_200,
        replayStore,
        session,
        signatureProvider: signatureProvider(),
        signed: {
          ...signed,
          signature: { ...signed.signature, signature: Uint8Array.of(0) },
        },
      }),
    ).rejects.toMatchObject({
      code: "authentication-failed",
    } satisfies Partial<FederationError>);
    expect(claims).toBe(0);
    expect(
      await verifyFederationEnvelope({
        limits,
        localDomain: "bob.example",
        now: 1_200,
        replayStore,
        session,
        signatureProvider: signatureProvider(),
        signed,
      }),
    ).toMatchObject({ id: "message-1", routeId: "opaque-route-1" });
    await expect(
      verifyFederationEnvelope({
        limits,
        localDomain: "bob.example",
        now: 1_200,
        replayStore,
        session,
        signatureProvider: signatureProvider(),
        signed,
      }),
    ).rejects.toMatchObject({
      code: "replay",
    } satisfies Partial<FederationError>);
  });

  test("seals abuse evidence to a designated key under explicit authorization", async () => {
    let observedEvidence = "";
    const report = await createFederationAbuseReport({
      allegedSender: "sender-device-1",
      authorization: { approvalId: "approval-1", method: "user-approved" },
      createdAt: 1_000,
      evidence: text.encode("private evidence"),
      evidenceProvider: {
        id: "test-evidence",
        seal: async (input) => {
          observedEvidence = new TextDecoder().decode(input.evidence);
          return {
            bytes: Uint8Array.of(99),
            evidenceId: "evidence-1",
            providerId: "test-evidence",
            protocol: "TEST-SEALED-1",
            recipientKeyId: input.recipientKeyId,
            senderAuthenticity: "receiver-asserted",
          };
        },
      },
      expiresAt: 1_500,
      maximumEvidenceBytes: 1_024,
      maximumSealedEvidenceBytes: 2_048,
      maximumTtlMs: 1_000,
      messageIds: ["message-1"],
      reason: "fraud",
      recipientKeyId: "moderation-key-1",
      reportId: "report-1",
      roomId: "opaque-room-1",
    });
    expect(observedEvidence).toBe("private evidence");
    expect(report.evidence).toEqual({
      bytes: Uint8Array.of(99),
      evidenceId: "evidence-1",
      providerId: "test-evidence",
      protocol: "TEST-SEALED-1",
      recipientKeyId: "moderation-key-1",
      senderAuthenticity: "receiver-asserted",
    });
    expect(report).not.toHaveProperty("plaintext");
  });
});
