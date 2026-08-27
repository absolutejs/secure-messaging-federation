import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  maximumFrameBytes?: number;
  maximumOfferTtlMs?: number;
  maximumTtlMs?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "federate encrypted messaging across provider domains",
      "negotiate an exact secure messaging profile without downgrade",
      "authenticate remote provider envelopes before delivery",
      "send confidential abuse evidence with explicit authorization",
      "enforce replay size expiry and routing metadata boundaries",
    ],
    keywords: [
      "secure messaging federation",
      "MIMI",
      "MLS federation",
      "downgrade resistance",
      "confidential abuse report",
      "message franking",
    ],
    protocols: ["AbsoluteJS federation contract 1"],
  },
  identity: {
    accent: "#4338ca",
    category: "security",
    description:
      "Provider-neutral federation negotiation, authenticated envelopes, replay defense, and confidential abuse evidence.",
    docsUrl: "https://github.com/absolutejs/secure-messaging-federation",
    name: "@absolutejs/secure-messaging-federation",
    tagline: "Federate E2EE messaging without silent downgrade.",
  },
  settings: Type.Object(
    {
      maximumFrameBytes: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum frame bytes" }),
      ),
      maximumOfferTtlMs: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum offer lifetime" }),
      ),
      maximumTtlMs: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum envelope lifetime" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
