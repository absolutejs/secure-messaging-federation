# `@absolutejs/secure-messaging-federation`

Provider-neutral secure messaging federation for AbsoluteJS. The stable core
keeps domain authentication, transports, and abuse-evidence cryptography behind
interchangeable contracts while enforcing one downgrade-resistant API.

The first release provides:

- exact bilateral profile matching; profiles bind the federation protocol and
  revision, E2EE protocol, content types, feature set, frame limit, and explicit
  `strict-e2ee` or `managed-recovery` security mode;
- transcript hashes over both offers and mutual domain signatures before a
  session becomes active;
- signed opaque envelopes bound to that transcript, with expiry, clock-skew,
  size, local-domain, route, and durable replay checks;
- strict bounded wire codecs and explicit transport acknowledgement, allowing a
  delivery bridge to acknowledge only after durable MLS processing;
- confidential abuse-evidence contracts that require a concrete user approval
  or standing-policy mandate and disclose only ciphertext to federation code.

There is deliberately no plaintext, legacy, or weaker-mode fallback. If peers do
not advertise an exactly matching locally preferred profile, negotiation fails.
Managed recovery also has to name the same recovery authority on both sides.

```ts
const transcript = await negotiateFederation({
  initiatorOffer,
  responderOffer,
  preferredProfileIds: ["abs.mls.strict.v1"],
  sessionId: "random-session-id",
  limits,
  now: Date.now(),
});

// Each domain signs the exact transcript through a signature provider.
const session = await activateFederationSession({
  initiatorOffer,
  responderOffer,
  transcript,
  initiatorConfirmation,
  responderConfirmation,
  signatureProvider,
  now: Date.now(),
});
```

## Standards position

The IETF MIMI architecture and protocol are active Internet-Drafts, not finished
standards. This core therefore does not claim MIMI interoperability. A MIMI
adapter must identify and pin the exact draft revision, expose it in the
negotiated profile, require explicit experimental opt-in, and fail when the peer
does not match. The separation lets AbsoluteJS track MIMI without destabilizing
the application API.

The model follows MLS's authenticated epoch and group-state boundaries from
[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), the federation roles and
minimal-provider-access direction in the
[MIMI architecture draft](https://datatracker.ietf.org/doc/html/draft-ietf-mimi-arch-03),
and bilateral capability/message-franking work in the
[MIMI protocol draft](https://datatracker.ietf.org/doc/html/draft-ietf-mimi-protocol-06).

## Abuse and AI safety

Evidence sealing happens at the endpoint. The report object carries sealed bytes
and bounded metadata, never a plaintext field. `receiver-asserted` means a
recipient supplied the evidence and could have fabricated it; only a provider
that actually validates a sender-bound cryptographic frank may return `franked`.
Message franking in MIMI remains draft work.

An agent must not infer permission from the content it sees. It must supply either
a phishing-resistant `user-approved` approval ID or an exact `standing-policy`
mandate ID before evidence can be sealed. Applications should show the recipient,
reason, messages, destination moderation key, and disclosure scope outside
model-controlled content.

## License

Apache-2.0
