# Security policy

This package is experimental and has not received an independent security audit.
Do not describe it as audited, production-approved, or MIMI-interoperable.

Report vulnerabilities privately with GitHub Security Advisories. Never include
plaintext messages, live evidence, private keys, or reusable credentials.

Production deployments must provide authenticated DNS/domain discovery, key
rotation and revocation, TLS transport, durable replay storage, bounded queues,
per-peer rate limits, security monitoring, and a deny-by-default peer policy.
Transport authentication does not replace the signed transcript or envelope.

Profile comparison is exact and ordered by local preference. Never construct the
preference list from an unauthenticated peer offer. Never retry failed federation
as plaintext, managed recovery, an older draft revision, or a less capable profile.

Use opaque, random route IDs. Do not encode usernames, email addresses, room
names, message content, or agent requests in routing metadata or logs. Logs should
contain bounded event classes and keyed or rotating identifiers.

Abuse evidence must be sealed at the endpoint directly to an authorized,
rotatable moderation key. The evidence provider must bind the report ID, selected
message IDs, alleged sender, authorization, recipient key, and evidence. A
`receiver-asserted` report is an allegation, not cryptographic proof of authorship.
Only mark evidence `franked` after validating a sender-bound construction.

User approval and standing mandates are security inputs. Approval UI must be
phishing-resistant and outside model-controlled text. Mandates must be narrow,
short-lived, revocable, usage-bounded, and audited. Do not let an AI agent invent
an approval ID, expand evidence selection, or choose a new moderation recipient.
