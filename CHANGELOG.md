# Changelog

## 0.0.2

- Give signature verification the expected destination domain so providers can
  cryptographically separate source, destination, purpose, and payload.

## 0.0.1

- Add exact bilateral security-profile negotiation bound into a transcript hash
  and confirmed by both provider domains.
- Add signed, size- and time-bounded opaque federation envelopes with durable
  replay claims and minimal routing metadata.
- Add provider-neutral transport, signature, replay, and confidential abuse
  evidence contracts.
- Keep strict E2EE and managed recovery explicit, distinct modes with no fallback.
