# Changelog

## 0.1.0

- Add strict, bounded, canonical wire encoding and decoding for signed federation
  envelopes, including rejection of extension smuggling and malformed base64url.
- Add explicit transport acknowledgement so adapters can preserve
  acknowledge-after-durable-processing delivery semantics.

## 0.0.3

- Reject missing and non-string token or domain values at runtime instead of
  allowing regular-expression string coercion.

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
