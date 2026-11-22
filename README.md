# cas-threat-index

Artifact identity and trust registry for the CAS-XDP ecosystem.

## Responsibility

The threat index is intended to record immutable artifact identity, upstream provenance, SPDX licensing, SHA-256 digests, publisher signature verification, signer identity, and revocation/trust status. Integrity and publisher trust are separate checks.

## Network boundary

The core registry is intended to work offline. Any upstream retrieval is a narrow, explicitly authorized exception: it must target a declared source and immutable identifier, remain disabled by default, and never execute retrieved content. This component is not an outbound scanner or threat-hunting crawler.

## Current status

**Lifecycle: planned.** No registry engine, signature verifier, trust database, retrieval client, or test suite has yet been verified. Missing provenance must remain explicitly missing. See [COMPATIBILITY.json](COMPATIBILITY.json).

## Development

Follow [CONTRACT.md](CONTRACT.md). Mutable branch labels such as `main`, `master`, and `latest` are not artifact pins.
