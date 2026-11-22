# Prototype Release Record

**Release stage:** Prototype candidate documentation complete  
**Lifecycle:** Prototype  
**Verified source commit:** `5570bef0ccfd2910d8f0abb618a7f203cc4b03cd`  
**Evidence ceiling:** TIER-2  
**GitHub Release/tag:** Not published by this record

## Purpose

An offline-first artifact integrity, provenance, publisher-verification, revocation, and local catalog component.

## Included capabilities

- Streaming SHA-256 and exact byte-size calculation.
- Strict versioned provenance records with immutable Git commit references and SPDX identifiers.
- Ed25519 signature verification against an explicitly configured local trust store.
- Distinct verified, unknown, untrusted, revoked, rejected, and dependency-unavailable outcomes.
- SQLite registration only after verification, with name/version overwrite protection.
- Duplicate JSON keys rejected; artifacts are not executed or retrieved.

## Verify locally

```sh
python3 cas_threat_index.py digest ./artifact.bin
python3 cas_threat_index.py validate --manifest artifact-record.json --trust-store trust-store.json
python3 -m pip install -r requirements-crypto.txt
python3 cas_threat_index.py verify ./artifact.bin --manifest artifact-record.json --trust-store trust-store.json
python3 -m unittest discover -v
```

## Evidence

The recorded CI run passed 14 deterministic tests and schema checks across Python 3.9 through 3.13 on Ubuntu 24.04: [workflow run](https://github.com/HuffmanMainNode/cas-threat-index/actions/runs/44976290165).

## Explicit limitations

SHA-256 proves byte identity, not publisher identity. Signature acceptance depends on locally configured trust roots and revocation data. This prototype does not fetch upstream artifacts, execute artifacts, or implement Sigstore/cosign. Other operating systems and independent security review remain outstanding.

## Next milestone

Add independently reviewed trust-store lifecycle and key-rotation procedures, then evaluate bounded immutable-source retrieval as a separately gated feature. Keep artifact execution out of scope.

## Ecosystem context

Related public components:
- [cas-xdp-supervisor](https://github.com/HuffmanMainNode/cas-xdp-supervisor)
- [posix-containment-kit](https://github.com/HuffmanMainNode/posix-containment-kit)
- [xdp-ingress-primitives](https://github.com/HuffmanMainNode/xdp-ingress-primitives)
- [canary-labyrinth-httpd](https://github.com/HuffmanMainNode/canary-labyrinth-httpd)

These repositories are separate prototypes. This record does not claim a shared end-to-end runtime.
