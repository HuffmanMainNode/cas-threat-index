# cas-threat-index

Offline-first artifact provenance, integrity, publisher verification, and trust registry for the CAS-XDP ecosystem.

## Implemented prototype

The repository now provides a working Python CLI and local SQLite catalog:

- SHA-256 digest calculation with streaming file reads.
- Strict versioned artifact provenance records with upstream HTTPS URL, immutable 40-character Git commit, SPDX license identifier, exact byte size, and SHA-256 digest.
- Ed25519 signature verification against an explicitly configured local trust store.
- Distinct `verified`, `unknown`, `untrusted`, `revoked`, `rejected`, and `dependency_unavailable` outcomes.
- Revocation checks before signature acceptance.
- SQLite catalog registration only after integrity and publisher verification. Existing name/version entries cannot be overwritten.
- Duplicate JSON object keys are rejected to avoid ambiguous signed inputs.

## Quick start

The digest and JSON validation commands use the Python standard library:

```sh
python3 cas_threat_index.py digest ./artifact.bin
python3 cas_threat_index.py validate --manifest artifact-record.json --trust-store trust-store.json
```

Install the pinned optional Ed25519 dependency before signature verification:

```sh
python3 -m pip install -r requirements-crypto.txt
python3 cas_threat_index.py verify ./artifact.bin --manifest artifact-record.json --trust-store trust-store.json
python3 cas_threat_index.py register ./artifact.bin --manifest artifact-record.json --trust-store trust-store.json --catalog ./cas-threat-index.sqlite3
python3 cas_threat_index.py list --catalog ./cas-threat-index.sqlite3
```

A record's signature covers canonical UTF-8 JSON of the complete record with the `signature` member omitted. Canonicalization sorts object keys, removes insignificant whitespace, and preserves Unicode. The public key must be present in the local trust store under the exact publisher and key identifiers.

## Trust semantics

SHA-256 proves byte integrity only. It does not establish publisher identity. A signature is accepted only when:
1. the artifact digest and byte size match;
2. the publisher/key pair exists in the local trust store and is marked trusted;
3. the key is not listed in the local revocation records; and
4. Ed25519 verification succeeds over the canonical signed payload.

Unknown keys remain unknown. Untrusted or revoked keys are not accepted. Missing crypto support produces an explicit unavailable result, never a successful verification.

## Network and execution boundary

The current implementation performs no network access, upstream retrieval, package installation on behalf of a user, or artifact execution. Any future retrieval feature remains disabled by default and must be explicitly bounded to declared sources and immutable identifiers. Retrieved artifacts must never be executed by this tool.

## Security and record formats

- [Security model and limitations](SECURITY.md).
- [Artifact record, signature construction, and trust evaluation](docs/FORMAT.md).

## Schemas

- `schemas/artifact-record.schema.json`: signed artifact provenance record.
- `schemas/trust-store.schema.json`: local publisher trust and revocation data.
- `schemas/compatibility.schema.json`: shared repository compatibility manifest.

## Development and verification

```sh
python3 -m pip install -r requirements-crypto.txt 'jsonschema==4.23.0'
python3 -m unittest discover -v
```

See [CONTRACT.md](CONTRACT.md) for the shared safety and evidence requirements. CI validates all three schemas, the repository manifest, contract/schema identity, and the deterministic unit test suite.

**Lifecycle:** prototype. The CI workflow has passed on Python 3.12 / ubuntu-24.04 with 14 unit tests and schema validation. Other Python versions, operating systems, and independent security review remain outstanding.

## Prototype release record

See [PROTOTYPE-RELEASE.md](PROTOTYPE-RELEASE.md) for the verified source commit, evidence ceiling, supported prototype scope, limitations, and next milestone. This document stages a prototype handoff; it does not create a GitHub Release or claim production readiness.
