# Record and Trust Format

## Artifact record v1.0

The strict record is validated against `schemas/artifact-record.schema.json` and contains four top-level members:

- `schema_version`: `1.0`.
- `artifact`: name, version, SHA-256 digest, exact byte size, and source provenance.
- `publisher`: stable publisher identifier and signing key identifier.
- `signature`: Ed25519 algorithm and base64-encoded 64-byte signature.

The source requires an HTTPS URL, a full 40-character Git commit SHA, and an SPDX license identifier. Mutable branch or tag names are not accepted as commit pins.

## Signature construction

The signature is computed over canonical UTF-8 JSON of the complete record with the top-level `signature` member omitted:

1. Remove the `signature` member.
2. Serialize with sorted object keys, separators `,` and `:`, and `ensure_ascii=False`.
3. Encode the serialized JSON as UTF-8.
4. Sign those bytes with the publisher's Ed25519 private key.

The trust store contains the corresponding raw 32-byte Ed25519 public key, base64 encoded. The trust store schema is `schemas/trust-store.schema.json`.

## Trust evaluation

| Result | Meaning |
|---|---|
| `verified` | Bytes match, signer key is trusted and not revoked, signature verifies. |
| `unknown` | No matching publisher/key pair exists in the trust store. |
| `untrusted` | Matching key exists but is not trusted. |
| `revoked` | Matching key is listed in the local revocation set. |
| `rejected` | Digest, size, or signature verification failed. |
| `dependency_unavailable` | Ed25519 implementation is not installed. |

Only `verified` records may be registered in the SQLite catalog.

## CLI

```sh
python3 cas_threat_index.py digest ./artifact.bin
python3 cas_threat_index.py validate --manifest record.json --trust-store trust-store.json
python3 cas_threat_index.py verify ./artifact.bin --manifest record.json --trust-store trust-store.json
python3 cas_threat_index.py register ./artifact.bin --manifest record.json --trust-store trust-store.json --catalog ./catalog.sqlite3
python3 cas_threat_index.py list --catalog ./catalog.sqlite3
```

The `register` command verifies the artifact and publisher again before writing. The catalog uses a unique name/version key and refuses to replace an existing record with different content. A repeated identical registration is idempotent.

## Network boundary

No command retrieves remote data. All inputs are local files. Future upstream retrieval would require a separate design and explicit opt-in, bounded immutable identifiers, and a guarantee that retrieved bytes are never executed.
