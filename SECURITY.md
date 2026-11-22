# Security Model

## Intended use

`cas-threat-index` is a local artifact integrity and publisher-trust verifier. It helps an operator distinguish byte integrity from publisher authentication and maintain a local catalog of records that passed both checks.

## Security properties implemented

- SHA-256 is calculated from the exact file bytes using streaming reads.
- Artifact records require a full Git commit identifier, HTTPS upstream URL, SPDX license identifier, digest, and byte size.
- Ed25519 signatures cover a canonical UTF-8 JSON representation of the record with the `signature` member omitted.
- A signer is accepted only when its exact publisher/key identity is present and trusted in the local trust store and is not revoked.
- Catalog registration invokes verification internally. Callers cannot authorize insertion by passing a caller-created `verified` flag.
- Existing artifact name/version entries cannot be overwritten with different content.
- JSON duplicate keys are rejected.

## Explicit limitations

- The local trust store is an operator-managed trust anchor. This application does not authenticate the trust store itself or distribute trust roots.
- Revocation is only as current as the local trust store supplied at verification time.
- A catalog entry records the result at registration time. Use `verify` again with the current trust store to reassess current revocation/trust status.
- The implementation does not establish whether an upstream publisher account or repository has been compromised.
- The SPDX identifier is syntax-checked but is not resolved against the complete SPDX license list.
- Sigstore/cosign verification, transparency-log inclusion, timestamp authority validation, and remote retrieval are not implemented.
- SQLite protects catalog consistency for local transactions but does not provide tamper-evident storage against a privileged local attacker.
- No artifacts are executed, loaded, unpacked, or installed by this tool.

## Operational guidance

- Obtain publisher public keys through an independently authenticated channel.
- Keep private signing keys outside this repository and outside the local trust store.
- Review key additions and revocations before editing the trust store.
- Back up the SQLite catalog and trust store using the operator's normal protected backup process.
- Treat `unknown`, `untrusted`, `revoked`, `rejected`, and `dependency_unavailable` as non-verified outcomes.
- Do not use an unverified artifact merely because its SHA-256 digest matches a manifest.
