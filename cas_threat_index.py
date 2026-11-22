#!/usr/bin/env python3
"""Offline-first artifact provenance and trust verification for CAS-XDP.

The core uses Python's standard library. Ed25519 verification is optional and
requires the explicitly pinned cryptography extra. This tool never executes
artifacts and performs no network retrieval.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = "1.0"
GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SPDX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
TOP_KEYS = {"schema_version", "artifact", "publisher", "signature"}
ARTIFACT_KEYS = {"name", "version", "sha256", "size_bytes", "source"}
SOURCE_KEYS = {"url", "commit", "license_spdx"}
PUBLISHER_KEYS = {"id", "key_id"}
SIGNATURE_KEYS = {"algorithm", "value"}
TRUST_KEYS = {"schema_version", "keys", "revocations"}


class RegistryError(ValueError):
    """Raised when a record or local registry violates the format contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    """Load UTF-8 JSON while rejecting duplicate object keys."""
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read JSON file {path}: {exc}") from exc


def canonical_json(value: Any) -> bytes:
    """Canonical UTF-8 JSON representation used as the signature payload."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise RegistryError(f"cannot read artifact {path}: {exc}") from exc
    return digest.hexdigest(), size


def _require_object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object")
    missing = keys - set(value)
    extra = set(value) - keys
    if missing:
        raise RegistryError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise RegistryError(f"{label} has unexpected keys: {', '.join(sorted(extra))}")
    return value


def validate_manifest(record: Any) -> dict[str, Any]:
    """Validate a strict version-1 signed artifact provenance record."""
    root = _require_object(record, "manifest", TOP_KEYS)
    if root["schema_version"] != SCHEMA_VERSION:
        raise RegistryError("schema_version must be '1.0'")

    artifact = _require_object(root["artifact"], "artifact", ARTIFACT_KEYS)
    source = _require_object(artifact["source"], "artifact.source", SOURCE_KEYS)
    publisher = _require_object(root["publisher"], "publisher", PUBLISHER_KEYS)
    signature = _require_object(root["signature"], "signature", SIGNATURE_KEYS)

    for key, value in (("artifact.name", artifact["name"]), ("artifact.version", artifact["version"]),
                       ("publisher.id", publisher["id"]), ("publisher.key_id", publisher["key_id"])):
        if not isinstance(value, str) or not value.strip():
            raise RegistryError(f"{key} must be a non-empty string")

    if not isinstance(artifact["sha256"], str) or not SHA256_RE.fullmatch(artifact["sha256"]):
        raise RegistryError("artifact.sha256 must be a 64-character hexadecimal digest")
    if isinstance(artifact["size_bytes"], bool) or not isinstance(artifact["size_bytes"], int) or artifact["size_bytes"] < 0:
        raise RegistryError("artifact.size_bytes must be a non-negative integer")

    url = source["url"]
    if not isinstance(url, str):
        raise RegistryError("artifact.source.url must be a string")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RegistryError("artifact.source.url must be an HTTPS URL")

    if not isinstance(source["commit"], str) or not GIT_SHA_RE.fullmatch(source["commit"]):
        raise RegistryError("artifact.source.commit must be a full 40-character Git commit SHA")
    if not isinstance(source["license_spdx"], str) or not SPDX_RE.fullmatch(source["license_spdx"]):
        raise RegistryError("artifact.source.license_spdx must be an SPDX identifier")

    if signature["algorithm"] != "Ed25519":
        raise RegistryError("signature.algorithm must be 'Ed25519'")
    if not isinstance(signature["value"], str) or not signature["value"]:
        raise RegistryError("signature.value must be a non-empty base64 string")
    try:
        decoded_signature = base64.b64decode(signature["value"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RegistryError("signature.value is not valid base64") from exc
    if len(decoded_signature) != 64:
        raise RegistryError("Ed25519 signature must decode to exactly 64 bytes")
    return root


def validate_trust_store(store: Any) -> dict[str, Any]:
    root = _require_object(store, "trust store", TRUST_KEYS)
    if root["schema_version"] != SCHEMA_VERSION:
        raise RegistryError("trust store schema_version must be '1.0'")
    if not isinstance(root["keys"], list) or not isinstance(root["revocations"], list):
        raise RegistryError("trust store keys and revocations must be arrays")

    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(root["keys"]):
        key = _require_object(item, f"trust store keys[{index}]", {
            "publisher_id", "key_id", "algorithm", "public_key", "status"
        })
        identity = (key["publisher_id"], key["key_id"])
        if not all(isinstance(part, str) and part for part in identity):
            raise RegistryError(f"trust store keys[{index}] identity fields must be non-empty strings")
        if identity in seen:
            raise RegistryError(f"duplicate trust key identity: {identity[0]} / {identity[1]}")
        seen.add(identity)
        if key["algorithm"] != "Ed25519":
            raise RegistryError(f"trust store keys[{index}] algorithm must be Ed25519")
        if key["status"] not in {"trusted", "untrusted"}:
            raise RegistryError(f"trust store keys[{index}] status must be trusted or untrusted")
        try:
            raw_key = base64.b64decode(key["public_key"], validate=True)
        except (TypeError, binascii.Error, ValueError) as exc:
            raise RegistryError(f"trust store keys[{index}] public_key is invalid base64") from exc
        if len(raw_key) != 32:
            raise RegistryError(f"trust store keys[{index}] Ed25519 public key must be 32 bytes")

    for index, item in enumerate(root["revocations"]):
        revocation = _require_object(item, f"trust store revocations[{index}]", {
            "publisher_id", "key_id", "revoked_at", "reason"
        })
        for field in ("publisher_id", "key_id", "revoked_at", "reason"):
            if not isinstance(revocation[field], str) or not revocation[field].strip():
                raise RegistryError(f"trust store revocations[{index}].{field} must be a non-empty string")
        try:
            datetime.fromisoformat(revocation["revoked_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise RegistryError(f"trust store revocations[{index}].revoked_at must be ISO-8601") from exc
    return root


def _signed_payload(record: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in record.items() if key != "signature"}
    return canonical_json(unsigned)


def verify_record(artifact_path: Path, manifest: Any, trust_store: Any) -> dict[str, Any]:
    """Verify byte integrity, trusted signer identity, signature, and revocation."""
    record = validate_manifest(manifest)
    store = validate_trust_store(trust_store)
    artifact_digest, artifact_size = sha256_file(artifact_path)
    expected_digest = record["artifact"]["sha256"].lower()
    expected_size = record["artifact"]["size_bytes"]
    if artifact_digest != expected_digest or artifact_size != expected_size:
        return {
            "status": "rejected",
            "integrity": "mismatch",
            "publisher_trust": "not_evaluated",
            "errors": ["artifact bytes do not match the manifest SHA-256 digest and size"],
        }

    publisher = record["publisher"]
    identity = (publisher["id"], publisher["key_id"])
    revocations = [
        item for item in store["revocations"]
        if (item["publisher_id"], item["key_id"]) == identity
    ]
    if revocations:
        return {
            "status": "revoked",
            "integrity": "verified",
            "publisher_trust": "revoked",
            "revocation": revocations[0],
            "errors": ["signing key is present in the local revocation list"],
        }

    trusted_key = next(
        (item for item in store["keys"]
         if (item["publisher_id"], item["key_id"]) == identity),
        None,
    )
    if trusted_key is None:
        return {
            "status": "unknown",
            "integrity": "verified",
            "publisher_trust": "unknown",
            "errors": ["no matching publisher key exists in the configured trust store"],
        }
    if trusted_key["status"] != "trusted":
        return {
            "status": "untrusted",
            "integrity": "verified",
            "publisher_trust": "untrusted",
            "errors": ["matching publisher key is not trusted"],
        }

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return {
            "status": "dependency_unavailable",
            "integrity": "verified",
            "publisher_trust": "not_evaluated",
            "errors": ["install the pinned optional crypto dependency to verify Ed25519 signatures"],
        }

    try:
        public_bytes = base64.b64decode(trusted_key["public_key"], validate=True)
        signature_bytes = base64.b64decode(record["signature"]["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature_bytes, _signed_payload(record)
        )
    except InvalidSignature:
        return {
            "status": "rejected",
            "integrity": "verified",
            "publisher_trust": "rejected",
            "errors": ["Ed25519 signature verification failed"],
        }
    except (ValueError, binascii.Error) as exc:
        return {
            "status": "rejected",
            "integrity": "verified",
            "publisher_trust": "rejected",
            "errors": [f"invalid Ed25519 key or signature encoding: {exc}"],
        }

    return {
        "status": "verified",
        "integrity": "verified",
        "publisher_trust": "verified",
        "artifact": record["artifact"]["name"],
        "version": record["artifact"]["version"],
        "sha256": artifact_digest,
        "publisher_id": publisher["id"],
        "key_id": publisher["key_id"],
        "signature_algorithm": "Ed25519",
        "source_commit": record["artifact"]["source"]["commit"],
        "license_spdx": record["artifact"]["source"]["license_spdx"],
        "errors": [],
    }


def register_verified_record(
    catalog_path: Path, artifact_path: Path, manifest: Any, trust_store: Any
) -> dict[str, Any]:
    """Verify the supplied bytes and signer internally before catalog insertion."""
    record = validate_manifest(manifest)
    verification = verify_record(artifact_path, record, trust_store)
    if verification.get("status") != "verified":
        raise RegistryError(
            "catalog registration requires successful integrity and publisher verification: "
            + verification.get("status", "unknown")
        )
    artifact = record["artifact"]
    canonical_record = canonical_json(record).decode("utf-8")
    try:
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(catalog_path), timeout=10) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    PRIMARY KEY (name, version)
                )
            """)
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT sha256, manifest_json FROM artifacts WHERE name=? AND version=?",
                (artifact["name"], artifact["version"]),
            ).fetchone()
            if existing:
                if existing[0] == artifact["sha256"].lower() and existing[1] == canonical_record:
                    return {
                        "status": "verified",
                        "verification": verification,
                        "catalog": {"status": "already_registered", "name": artifact["name"], "version": artifact["version"]},
                    }
                raise RegistryError("catalog already contains this artifact name/version with different content")
            registered_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            connection.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?)",
                (artifact["name"], artifact["version"], artifact["sha256"].lower(), canonical_record, registered_at),
            )
            connection.commit()
    except sqlite3.Error as exc:
        raise RegistryError(f"catalog operation failed: {exc}") from exc
    return {
        "status": "verified",
        "verification": verification,
        "catalog": {"status": "registered", "name": artifact["name"], "version": artifact["version"]},
    }

def list_catalog(catalog_path: Path) -> list[dict[str, Any]]:
    if not catalog_path.exists():
        return []
    try:
        with sqlite3.connect(str(catalog_path)) as connection:
            rows = connection.execute(
                "SELECT name, version, sha256, registered_at FROM artifacts ORDER BY name, version"
            ).fetchall()
    except sqlite3.Error as exc:
        raise RegistryError(f"catalog read failed: {exc}") from exc
    return [
        {"name": row[0], "version": row[1], "sha256": row[2], "registered_at": row[3]}
        for row in rows
    ]


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cas-threat-index",
        description="Offline-first artifact digest, provenance, signature, and trust registry.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    digest = commands.add_parser("digest", help="calculate SHA-256 and byte size")
    digest.add_argument("artifact", type=Path)

    validate = commands.add_parser("validate", help="validate a provenance manifest and trust store")
    validate.add_argument("--manifest", required=True, type=Path)
    validate.add_argument("--trust-store", required=True, type=Path)

    verify = commands.add_parser("verify", help="verify artifact integrity and publisher trust")
    verify.add_argument("artifact", type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--trust-store", required=True, type=Path)

    register = commands.add_parser("register", help="verify then add an artifact to a local SQLite catalog")
    register.add_argument("artifact", type=Path)
    register.add_argument("--manifest", required=True, type=Path)
    register.add_argument("--trust-store", required=True, type=Path)
    register.add_argument("--catalog", required=True, type=Path)

    catalog = commands.add_parser("list", help="list entries in a local SQLite catalog")
    catalog.add_argument("--catalog", required=True, type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "digest":
            digest, size = sha256_file(args.artifact)
            _print_json({"sha256": digest, "size_bytes": size})
            return 0
        if args.command == "validate":
            validate_manifest(load_json(args.manifest))
            validate_trust_store(load_json(args.trust_store))
            _print_json({"status": "valid"})
            return 0
        if args.command in {"verify", "register"}:
            manifest = load_json(args.manifest)
            trust_store = load_json(args.trust_store)
            if args.command == "register":
                result = register_verified_record(args.catalog, args.artifact, manifest, trust_store)
            else:
                result = verify_record(args.artifact, manifest, trust_store)
            _print_json(result)
            return 0 if result["status"] == "verified" else 2
        if args.command == "list":
            _print_json({"entries": list_catalog(args.catalog)})
            return 0
    except RegistryError as exc:
        _print_json({"status": "invalid", "errors": [str(exc)]})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
