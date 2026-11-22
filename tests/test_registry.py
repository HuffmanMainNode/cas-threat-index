import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cas_threat_index as registry


class ThreatIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifact_path = self.root / "sample.bin"
        self.artifact_path.write_bytes(b"CAS-XDP test artifact\x00\x01")
        digest, size = registry.sha256_file(self.artifact_path)
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key_b64 = base64.b64encode(public_key).decode("ascii")
        self.record = {
            "schema_version": "1.0",
            "artifact": {
                "name": "sample-agent",
                "version": "1.2.3",
                "sha256": digest,
                "size_bytes": size,
                "source": {
                    "url": "https://github.com/example/sample-agent",
                    "commit": "a" * 40,
                    "license_spdx": "Apache-2.0",
                },
            },
            "publisher": {"id": "example.publisher", "key_id": "release-2026"},
            "signature": {"algorithm": "Ed25519", "value": ""},
        }
        payload = registry._signed_payload(self.record)
        signature = self.private_key.sign(payload)
        self.record["signature"]["value"] = base64.b64encode(signature).decode("ascii")
        self.trust_store = {
            "schema_version": "1.0",
            "keys": [{
                "publisher_id": "example.publisher",
                "key_id": "release-2026",
                "algorithm": "Ed25519",
                "public_key": self.public_key_b64,
                "status": "trusted",
            }],
            "revocations": [],
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_sha256_digest_and_size(self):
        digest, size = registry.sha256_file(self.artifact_path)
        self.assertEqual(digest, self.record["artifact"]["sha256"])
        self.assertEqual(size, self.record["artifact"]["size_bytes"])

    def test_valid_record_and_trust_store(self):
        registry.validate_manifest(self.record)
        registry.validate_trust_store(self.trust_store)

    def test_valid_signature_and_integrity(self):
        result = registry.verify_record(self.artifact_path, self.record, self.trust_store)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["integrity"], "verified")
        self.assertEqual(result["publisher_trust"], "verified")

    def test_tampered_artifact_is_rejected(self):
        self.artifact_path.write_bytes(b"tampered")
        result = registry.verify_record(self.artifact_path, self.record, self.trust_store)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["integrity"], "mismatch")

    def test_tampered_manifest_signature_is_rejected(self):
        changed = json.loads(json.dumps(self.record))
        changed["artifact"]["version"] = "9.9.9"
        result = registry.verify_record(self.artifact_path, changed, self.trust_store)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["publisher_trust"], "rejected")

    def test_unknown_signer_is_not_trusted(self):
        result = registry.verify_record(
            self.artifact_path, self.record,
            {"schema_version": "1.0", "keys": [], "revocations": []},
        )
        self.assertEqual(result["status"], "unknown")

    def test_untrusted_signer_is_not_verified(self):
        store = json.loads(json.dumps(self.trust_store))
        store["keys"][0]["status"] = "untrusted"
        result = registry.verify_record(self.artifact_path, self.record, store)
        self.assertEqual(result["status"], "untrusted")

    def test_revoked_signer_is_rejected(self):
        store = json.loads(json.dumps(self.trust_store))
        store["revocations"].append({
            "publisher_id": "example.publisher",
            "key_id": "release-2026",
            "revoked_at": "2026-11-21T00:00:00Z",
            "reason": "test revocation",
        })
        result = registry.verify_record(self.artifact_path, self.record, store)
        self.assertEqual(result["status"], "revoked")

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
        with self.assertRaises(registry.RegistryError):
            registry.load_json(path)

    def test_manifest_rejects_mutable_or_short_git_reference(self):
        changed = json.loads(json.dumps(self.record))
        changed["artifact"]["source"]["commit"] = "main"
        with self.assertRaises(registry.RegistryError):
            registry.validate_manifest(changed)

    def test_catalog_registers_only_verified_records_and_prevents_overwrite(self):
        catalog = self.root / "catalog.sqlite3"
        registered = registry.register_verified_record(
            catalog, self.artifact_path, self.record, self.trust_store
        )
        self.assertEqual(registered["catalog"]["status"], "registered")
        repeated = registry.register_verified_record(
            catalog, self.artifact_path, self.record, self.trust_store
        )
        self.assertEqual(repeated["catalog"]["status"], "already_registered")
        self.assertEqual(len(registry.list_catalog(catalog)), 1)

        changed = json.loads(json.dumps(self.record))
        changed["artifact"]["source"]["commit"] = "b" * 40
        unsigned = {key: value for key, value in changed.items() if key != "signature"}
        changed["signature"]["value"] = base64.b64encode(
            self.private_key.sign(registry.canonical_json(unsigned))
        ).decode("ascii")
        with self.assertRaises(registry.RegistryError):
            registry.register_verified_record(
                catalog, self.artifact_path, changed, self.trust_store
            )

    def test_catalog_rejects_unverified_records(self):
        changed = json.loads(json.dumps(self.record))
        changed["signature"]["value"] = base64.b64encode(b"x" * 64).decode("ascii")
        with self.assertRaises(registry.RegistryError):
            registry.register_verified_record(
                self.root / "catalog.sqlite3", self.artifact_path, changed, self.trust_store
            )


if __name__ == "__main__":
    unittest.main()
