import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = next(parent / "scripts/collect_windows_lab.py"
              for parent in Path(__file__).resolve().parents
              if (parent / "scripts/collect_windows_lab.py").is_file())
spec = importlib.util.spec_from_file_location("collector", SCRIPT)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gate = self.root / "native/windows-sandbox/src/lib.rs"
        self.gate.parent.mkdir(parents=True)
        self.gate.write_text("pub const NATIVE_VALIDATED: bool = false;\n")
        self.manifest = self.root / "SOURCE_SHA256SUMS.txt"
        self.freeze()

    def freeze(self):
        self.manifest.write_text(hashlib.sha256(self.gate.read_bytes()).hexdigest() + "  native/windows-sandbox/src/lib.rs\n")

    def test_success_is_only_blocked_preparation(self):
        with patch("subprocess.Popen", side_effect=AssertionError("must not launch")), patch("socket.socket", side_effect=AssertionError("must not network")):
            report = c.collect(self.root)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["nativeEnforcementAttested"])
        self.assertFalse(report["cleanupVerified"])
        self.assertEqual(len(report["tests"]), 8)
        self.assertTrue(all(t["status"] == "NOT_RUN" for t in report["tests"]))
        self.assertTrue(report["source"]["allListedFilesMatch"])

    def test_changed_source_is_recorded(self):
        self.gate.write_text("pub const NATIVE_VALIDATED: bool = true;\n")
        report = c.collect(self.root)
        self.assertFalse(report["source"]["allListedFilesMatch"])
        self.assertFalse(report["source"]["nativeFalseDeclarationObserved"])
        self.assertEqual(report["status"], "BLOCKED")

    def test_helper_only_hashed(self):
        helper = self.root / "not-executable.exe"
        helper.write_bytes(b"never execute")
        report = c.collect(self.root, helper)
        self.assertEqual(report["build"]["helper"]["sha256"], c.digest(b"never execute"))
        self.assertFalse(report["build"]["correspondenceVerified"])

    def test_evidence_cannot_claim_pass(self):
        evidence = self.root / "fake-pass.json"
        evidence.write_text('{"status":"PASS","nativeEnforcementAttested":true}')
        report = c.collect(self.root, evidence=[evidence])
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["nativeEnforcementAttested"])

    def test_policy_content_not_output(self):
        policy = self.root / "policy.json"
        policy.write_text("benign-test-content-must-not-appear")
        self.assertNotIn("benign-test-content-must-not-appear", json.dumps(c.collect(self.root, policy=policy)))

    def test_bad_paths(self):
        for name in ("../escape", "/root/file", "C:/secret", "a\\b", "a/../b", "a//b", "./file", "a/", "a:stream", "NUL.txt", "a. ", "target/a", ".git/config", "a\n"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                c.relative_source(name)

    def test_empty_manifest(self):
        self.manifest.write_text("")
        with self.assertRaises(ValueError):
            c.collect(self.root)

    def test_duplicate_manifest(self):
        self.manifest.write_text(self.manifest.read_text() * 2)
        with self.assertRaises(ValueError):
            c.collect(self.root)

    def test_missing_gate(self):
        self.manifest.write_text(c.digest(b"x") + "  other.txt\n")
        (self.root / "other.txt").write_bytes(b"x")
        with self.assertRaises(ValueError):
            c.collect(self.root)

    def test_malformed_manifest(self):
        self.manifest.write_text("not a hash\n")
        with self.assertRaises(ValueError):
            c.collect(self.root)

    def test_symlink_file(self):
        link = self.root / "link"
        try:
            link.symlink_to(self.gate)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            c.read_regular(link)

    def test_symlink_ancestor(self):
        link = self.root / "linked-directory"
        try:
            link.symlink_to(self.gate.parent, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            c.read_regular(link / "lib.rs")

    def test_hardlink(self):
        import os
        try:
            os.link(self.gate, self.root / "hardlink")
        except OSError:
            self.skipTest("hardlinks unavailable")
        with self.assertRaises(ValueError):
            c.read_regular(self.gate)

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            c.read_regular(self.gate, limit=2)

    def test_no_source_mutation(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        c.collect(self.root)
        after = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


class SchemaTests(unittest.TestCase):
    # Keep schema tooling optional; collector and its own tests use stdlib only.
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        gate = self.root / "native/windows-sandbox/src/lib.rs"
        gate.parent.mkdir(parents=True)
        gate.write_text("pub const NATIVE_VALIDATED: bool = false;\n")
        (self.root / "SOURCE_SHA256SUMS.txt").write_text(c.digest(gate.read_bytes()) + "  native/windows-sandbox/src/lib.rs\n")
        try:
            import jsonschema
        except ImportError:
            self.skipTest("optional jsonschema validator unavailable")
        self.validator_module = jsonschema
        schema = json.loads((SCRIPT.parents[1] / "schemas/windows-test-result.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        self.validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())

    def test_records_validate(self):
        for record in c.collect(self.root)["tests"]:
            self.validator.validate(record)

    def test_pass_without_evidence_rejected(self):
        record = c.collect(self.root)["tests"][0]
        record["status"] = "PASS"
        with self.assertRaises(self.validator_module.ValidationError):
            self.validator.validate(record)

    def test_not_run_with_observed_result_rejected(self):
        record = c.collect(self.root)["tests"][0]
        record["observed"] = {"success": True}
        with self.assertRaises(self.validator_module.ValidationError):
            self.validator.validate(record)


if __name__ == "__main__":
    unittest.main()
