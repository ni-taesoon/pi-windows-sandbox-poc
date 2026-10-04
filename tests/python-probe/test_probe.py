import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location(
    "probe", Path(__file__).resolve().parents[2] / "scripts" / "python-sandbox-probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_self_test_has_no_external_effects(self):
        with patch.object(Path, "open", side_effect=AssertionError("filesystem access")), \
                patch.object(probe.socket, "socket", side_effect=AssertionError("network access")):
            self.assertEqual(probe.self_test()["status"], "PASS")

    def test_non_windows_actual_probe_refused(self):
        output = io.StringIO()
        with patch.object(probe.sys, "platform", "linux"), contextlib.redirect_stdout(output), \
                patch.object(probe, "probe_allowed", side_effect=AssertionError("real probe")):
            self.assertEqual(probe.main([]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "INCONCLUSIVE")

    def test_approval_required(self):
        with patch.object(probe.sys, "platform", "win32"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main([]), 2)

    def test_permission_denial(self):
        self.assertEqual(probe.classify_negative_error("n", PermissionError(errno.EACCES, ""))["status"], "PASS")

    def test_other_errors_inconclusive(self):
        for exc in (TimeoutError(), ConnectionRefusedError(errno.ECONNREFUSED, ""),
                    FileNotFoundError(errno.ENOENT, ""), OSError(errno.EROFS, ""),
                    OSError(errno.ENETUNREACH, ""), probe.socket.gaierror(-2, "")):
            with self.subTest(exc=exc):
                self.assertEqual(probe.classify_negative_error("n", exc)["status"], "INCONCLUSIVE")

    def test_canary_success_is_failure_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "keep.txt"
            sentinel.write_bytes(b"unchanged")
            outcome = probe.probe_denied(root)
            self.assertEqual(outcome["status"], "FAIL")
            self.assertEqual(Path(outcome["artifact"]).read_bytes(), b"")
            self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_mocked_denied_canary(self):
        with patch.object(Path, "open", side_effect=PermissionError(errno.EACCES, "")):
            self.assertEqual(probe.probe_denied(Path("fixture"))["status"], "PASS")

    def test_exclusive_creation_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixed = uuid.uuid4()
            sentinel = root / ("pi-python-allowed-" + fixed.hex + ".probe")
            sentinel.write_bytes(b"do not touch")
            with patch.object(probe.uuid, "uuid4", return_value=fixed):
                self.assertEqual(probe.probe_allowed(root, True)["status"], "FAIL")
            self.assertEqual(sentinel.read_bytes(), b"do not touch")

    def test_allowed_roundtrip_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            outcome = probe.probe_allowed(Path(directory), True)
            self.assertEqual(outcome["status"], "PASS")
            self.assertFalse(Path(outcome["artifact"]).exists())

    def test_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            with self.assertRaises(ValueError):
                probe.validate_directories(root, nested)

    def test_marker_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            token = str(uuid.uuid4())
            root = Path(directory)
            marker = root / ("pi-python-canary-" + token + ".marker")
            with self.assertRaises(FileNotFoundError):
                probe.validate_canary_marker(root, token)
            marker.write_bytes(("pi-python-sandbox-canary-v1\n" + token + "\n").encode("ascii"))
            probe.validate_canary_marker(root, token)
            marker.write_bytes(b"wrong marker")
            with self.assertRaises(ValueError):
                probe.validate_canary_marker(root, token)

    def test_ambiguous_paths_rejected(self):
        for path in ("C:\\", "C:relative", "\\\\server\\share", "C:\\test\\..\\oops", "C:\\test~1", "C:\\NUL", "C:\\test."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                probe.validate_windows_path(path)

    def test_network_skip_does_not_open_socket(self):
        with patch.object(probe.socket, "socket", side_effect=AssertionError("network access")):
            self.assertEqual(probe.probe_network()["status"], "SKIP")

    def test_network_error_classification_without_network(self):
        for exc, status in ((PermissionError(errno.EACCES, ""), "PASS"),
                            (TimeoutError(), "INCONCLUSIVE"),
                            (ConnectionRefusedError(errno.ECONNREFUSED, ""), "INCONCLUSIVE")):
            with self.subTest(exc=exc), patch.object(probe.socket, "socket") as factory:
                factory.return_value.__enter__.return_value.connect.side_effect = exc
                self.assertEqual(probe.probe_network("192.0.2.1", 12345)["status"], status)

    def test_network_success_is_failure_without_network(self):
        with patch.object(probe.socket, "socket"):
            self.assertEqual(probe.probe_network("192.0.2.1", 12345)["status"], "FAIL")

    def test_summary_failure_precedence(self):
        self.assertEqual(probe.summarize([{"status": "PASS"}, {"status": "FAIL"}, {"status": "INCONCLUSIVE"}]), "FAIL")


if __name__ == "__main__":
    unittest.main()
