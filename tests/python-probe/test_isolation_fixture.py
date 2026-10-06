"""Portable mock/temporary-file tests; never execute the Windows lab or network."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "python-isolation-fixture.py"
SPEC = importlib.util.spec_from_file_location("isolation_fixture", SOURCE)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class IsolationFixtureTests(unittest.TestCase):
    def test_probe_preserves_unexpected_success(self):
        self.assertEqual(fixture.probe(lambda: None), {"outcome": "SUCCESS"})

    def test_only_explicit_windows_permission_denials_qualify(self):
        for code in (5, 10013):
            error = OSError()
            error.winerror = code
            with self.subTest(code=code), patch.object(fixture, "read_exact", side_effect=error):
                self.assertEqual(fixture.probe(lambda: fixture.read_exact(None, None)),
                                 {"outcome": "PERMISSION_DENIED", "winerror": code,
                                  "errno": None, "errorType": "OSError"})

    def test_missing_refused_timeout_and_other_errors_are_inconclusive(self):
        for code in (None, 2, 3, 32, 10060, 10061, 10065):
            error = OSError()
            error.winerror = code
            def raises():
                raise error
            with self.subTest(code=code):
                self.assertEqual(fixture.probe(raises),
                                 {"outcome": "INCONCLUSIVE", "winerror": code,
                                  "errno": None, "errorType": "OSError"})

    def test_errno_only_permission_error_preserves_crt_evidence(self):
        for number in (fixture.errno.EACCES, fixture.errno.EPERM):
            error = PermissionError(number, "never publish this exception text")
            with self.subTest(errno=number), patch.object(fixture, "read_exact", side_effect=error):
                observed = fixture.probe(lambda: fixture.read_exact(None, None))
                self.assertEqual(observed, {"outcome": "PERMISSION_DENIED", "winerror": None,
                                           "errno": number, "errorType": "PermissionError"})
                self.assertNotIn("never publish", str(observed))

    def test_nonpermission_type_cannot_pass_with_errno_only(self):
        error = OSError()
        error.errno = fixture.errno.EACCES
        with patch.object(fixture, "read_exact", side_effect=error):
            observed = fixture.probe(lambda: fixture.read_exact(None, None))
        self.assertEqual(observed, {"outcome": "INCONCLUSIVE", "winerror": None,
                                   "errno": fixture.errno.EACCES, "errorType": "OSError"})

    def test_refused_winerror_cannot_be_overridden_by_permission_errno(self):
        error = PermissionError(fixture.errno.EACCES, "synthetic")
        error.winerror = 10061
        with patch.object(fixture, "read_exact", side_effect=error):
            observed = fixture.probe(lambda: fixture.read_exact(None, None))
        self.assertEqual(observed["outcome"], "INCONCLUSIVE")
        self.assertEqual(observed["winerror"], 10061)

    def test_missing_file_and_timeout_keep_actual_type_and_errno(self):
        for error in (FileNotFoundError(fixture.errno.ENOENT, "synthetic"),
                      TimeoutError(fixture.errno.ETIMEDOUT, "synthetic")):
            with self.subTest(error=type(error).__name__), patch.object(fixture, "read_exact", side_effect=error):
                observed = fixture.probe(lambda: fixture.read_exact(None, None))
                self.assertEqual(observed, {"outcome": "INCONCLUSIVE", "winerror": None,
                                           "errno": error.errno, "errorType": type(error).__name__})

    def test_exclusive_write_never_overwrites_existing_synthetic_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "owned.txt"
            fixture.write_new(target, b"first")
            with self.assertRaises(FileExistsError):
                fixture.write_new(target, b"second")
            self.assertEqual(target.read_bytes(), b"first")

    def test_read_exact_rejects_corrupt_fixture_without_echoing_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "owned.txt"
            target.write_bytes(b"synthetic")
            fixture.read_exact(target, b"synthetic")
            with self.assertRaisesRegex(RuntimeError, "synthetic input contents mismatch"):
                fixture.read_exact(target, b"different")

    def test_tcp_wrapper_uses_supplied_numeric_loopback_without_resolution(self):
        for family, address in ((fixture.socket.AF_INET, ("127.0.0.1", 43871)),
                                (fixture.socket.AF_INET6, ("::1", 43872))):
            with self.subTest(address=address), patch.object(fixture.socket, "socket") as factory, \
                    patch.object(fixture.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
                fixture.connect(family, address)
                factory.assert_called_once_with(family, fixture.socket.SOCK_STREAM)
                stream = factory.return_value.__enter__.return_value
                stream.settimeout.assert_called_once_with(2)
                stream.connect.assert_called_once_with(address)

    def test_bad_mode_never_reaches_files_network_or_processes(self):
        with patch.object(fixture.sys, "argv", ["fixture.py", "arbitrary-command"]), \
                patch.object(fixture.pathlib.Path, "open", side_effect=AssertionError("file access")), \
                patch.object(fixture.socket, "socket", side_effect=AssertionError("network")), \
                patch.object(fixture.subprocess, "Popen", side_effect=AssertionError("process")):
            with self.assertRaises(RuntimeError):
                fixture.main()

    def test_fixture_has_only_declared_modes_and_endpoints(self):
        self.assertEqual(fixture.MODES, frozenset(("ordinary-outside", "strict-boundary",
            "strict-child-normal-exit", "strict-child-timeout", "pinned-boundary",
            "pinned-child-normal-exit", "pinned-child-timeout", "descendant-hold")))
        source = SOURCE.read_text()
        self.assertNotIn("getaddrinfo(", source)
        self.assertNotIn("gethostbyname(", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)


if __name__ == "__main__":
    unittest.main()
