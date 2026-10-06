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

    def test_only_session_boundary_probes_authorized_fixed_logon_leaf(self):
        for label in ("strict", "pinned", "candidate", "session", "codex"):
            with self.subTest(label=label), \
                    patch.object(fixture.sys, "platform", "win32"), \
                    patch.object(fixture.sys, "version_info", (3, 12, 10)), \
                    patch.object(fixture.sys, "argv", ["fixture.py", label + "-boundary"]), \
                    patch.object(fixture.sys, "executable", str(fixture.ROOT / "runtime" / "python.exe")), \
                    patch.object(fixture.pathlib.Path, "cwd", return_value=fixture.WORK), \
                    patch.object(fixture.pathlib.Path, "open"), \
                    patch.object(fixture, "read_exact"), patch.object(fixture, "write_new") as write, \
                    patch.object(fixture, "connect") as connect, patch.object(fixture.os, "fsync"), \
                    patch("builtins.print") as output:
                fixture.main()
                logon_calls = [call for call in write.call_args_list
                               if "outside-logon" in call.args[0].parts]
                self.assertEqual(len(logon_calls), int(label == "session"))
                result = fixture.json.loads(output.call_args.args[0])
                self.assertEqual("sessionGrantWrite" in result, label == "session")
                self.assertEqual("privateOutsideWrite" in result, label == "codex")
                if label == "codex":
                    write.assert_any_call(fixture.ROOT / "fixtures" / "outside-private" / "codex-write.txt",
                                          b"UNEXPECTED_PRIVATE_WRITE\n")
                if label == "session":
                    self.assertEqual(logon_calls[0].args, (
                        fixture.ROOT / "fixtures" / "outside-logon" / "session-write.txt",
                        b"AUTHORIZED_SESSION_GRANT_OBSERVED\n"))
                    self.assertEqual(result["sessionGrantWrite"], {"outcome": "SUCCESS"})
                write.assert_any_call(fixture.OUTSIDE / (label + "-write.txt"),
                                      b"SYNTHETIC_OUTSIDE_WRITE\n")
                self.assertEqual(connect.call_count, 2)

    def test_session_child_keeps_fixed_child_and_no_filesystem_or_network_probes(self):
        for mode in ("session-child-normal-exit", "session-child-timeout",
                     "codex-child-normal-exit", "codex-child-timeout"):
            with self.subTest(mode=mode), \
                    patch.object(fixture.sys, "platform", "win32"), \
                    patch.object(fixture.sys, "version_info", (3, 12, 10)), \
                    patch.object(fixture.sys, "argv", ["fixture.py", mode]), \
                    patch.object(fixture.sys, "executable", str(fixture.ROOT / "runtime" / "python.exe")), \
                    patch.object(fixture.pathlib.Path, "cwd", return_value=fixture.WORK), \
                    patch.object(fixture, "read_exact", side_effect=AssertionError("file read")), \
                    patch.object(fixture, "write_new", side_effect=AssertionError("file write")), \
                    patch.object(fixture, "connect", side_effect=AssertionError("network")), \
                    patch.object(fixture.subprocess, "Popen") as spawn, \
                    patch.object(fixture.time, "sleep") as sleep, patch("builtins.print") as output:
                fixture.main()
                spawn.assert_called_once_with([str(fixture.ROOT / "runtime" / "python.exe"),
                    "-I", "-S", "-B", str(fixture.ROOT / "trusted" / "python-isolation-fixture.py"),
                    "descendant-hold"], stdin=fixture.subprocess.DEVNULL,
                    stdout=fixture.subprocess.DEVNULL, stderr=fixture.subprocess.DEVNULL, close_fds=True)
                sleep.assert_called_once_with(60 if mode.endswith("timeout") else 3)
                result = fixture.json.loads(output.call_args.args[0])
                self.assertEqual(result["marker"], "CHILD_STARTED")
                self.assertNotIn("sessionGrantWrite", result)

    def test_fixed_mutation_probes_keep_allowed_and_protected_results_separate(self):
        denied = PermissionError(fixture.errno.EACCES, "synthetic")
        denied.winerror = 5
        def mutation(path, *args):
            if "protected" in path.name:
                raise denied
        def writing(path, *args):
            if "codex-protected-dir" in path.parts:
                raise denied
        with patch.object(fixture, "write_new", side_effect=writing) as write, \
                patch.object(fixture, "read_exact") as read, \
                patch.object(fixture.pathlib.Path, "mkdir") as mkdir, \
                patch.object(fixture.pathlib.Path, "open", side_effect=denied), \
                patch.object(fixture.pathlib.Path, "rename", autospec=True, side_effect=mutation) as rename, \
                patch.object(fixture.pathlib.Path, "unlink", autospec=True, side_effect=mutation) as unlink, \
                patch.object(fixture.pathlib.Path, "rmdir", autospec=True, side_effect=mutation) as rmdir, \
                patch.object(fixture, "connect", side_effect=AssertionError("network")):
            results = fixture.file_operations()
        self.assertEqual(len(results), 11)
        for name, result in results.items():
            expected = "SUCCESS" if name.startswith("allowed") or name == "protectedFileRead" else "PERMISSION_DENIED"
            self.assertEqual(result["outcome"], expected, name)
        self.assertEqual(rename.call_count, 4)
        self.assertEqual(unlink.call_count, 2)
        self.assertEqual(rmdir.call_count, 2)
        unlink.assert_any_call(fixture.WORK / "codex-protected-file.txt")
        rmdir.assert_any_call(fixture.WORK / "codex-protected-dir")
        read.assert_called_once_with(fixture.WORK / "codex-protected-file.txt", b"CODEX_PROTECTED_FILE\n")
        mkdir.assert_called_once()
        self.assertEqual(write.call_count, 2)

    def test_mutation_sharing_violations_do_not_become_permission_denials(self):
        sharing = PermissionError(fixture.errno.EACCES, "synthetic")
        sharing.winerror = 32
        with patch.object(fixture, "write_new"), patch.object(fixture, "read_exact"), \
                patch.object(fixture.pathlib.Path, "mkdir"), \
                patch.object(fixture.pathlib.Path, "open", side_effect=sharing), \
                patch.object(fixture.pathlib.Path, "rename", side_effect=sharing), \
                patch.object(fixture.pathlib.Path, "unlink", side_effect=sharing), \
                patch.object(fixture.pathlib.Path, "rmdir", side_effect=sharing):
            results = fixture.file_operations()
        for name in ["protectedFileWrite", "protectedFileRename", "protectedFileDelete",
                     "protectedDirRename", "protectedDirDelete"]:
            self.assertEqual(results[name]["outcome"], "INCONCLUSIVE")
            self.assertEqual(results[name]["winerror"], 32)

    def test_unexpected_rename_is_not_repaired_or_hidden_by_missing_delete_target(self):
        missing = FileNotFoundError(fixture.errno.ENOENT, "synthetic")
        missing.winerror = 2
        with patch.object(fixture, "write_new"), patch.object(fixture, "read_exact"), \
                patch.object(fixture.pathlib.Path, "mkdir"), patch.object(fixture.pathlib.Path, "open"), \
                patch.object(fixture.os, "fsync"), \
                patch.object(fixture.pathlib.Path, "rename") as rename, \
                patch.object(fixture.pathlib.Path, "unlink", side_effect=missing), \
                patch.object(fixture.pathlib.Path, "rmdir", side_effect=missing):
            results = fixture.file_operations()
        self.assertEqual(results["protectedFileRename"], {"outcome": "SUCCESS"})
        self.assertEqual(results["protectedDirRename"], {"outcome": "SUCCESS"})
        self.assertEqual(results["protectedFileDelete"]["outcome"], "INCONCLUSIVE")
        self.assertEqual(results["protectedDirDelete"]["winerror"], 2)
        self.assertEqual(rename.call_count, 4)  # no reverse rename / restoration

    def test_fixture_has_only_declared_modes_and_endpoints(self):
        self.assertEqual(fixture.MODES, frozenset(("ordinary-outside", "strict-boundary",
            "strict-child-normal-exit", "strict-child-timeout", "pinned-boundary",
            "pinned-child-normal-exit", "pinned-child-timeout", "candidate-boundary",
            "candidate-child-normal-exit", "candidate-child-timeout", "session-boundary",
            "session-child-normal-exit", "session-child-timeout", "codex-boundary",
            "codex-file-operations", "codex-child-normal-exit", "codex-child-timeout", "descendant-hold")))
        source = SOURCE.read_text()
        self.assertNotIn("getaddrinfo(", source)
        self.assertNotIn("gethostbyname(", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)


if __name__ == "__main__":
    unittest.main()
