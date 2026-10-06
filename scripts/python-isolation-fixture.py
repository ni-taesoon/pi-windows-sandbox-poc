"""Immutable, fixed Python 3.12.10 acceptance fixture. No user paths or endpoints."""
import errno
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(r"C:\PiSandboxLab")
WORK = ROOT / "work"
OUTSIDE = ROOT / "fixtures" / "outside-world"
MODES = frozenset(("ordinary-outside", "strict-boundary", "strict-child-normal-exit",
                   "strict-child-timeout", "pinned-boundary", "pinned-child-normal-exit",
                   "pinned-child-timeout", "candidate-boundary", "candidate-child-normal-exit",
                   "candidate-child-timeout", "session-boundary", "session-child-normal-exit",
                   "session-child-timeout", "codex-boundary", "codex-file-operations",
                   "codex-child-normal-exit", "codex-child-timeout", "descendant-hold"))

def probe(action):
    try:
        action()
        return {"outcome": "SUCCESS"}
    except OSError as error:
        code = getattr(error, "winerror", None)
        number = getattr(error, "errno", None)
        detail = {"winerror": code, "errno": number, "errorType": type(error).__name__[:64]}
        # CRT file errors can be PermissionError/EACCES with no native winerror.
        # Preserve the actual fields; never synthesize a Windows error code.
        permission = code in (5, 10013) or (code is None and type(error) is PermissionError
                                          and number in (errno.EACCES, errno.EPERM))
        return {"outcome": "PERMISSION_DENIED" if permission else "INCONCLUSIVE", **detail}

def read_exact(path, expected):
    if path.read_bytes() != expected:
        raise RuntimeError("synthetic input contents mismatch")

def write_new(path, data):
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())

def connect(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        stream.connect(address)

def file_operations():
    # Only these synthetic late targets exist; no caller paths are accepted.
    # Rename and delete are separately attempted on each original target. Never
    # repair an unexpected rename/delete: host-side artifact checks preserve it.
    allowed_file = WORK / "codex-allowed-file.txt"
    renamed_file = WORK / "codex-allowed-file-renamed.txt"
    allowed_dir = WORK / "codex-allowed-dir"
    renamed_dir = WORK / "codex-allowed-dir-renamed"
    write_new(allowed_file, b"CODEX_ALLOWED_FILE\n")
    allowed_dir.mkdir()
    protected_file = WORK / "codex-protected-file.txt"
    protected_dir = WORK / "codex-protected-dir"
    def modify_protected():
        with protected_file.open("r+b") as output:
            output.write(b"UNEXPECTED_PROTECTED_WRITE\n")
            output.flush()
            os.fsync(output.fileno())
    return {
        "allowedFileRename": probe(lambda: allowed_file.rename(renamed_file)),
        "allowedFileDelete": probe(lambda: renamed_file.unlink()),
        "allowedDirRename": probe(lambda: allowed_dir.rename(renamed_dir)),
        "allowedDirDelete": probe(lambda: renamed_dir.rmdir()),
        "protectedFileRead": probe(lambda: read_exact(protected_file, b"CODEX_PROTECTED_FILE\n")),
        "protectedFileWrite": probe(modify_protected),
        "protectedFileRename": probe(lambda: protected_file.rename(WORK / "codex-protected-file-renamed.txt")),
        "protectedFileDelete": probe(lambda: protected_file.unlink()),
        "protectedDirWrite": probe(lambda: write_new(protected_dir / "codex-write.txt", b"UNEXPECTED_PROTECTED_WRITE\n")),
        "protectedDirRename": probe(lambda: protected_dir.rename(WORK / "codex-protected-dir-renamed")),
        # This is an empty directory when the preceding write was denied. Testing
        # rmdir directly avoids a nonempty-directory false proof of DELETE denial.
        "protectedDirDelete": probe(lambda: protected_dir.rmdir()),
    }

def main():
    if (sys.platform != "win32" or len(sys.argv) != 2 or sys.argv[1] not in MODES
            or sys.version_info[:3] != (3, 12, 10)
            or pathlib.Path(sys.executable) != ROOT / "runtime" / "python.exe"
            or pathlib.Path.cwd() != WORK):
        raise RuntimeError("fixed fixture/mode/version required")
    mode = sys.argv[1]
    if mode == "descendant-hold":
        time.sleep(60)
        return
    label = mode.split("-", 1)[0]
    result = {"schemaVersion": 1, "mode": mode, "python": list(sys.version_info[:3]),
              "marker": "PYTHON_ISOLATION_OK", "outsideRead": None, "outsideWrite": None,
              "inputOk": None, "outputOk": None, "deniedRead": None, "deniedWrite": None,
              "tcp4": None, "tcp6": None}
    if "child-" in mode:
        subprocess.Popen([str(ROOT / "runtime" / "python.exe"), "-I", "-S", "-B",
                          str(ROOT / "trusted" / "python-isolation-fixture.py"), "descendant-hold"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True)
        result["marker"] = "CHILD_STARTED"
        print(json.dumps(result, separators=(",", ":")), flush=True)
        # Native observer discovers and retains the actual Job child, independent of stdout.
        time.sleep(60 if mode.endswith("timeout") else 3)
        return
    if mode == "codex-file-operations":
        result["fileOperations"] = file_operations()
        print(json.dumps(result, separators=(",", ":")), flush=True)
        return
    result["outsideRead"] = probe(lambda: read_exact(OUTSIDE / "read.txt", b"SYNTHETIC_OUTSIDE_READ\n"))
    result["outsideWrite"] = probe(lambda: write_new(OUTSIDE / (label + "-write.txt"), b"SYNTHETIC_OUTSIDE_WRITE\n"))
    if mode == "codex-boundary":
        result["privateOutsideWrite"] = probe(lambda: write_new(
            ROOT / "fixtures" / "outside-private" / "codex-write.txt", b"UNEXPECTED_PRIVATE_WRITE\n"))
    if mode == "session-boundary":
        result["sessionGrantWrite"] = probe(lambda: write_new(
            ROOT / "fixtures" / "outside-logon" / "session-write.txt", b"AUTHORIZED_SESSION_GRANT_OBSERVED\n"))
    if mode.endswith("boundary"):
        read_exact(WORK / "input.txt", b"PYTHON_ISOLATION_INPUT\n")
        result["inputOk"] = True
        output_path = WORK / ("python-" + label + ".txt")
        write_new(output_path, b"PYTHON_ISOLATION_CREATED\n")
        read_exact(output_path, b"PYTHON_ISOLATION_CREATED\n")
        with output_path.open("wb") as output:
            output.write(b"PYTHON_ISOLATION_OK\n")
            output.flush()
            os.fsync(output.fileno())
        read_exact(output_path, b"PYTHON_ISOLATION_OK\n")
        result["outputOk"] = True
        result["deniedRead"] = probe(lambda: read_exact(WORK / "denied-read" / "secret.txt", b"SYNTHETIC_DENIED_READ\n"))
        result["deniedWrite"] = probe(lambda: write_new(WORK / "denied-write" / (label + ".txt"), b"SYNTHETIC_DENIED_WRITE\n"))
        result["tcp4"] = probe(lambda: connect(socket.AF_INET, ("127.0.0.1", 43871)))
        result["tcp6"] = probe(lambda: connect(socket.AF_INET6, ("::1", 43872)))
    print(json.dumps(result, separators=(",", ":")), flush=True)

if __name__ == "__main__":
    main()
