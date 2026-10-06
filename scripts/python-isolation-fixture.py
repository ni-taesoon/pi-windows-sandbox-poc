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
                   "pinned-child-timeout", "descendant-hold"))

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
    result["outsideRead"] = probe(lambda: read_exact(OUTSIDE / "read.txt", b"SYNTHETIC_OUTSIDE_READ\n"))
    result["outsideWrite"] = probe(lambda: write_new(OUTSIDE / (label + "-write.txt"), b"SYNTHETIC_OUTSIDE_WRITE\n"))
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
