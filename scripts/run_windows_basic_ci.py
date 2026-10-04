#!/usr/bin/env python3
"""Windows build plus a reviewed, exact-name test allowlist. No native lab execution."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "native/windows-sandbox/Cargo.toml"
TARGET = "x86_64-pc-windows-msvc"


def run(*args, env=None):
    print("+ " + " ".join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace", timeout=600)
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}")
    return result.stdout


def main():
    if sys.platform != "win32":
        raise RuntimeError("This runner must execute on real Windows, not cross compilation")
    gate = (ROOT / "native/windows-sandbox/src/lib.rs").read_text(encoding="utf-8")
    if "pub const NATIVE_VALIDATED: bool = false;" not in gate:
        raise RuntimeError("Production activation gate must stay closed")
    run("node", "--version")
    run(sys.executable, "--version")
    run("node", "scripts/check-source.mjs")
    env = os.environ.copy()
    sdk = ROOT / ".local/pi-sdk-smoke/node_modules/@earendil-works/pi-coding-agent"
    if json.loads((sdk / "package.json").read_text(encoding="utf-8"))["version"] != "1.0.2":
        raise RuntimeError("Unexpected Pi SDK version")
    env["PI_SDK_ENTRY"] = str(sdk / "dist/index.js")
    env["PI_OFFLINE"] = "1"
    # Named files only: adding another test file does not implicitly execute it.
    output = run("node", "--test", "--test-reporter=tap",
                 "tests/core/core.test.mjs", "tests/native-backend/native.test.mjs",
                 "tests/native-backend/file-worker.test.mjs",
                 "tests/native-backend/file-regressions.test.mjs",
                 "tests/pi-adapter/adapter.test.js", "tests/pi-adapter/real-sdk.test.js", env=env)
    if not re.search(r"^# pass 66$", output, re.M) or not re.search(r"^# skipped 0$", output, re.M):
        raise RuntimeError("Expected all 66 JavaScript tests, including real Pi SDK, with no skips")
    # Both suites use mocks / disposable ordinary files only. No actual network probe.
    run(sys.executable, "-m", "unittest", "discover", "-s", "tests/python-probe",
        "-p", "test_probe.py", "-v")
    run(sys.executable, "-m", "unittest", "discover", "-s", "tests/windows-lab",
        "-p", "test_collector.py", "-v")
    run(sys.executable, "scripts/python-sandbox-probe.py", "--self-test")
    cargo = ("rustup", "run", "stable", "cargo")
    common = ("--manifest-path", MANIFEST, "--locked", "--target", TARGET)
    # Real executable link, and compile/link every library test without running it.
    run(*cargo, "build", *common, "--release", "--bins")
    run(*cargo, "test", *common, "--lib", "--no-run")
    listed = run(*cargo, "test", *common, "--lib", "--", "--list")
    available = set(re.findall(r"^(.+): test$", listed, re.M))
    names = json.loads((ROOT / "scripts/windows-basic-rust-tests.json").read_text(encoding="utf-8"))
    if len(names) != 33 or len(set(names)) != 33 or not set(names) <= available:
        raise RuntimeError("Reviewed 33-test Rust allowlist does not match compiled tests")
    print("Rust tests excluded from execution:", sorted(available - set(names)), flush=True)
    for name in names:
        output = run(*cargo, "test", *common, "--lib", name, "--", "--exact", "--nocapture")
        if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in output:
            raise RuntimeError(f"Allowlisted test did not execute exactly once: {name}")
    executable = ROOT / "native/windows-sandbox/target" / TARGET / "release/pi-windows-sandbox.exe"
    # status is read-only; never invoke run or internal-experimental-helper.
    status = json.loads(run(executable, "status"))
    if status.get("nativeValidated") is not False or status.get("platformSupported") is not True:
        raise RuntimeError("Unexpected Windows executable status")
    print("PASS: Windows build/basic checks. Native enforcement remains NOT VALIDATED.", flush=True)


if __name__ == "__main__":
    main()
