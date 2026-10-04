#!/usr/bin/env python3
"""Narrow, operator-directed Windows sandbox observations; no provisioning."""
import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import sys
import uuid

DISCLAIMER = (
    "Observations apply only to the supplied test targets. They do not certify "
    "global sandbox security, identity, read isolation, or descendant cleanup. "
    "Permission errors alone do not identify which security layer denied access."
)


def result(name, status, detail, **extra):
    return dict(name=name, status=status, detail=detail, **extra)


def error_info(exc):
    # Do not copy arbitrary exception text or environment contents into output.
    return dict(errorType=type(exc).__name__, errno=exc.errno,
                winerror=getattr(exc, "winerror", None))


def permission_denied(exc):
    return (exc.errno in (errno.EACCES, errno.EPERM)
            or getattr(exc, "winerror", None) in (5, 10013))


def classify_negative_error(name, exc):
    if permission_denied(exc):
        return result(name, "PASS", "Explicit permission denial observed.",
                      **error_info(exc))
    return result(name, "INCONCLUSIVE", "Failure was not an explicit permission denial.",
                  **error_info(exc))


def validate_windows_path(value):
    if not re.match(r"^[A-Za-z]:\\", value):
        raise ValueError("Use an absolute local Windows drive path, with backslashes.")
    parts = value[3:].split("\\")
    if (not parts or any(not p or p in (".", "..") or p.endswith((" ", "."))
                         or re.search(r'[<>:"/|?*~\x00-\x1f]', p)
                         or re.match(r"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)", p, re.I)
                         for p in parts)):
        raise ValueError("Ambiguous, root, device, or aliased Windows path rejected.")
    return Path(value)


def validate_directories(workspace, denied):
    # Inspect metadata only. Do not resolve symlinks or read existing file contents.
    for directory in (workspace, denied):
        for component in reversed((directory, *directory.parents)):
            metadata = component.lstat()
            if (stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & 0x400):
                raise ValueError("Symlinks and reparse points are not allowed in test paths.")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Both test directories and ancestors must already exist.")
    a, b = os.path.normcase(str(workspace)), os.path.normcase(str(denied))
    if (a == b or a.startswith(b + os.sep) or b.startswith(a + os.sep)):
        raise ValueError("Test directories must be separate, non-overlapping locations.")
    # This is preflight hygiene, not a race-free security boundary. Operator must
    # prevent directory replacement, junction changes, and concurrent modification.


def validate_canary_marker(denied, token):
    if str(uuid.UUID(token)) != token:
        raise ValueError("Canary token must be a canonical lowercase UUID.")
    marker = denied / ("pi-python-canary-" + token + ".marker")
    metadata = marker.lstat()
    if (not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & 0x400
            or metadata.st_nlink != 1):
        raise ValueError("Canary marker must be a regular, non-reparse, single-link fixture file.")
    expected = ("pi-python-sandbox-canary-v1\n" + token + "\n").encode("ascii")
    with marker.open("rb") as handle:
        if handle.read(len(expected) + 1) != expected:
            raise ValueError("Dedicated canary marker content does not match the operator token.")


def probe_allowed(workspace, cleanup=False):
    path = workspace / ("pi-python-allowed-" + uuid.uuid4().hex + ".probe")
    payload = b"Benign Python sandbox probe.\n"
    created = False
    try:
        with path.open("x+b") as handle:
            created = True
            handle.write(payload)
            handle.flush()
            handle.seek(0)
            observed = handle.read(len(payload) + 1)
        outcome = result("workspace_write_read", "PASS" if observed == payload else "FAIL",
                         "Exclusive create and read-back completed.", artifact=str(path))
    except OSError as exc:
        outcome = result("workspace_write_read", "FAIL", "Allowed operation failed.",
                         artifact=str(path) if created else None, **error_info(exc))
    if cleanup and created:
        try:
            path.unlink()
            outcome["cleanup"] = "removed own artifact"
        except OSError as exc:
            outcome["cleanup"] = dict(status="INCONCLUSIVE", **error_info(exc))
            if outcome["status"] == "PASS":
                outcome["status"] = "INCONCLUSIVE"
    return outcome


def probe_denied(denied):
    path = denied / ("pi-python-denied-" + uuid.uuid4().hex + ".probe")
    try:
        # Empty exclusive-create canary: never open or overwrite an existing file.
        with path.open("xb"):
            pass
    except OSError as exc:
        return classify_negative_error("outside_workspace_write", exc)
    return result("outside_workspace_write", "FAIL",
                  "Canary creation unexpectedly succeeded; operator must remove this artifact.",
                  artifact=str(path))


def probe_network(host=None, port=None, timeout=3.0):
    if host is None:
        return result("offline_tcp", "SKIP", "No operator-controlled TCP target supplied.")
    address = ipaddress.ip_address(host)  # Numeric address: no DNS query or lookup.
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect((str(address), port))
    except OSError as exc:
        return classify_negative_error("offline_tcp", exc)
    return result("offline_tcp", "FAIL", "TCP connection succeeded; no application data sent.")


def summarize(checks):
    statuses = {check["status"] for check in checks}
    if "FAIL" in statuses:
        return "FAIL"
    if "INCONCLUSIVE" in statuses:
        return "INCONCLUSIVE"
    return "PASS" if "PASS" in statuses else "SKIP"


def self_test():
    assert classify_negative_error("test", PermissionError(errno.EACCES, ""))["status"] == "PASS"
    assert classify_negative_error("test", TimeoutError())["status"] == "INCONCLUSIVE"
    assert classify_negative_error("test", ConnectionRefusedError(errno.ECONNREFUSED, ""))["status"] == "INCONCLUSIVE"
    assert probe_network()["status"] == "SKIP"
    assert summarize([result("test", "FAIL", "")]) == "FAIL"
    return result("self_test", "PASS", "Logic only; no filesystem or network probe executed.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--workspace")
    parser.add_argument("--denied-write-canary-dir")
    parser.add_argument("--canary-token", help="UUID in the trusted operator-created benign fixture marker.")
    parser.add_argument("--operator-approved-test-targets", action="store_true",
                        help="Attest disposable Windows environment, dedicated benign fixture, verified host write baseline, and controlled TCP target.")
    parser.add_argument("--cleanup-allowed", action="store_true")
    parser.add_argument("--network-host", help="Explicit operator-controlled numeric IPv4/IPv6 address; no DNS.")
    parser.add_argument("--network-port", type=int)
    parser.add_argument("--network-timeout", type=float, default=3.0)
    args = parser.parse_args(argv)
    if args.self_test:
        checks = [self_test()]
        mode = "logic-only"
    else:
        mode = "windows-observation"
        try:
            if sys.platform != "win32":
                raise ValueError("Actual probes require Windows; use --self-test for logic-only validation.")
            if not args.operator_approved_test_targets or not args.workspace or not args.denied_write_canary_dir or not args.canary_token:
                raise ValueError("Explicit workspace, dedicated benign denied-write directory, canary token, and operator approval are required.")
            if (args.network_host is None) != (args.network_port is None):
                raise ValueError("Network host and port must be supplied together.")
            if args.network_host is not None:
                ipaddress.ip_address(args.network_host)
                if not 1 <= args.network_port <= 65535:
                    raise ValueError("TCP port must be between 1 and 65535.")
            if not 0 < args.network_timeout <= 30:
                raise ValueError("Timeout must be greater than zero and at most 30 seconds.")
            workspace = validate_windows_path(args.workspace)
            denied = validate_windows_path(args.denied_write_canary_dir)
            validate_directories(workspace, denied)
            validate_canary_marker(denied, args.canary_token)
        except (ValueError, OSError) as exc:
            checks = [result("preflight", "INCONCLUSIVE",
                             str(exc) if isinstance(exc, ValueError) else "Directory metadata unavailable.")]
        else:
            checks = [probe_allowed(workspace, args.cleanup_allowed), probe_denied(denied),
                      probe_network(args.network_host, args.network_port, args.network_timeout)]
            checks.append(result("descendant_lifetime", "SKIP", "Requires an external trusted observer."))
    report = dict(schemaVersion=1, mode=mode, platform=sys.platform,
                  pythonVersion=platform.python_version(), status=summarize(checks),
                  checks=checks, disclaimer=DISCLAIMER,
                  nativeEnforcementAttested=False, cleanupVerified=False)
    print(json.dumps(report, indent=2))
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2, "SKIP": 0}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
