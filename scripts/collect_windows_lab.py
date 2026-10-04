#!/usr/bin/env python3
"""Read-only preparation evidence; never launches a program or changes security."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys

MAX_BYTES = 128 * 1024 * 1024
CASES = {
    "python_document_create": "Approved Python creates a benign document in writable root; trusted observer verifies bytes.",
    "outside_write_denied": "Dedicated canary create/write is denied; trusted observer verifies unchanged directory.",
    "explicit_read_denied": "Existing benign read-deny fixture returns explicit permission denial with valid baseline.",
    "offline_tcp_ipv4": "Controlled reachable IPv4 listener; sandbox connect denied; correlate filter and observer evidence.",
    "offline_tcp_ipv6": "Controlled reachable IPv6 listener; sandbox connect denied; correlate filter and observer evidence.",
    "descendant_normal_exit": "Root exits with background child/grandchild; all observed process handles become signaled.",
    "descendant_broker_death": "Approved termination of lab broker; helper/root/child/grandchild handles become signaled.",
    "cleanup_security_state": "Record residual owned account/ACL/filter/store state and verify approved snapshot recovery.",
}
BLOCKERS = [
    "Disposable Windows VM, OS build, security/GPO inventory and recovery snapshot not verified.",
    "Specific account, protected credential store, ACL, firewall/WFP, activation and recovery changes require approval.",
    "Separate trusted lab driver and independent process/file/network observer are not implemented or reviewed.",
    "Controlled endpoint and explicit network-probe authorization are not verified.",
    "Windows build provenance, effective offline controls and helper/path integrity require native verification.",
]


def read_regular(path, limit=MAX_BYTES):
    """Reject links/reparses and special files before bounded read. No race-free pin claim."""
    path = Path(os.path.abspath(path))
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Links and reparse points are not accepted")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("Expected a single-link regular file")
    if before.st_size > limit:
        raise ValueError("Input exceeds size limit")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(data) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("Input changed during collection")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative_source(value):
    # One portable, canonical format; reject Windows drives/ADS even on Linux.
    path = PurePosixPath(value)
    if not value or value != str(path) or path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise ValueError("Manifest path must be canonical and relative")
    if "\\" in value or ":" in value or any(ord(ch) < 32 for ch in value):
        raise ValueError("Unsupported manifest path")
    if any(part.endswith((" ", ".")) or re.match(r"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)", part, re.I) for part in path.parts):
        raise ValueError("Ambiguous manifest path")
    if set(path.parts) & {".git", ".local", "node_modules", "target", ".aws", ".codex"}:
        raise ValueError("Excluded generated or private directory")
    return path


def source_identity(root):
    raw = read_regular(root / "SOURCE_SHA256SUMS.txt", 1024 * 1024)
    entries = []
    seen = set()
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError("Invalid source manifest line")
        expected, name = match.groups()
        relative_source(name)
        if name.casefold() in seen:
            raise ValueError("Duplicate or case-colliding source manifest path")
        seen.add(name.casefold())
        observed = digest(read_regular(root / name))
        entries.append(dict(path=name, expectedSha256=expected, sha256=observed, matches=expected == observed))
    if not entries:
        raise ValueError("Empty source manifest")
    gate_path = "native/windows-sandbox/src/lib.rs"
    if gate_path.casefold() not in seen:
        raise ValueError("Source manifest omits native gate source")
    gate = read_regular(root / gate_path).decode("utf-8")
    gate_seen = bool(re.search(r"^pub const NATIVE_VALIDATED: bool = false;$", gate, re.M))
    return dict(manifestSha256=digest(raw), allListedFilesMatch=all(e["matches"] for e in entries),
                nativeFalseDeclarationObserved=gate_seen, files=entries,
                limitation="Listed file hashes and source declaration only; no completeness, build correspondence, runtime enforcement or authorization attestation.")


def hash_input(path):
    return dict(name=Path(path).name, sha256=digest(read_regular(path)))


def collect(root, helper=None, policy=None, evidence=()):
    source = source_identity(Path(root))
    blockers = list(BLOCKERS)
    if not source["allListedFilesMatch"]:
        blockers.insert(0, "Source manifest mismatch: freeze source and regenerate/verify provenance before Windows work.")
    if not source["nativeFalseDeclarationObserved"]:
        blockers.insert(0, "Expected disabled native source declaration is absent; do not launch.")
    return dict(
        schemaVersion=1, mode="preparation-only", collectedAt=datetime.now(timezone.utc).isoformat(),
        status="BLOCKED", nativeEnforcementAttested=False, cleanupVerified=False,
        collector=dict(platform=sys.platform, osRelease=platform.release(), osVersion=platform.version(),
                       architecture=platform.machine(), pythonVersion=platform.python_version(),
                       sha256=digest(read_regular(__file__))),
        source=source,
        build=dict(helper=hash_input(helper) if helper else None, correspondenceVerified=False,
                   note="Hashing a supplied helper never executes it or establishes trusted source/build correspondence."),
        policy=hash_input(policy) if policy else None,
        evidence=[hash_input(p) for p in evidence],
        blockers=blockers,
        tests=[dict(id=key, status="NOT_RUN", expected=value, observed=None, startedAt=None,
                    endedAt=None, command=None, policySha256=None, sourceManifestSha256=source["manifestSha256"],
                    rawEvidence=[], reproduction=None) for key, value in CASES.items()],
        limitations=["No account, ACL, WFP, firewall, service, GPO or elevation changes.",
                    "No child process, executable, shell, network probe or sandbox launch.",
                    "No directory crawl, environment dump, credentials or fixture content collection.",
                    "Input files must be trusted and quiescent; metadata checks are not a security boundary.",
                    "Evidence hashes are inventories, not evaluations; supplied evidence never upgrades status."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--helper", type=Path, help="Hash only; never run")
    parser.add_argument("--policy", type=Path, help="Hash only; never print contents")
    parser.add_argument("--evidence-file", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        report = collect(args.source_root, args.helper, args.policy, args.evidence_file)
    except (OSError, ValueError, UnicodeError) as exc:
        # Avoid exposing arbitrary path/data from exception messages.
        report = dict(schemaVersion=1, mode="preparation-only", status="BLOCKED",
                      nativeEnforcementAttested=False, cleanupVerified=False,
                      errorType=type(exc).__name__, error="Input validation or read failed; no probes were run.")
        print(json.dumps(report, indent=2))
        return 2
    print(json.dumps(report, indent=2))
    # Zero means preparation collected, NEVER Windows security passed.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
