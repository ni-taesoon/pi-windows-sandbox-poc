"""Fixed online pip + PDF canary. No caller-selected code, package, URL or file.

The sandbox's own pip performs three live HTTP requests to the dedicated loopback
relay. --no-index disables package discovery, not the direct requirement URLs.
The trusted owner relay independently fetches and hashes exact HTTPS wheel bytes.
"""
import contextlib
import errno
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
import pathlib
import re
import runpy
import struct
import sys
import time

ROOT = pathlib.Path(r"C:\PiSandboxLab")
WORK = ROOT / "work"
DEPS = WORK / "pdf-deps"
REPORT = WORK / "pdf-install-report.json"
PDF = WORK / "sandbox-test.pdf"
TRUSTED = ROOT / "trusted"
RUNTIME_SITE = ROOT / "runtime" / "Lib" / "site-packages"
PINS = (
    ("reportlab", "5.0.1", "reportlab-5.0.1-py3-none-any.whl", "1c36e6bb0e71780c72331eba60da7f602e8d4389a8723825af71342e49d791e8"),
    ("pillow", "12.3.0", "pillow-12.3.0-cp312-cp312-win_amd64.whl", "a2b55dd6b2a4c4b7d87ffa56bdb33fdc5fdb9a462173861a7bc097f17d91cb09"),
    ("charset-normalizer", "3.5.2", "charset_normalizer-3.5.2-py3-none-any.whl", "b6b751274acb69d77b3323d6b7dbaa3c7fdfc1eb829b7eb61d262f32e1af9685"),
)
MODES = frozenset(("online-install", "online-pdf"))
PIP_ARGS = (
    "install", "--no-index", "--require-hashes", "--only-binary=:all:", "--no-deps",
    "--no-cache-dir", "--no-compile", "--disable-pip-version-check", "--retries", "0",
    "--timeout", "20", "--target", str(DEPS), "--report", str(REPORT),
    "-r", str(TRUSTED / "python-online-pdf-requirements.txt"),
)


STAGES = frozenset((
    "ENTRY", "INSTALL_FRESHNESS", "INSTALL_CREATE_TARGET", "INSTALL_CHECK_TARGET_EMPTY",
    "INSTALL_BOOTSTRAP_PATH", "INSTALL_PROCESS_GUARD", "INSTALL_RUN_PIP", "INSTALL_VERIFY_REPORT",
    "INSTALL_TARGET_IMPORTS", "INSTALL_DISTRIBUTION_READBACK", "INSTALL_MODULE_IMPORTS",
    "PDF_BOOTSTRAP_PATH", "PDF_DISTRIBUTION_READBACK", "PDF_MODULE_IMPORTS",
    "PDF_IMPORT_CANVAS", "PDF_CREATE_DOCUMENT", "PDF_WRITE_DOCUMENT",
))
_OPERATION_STAGE = "ENTRY"
_PIP_CAPTURE = None


def mark_stage(value):
    global _OPERATION_STAGE
    if value not in STAGES:
        raise RuntimeError("unknown fixed operation stage")
    _OPERATION_STAGE = value


def failure_evidence(error):
    """Static operation and numeric errors only: no message, locals or raw path."""
    def numeric(name):
        value = getattr(error, name, None)
        return value if type(value) is int and -(2**31) <= value <= 2**32-1 else None

    fixture_name = str(pathlib.Path(__file__)).replace("\\", "/").lower()
    runtime_lib = str(ROOT / "runtime" / "Lib").replace("\\", "/").lower() + "/"
    frames = []
    trace = error.__traceback__
    visited = 0
    while trace is not None and visited < 32:
        name = trace.tb_frame.f_code.co_filename.replace("\\", "/").lower()
        frame = {"sourceRole": "OTHER", "line": int(trace.tb_lineno)}
        if name == fixture_name:
            frame["sourceRole"] = "FIXED_FIXTURE"
        elif name.startswith(runtime_lib):
            relative = name[len(runtime_lib):]
            module = relative.removeprefix("site-packages/")
            if (len(module) <= 160 and len(module.split("/")) <= 12
                    and re.fullmatch(r"(?:[a-z0-9_]+/)*[a-z0-9_]+\.py", module)
                    and (not relative.startswith("site-packages/") or relative.startswith("site-packages/pip/"))):
                frame["sourceRole"] = "TRUSTED_PIP" if relative.startswith("site-packages/pip/") else "TRUSTED_STDLIB"
                frame["module"] = module
        frames.append(frame)
        trace = trace.tb_next
        visited += 1
    # Keep the last eight visited frames; disclose the bounded traversal limit.
    return {"stage": _OPERATION_STAGE, "errno": numeric("errno"), "winerror": numeric("winerror"),
            "sourceTrace": frames[-8:], "traceTruncated": visited > 8 or trace is not None,
            "capturedPipOutputByteCount": _PIP_CAPTURE.size if _PIP_CAPTURE is not None else 0,
            "capturedPipOutputTruncated": _PIP_CAPTURE.truncated if _PIP_CAPTURE is not None else False}


PIP_GUARD_SCOPE = "FIXED_INSTALL_COOPERATIVE_GUARD_NOT_SECURITY_BOUNDARY"
_PIP_PROCESS_GUARD = {"active": False, "blockedSubprocessAttempts": 0,
                      "attemptsTruncated": False, "scope": PIP_GUARD_SCOPE}


def pip_process_audit(event, _args):
    # Public audit API, cooperative fixed-fixture behavior only. It is not a
    # security boundary; the native token/Job observer still rejects extra children.
    if event == "pi.online_pdf.process_guard_probe":
        _PIP_PROCESS_GUARD["active"] = True
    elif event == "subprocess.Popen":
        count = _PIP_PROCESS_GUARD["blockedSubprocessAttempts"]
        _PIP_PROCESS_GUARD["attemptsTruncated"] |= count >= 16
        _PIP_PROCESS_GUARD["blockedSubprocessAttempts"] = min(count + 1, 16)
        # CPython's optional Windows `ver` probe catches OSError and naturally
        # falls back to sys.getwindowsversion. Never expose command arguments.
        raise PermissionError(errno.EACCES, "fixed install fixture disallows child processes")


def activate_pip_process_guard():
    if _PIP_PROCESS_GUARD["active"]:
        raise RuntimeError("fixed install process guard already active")
    sys.addaudithook(pip_process_audit)
    sys.audit("pi.online_pdf.process_guard_probe")
    if not _PIP_PROCESS_GUARD["active"]:
        raise RuntimeError("fixed install process guard registration unverified")


def canonical_name(value):
    return value.lower().replace("_", "-").replace(".", "-")


class BoundedOutput(io.TextIOBase):
    """Pip may be chatty; always emit just one bounded JSON stdout frame."""
    def __init__(self):
        self.parts = []
        self.size = 0
        self.truncated = False

    @property
    def encoding(self):
        return "utf-8"

    def writable(self):
        return True

    def isatty(self):
        return False

    def write(self, text):
        text = str(text)
        # Bound UTF-8 bytes, including output from pip and imported libraries.
        encoded = text.encode("utf-8", "replace")
        remaining = max(0, 1024 - self.size)
        keep = encoded[:remaining].decode("utf-8", "ignore")
        if keep:
            self.parts.append(keep)
        self.size += len(keep.encode("utf-8"))
        self.truncated |= len(encoded) > remaining
        return len(text)

    def value(self):
        return "".join(self.parts)


class FixedPipFailure(RuntimeError):
    def __init__(self, exit_code, output):
        super().__init__("fixed sandbox pip installation failed")
        self.exit_code = exit_code
        self.output = output.value()
        self.truncated = output.truncated


def utc_ms():
    return time.time_ns() // 1_000_000


def sanitize_environment():
    # In particular discard every inherited PIP_*, PYTHON*, proxy, certificate,
    # ReportLab setting and user-profile selector before entering pip.
    os.environ.clear()
    os.environ.update({"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows",
                       "TEMP": str(WORK), "TMP": str(WORK), "PIP_CONFIG_FILE": os.devnull,
                       "USERPROFILE": str(WORK), "APPDATA": str(WORK), "LOCALAPPDATA": str(WORK),
                       "WIN_PD_OVERRIDE_LOCAL_APPDATA": str(WORK),
                       "WIN_PD_OVERRIDE_APPDATA": str(WORK),
                       "WIN_PD_OVERRIDE_COMMON_APPDATA": str(WORK)})
    # pip 26.2.1 computes platformdirs paths during import, even with --no-cache-dir.
    # Its supported WIN_PD_OVERRIDE_* variables precede the Windows known-folder
    # API. Keep these process-local paths inside existing WORK; do not load or
    # create an OS user profile, change permissions, or enable pip caching.
    # https://github.com/pypa/pip/blob/26.2.1/src/pip/_vendor/platformdirs/windows.py#L381-L390
    # PIP_CONFIG_FILE=os.devnull is pip's documented all-config-file disable.
    # Use the exact lowercase Windows spelling: pip compares it case-sensitively.
    if os.devnull.lower() != "nul":
        raise RuntimeError("Windows null configuration required")


def distribution_evidence():
    records = sorted((canonical_name(dist.metadata["Name"]), dist.version)
                     for dist in importlib.metadata.distributions(path=[str(DEPS)]))
    if records != sorted((name, version) for name, version, _, _ in PINS):
        raise RuntimeError("exact three installed distributions required")
    return [{"name": name, "version": version} for name, version in records]


def import_evidence():
    origins = {}
    root = DEPS.resolve(strict=True)
    for name in ("reportlab", "PIL", "charset_normalizer", "PIL._imaging"):
        module = importlib.import_module(name)
        origin = pathlib.Path(module.__file__).resolve(strict=True)
        if not origin.is_relative_to(root):
            raise RuntimeError("package import escaped pdf-deps")
        if name == "PIL._imaging" and origin.suffix.lower() != ".pyd":
            raise RuntimeError("Windows native Pillow extension required")
        origins[name] = str(origin)
    return origins


def verify_report():
    if REPORT.stat().st_size > 262144:
        raise RuntimeError("pip report bounds exceeded")
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    entries = report.get("install", [])
    if report.get("version") != "1" or len(entries) != 3:
        raise RuntimeError("three exact installation report entries required")
    expected = {name: (version, filename, digest) for name, version, filename, digest in PINS}
    seen = set()
    for entry in entries:
        metadata = entry["metadata"]
        name = canonical_name(metadata["name"])
        if name not in expected or name in seen:
            raise RuntimeError("unexpected or duplicate pip report package")
        version, filename, digest = expected[name]
        download = entry["download_info"]
        if (metadata["version"] != version or entry.get("requested") is not True
                or entry.get("is_direct") is not True
                or download["url"] != "http://127.0.0.1:43873/wheels/" + filename
                or download["archive_info"]["hashes"].get("sha256") != digest):
            raise RuntimeError("pip installation report pin mismatch")
        seen.add(name)
    return True


def online_install():
    global _PIP_CAPTURE
    _PIP_CAPTURE = None
    started = utc_ms()
    mark_stage("INSTALL_FRESHNESS")
    # A rerun, prestaged distribution or report cannot produce a success receipt.
    if DEPS.exists() or REPORT.exists() or PDF.exists():
        raise RuntimeError("fresh installation target and artifacts required")
    mark_stage("INSTALL_CREATE_TARGET")
    DEPS.mkdir()
    mark_stage("INSTALL_CHECK_TARGET_EMPTY")
    if any(DEPS.iterdir()):
        raise RuntimeError("empty fresh install target required")
    mark_stage("INSTALL_BOOTSTRAP_PATH")
    initial_path = tuple(sys.path)
    if any("site-packages" in part.lower() for part in initial_path):
        raise RuntimeError("isolated startup contained site-packages")
    mark_stage("INSTALL_PROCESS_GUARD")
    activate_pip_process_guard()
    sys.path.insert(0, str(RUNTIME_SITE))
    output = BoundedOutput()
    _PIP_CAPTURE = output
    pip_exit_code = 0
    mark_stage("INSTALL_RUN_PIP")
    try:
        sys.argv = ["pip", *PIP_ARGS]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                # Public Python stdlib interface, not a pip internal API.
                runpy.run_module("pip", run_name="__main__", alter_sys=True)
            except SystemExit as error:
                pip_exit_code = error.code if isinstance(error.code, int) else (0 if error.code is None else 1)
    finally:
        sys.path[:] = initial_path
    if pip_exit_code != 0:
        raise FixedPipFailure(pip_exit_code, output)
    mark_stage("INSTALL_VERIFY_REPORT")
    report_verified = verify_report()
    # Pip/bootstrap site-packages never participate in the evidence imports.
    mark_stage("INSTALL_TARGET_IMPORTS")
    if any(name in sys.modules for name in ("reportlab", "PIL", "charset_normalizer")):
        raise RuntimeError("package imported before target-only import check")
    sys.path.insert(0, str(DEPS))
    mark_stage("INSTALL_DISTRIBUTION_READBACK")
    installed = distribution_evidence()
    mark_stage("INSTALL_MODULE_IMPORTS")
    origins = import_evidence()
    return {"startedUnixMs": started, "finishedUnixMs": utc_ms(), "pipExitCode": pip_exit_code,
            "target": str(DEPS), "reportPath": str(REPORT), "targetWasFresh": True,
            "reportVerified": report_verified, "installed": installed, "moduleOrigins": origins,
            "pipOutput": output.value(), "pipOutputTruncated": output.truncated,
            "pipProcessGuard": dict(_PIP_PROCESS_GUARD)}


def online_pdf():
    mark_stage("PDF_BOOTSTRAP_PATH")
    if any("site-packages" in part.lower() for part in sys.path):
        raise RuntimeError("PDF process may not import runtime site-packages")
    sys.path.insert(0, str(DEPS))
    mark_stage("PDF_DISTRIBUTION_READBACK")
    installed = distribution_evidence()
    mark_stage("PDF_MODULE_IMPORTS")
    origins = import_evidence()
    mark_stage("PDF_IMPORT_CANVAS")
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.lib.pagesizes import A4
    # A stdlib buffer supplies a fixed synthetic document; no external fonts,
    # images, user documents or package validators are invoked.
    mark_stage("PDF_CREATE_DOCUMENT")
    buffer = io.BytesIO()
    canvas = Canvas(buffer, pagesize=A4, pdfVersion=(1, 4), pageCompression=0, invariant=1)
    canvas.setTitle("Sandbox PDF test")
    canvas.setAuthor("Pi sandbox")
    canvas.setCreator("Pi sandbox PDF acceptance")
    canvas.setFont("Helvetica", 12)
    canvas.drawString(72, 720, "Sandbox PDF test")
    canvas.showPage()
    canvas.save()
    data = buffer.getvalue()
    if not 512 <= len(data) <= 65536:
        raise RuntimeError("fixed PDF byte bounds failed")
    mark_stage("PDF_WRITE_DOCUMENT")
    with PDF.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    return {"path": str(PDF), "byteCount": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "pageCount": 1, "expectedText": "Sandbox PDF test", "pageCompression": 0,
            "invariant": True, "installed": installed, "moduleOrigins": origins}


def main():
    if (sys.platform != "win32" or len(sys.argv) != 2 or sys.argv[1] not in MODES
            or sys.version_info[:3] != (3, 12, 10) or struct.calcsize("P") != 8
            or pathlib.Path(sys.executable) != ROOT / "runtime" / "python.exe"
            or pathlib.Path(__file__) != TRUSTED / "python-online-pdf-fixture.py"
            or pathlib.Path.cwd() != WORK
            or not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode)):
        raise RuntimeError("fixed isolated x64 runtime, fixture, mode and cwd required")
    mode = sys.argv[1]
    sanitize_environment()
    result = {"schemaVersion": 1, "mode": mode, "python": list(sys.version_info[:3]),
              "marker": "PYTHON_ISOLATION_OK", "outsideRead": None, "outsideWrite": None,
              "inputOk": None, "outputOk": None, "deniedRead": None, "deniedWrite": None,
              "tcp4": None, "tcp6": None}
    # Capture imported-library noise as well as pip itself. Errors still produce
    # exactly one bounded frame, but nonzero exit prevents a success assessment.
    captured = BoundedOutput()
    exit_code = 0
    try:
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            if mode == "online-install":
                result["onlineInstall"] = online_install()
            else:
                result["onlinePdf"] = online_pdf()
    except Exception as error:
        result["marker"] = "ONLINE_CASE_FAILED"
        # The fixed type is diagnostic only; no local paths or unbounded errors.
        result["errorType"] = type(error).__name__[:64]
        result["failure"] = failure_evidence(error)
        result["failure"]["pipProcessGuard"] = dict(_PIP_PROCESS_GUARD)
        if isinstance(error, FixedPipFailure):
            result["pipFailure"] = {"exitCode": error.exit_code, "output": error.output,
                                    "outputTruncated": error.truncated}
        exit_code = 1
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=True), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
