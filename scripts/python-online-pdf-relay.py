"""Fixed, owner-side ONLINE PyPI wheel relay. Never imports/installs wheel payloads.

No prefetched wheels/cache, CONNECT tunnel, caller-selected URLs or redirects.
The three approved wheels are fetched only after an actual sandbox pip GET.
This public-artifact listener does not authenticate every local TCP caller.
"""
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(r"C:\PiSandboxLab")
TRUSTED = ROOT / "trusted"
HOST = "127.0.0.1"
PORT = 43873
LIFETIME_SECONDS = 300
REQUEST_SECONDS = 45
MAX_EVENTS = 64
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024
EXPECTED = {
    "reportlab": ("5.0.1", "reportlab-5.0.1-py3-none-any.whl", 1957258,
                  "1c36e6bb0e71780c72331eba60da7f602e8d4389a8723825af71342e49d791e8"),
    "pillow": ("12.3.0", "pillow-12.3.0-cp312-cp312-win_amd64.whl", 7227137,
               "a2b55dd6b2a4c4b7d87ffa56bdb33fdc5fdb9a462173861a7bc097f17d91cb09"),
    "charset-normalizer": ("3.5.2", "charset_normalizer-3.5.2-py3-none-any.whl", 68872,
                           "b6b751274acb69d77b3323d6b7dbaa3c7fdfc1eb829b7eb61d262f32e1af9685"),
}


def clock_fields():
    unix_ms = time.time_ns() // 1_000_000
    now = datetime.datetime.fromtimestamp(unix_ms // 1000, datetime.timezone.utc).replace(
        microsecond=(unix_ms % 1000) * 1000)
    return {"utc": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "unixMs": unix_ms, "monotonicNs": time.monotonic_ns()}


def load_manifest():
    path = TRUSTED / "python-online-pdf-packages.json"
    if path.stat().st_size > 16384:
        raise RuntimeError("manifest exceeds bound")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if set(manifest) != {"schemaVersion", "target", "packages"} or manifest["schemaVersion"] != 1 or manifest["target"] != "cp312-win_amd64":
        raise RuntimeError("fixed manifest identity required")
    packages = manifest["packages"]
    if not isinstance(packages, list) or len(packages) != 3:
        raise RuntimeError("exact three approved wheels required")
    routes = {}
    seen = set()
    for package in packages:
        if set(package) != {"name", "version", "filename", "url", "sha256", "size"}:
            raise RuntimeError("unexpected package fields")
        name = package["name"]
        if name not in EXPECTED or name in seen:
            raise RuntimeError("unexpected or duplicate package")
        seen.add(name)
        if (package["version"], package["filename"], package["size"], package["sha256"]) != EXPECTED[name]:
            raise RuntimeError("approved wheel identity changed")
        parsed = urllib.parse.urlsplit(package["url"])
        if (parsed.scheme != "https" or parsed.netloc != "files.pythonhosted.org"
                or parsed.query or parsed.fragment or parsed.username or parsed.password
                or not re.fullmatch(r"/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]+/" + re.escape(package["filename"]), parsed.path)):
            raise RuntimeError("fixed official HTTPS wheel URL required")
        routes["/wheels/" + package["filename"]] = package
    return routes


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("upstream redirects are forbidden")


def fetch_wheel(package, record, deadline):
    """One live HTTPS GET, bounded memory, exact length/SHA before any forwarding."""
    context = ssl.create_default_context()
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise RuntimeError("verified TLS context required")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), NoRedirect())
    request = urllib.request.Request(package["url"], headers={
        "User-Agent": "PiSandboxOnlinePdfLab/1", "Accept-Encoding": "identity"}, method="GET")
    record("upstream_fetch_started", upstreamHost="files.pythonhosted.org")
    with opener.open(request, timeout=20) as response:
        if response.status != 200 or response.geturl() != package["url"]:
            raise RuntimeError("exact upstream response required")
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            raise RuntimeError("encoded upstream responses forbidden")
        if response.headers.get("Content-Length") != str(package["size"]):
            raise RuntimeError("exact upstream content length required")
        chunks = bytearray()
        while len(chunks) <= package["size"]:
            if time.monotonic() >= deadline:
                raise TimeoutError("fixed online fetch deadline exceeded")
            part = response.read1(min(65536, package["size"] + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
            if len(chunks) > MAX_PAYLOAD_BYTES:
                raise RuntimeError("wheel response exceeds bound")
        data = bytes(chunks)
    if len(data) != package["size"] or hashlib.sha256(data).hexdigest() != package["sha256"]:
        raise RuntimeError("online wheel size/hash mismatch")
    record("upstream_hash_verified", bytes=len(data), sha256=package["sha256"])
    return data


class Relay(http.server.HTTPServer):
    allow_reuse_address = False
    def __init__(self, routes, log):
        self.routes = routes
        self.log = log
        self.deadline = time.monotonic() + LIFETIME_SECONDS
        self.fetch_count = 0
        self.requests = 0
        self.events = 0
        self.requested = set()
        super().__init__((HOST, PORT), Handler, bind_and_activate=False)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.server_bind()
            self.server_activate()
        except BaseException:
            self.server_close()
            raise
        self.timeout = 0.2

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(min(10, max(0.1, self.deadline - time.monotonic())))
        return connection, address

    def record(self, event, **fields):
        self.events += 1
        if self.events > MAX_EVENTS:
            raise RuntimeError("relay event bound exceeded")
        item = {"schemaVersion": 1, "event": event, **clock_fields(), **fields}
        encoded = json.dumps(item, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"
        if len(encoded) > 2048:
            raise RuntimeError("relay event size exceeded")
        self.log.write(encoded)
        self.log.flush()
        os.fsync(self.log.fileno())


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "PiFixedWheelRelay/1"
    sys_version = ""
    def log_message(self, format, *args):
        pass  # Never echo request paths, headers or arbitrary client text.

    def finish(self):
        try:
            super().finish()
        except (OSError, TimeoutError):
            pass

    def reply(self, code, data, content_type="application/json"):
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def reject(self, reason):
        self.server.record("request_rejected", reason=reason)
        self.reply(403, b'{"error":"fixed relay request refused"}')

    def do_GET(self):
        server = self.server
        server.requests += 1
        if server.requests > 12 or time.monotonic() >= server.deadline:
            self.reject("REQUEST_BOUND_OR_DEADLINE")
            return
        if (self.headers.get("Transfer-Encoding") is not None
                or self.headers.get("Content-Length", "0") != "0"):
            self.reject("BODY_FORBIDDEN")
            return
        if self.path == "/health":
            server.record("health", packageFetchCount=server.fetch_count)
            self.reply(200, json.dumps({"schemaVersion": 1,
                "packageFetchCount": server.fetch_count}).encode("ascii"))
            return
        package = server.routes.get(self.path)
        if package is None:
            self.reject("ROUTE_NOT_APPROVED")
            return
        if package["filename"] in server.requested:
            self.reject("DUPLICATE_PACKAGE_REQUEST")
            return
        server.requested.add(package["filename"])
        server.fetch_count += 1
        fields = {"requestId": server.fetch_count, "package": package["name"], "filename": package["filename"]}
        def record(event, **extra):
            server.record(event, **fields, **extra)
        record("package_request")
        try:
            data = fetch_wheel(package, record, min(server.deadline, time.monotonic() + REQUEST_SECONDS))
            self.reply(200, data, "application/octet-stream")
            record("wheel_served", bytes=len(data), sha256=package["sha256"])
        except Exception as error:
            record("fetch_failed", errorType=type(error).__name__[:64])
            try:
                self.reply(502, b'{"error":"fixed online fetch failed"}')
            except OSError:
                pass

    def do_CONNECT(self):
        self.reject("CONNECT_FORBIDDEN")
    def do_POST(self):
        self.reject("UPLOAD_FORBIDDEN")
    def do_HEAD(self):
        self.reject("METHOD_NOT_APPROVED")


def main():
    if (os.name != "nt" or sys.version_info[:3] != (3, 12, 10) or len(sys.argv) != 1
            or pathlib.Path(sys.executable) != ROOT / "runtime" / "python.exe"
            or pathlib.Path.cwd() != TRUSTED):
        raise RuntimeError("fixed Windows relay launch required")
    # A hard process-local watchdog bounds slow headers/body reads even when a
    # socket peer trickles bytes. Owner Job cleanup independently supervises us.
    watchdog = threading.Timer(LIFETIME_SECONDS, os._exit, args=(124,))
    watchdog.daemon = True
    watchdog.start()
    routes = load_manifest()
    # Fresh log/ready artifacts make reuse visible; never touch a wheel cache.
    with (TRUSTED / "python-online-pdf-relay.log").open("xb") as log:
        with Relay(routes, log) as server:
            now = clock_fields()
            ready = {"schemaVersion": 1, "pid": os.getpid(), "host": HOST, "port": PORT,
                     "packageFetchCount": 0, "startedUtc": now["utc"], "startedUnixMs": now["unixMs"]}
            pending = TRUSTED / "python-online-pdf-relay-ready.pending"
            with pending.open("xb") as output:
                output.write(json.dumps(ready, separators=(",", ":")).encode("ascii"))
                output.flush()
                os.fsync(output.fileno())
            # Windows rename publishes the closed complete file atomically and
            # refuses an existing destination; never expose partial JSON.
            pending.rename(TRUSTED / "python-online-pdf-relay-ready.json")
            server.record("relay_ready", **ready)
            while time.monotonic() < server.deadline and server.requests <= 12:
                server.handle_request()
            server.record("relay_stopped", packageFetchCount=server.fetch_count)
    watchdog.cancel()


if __name__ == "__main__":
    main()
