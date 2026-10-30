#!/usr/bin/env python3
"""Stateful Layer-7 HTTP deception sink. Standard library only."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, unquote_plus, urlsplit

HOST = "0.0.0.0"
PORT = 8080
SERVER_DOMAIN = "support-desk.ddns.net"
LOG_PATH = "/var/log/honeypot/raw_events.json"
MAX_CAPTURE_BYTES = 131072
MAX_DRAIN_BYTES = 2097152
SESSION_LIMIT = 5000
TRUSTED_PROXIES = {"127.0.0.1", "10.10.0.1"}

SESSIONS: OrderedDict[str, dict] = OrderedDict()
SESSIONS_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()

COOKIE_RE = re.compile(r"PHPSESSID=([a-f0-9]{26})")
CANARY_RE = re.compile(r"AKIAIOSFODNN7CANARY|canary_token_99a8b7c6")
CONFIG_RE = re.compile(r"(?:\.env|config\.php|wp-config\.php|\.git/config)", re.I)
PHPINFO_CALL_RE = re.compile(r"phpinfo\s*\(\s*\)", re.I)
PHPINFO_URI_RE = re.compile(r"phpinfo", re.I)
MATH_RE = re.compile(
    r"(?:expr\s+|print\s*\(\s*|echo\s+\$\(\(\s*)(\d{1,10})\s*([\+\-\*])\s*(\d{1,10})",
    re.I,
)
MD5_RE = re.compile(r"md5\s*\(\s*['\"]([^'\"]{1,64})['\"]\s*\)", re.I)
ECHO_RE = re.compile(
    r"(?:echo|printf)\s+(?:-e\s+|-n\s+)?['\"]?([a-zA-Z0-9_\-\.]{4,48})['\"]?",
    re.I,
)
ID_RE = re.compile(r"\bid\b")
WHOAMI_RE = re.compile(r"\bwhoami\b", re.I)
UNAME_RE = re.compile(r"\buname(?:\s+-[a-zA-Z]+)?\b", re.I)
PASSWD_RE = re.compile(r"/etc/passwd", re.I)
FS_RE = re.compile(r"\b(?:pwd|ls(?:\s+-[la]+)?)\b", re.I)
STAGE2_RE = re.compile(
    r"(?:wget|curl|fetch)\s+https?://|\bchmod\s+(?:\+x|777|755)|\b(?:bash|sh)\s+-c|/dev/tcp/",
    re.I,
)
PHP_STREAM_RE = re.compile(
    r"php://(?:filter|input)|auto_prepend_file|allow_url_include|convert\.iconv",
    re.I,
)
FIELD_RE = re.compile(
    r"Content-Disposition:[^\r\n]*?\bname=[\"']([^\"']+)[\"']",
    re.I,
)
FILENAME_RE = re.compile(
    r"Content-Disposition:[^\r\n]*?\bfilename=[\"']([^\"']+)[\"']",
    re.I,
)

KNOWN_PATHS = {"/", "/index.php", "/upload.php", "/diagnostics.php", "/robots.txt"}
PORTAL_PATHS = {"/", "/index.php", "/upload.php", "/diagnostics.php"}

ROBOTS = (
    "User-agent: *\n"
    "Disallow: /.env\n"
    "Disallow: /config.php\n"
    "Disallow: /phpinfo.php\n"
    "Disallow: /diagnostics.php\n"
    "Disallow: /vendor/\n"
)
CONFIG_BODY = (
    "APP_ENV=production\n"
    "APP_URL=https://support-desk.ddns.net\n"
    "DB_HOST=10.20.1.14\n"
    "DB_USER=support_admin\n"
    "DB_PASS=Pr0d_Supp0rt_2026!\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7CANARY\n"
    "AWS_SECRET_ACCESS_KEY=canary_token_99a8b7c6\n"
)
PHP_CGI_SOURCE = (
    "<?php\n"
    "session_start();\n"
    "include __DIR__ . '/diagnostics.php';\n"
    "include '/var/www/html/config.php';\n"
    "header('Content-Type: text/html; charset=UTF-8');\n"
    "?>\n"
)
CANARY_JSON = (
    '{"status":"authenticated","node":"support-desk-gw","role":"admin",'
    '"backup_path":"/var/backups/db_dump.sql.gz"}\n'
)
PHPINFO_HTML = (
    '<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>'
    '<h1 class="p">PHP Version 8.4.26</h1><table>'
    '<tr><td class="e">System</td><td class="v">Linux support-desk 6.8.0-45-generic '
    "#45-Ubuntu SMP PREEMPT_DYNAMIC x86_64</td></tr>"
    '<tr><td class="e">Server API</td><td class="v">Apache 2.0 Handler</td></tr>'
    '<tr><td class="e">session.upload_progress.enabled</td><td class="v">On</td></tr>'
    "</table></body></html>\n"
)
ID_BODY = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
WHOAMI_BODY = "www-data\n"
UNAME_BODY = (
    "Linux support-desk 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC "
    "x86_64 GNU/Linux\n"
)
PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
FS_BODY = "/var/www/html\nindex.php\nupload.php\ndiagnostics.php\n.env\n"
UPLOAD_JSON = (
    '{"status":"upload_buffered","bytes_processed":4096,"temp_name":"/tmp/phpU8a9f2"}\n'
)
STREAM_BODY = "Stream filter context initialized.\n"
# Metasploit's CVE-2024-4577 check treats HTTP 200 plus this quoted wrapper as vulnerable.
PHP_CGI_CHECK = (
    "<br />\n"
    "<b>Warning</b>: Unknown(): Failed opening 'php://input' for inclusion "
    "(include_path='.:/usr/share/php') in <b>Unknown</b> on line <b>0</b><br />\n"
)
NOT_FOUND = (
    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'
    "<html><head><title>404 Not Found</title></head><body>"
    "<h1>Not Found</h1>"
    "<p>The requested URL was not found on this server.</p><hr>"
    "<address>Apache/2.4.58 (Ubuntu) Server at support-desk.ddns.net "
    "Port 443</address></body></html>"
)
PORTAL_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IT Support &amp; System Diagnostics Gateway</title>
</head>
<body>
<!-- IT Support & Diagnostics Gateway v2.4.1 | Runtime: Apache/2.4.58 (Ubuntu) PHP/8.4.26 | Env: /.env -->
<h1>IT Support &amp; System Diagnostics Gateway</h1>
<form action="/index.php" method="POST" enctype="multipart/form-data">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="diag_upload">
<input type="file" name="diagnostic_archive">
<button type="submit">Upload Diagnostic Archive</button>
</form>
<form action="/diagnostics.php" method="POST">
<input type="hidden" name="_csrf_token" value="9f8e7d6c5b4a3210">
<input type="text" name="target" placeholder="127.0.0.1">
<button type="submit">Verify Host Connectivity</button>
</form>
<p><a href="/index.php?view=system_health.log">View System Health Log</a></p>
<p><a href="/index.php?view=runtime_env.conf">View Runtime Config</a></p>
</body>
</html>
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_client_ip(peer: str, forwarded: str | None) -> str:
    if peer in TRUSTED_PROXIES and forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return peer


def session_id_for(client_ip: str, cookie_header: str) -> tuple[str, bool]:
    match = COOKIE_RE.search(cookie_header or "")
    if match:
        return match.group(1), True
    digest = hashlib.sha1((client_ip + "support-desk-salt").encode()).hexdigest()
    return digest[:26], False


def read_exact(stream, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        try:
            chunk = stream.read(min(65536, count - len(buf)))
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def read_content_length(headers, stream) -> tuple[bytes, bool]:
    raw_length = headers.get("Content-Length", "") or ""
    try:
        declared = int(raw_length) if str(raw_length).strip() else 0
    except ValueError:
        declared = 0
    if declared < 0:
        declared = 0
    to_read = min(declared, MAX_DRAIN_BYTES)
    data = read_exact(stream, to_read) if to_read else b""
    truncated = declared > MAX_CAPTURE_BYTES
    return data[:MAX_CAPTURE_BYTES], truncated


def read_chunked_result(stream) -> tuple[bytes, bool]:
    captured = bytearray()
    seen = 0
    truncated = False
    while seen < MAX_DRAIN_BYTES:
        try:
            line = stream.readline(8192)
        except (TimeoutError, socket.timeout):
            truncated = True
            break
        if not line:
            break
        size_token = line.split(b";", 1)[0].strip()
        try:
            size = int(size_token or b"0", 16)
        except ValueError:
            truncated = True
            break
        if size == 0:
            while True:
                try:
                    trailer = stream.readline(8192)
                except (TimeoutError, socket.timeout):
                    break
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break
        budget = min(size, MAX_DRAIN_BYTES - seen)
        got = read_exact(stream, budget)
        seen += len(got)
        if len(captured) < MAX_CAPTURE_BYTES:
            room = MAX_CAPTURE_BYTES - len(captured)
            captured.extend(got[:room])
        if len(got) < size or seen >= MAX_DRAIN_BYTES:
            truncated = True
            break
        try:
            stream.read(2)
        except (TimeoutError, socket.timeout):
            truncated = True
            break
    if seen > MAX_CAPTURE_BYTES:
        truncated = True
    return bytes(captured), truncated


def multipart_parts(body_text: str) -> tuple[list[str], list[str]]:
    sample = body_text[:65536]
    return FIELD_RE.findall(sample), FILENAME_RE.findall(sample)


def apply_math(match: re.Match[str]) -> str:
    left = int(match.group(1))
    op = match.group(2)
    right = int(match.group(3))
    if op == "+":
        result = left + right
    elif op == "-":
        result = left - right
    else:
        result = left * right
    return f"{result}\n"


def decide(
    route_path: str,
    decoded_uri: str,
    payload_zone: str,
    header_blob: str,
    fields: list[str],
    transfer_encoding: str,
    body_text: str,
) -> tuple[int, str, bytes, str]:
    anywhere = "\n".join((decoded_uri, header_blob, payload_zone))
    if CANARY_RE.search(anywhere):
        return 200, "application/json; charset=UTF-8", CANARY_JSON.encode(), "lure:canary_replay"
    decoded_l = decoded_uri.lower()
    if "?-s" in decoded_l or "?%2ds" in decoded_l:
        return (
            200,
            "text/html",
            PHP_CGI_SOURCE.encode(),
            "lure:phpcgi_src_disclosure",
        )
    if CONFIG_RE.search(decoded_uri):
        return 200, "text/plain; charset=UTF-8", CONFIG_BODY.encode(), "lure:config_canary"
    if PHPINFO_URI_RE.search(decoded_uri) or PHPINFO_CALL_RE.search(payload_zone):
        return 200, "text/html; charset=UTF-8", PHPINFO_HTML.encode(), "lure:phpinfo"
    math = MATH_RE.search(payload_zone)
    if math:
        return 200, "text/plain; charset=UTF-8", apply_math(math).encode(), "primitive:math_verify"
    md5_match = MD5_RE.search(payload_zone)
    if md5_match:
        digest = hashlib.md5(md5_match.group(1).encode()).hexdigest()
        return 200, "text/plain; charset=UTF-8", f"{digest}\n".encode(), "primitive:md5_verify"
    echo = ECHO_RE.search(payload_zone)
    if echo:
        return 200, "text/plain; charset=UTF-8", f"{echo.group(1)}\n".encode(), "primitive:echo_verify"
    if ID_RE.search(body_text):
        return 200, "text/plain; charset=UTF-8", ID_BODY.encode(), "primitive:id"
    if WHOAMI_RE.search(payload_zone):
        return 200, "text/plain; charset=UTF-8", WHOAMI_BODY.encode(), "primitive:whoami"
    if UNAME_RE.search(payload_zone):
        return 200, "text/plain; charset=UTF-8", UNAME_BODY.encode(), "primitive:uname"
    if PASSWD_RE.search(payload_zone):
        return 200, "text/plain; charset=UTF-8", PASSWD_BODY.encode(), "primitive:passwd"
    if FS_RE.search(payload_zone):
        return 200, "text/plain; charset=UTF-8", FS_BODY.encode(), "primitive:fs_recon"
    if STAGE2_RE.search(payload_zone):
        return 200, "text/plain; charset=UTF-8", b"\n", "primitive:stage2_dropper"
    chunked = "chunked" in transfer_encoding.lower()
    if "PHP_SESSION_UPLOAD_PROGRESS" in fields or chunked:
        return 200, "application/json; charset=UTF-8", UPLOAD_JSON.encode(), "lure:multipart_progress"
    if "auto_prepend_file" in payload_zone.lower() and "php://input" in payload_zone.lower():
        return 200, "text/html", PHP_CGI_CHECK.encode(), "lure:phpcgi_arg_check"
    if PHP_STREAM_RE.search(payload_zone):
        return 200, "text/plain; charset=UTF-8", STREAM_BODY.encode(), "lure:php_stream"
    if route_path == "/robots.txt":
        return 200, "text/plain; charset=UTF-8", ROBOTS.encode(), "route:robots"
    if route_path in PORTAL_PATHS:
        return 200, "text/html; charset=UTF-8", PORTAL_HTML.encode(), "route:portal"
    return 404, "text/html; charset=UTF-8", NOT_FOUND.encode(), "route:not_found"


def update_session(
    session_id: str,
    cookie_present: bool,
    action: str,
    canary_hit: bool,
) -> dict:
    now = utc_now()
    with SESSIONS_LOCK:
        record = SESSIONS.get(session_id)
        if record is None:
            record = {
                "request_count": 0,
                "first_seen": now,
                "last_seen": now,
                "action_history": [],
                "canary_issued": False,
                "canary_replayed": False,
            }
            SESSIONS[session_id] = record
        else:
            SESSIONS.move_to_end(session_id)
        record["request_count"] += 1
        record["last_seen"] = now
        record["action_history"].append(action)
        del record["action_history"][:-20]
        if action == "lure:config_canary":
            record["canary_issued"] = True
        if canary_hit:
            record["canary_replayed"] = True
        while len(SESSIONS) > SESSION_LIMIT:
            SESSIONS.popitem(last=False)
        return {
            "id": session_id,
            "cookie_present": cookie_present,
            "request_count": record["request_count"],
            "action_history": list(record["action_history"]),
            "canary_issued": record["canary_issued"],
            "canary_replayed": record["canary_replayed"],
        }


def body_fields(raw_body: bytes, ingested: dict) -> dict:
    fields = {
        "bytes": len(raw_body),
        "truncated": ingested["truncated"],
        "hash": {"sha256": hashlib.sha256(raw_body).hexdigest()},
        "content": ingested["body_text"],
    }
    if len(raw_body) <= 4096:
        fields["b64"] = base64.b64encode(raw_body).decode("ascii")
    else:
        fields["b64_omitted"] = True
    return fields


def write_event(event: dict) -> None:
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with LOG_LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4.58"
    sys_version = "(Ubuntu)"

    def version_string(self) -> str:
        return "Apache/2.4.58 (Ubuntu)"

    def log_message(self, fmt: str, *args) -> None:
        return

    def setup(self) -> None:
        super().setup()
        self.request.settimeout(10.0)

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request(send_body=True)

    def do_POST(self) -> None:  # noqa: N802
        self._handle_request(send_body=True)

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_request(send_body=True)

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_request(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_request(send_body=False)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle_options()

    def _peer(self) -> tuple[str, int]:
        host = self.client_address[0]
        port = int(self.client_address[1])
        return host, port

    def _ingest(self) -> dict:
        peer_ip, peer_port = self._peer()
        client_ip = resolve_client_ip(peer_ip, self.headers.get("X-Forwarded-For"))
        transfer = self.headers.get("Transfer-Encoding", "") or ""
        try:
            if "chunked" in transfer.lower():
                raw_body, truncated = read_chunked_result(self.rfile)
            else:
                raw_body, truncated = read_content_length(self.headers, self.rfile)
        except (TimeoutError, socket.timeout, OSError):
            raw_body, truncated = b"", True
        body_text = raw_body.decode("utf-8", errors="replace")
        parsed = urlsplit(self.path)
        route_path = unquote(parsed.path or "/")
        decoded_uri = unquote_plus(self.path)
        payload_zone = decoded_uri + "\n" + body_text
        fields, filenames = multipart_parts(body_text)
        header_items = {key: value for key, value in self.headers.items()}
        header_blob = "\n".join(f"{key}: {value}" for key, value in header_items.items())
        cookie_header = self.headers.get("Cookie", "") or ""
        sid, cookie_present = session_id_for(client_ip, cookie_header)
        return {
            "peer_port": peer_port,
            "client_ip": client_ip,
            "raw_body": raw_body,
            "truncated": truncated,
            "transfer": transfer,
            "body_text": body_text,
            "parsed": parsed,
            "route_path": route_path,
            "decoded_uri": decoded_uri,
            "payload_zone": payload_zone,
            "fields": fields,
            "filenames": filenames,
            "header_items": header_items,
            "header_blob": header_blob,
            "sid": sid,
            "cookie_present": cookie_present,
        }

    def _send(self, status: int, content_type: str, body: bytes, send_body: bool, session: dict) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if not session["cookie_present"]:
            self.send_header(
                "Set-Cookie",
                f"PHPSESSID={session['id']}; path=/; HttpOnly",
            )
        self.end_headers()
        if send_body and body:
            self.wfile.write(body)

    def _event(self, ingested: dict, session: dict, status: int, body: bytes, action: str) -> None:
        parsed = ingested["parsed"]
        raw_body = ingested["raw_body"]
        user_agent = self.headers.get("User-Agent", "") or ""
        write_event(
            {
                "@timestamp": utc_now(),
                "ecs": {"version": "8.11.0"},
                "client": {"ip": ingested["client_ip"], "port": ingested["peer_port"]},
                "server": {"domain": SERVER_DOMAIN, "port": PORT},
                "session": session,
                "http": {
                    "version": "1.1",
                    "request": {
                        "method": self.command,
                        "mime_type": self.headers.get("Content-Type", "") or "",
                        "transfer_encoding": ingested["transfer"] or "",
                        "headers": ingested["header_items"],
                        "multipart": {
                            "fields": ingested["fields"],
                            "filenames": ingested["filenames"],
                        },
                        "body": body_fields(raw_body, ingested),
                    },
                    "response": {"status_code": status, "bytes": len(body)},
                },
                "url": {
                    "original": self.path,
                    "path": parsed.path or "/",
                    "query": parsed.query,
                    "decoded": ingested["decoded_uri"],
                },
                "user_agent": {"original": user_agent},
                "sensor": {"action": action},
            }
        )

    def _handle_request(self, send_body: bool) -> None:
        sent = False
        try:
            ingested = self._ingest()
            status, content_type, body, action = decide(
                ingested["route_path"],
                ingested["decoded_uri"],
                ingested["payload_zone"],
                ingested["header_blob"],
                ingested["fields"],
                ingested["transfer"],
                ingested["body_text"],
            )
            canary_hit = CANARY_RE.search(
                "\n".join(
                    (ingested["decoded_uri"], ingested["header_blob"], ingested["payload_zone"])
                )
            ) is not None
            session = update_session(
                ingested["sid"],
                ingested["cookie_present"],
                action,
                canary_hit,
            )
            self._send(status, content_type, body, send_body, session)
            sent = True
            self._event(ingested, session, status, body, action)
        except Exception:
            self.close_connection = True
            if sent:
                return
            try:
                fallback = b"\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=UTF-8")
                self.send_header("Content-Length", str(len(fallback)))
                self.send_header("Connection", "close")
                self.end_headers()
                if send_body:
                    self.wfile.write(fallback)
            except OSError:
                return

    def _handle_options(self) -> None:
        try:
            ingested = self._ingest()
            action = "route:options"
            canary_hit = CANARY_RE.search(
                "\n".join(
                    (ingested["decoded_uri"], ingested["header_blob"], ingested["payload_zone"])
                )
            ) is not None
            session = update_session(
                ingested["sid"],
                ingested["cookie_present"],
                action,
                canary_hit,
            )
            self.close_connection = True
            self.send_response(200)
            self.send_header("X-Powered-By", "PHP/8.4.26")
            self.send_header("Allow", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            if not session["cookie_present"]:
                self.send_header("Set-Cookie", f"PHPSESSID={session['id']}; path=/; HttpOnly")
            self.end_headers()
            self._event(ingested, session, 200, b"", action)
        except OSError:
            self.close_connection = True


class HoneypotServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    server = HoneypotServer((HOST, PORT), Handler)
    print(f"honeypot listening on {HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
