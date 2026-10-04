#!/usr/bin/env python3
"""End-to-end tests for dcs, for agena, and for the Gemini implementation in
Indy that both are built on.

Three layers are covered:

  protocol  raw TLS sockets speaking the wire format directly, so the server
            side of IdGeminiServer is tested on its own rather than through a
            client that would normalise away the very thing under test
  client    the dcs binary against agena, which covers IdGemini's client side
            together with dcs's argument handling and output
  stub      dcs against a scripted listener, for the parts of the client that
            agena has no way to reach, such as the status 10 input handshake

Run it with:

    python3 tests/run_tests.py

Environment:
    DCS_BIN    path to the dcs binary   (default ../build/dcs)
    AGENA_DIR  the agena checkout       (default sibling ../agena)

A server certificate and the document root are built per run, so the suite
depends on nothing checked in.

Tests that assert behaviour the code does not have are marked xfail rather
than deleted. They are reported separately and do not fail the run, but one of
them passing is itself reported as a failure, so a fix cannot slip through
unnoticed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DCS_BIN = Path(os.environ.get("DCS_BIN", HERE.parent / "build" / "dcs")).resolve()
AGENA_DIR = Path(os.environ.get("AGENA_DIR", HERE.parent.parent / "agena")).resolve()
AGENA_BIN = AGENA_DIR / "build" / "agena"

HOST = "127.0.0.1"
REQUEST_LIMIT = 1024  # IdGeminiServer reads the request line with this cap

# --------------------------------------------------------------------------
# tiny test registry
# --------------------------------------------------------------------------

TESTS: list[tuple[str, str, str | None]] = []


def test(group: str, xfail: str | None = None):
    """Register a test. xfail names the defect the test is currently pinning."""

    def deco(fn):
        TESTS.append((group, fn.__name__, fn, xfail))
        return fn

    return deco


class Failure(AssertionError):
    pass


def check(cond, msg: str) -> None:
    if not cond:
        raise Failure(msg)


def check_eq(got, want, what: str) -> None:
    if got != want:
        raise Failure(f"{what}: got {got!r}, want {want!r}")


def check_in(needle, hay, what: str) -> None:
    if needle not in hay:
        raise Failure(f"{what}: {needle!r} not found in {hay!r}")


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

CGI_ECHO = """#!/usr/bin/env python3
import os, sys

n = int(os.environ.get("CONTENT_LENGTH") or 0)
data = sys.stdin.buffer.read(n) if n else b""
sys.stdout.write("echo\\n")
sys.stdout.write("path=%s\\n" % os.environ.get("PATH_INFO", ""))
sys.stdout.write("query=%s\\n" % os.environ.get("QUERY_STRING", ""))
sys.stdout.write("method=%s\\n" % os.environ.get("REQUEST_METHOD", ""))
sys.stdout.write("url=%s\\n" % os.environ.get("GEMINI_URL", ""))
sys.stdout.write("proto=%s\\n" % os.environ.get("SERVER_PROTOCOL", ""))
sys.stdout.write("remote=%s\\n" % os.environ.get("REMOTE_ADDR", ""))
sys.stdout.write("len=%d\\n" % len(data))
sys.stdout.write("data=%s\\n" % data.decode("utf-8", "replace"))
"""

CGI_TYPE = """#!/usr/bin/env python3
import sys
sys.stdout.write("Content-Type: text/plain; charset=utf-8\\n")
sys.stdout.write("\\n")
sys.stdout.write("plain text from cgi\\n")
"""

CGI_FAIL = """#!/usr/bin/env python3
import sys
sys.stdout.write("partial output before dying\\n")
sys.exit(3)
"""

# extension -> metadata agena is expected to send (see AgenaMime.MetaForPath)
MIME_CASES = {
    "page.gmi": "text/gemini; charset=utf-8",
    "page.gemini": "text/gemini; charset=utf-8",
    "page.txt": "text/plain; charset=utf-8",
    "page.md": "text/markdown; charset=utf-8",
    "page.html": "text/html; charset=utf-8",
    "page.htm": "text/html; charset=utf-8",
    "page.css": "text/css; charset=utf-8",
    "page.js": "text/javascript; charset=utf-8",
    "page.json": "application/json",
    "page.svg": "image/svg+xml",
    "page.png": "image/png",
    "page.jpg": "image/jpeg",
    "page.jpeg": "image/jpeg",
    "page.gif": "image/gif",
    "page.webp": "image/webp",
    "page.ico": "image/vnd.microsoft.icon",
    "page.xyz": "application/octet-stream",
    "noext": "text/plain",
}


def write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mode is not None:
        path.chmod(mode)


def build_docroot(root: Path) -> Path:
    docroot = root / "www"
    write(docroot / "index.gmi", "# fixture index\n\n=> /about.gmi about\n=> /sub/ sub\n")
    write(docroot / "about.gmi", "# about the fixture\n\nfixture body line\n")
    write(docroot / "sub" / "index.gmi", "# sub index\n")
    for name in MIME_CASES:
        write(docroot / name, "payload for %s\n" % name)
    cgi = docroot / "cgi-bin"
    write(cgi / "echo", CGI_ECHO, 0o755)
    write(cgi / "type", CGI_TYPE, 0o755)
    write(cgi / "fail", CGI_FAIL, 0o755)
    write(cgi / "noexec", "#!/usr/bin/env python3\nprint('never runs')\n", 0o644)
    # lives outside the document root, for the traversal checks
    write(root / "secret.txt", "TOP SECRET\n")
    return docroot


def make_cert(root: Path) -> tuple[Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert), "-days", "2", "-nodes",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return cert, key


def make_client_cert(target: Path, cn: str, mail: str | None = None) -> tuple[Path, Path]:
    target.mkdir(parents=True, exist_ok=True)
    key, crt = target / "id.key", target / "id.crt"
    subj = "/CN=%s" % cn + ("/emailAddress=%s" % mail if mail else "")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(crt), "-days", "2", "-nodes", "-subj", subj],
        check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", str(crt), "-outform", "DER"],
                         check=True, capture_output=True).stdout
    fp = hashlib.sha256(der).hexdigest()
    named_crt, named_key = target / (fp + ".crt"), target / (fp + ".key")
    crt.replace(named_crt)
    key.replace(named_key)
    return named_crt, named_key


# --------------------------------------------------------------------------
# agena, the real server under test
# --------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


class Agena:
    def __init__(self, root: Path, port: int, cert: Path, key: Path,
                 require_tls13: bool = False):
        self.root = root
        self.port = port
        self.require_tls13 = require_tls13
        self.cert, self.key = cert, key
        self.proc: subprocess.Popen | None = None
        self.logfile = root / "agena.log"
        self.logfh = None

    def url(self, path: str = "") -> str:
        return "gemini://%s:%d%s" % (HOST, self.port, path)

    def start(self) -> None:
        docroot = build_docroot(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        ini = self.root / "agena.ini"
        ini.write_text(
            "[server]\n"
            "BindAddress = %s\n"
            "Port = %d\n"
            "DocumentRoot = %s\n\n"
            "[tls]\n"
            "CertificateFile = %s\n"
            "PrivateKeyFile = %s\n"
            "RequireTLS13 = %s\n\n"
            "[cgi]\n"
            "PathPrefix = /cgi-bin/\n"
            % (HOST, self.port, docroot, self.cert, self.key,
               "true" if self.require_tls13 else "false"))

        self.logfh = self.logfile.open("w")
        self.proc = subprocess.Popen([str(AGENA_BIN), str(ini)],
                                     stdout=self.logfh, stderr=subprocess.STDOUT)
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("agena exited early:\n" + self.log())
            try:
                with socket.create_connection((HOST, self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("agena did not start listening:\n" + self.log())

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self.logfh:
            self.logfh.close()

    def log(self) -> str:
        try:
            return self.logfile.read_text()
        except OSError:
            return ""

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


# --------------------------------------------------------------------------
# a scripted listener, for what agena cannot be asked to do
# --------------------------------------------------------------------------

class Stub:
    """Answers each connection with the next scripted response, recording the
    request lines it was sent."""

    def __init__(self, cert: Path, key: Path, responses: list[bytes]):
        self.responses = list(responses)
        self.cert, self.key = cert, key
        self.received: list[str] = []
        self.port = free_port()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, self.port))
        self.sock.listen(8)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def url(self, path: str = "") -> str:
        return "gemini://%s:%d%s" % (HOST, self.port, path)

    def start(self) -> "Stub":
        self.thread.start()
        return self

    def _serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                data = b""
                while b"\r\n" not in data and len(data) < 8192:
                    part = tls.recv(4096)
                    if not part:
                        return
                    data += part
                line = data.split(b"\r\n", 1)[0]
                self.received.append(line.decode("utf-8", "replace"))
                reply = self.responses.pop(0) if self.responses else b"51 gone\r\n"
                tls.sendall(reply)
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def wait_for(self, count: int, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.received) < count:
            time.sleep(0.02)


# --------------------------------------------------------------------------
# raw wire access, for the server side
# --------------------------------------------------------------------------

def tls_context(minimum=None, maximum=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if minimum is not None:
        ctx.minimum_version = minimum
    if maximum is not None:
        ctx.maximum_version = maximum
    return ctx


def raw_request(port: int, payload: bytes, timeout: float = 5.0) -> bytes:
    """Send payload, read to end of stream, return whatever came back."""
    ctx = tls_context()
    with socket.create_connection((HOST, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock) as ssock:
            ssock.sendall(payload)
            chunks = []
            try:
                while True:
                    part = ssock.recv(65536)
                    if not part:
                        break
                    chunks.append(part)
            except (socket.timeout, ssl.SSLError, OSError):
                pass
            return b"".join(chunks)


def raw_get(port: int, path: str, timeout: float = 5.0) -> bytes:
    """The request as the spec has it: a bare URL, then CRLF."""
    return raw_request(port, ("gemini://%s:%d%s\r\n" % (HOST, port, path)).encode(),
                       timeout)


def header(raw: bytes) -> str:
    """The response header is one line: the status, a space, then the metadata."""
    return raw.split(b"\r\n", 1)[0].decode("utf-8", "replace")


def body(raw: bytes) -> str:
    parts = raw.split(b"\r\n", 1)
    return parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""


def negotiate_tls(port: int, minimum=None, maximum=None) -> str:
    """Return the negotiated version, or raise if the handshake failed."""
    ctx = tls_context(minimum, maximum)
    with socket.create_connection((HOST, port), timeout=5) as sock:
        with ctx.wrap_socket(sock) as ssock:
            return ssock.version()


# --------------------------------------------------------------------------
# driving dcs
# --------------------------------------------------------------------------

class Dcs:
    def __init__(self, server: Agena, xdg: Path):
        self.server = server
        self.xdg = xdg

    def run(self, *args, stdin: bytes | None = None, xdg: Path | None = None,
            cwd: Path | None = None):
        env = dict(os.environ)
        env["XDG_CONFIG_HOME"] = str(xdg or self.xdg)
        proc = subprocess.run([str(DCS_BIN), *[str(a) for a in args]],
                              input=stdin, capture_output=True, env=env,
                              cwd=str(cwd) if cwd else None, timeout=30)
        return proc

    def url(self, path: str = "") -> str:
        return self.server.url(path)


def dcs_fields(proc) -> dict:
    """Pull the label: value lines out of dcs's report."""
    out = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        for key, label in (("url", "url:"), ("status", "status:"),
                           ("meta", "meta:"), ("wrote", "wrote:"),
                           ("identity", "identity:"), ("error", "error:")):
            if line.startswith(label):
                out[key] = line[len(label):].strip()
    return out


def dcs_status(proc) -> int | None:
    value = dcs_fields(proc).get("status")
    if value is None:
        return None
    try:
        return int(value.split()[0])
    except (IndexError, ValueError):
        return None


def dcs_meta(proc) -> str:
    return dcs_fields(proc).get("meta", "").strip('"')


def dcs_body(proc) -> str:
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    for i, line in enumerate(lines):
        if not line.strip():
            return "\n".join(lines[i + 1:])
    return ""


def kv(text: str) -> dict:
    """Parse the CGI echo fixture's key=value lines."""
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def fingerprint_of(proc) -> str:
    return proc.stdout.decode().strip()


# --------------------------------------------------------------------------
# protocol: the server side of IdGeminiServer, over raw sockets
# --------------------------------------------------------------------------

@test("protocol")
def plain_get_succeeds(ctx):
    raw = raw_get(ctx.server.port, "/index.gmi")
    check(raw.startswith(b"20 "), "expected a 20 status, got %r" % raw[:40])
    check_eq(header(raw), "20 text/gemini; charset=utf-8", "response header")
    check_in("# fixture index", body(raw), "body")


@test("protocol")
def header_is_a_single_line(ctx):
    """The spec has no second header line: STATUS SP META, then the body."""
    raw = raw_get(ctx.server.port, "/about.gmi")
    check_eq(header(raw), "20 text/gemini; charset=utf-8", "response header")
    check(not body(raw).startswith("\n"),
          "there should be no blank line between the header and the body")


@test("protocol")
def request_line_uses_crlf_only(ctx):
    """A bare LF is not a terminator, so the server must not answer 20."""
    url = "gemini://%s:%d/index.gmi" % (HOST, ctx.server.port)
    raw = raw_request(ctx.server.port, b"%s\n" % url.encode(), timeout=2.0)
    check(not raw.startswith(b"20 "),
          "a bare LF was accepted as a request terminator: %r" % raw[:40])


@test("protocol")
def over_long_request_line_is_59(ctx):
    path = "/" + "a" * (REQUEST_LIMIT + 64)
    raw = raw_get(ctx.server.port, path)
    check(raw.startswith(b"59 "), "expected 59 for an over-long line, got %r" % raw[:40])
    check_in("too long", raw.lower().decode(), "59 should say the line was too long")


@test("protocol")
def request_line_at_the_limit_is_parsed(ctx):
    """A line right at the cap must be parsed rather than rejected.

    It cannot be served, since no filename is 1000 characters long, so a 40 is
    the evidence that it was understood: a 59 would mean the cap is off by one
    and a 59 for a shorter line would mean it is off in the other direction.
    """
    pad = REQUEST_LIMIT - len("gemini://%s:%d/\r\n" % (HOST.encode(), ctx.server.port))
    raw = raw_get(ctx.server.port, "/" + "b" * (pad - 1))
    check(not raw.startswith(b"59 "),
          "a line at the cap was rejected as too long: %r" % raw[:40])


@test("protocol")
def empty_request_is_59(ctx):
    raw = raw_request(ctx.server.port, b"\r\n")
    check(raw.startswith(b"59 "), "expected 59 for an empty request, got %r" % raw[:40])


@test("protocol")
def userinfo_in_url_is_refused(ctx):
    url = "gemini://someone@%s:%d/index.gmi" % (HOST, ctx.server.port)
    raw = raw_request(ctx.server.port, b"%s\r\n" % url.encode())
    check(raw.startswith(b"59 "), "expected 59 for userinfo, got %r" % raw[:40])
    check_in("userinfo", raw.lower().decode(), "59 should mention userinfo")


@test("protocol")
def fragment_in_url_is_refused(ctx):
    url = "gemini://%s:%d/index.gmi#frag" % (HOST, ctx.server.port)
    raw = raw_request(ctx.server.port, b"%s\r\n" % url.encode())
    check(raw.startswith(b"59 "), "expected 59 for a fragment, got %r" % raw[:40])
    check_in("fragment", raw.lower().decode(), "59 should mention fragments")


@test("protocol")
def query_string_reaches_the_script_verbatim(ctx):
    raw = raw_get(ctx.server.port, "/cgi-bin/echo?a=1&b=two%20words")
    check(raw.startswith(b"20 "), "expected 20, got %r" % raw[:40])
    check_in("query=a=1&b=two%20words", body(raw),
             "the query should reach QUERY_STRING unchanged")


@test("protocol")
def missing_document_is_not_found(ctx):
    raw = raw_get(ctx.server.port, "/nope")
    check(raw.startswith(b"40 "), "expected 40 for a missing document, got %r" % raw[:40])


@test("protocol")
def path_traversal_is_refused(ctx):
    for path in ("/../secret.txt", "/..%2fsecret.txt", "/sub/../../secret.txt"):
        raw = raw_get(ctx.server.port, path)
        check(not raw.startswith(b"20 "),
              "traversal %s was served: %r" % (path, raw[:60]))
        check(b"TOP SECRET" not in raw, "traversal %s leaked the file" % path)


@test("protocol")
def deep_traversal_clamps_at_the_root(ctx):
    raw = raw_get(ctx.server.port, "/" + "../" * 40 + "secret.txt")
    check(b"TOP SECRET" not in raw, "deep traversal leaked the file")


@test("protocol")
def input_after_the_request_line_is_handed_to_the_script(ctx):
    """Not in the request grammar, which is `absolute-URI CRLF` and nothing
    else, but agena reads anything left on the socket and treats it as input."""
    url = "gemini://%s:%d/cgi-bin/echo" % (HOST, ctx.server.port)
    sent = b"hello there\n"
    raw = raw_request(ctx.server.port, b"%s\r\n%s" % (url.encode(), sent))
    check(raw.startswith(b"20 "), "expected 20, got %r" % raw[:40])
    fields = kv(body(raw))
    check_eq(fields.get("method"), "POST", "REQUEST_METHOD with input present")
    check_eq(fields.get("path"), "cgi-bin/echo", "PATH_INFO")
    check_eq(fields.get("data"), "hello there", "the input should reach stdin")
    check_eq(int(fields.get("len", "0")), len(sent) + 1,
             "CONTENT_LENGTH should count the input plus the newline agena adds")


@test("protocol")
def server_survives_a_bad_request(ctx):
    """Malformed requests must not take the listener down."""
    raw_request(ctx.server.port, b"garbage without a scheme\r\n")
    raw_request(ctx.server.port, b"gemini://\x01\x02\x03/\r\n")
    raw_request(ctx.server.port, b"http://%s:%d/index.gmi\r\n" % (HOST.encode(), ctx.server.port))
    check(ctx.server.alive(), "the server stopped after malformed requests")
    raw = raw_get(ctx.server.port, "/index.gmi")
    check(raw.startswith(b"20 "), "the server stopped serving: %r" % raw[:40])


# --------------------------------------------------------------------------
# client: dcs against agena
# --------------------------------------------------------------------------

@test("client")
def fetch_index(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/"))
    check_eq(proc.returncode, 0, "exit code")
    check_eq(dcs_status(proc), 20, "status")
    check_eq(dcs_meta(proc), "text/gemini; charset=utf-8", "meta")
    check_in("# fixture index", dcs_body(proc), "body")


@test("client")
def fetch_about(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/about.gmi"))
    check_eq(dcs_status(proc), 20, "status")
    check_in("fixture body line", dcs_body(proc), "body")


@test("client")
def missing_document_reports_40(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/nope"))
    check_eq(dcs_status(proc), 40, "status")
    check_eq(proc.returncode, 0, "a completed request exits 0 whatever the status")
    check_eq(dcs_body(proc), "", "a failure should carry no document body")


@test("client")
def directory_resolves_to_index(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/sub/"))
    check_eq(dcs_status(proc), 20, "status")
    check_in("# sub index", dcs_body(proc), "body")


@test("client")
def query_is_sent_and_echoed(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/cgi-bin/echo?a=1&b=2"))
    check_eq(dcs_status(proc), 20, "status")
    fields = kv(dcs_body(proc))
    check_eq(fields.get("query"), "a=1&b=2", "QUERY_STRING")
    check_eq(fields.get("method"), "GET", "REQUEST_METHOD")
    check_eq(fields.get("proto"), "GEMINI", "SERVER_PROTOCOL")
    check_eq(fields.get("remote"), HOST, "REMOTE_ADDR")
    check_eq(fields.get("len"), "0", "CONTENT_LENGTH on a query with no input")
    check_eq(fields.get("data"), "", "stdin should stay empty")


@test("client")
def input_is_not_sent_until_the_server_asks(ctx):
    """agens never answers 10 or 11, so input must stay put.

    This is the spec: a client holds its input back until the server asks for
    it, which is what stops a mistyped URL from swallowing a password.
    """
    proc = ctx.dcs.run("--input", "-", ctx.dcs.url("/cgi-bin/echo"),
                       stdin=b"a secret\n")
    check_eq(proc.returncode, 0, "exit code")
    fields = kv(dcs_body(proc))
    check_eq(fields.get("method"), "GET", "REQUEST_METHOD should stay GET")
    check_eq(fields.get("data"), "", "the input must not be sent unasked")


@test("client")
def cgi_can_choose_its_metadata(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/cgi-bin/type"))
    check_eq(dcs_meta(proc), "text/plain; charset=utf-8", "meta from the CGI header")
    text = dcs_body(proc)
    check_in("plain text from cgi", text, "body")
    check("Content-Type" not in text, "the header line leaked into the body")


@test("client")
def non_executable_cgi_is_refused(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/cgi-bin/noexec"))
    check_eq(dcs_status(proc), 40, "a non-executable CGI should not run")
    check_in("is not executable", ctx.server.log(), "the reason should be logged")


@test("client")
def missing_cgi_is_refused(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/cgi-bin/nothere"))
    check_eq(dcs_status(proc), 40, "a missing CGI should fail")
    check_in("no such script", ctx.server.log(), "the reason should be logged")


@test("client", xfail="agena never sees P.ExitCode, so a CGI that exits "
                      "non-zero is served as 20 with whatever it printed first")
def failing_cgi_is_reported_as_a_failure(ctx):
    """Status 42 is the spec's code for a CGI that died unexpectedly."""
    proc = ctx.dcs.run(ctx.dcs.url("/cgi-bin/fail"))
    check_eq(dcs_status(proc), 42, "a CGI exiting 3 should be a 42")
    check_in("exited with 3", ctx.server.log(), "the exit code should be logged")


@test("client")
def path_traversal_via_the_client_is_refused(ctx):
    proc = ctx.dcs.run(ctx.dcs.url("/../secret.txt"))
    check(dcs_status(proc) != 20, "the client was served a file above the root")
    check("TOP SECRET" not in proc.stdout.decode("utf-8", "replace"), "leaked the file")


# --------------------------------------------------------------------------
# the status 10 and 11 handshake, which only a stub can drive
# --------------------------------------------------------------------------

@test("input")
def input_is_resent_after_a_10(ctx):
    stub = Stub(ctx.cert, ctx.key, [b"10 input required\r\n",
                                    b"20 text/gemini\r\naccepted\n"]).start()
    try:
        proc = ctx.dcs.run("--input", "-", stub.url("/ask"), stdin=b"my answer\n",
                           xdg=ctx.xdg)
        check_eq(proc.returncode, 0, "exit code")
        check_eq(dcs_status(proc), 20, "status after the handshake")
        stub.wait_for(2)
        check_eq(len(stub.received), 2, "expected two requests")
        check("?" not in stub.received[0],
              "the first request must not carry the input: %r" % stub.received[0])
        check("?" in stub.received[1],
              "the retry must carry the input as a query: %r" % stub.received[1])
        check_in("my", stub.received[1], "the input should be in the retry")
    finally:
        stub.stop()


@test("input")
def sensitive_input_also_triggers_the_retry(ctx):
    stub = Stub(ctx.cert, ctx.key, [b"11 sensitive input required\r\n",
                                    b"20 text/gemini\r\naccepted\n"]).start()
    try:
        proc = ctx.dcs.run("--input", "-", stub.url("/secret"), stdin=b"hunter2",
                           xdg=ctx.xdg)
        check_eq(proc.returncode, 0, "exit code")
        check_eq(dcs_status(proc), 20, "status after the handshake")
        stub.wait_for(2)
        check_eq(len(stub.received), 2, "expected two requests")
        check_in("hunter2", stub.received[1], "the input should be in the retry")
    finally:
        stub.stop()


@test("input")
def an_existing_query_is_extended_not_replaced(ctx):
    stub = Stub(ctx.cert, ctx.key, [b"10 input required\r\n",
                                    b"20 text/gemini\r\naccepted\n"]).start()
    try:
        proc = ctx.dcs.run("--input", "-", stub.url("/ask?already=1"),
                           stdin=b"answer", xdg=ctx.xdg)
        check_eq(dcs_status(proc), 20, "status after the handshake")
        stub.wait_for(2)
        check_in("already=1", stub.received[1],
                 "the original query must survive: %r" % stub.received[1])
        check_in("&", stub.received[1], "the input should be appended with an &")
    finally:
        stub.stop()


@test("input")
def an_input_the_server_never_asks_for_is_not_sent(ctx):
    stub = Stub(ctx.cert, ctx.key, [b"20 text/gemini\r\nfine\n"]).start()
    try:
        proc = ctx.dcs.run("--input", "-", stub.url("/"), stdin=b"unsolicited",
                           xdg=ctx.xdg)
        check_eq(dcs_status(proc), 20, "status")
        stub.wait_for(1)
        check_eq(len(stub.received), 1, "the client should not retry")
        check("unsolicited" not in stub.received[0], "the input must stay local")
    finally:
        stub.stop()


# --------------------------------------------------------------------------
# output handling in dcs
# --------------------------------------------------------------------------

@test("files")
def output_writes_the_body_verbatim(ctx):
    target = ctx.tmp / "saved.gmi"
    proc = ctx.dcs.run("--output", target, ctx.dcs.url("/about.gmi"))
    check_eq(proc.returncode, 0, "exit code")
    check_eq(target.read_text(), "# about the fixture\n\nfixture body line\n",
             "the file should hold the response and nothing else")
    check_in("wrote:", proc.stdout.decode(), "the report should say it wrote a file")


@test("files")
def output_is_not_written_for_a_failure(ctx):
    target = ctx.tmp / "never.gmi"
    proc = ctx.dcs.run("--output", target, ctx.dcs.url("/nope"))
    check_eq(dcs_status(proc), 40, "status")
    check(not target.exists(),
          "a failure body was written to disk, which would block the next attempt")


@test("files")
def save_names_the_file_after_the_url(ctx):
    work = ctx.tmp / "savework"
    work.mkdir(exist_ok=True)
    proc = ctx.dcs.run("--save", ctx.dcs.url("/about.gmi"), cwd=work)
    check_eq(proc.returncode, 0, "exit code")
    check((work / "about.gmi").exists(), "expected about.gmi in %s" % work)


@test("files")
def save_refuses_to_overwrite(ctx):
    work = ctx.tmp / "savework2"
    work.mkdir(exist_ok=True)
    (work / "about.gmi").write_text("already here\n")
    proc = ctx.dcs.run("--save", ctx.dcs.url("/about.gmi"), cwd=work)
    check_eq(proc.returncode, 1, "a clashing name should be an error")
    check_in("which exists", proc.stdout.decode(), "the clash should be explained")
    check_eq((work / "about.gmi").read_text(), "already here\n", "the file was touched")


@test("files")
def save_falls_back_to_the_host_for_the_root(ctx):
    work = ctx.tmp / "savework3"
    work.mkdir(exist_ok=True)
    proc = ctx.dcs.run("--save", ctx.dcs.url("/"), cwd=work)
    check_eq(proc.returncode, 0, "exit code")
    made = list(work.iterdir())
    check_eq(len(made), 1, "expected one file, found %s" % made)
    name = made[0].name
    check_in(HOST, name, "the host should appear in the name")
    check_in(str(ctx.server.port), name, "the port should appear in the name")


@test("files")
def usage_without_arguments_fails(ctx):
    proc = ctx.dcs.run()
    check_eq(proc.returncode, 1, "no arguments should be an error")
    check_in("usage", proc.stdout.decode().lower(), "usage should be printed")


@test("files")
def help_succeeds(ctx):
    proc = ctx.dcs.run("--help")
    check_eq(proc.returncode, 0, "--help should succeed")
    check_in("--fingerprint", proc.stdout.decode(), "help should list the options")


# --------------------------------------------------------------------------
# metadata by extension
# --------------------------------------------------------------------------

@test("mime")
def metadata_is_guessed_from_the_extension(ctx):
    bad = []
    for name, want in sorted(MIME_CASES.items()):
        got = dcs_meta(ctx.dcs.run(ctx.dcs.url("/" + name)))
        if got != want:
            bad.append("%s: got %r, want %r" % (name, got, want))
    check(not bad, "wrong metadata:\n  " + "\n  ".join(bad))


@test("mime")
def unknown_extension_falls_back_to_octet_stream(ctx):
    check_eq(dcs_meta(ctx.dcs.run(ctx.dcs.url("/page.xyz"))),
             "application/octet-stream", "meta")


# --------------------------------------------------------------------------
# TLS, which is TaurusTLS's whole reason for being here
# --------------------------------------------------------------------------

@test("tls")
def tls13_is_negotiated(ctx):
    check_eq(negotiate_tls(ctx.server.port, ssl.TLSVersion.TLSv1_3,
                           ssl.TLSVersion.TLSv1_3),
             "TLSv1.3", "negotiated version")


@test("tls")
def tls12_is_accepted_by_default(ctx):
    check_eq(negotiate_tls(ctx.server.port, ssl.TLSVersion.TLSv1_2,
                           ssl.TLSVersion.TLSv1_2),
             "TLSv1.2", "negotiated version")


@test("tls", xfail="agena accepts TLS 1.2 despite RequireTLS13=true; "
                   "the minimum is configured, but the cause is not yet established")
def require_tls13_refuses_tls12(ctx):
    strict = Agena(ctx.tmp / "strict", free_port(), ctx.cert, ctx.key,
                   require_tls13=True)
    strict.start()
    try:
        check_eq(negotiate_tls(strict.port, ssl.TLSVersion.TLSv1_3,
                               ssl.TLSVersion.TLSv1_3),
                 "TLSv1.3", "1.3 should still work")
        refused = False
        try:
            negotiate_tls(strict.port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        except (ssl.SSLError, OSError):
            refused = True
        check(refused, "RequireTLS13 = true should refuse a TLS 1.2 client")
    finally:
        strict.stop()


@test("tls")
def plaintext_get_is_not_answered(ctx):
    """A client that skips TLS must not get a usable Gemini response."""
    with socket.create_connection((HOST, ctx.server.port), timeout=5) as sock:
        sock.sendall(b"gemini://%s:%d/index.gmi\r\n" % (HOST.encode(), ctx.server.port))
        sock.settimeout(3)
        try:
            data = sock.recv(4096)
        except (socket.timeout, OSError):
            data = b""
    check(not data.startswith(b"20 "),
          "a plaintext request was answered: %r" % data[:60])
    check(ctx.server.alive(), "the server should survive a plaintext client")


# --------------------------------------------------------------------------
# pinning and identities
# --------------------------------------------------------------------------

@test("pins")
def fingerprint_is_sha256_in_colon_form(ctx):
    fp = fingerprint_of(ctx.dcs.run("--fingerprint", ctx.dcs.url("/about.gmi")))
    groups = fp.split(":")
    check_eq(len(groups), 32, "a SHA-256 fingerprint is 32 colon-separated bytes")
    check(all(len(g) == 2 and all(c in "0123456789ABCDEFabcdef" for c in g)
              for g in groups), "not colon-separated hex: %r" % fp)


@test("pins")
def fingerprint_only_makes_one_request(ctx):
    """--fingerprint must not also fetch, or it would double the traffic."""
    stub = Stub(ctx.cert, ctx.key, [b"20 text/gemini\r\nfine\n"]).start()
    try:
        proc = ctx.dcs.run("--fingerprint", stub.url("/"), xdg=ctx.xdg)
        check_eq(proc.returncode, 0, "exit code")
        stub.wait_for(1)
        time.sleep(0.2)
        check_eq(len(stub.received), 1, "expected exactly one request")
        check(len(fingerprint_of(proc)) > 0, "a fingerprint should be printed")
    finally:
        stub.stop()


@test("pins")
def matching_pin_is_accepted(ctx):
    fp = fingerprint_of(ctx.dcs.run("--fingerprint", ctx.dcs.url("/about.gmi")))
    check_eq(dcs_status(ctx.dcs.run("--pin", fp, ctx.dcs.url("/about.gmi"))),
             20, "status with a matching pin")


@test("pins")
def a_pin_without_colons_is_accepted(ctx):
    fp = fingerprint_of(ctx.dcs.run("--fingerprint", ctx.dcs.url("/about.gmi")))
    plain = fp.replace(":", "")
    check_eq(dcs_status(ctx.dcs.run("--pin", plain, ctx.dcs.url("/about.gmi"))),
             20, "status with a plain hex pin")


@test("pins")
def wrong_pin_is_refused(ctx):
    proc = ctx.dcs.run("--pin", "00:" * 31 + "00", ctx.dcs.url("/about.gmi"))
    check(dcs_status(proc) != 20, "a wrong pin should not fetch the document")
    check_eq(proc.returncode, 1, "a refused pin should be an error")
    check("error:" in proc.stdout.decode(), "the refusal should be reported")


@test("pins")
def a_pin_from_another_server_is_refused(ctx):
    fp = fingerprint_of(ctx.dcs.run("--fingerprint", ctx.dcs.url("/about.gmi")))
    cert, key = make_cert(ctx.tmp / "other")
    other = Agena(ctx.tmp / "other", free_port(), cert, key)
    other.start()
    try:
        proc = ctx.dcs.run("--pin", fp, other.url("/about.gmi"))
        check(dcs_status(proc) != 20, "a pin from another server was accepted")
    finally:
        other.stop()


@test("idents")
def no_identities_is_an_error(ctx):
    empty = ctx.tmp / "xdg-empty"
    empty.mkdir(exist_ok=True)
    check_eq(ctx.dcs.run("--idents", "--", ctx.dcs.url("/"), xdg=empty).returncode,
             0, "--idents with nothing to list should still succeed")
    proc = ctx.dcs.run("--ident", "ada", ctx.dcs.url("/"), xdg=empty)
    check_eq(proc.returncode, 1, "logging in with no identities should fail")
    check_in("no identities", proc.stdout.decode(), "the reason should be explained")


@test("idents")
def identities_are_listed_with_their_names(ctx):
    xdg = ctx.tmp / "xdg-one"
    make_client_cert(xdg / "dcs" / "idents", "ada", "ada@example.org")
    proc = ctx.dcs.run("--idents", ctx.dcs.url("/"), xdg=xdg)
    check_eq(proc.returncode, 0, "exit code")
    out = proc.stdout.decode()
    check_in("ada", out, "the common name should be listed")
    check_in("ada@example.org", out, "the mail address should be listed")


@test("idents")
def an_ambiguous_identity_is_refused(ctx):
    xdg = ctx.tmp / "xdg-two"
    idents = xdg / "dcs" / "idents"
    first, _ = make_client_cert(idents, "ada", "ada@example.org")
    second, _ = make_client_cert(idents, "ada")
    proc = ctx.dcs.run("--ident", "ada", ctx.dcs.url("/"), xdg=xdg)
    check_eq(proc.returncode, 1, "an ambiguous identity should fail")
    out = proc.stdout.decode()
    check_in("matches 2 identities", out, "the ambiguity should be stated")
    for crt in (first, second):
        check_in(crt.stem[:12], out, "both candidates should be listed")


@test("idents")
def an_unknown_identity_is_refused(ctx):
    xdg = ctx.tmp / "xdg-three"
    make_client_cert(xdg / "dcs" / "idents", "ada", "ada@example.org")
    proc = ctx.dcs.run("--ident", "grace", ctx.dcs.url("/"), xdg=xdg)
    check_eq(proc.returncode, 1, "an unknown identity should fail")
    check_in("no identity matches", proc.stdout.decode(), "the reason should be stated")


@test("idents")
def a_certificate_without_a_key_is_refused(ctx):
    crt, _ = make_client_cert(ctx.tmp / "halfpair", "ada")
    proc = ctx.dcs.run("--cert", crt, ctx.dcs.url("/"))
    check_eq(proc.returncode, 1, "half an identity should fail")
    check_in("both a certificate and a key", proc.stdout.decode(), "the reason")


@test("idents")
def a_missing_certificate_file_is_refused(ctx):
    proc = ctx.dcs.run("--cert", ctx.tmp / "nope.crt", "--key", ctx.tmp / "nope.key",
                       ctx.dcs.url("/"))
    check_eq(proc.returncode, 1, "a missing certificate should fail")
    check_in("no such certificate", proc.stdout.decode(), "the reason")


@test("idents")
def a_named_identity_is_reported_and_attached(ctx):
    """agena asks for no certificate, so the fetch still succeeds; what matters
    is that dcs resolved the name and attached the pair."""
    xdg = ctx.tmp / "xdg-four"
    make_client_cert(xdg / "dcs" / "idents", "ada", "ada@example.org")
    proc = ctx.dcs.run("--ident", "ada", ctx.dcs.url("/about.gmi"), xdg=xdg)
    check_eq(proc.returncode, 0, "exit code")
    check_in("identity:", proc.stdout.decode(), "the identity should be reported")
    check_eq(dcs_status(proc), 20, "the request should still succeed")


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------

class Ctx:
    def __init__(self, tmp: Path, cert: Path, key: Path):
        self.tmp = tmp
        self.cert, self.key = cert, key
        self.server = Agena(tmp / "main", free_port(), cert, key)
        self.xdg = tmp / "xdg"
        self.xdg.mkdir(exist_ok=True)
        self.dcs = Dcs(self.server, self.xdg)


def preflight() -> None:
    if not DCS_BIN.is_file() or not os.access(DCS_BIN, os.X_OK):
        sys.exit("dcs binary not found or not executable: %s\n"
                 "build it with: make -f Makefile.fpc" % DCS_BIN)
    if not AGENA_BIN.is_file() or not os.access(AGENA_BIN, os.X_OK):
        sys.exit("agena binary not found or not executable: %s\n"
                 "build it with: make -f Makefile.fpc" % AGENA_BIN)
    if not shutil.which("openssl"):
        sys.exit("openssl is needed to build the fixtures")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-k", "--filter", default="",
                        help="only run groups whose name contains this")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print each test as it runs")
    parser.add_argument("--keep", action="store_true",
                        help="leave the temporary directory behind")
    parser.add_argument("--xfail", action="store_true",
                        help="only run the tests pinned to known defects")
    args = parser.parse_args()

    preflight()

    tmp = Path(tempfile.mkdtemp(prefix="dcs-tests-"))
    cert, key = make_cert(tmp)
    ctx = Ctx(tmp, cert, key)
    ctx.server.start()

    if args.xfail:
        selected = [t for t in TESTS if t[3]]
    else:
        selected = [t for t in TESTS if args.filter in t[0]]

    passed, known, failures = [], [], []
    started = time.time()
    try:
        for group, name, fn, xfail in selected:
            label = "%s/%s" % (group, name)
            try:
                fn(ctx)
            except Failure as exc:
                (known if xfail else failures).append((label, str(exc), xfail))
            except Exception as exc:  # noqa: BLE001 - report and carry on
                (known if xfail else failures).append(
                    (label, "%s: %s" % (type(exc).__name__, exc), xfail))
            else:
                if xfail:
                    failures.append((label, "unexpectedly passed: " + xfail, xfail))
                else:
                    passed.append(label)
            if args.verbose:
                state = "ok" if label in passed else "FAIL"
                print("  %-56s %s" % (label, state))
    finally:
        ctx.server.stop()

    elapsed = time.time() - started
    print("\n%d passed, %d failed, %d known failures, %.1fs"
          % (len(passed), len(failures), len(known), elapsed))

    if known:
        print("\npinned to known defects:")
        for label, message, xfail in known:
            print("  %s\n      %s\n      pinned: %s" % (label, message, xfail))
    if failures:
        print("\nfailures:")
        for label, message, _ in failures:
            print("  %s\n      %s" % (label, message))
        print("\nartifacts kept in %s" % tmp)
        return 1
    if args.keep:
        print("\nartifacts kept in %s" % tmp)
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
