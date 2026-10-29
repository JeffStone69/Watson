"""Built-in example site. It never calls a real school.

The pages use example.edu placeholders and reserved names such as
``old-sponsor.invalid``. Document author metadata is planted so Watson can
prove it counts the field without copying the value.
"""

from __future__ import annotations

import io
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from watson.resources import resource_path

DOCUMENT_AUTHOR = "Confidential Person Name"
COOKIE_HEADER = "session=example"
SERVER_BANNER = "Apache/2.4.49 (Example)"
POWERED_BY = "PHP/7.2.34"
PRIVATE_MARKER = "SHOULD_NOT_FETCH"


def build_pdf(author: str) -> bytes:
    safe = author.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Title (Handbook) /Author ("
        + safe.encode("utf-8")
        + b") /Creator ("
        + safe.encode("utf-8")
        + b") >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R /Info 1 0 R >>\n%%EOF\n"
    )


def build_docx(author: str) -> bytes:
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>
"""
    core = f"""<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>Policy</dc:title>
  <dc:creator>{escape(author)}</dc:creator>
  <cp:lastModifiedBy>{escape(author)}</cp:lastModifiedBy>
</cp:coreProperties>
"""
    document = """<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Example policy</w:t></w:r></w:p></w:body>
</w:document>
"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("docProps/core.xml", core)
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()


class FixtureSite:
    """Serve the example site on 127.0.0.1 and a free port."""

    def __init__(self) -> None:
        self.hits: list[tuple[str, str, str]] = []
        self._pdf = build_pdf(DOCUMENT_AUTHOR)
        self._docx = build_docx(DOCUMENT_AUTHOR)
        handler = self._make_handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "FixtureSite":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def _make_handler(self):
        site = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args) -> None:
                return

            def do_HEAD(self) -> None:
                self._handle("HEAD")

            def do_GET(self) -> None:
                self._handle("GET")

            def _handle(self, method: str) -> None:
                path = urlparse(self.path).path
                agent = self.headers.get("User-Agent", "")
                site.hits.append((method, path, agent))
                if ".." in path.split("/"):
                    self._send(method, 400, b"bad path", "text/plain")
                    return
                route = site._route(path, method)
                if route is None:
                    self._send(method, 404, b"missing", "text/plain")
                    return
                status, body, content_type, extra = route
                self._send(method, status, body, content_type, extra)

            def _send(self, method: str, status: int, body: bytes, content_type: str, extra=None) -> None:
                self.close_connection = True
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", SERVER_BANNER)
                self.send_header("X-Powered-By", POWERED_BY)
                self.send_header("Set-Cookie", COOKIE_HEADER)
                self.send_header("Connection", "close")
                for key, value in extra or []:
                    self.send_header(key, value)
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(body)

        return Handler

    def _file(self, name: str) -> bytes | None:
        path = resource_path("data", "fixture", name)
        if not path.is_file():
            return None
        data = path.read_bytes()
        if name.endswith(".html"):
            data = data.replace(b"__WATSON_BASE__", self.base.encode("ascii"))
        return data

    def _route(self, path: str, method: str):
        if path == "/robots.txt":
            body = (
                "User-agent: *\n"
                "Disallow: /private-drafts\n"
                f"\nSitemap: {self.base}/sitemap.xml\n"
            ).encode()
            return 200, body, "text/plain; charset=utf-8", None
        if path == "/sitemap.xml":
            locs = ["/", "/news.html", "/calendar.html", "/staff-intranet", "/contact.html"]
            rows = "\n".join(f"  <url><loc>{self.base}{loc}</loc></url>" for loc in locs)
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                f"{rows}\n</urlset>\n"
            ).encode()
            return 200, body, "application/xml", None
        if path in {"/.well-known/security.txt", "/security.txt"}:
            return 404, b"missing", "text/plain", None
        if path == "/missing-page":
            return 404, b"missing", "text/plain", None
        if path == "/gone-page":
            return 410, b"gone", "text/plain", None
        if path == "/staff-intranet":
            return 403, b"Forbidden", "text/plain", None
        if path == "/broken-app":
            return 500, b"error", "text/plain", None
        if path == "/rate-limited":
            return 429, b"slow down", "text/plain", None
        if path == "/old-news":
            return 302, b"", "text/plain", [("Location", f"{self.base}/")]
        if path == "/removed-page":
            return 302, b"", "text/plain", [("Location", f"{self.base}/not-found.html")]
        if path == "/handbook":
            return 301, b"", "text/plain", [("Location", f"{self.base}/docs/handbook.pdf")]
        if path == "/only-get":
            if method == "HEAD":
                return 405, b"", "text/plain", [("Allow", "GET")]
            return 404, b"missing", "text/plain", None
        if path.startswith("/docs/") and path.endswith(".pdf"):
            return 200, self._pdf, "application/pdf", None
        if path.startswith("/docs/") and path.endswith(".docx"):
            return (
                200,
                self._docx,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                None,
            )
        relative = "index.html" if path in {"/", ""} else path.lstrip("/")
        data = self._file(relative)
        if data is None:
            return None
        content_type = "text/html; charset=utf-8"
        if relative.endswith(".js"):
            content_type = "text/javascript; charset=utf-8"
        elif relative.endswith(".css"):
            content_type = "text/css; charset=utf-8"
        return 200, data, content_type, None


def serve_fixture() -> FixtureSite:
    return FixtureSite()
