"""Content checks that must not copy addresses or metadata values."""

from watson.http_client import RateLimiter, is_nonresolving_host, polite_interval
from watson.libraries import detect_libraries, version_older
from watson.metadata_docs import docx_metadata_fields, pdf_metadata_fields
from watson.redact import excel_safe, redact
from watson.security import content_findings, insecure_form_targets, mixed_content_items

AUTHOR = "Confidential Person Name"


def test_library_thresholds():
    assert version_older("1.12.4", "3.0.0")
    assert not version_older("3.7.1", "3.7.1")
    high = detect_libraries("https://cdn.example/jquery-1.12.4.min.js", "page")
    assert any(hit.name == "jQuery" and hit.severity == "High" and hit.version == "1.12.4" for hit in high)
    medium = detect_libraries("jquery v3.4.1", "page")
    assert any(hit.severity == "Medium" for hit in medium)
    low = detect_libraries("jquery-3.6.0.min.js", "page")
    assert any(hit.severity == "Low" for hit in low)
    assert detect_libraries("jquery-3.7.1.min.js", "page") == []
    bootstrap = detect_libraries("https://cdn.example/bootstrap/3.4.1/js/bootstrap.min.js", "page")
    assert any(hit.name == "Bootstrap" and hit.version == "3.4.1" for hit in bootstrap)


def test_email_count_omits_the_address():
    html = '<p>Write to office@example.com</p><a href="mailto:office@example.com">Email the office</a>'
    findings = content_findings([("http://www.example.com/contact", html)])
    email = next(finding for finding in findings if finding.check == "exposed-email")
    assert "office@example.com" not in email.evidence
    assert "office@example.com" not in email.title
    assert "1 unique" in email.evidence


def test_two_pages_count_unique_addresses():
    first = "<p>office@example.com</p>"
    second = "<p>office@example.com and info@example.com</p>"
    findings = content_findings(
        [
            ("http://www.example.com/a", first),
            ("http://www.example.com/b", second),
        ]
    )
    email = next(finding for finding in findings if finding.check == "exposed-email")
    assert "2 unique" in email.evidence
    assert "office@example.com" not in email.evidence
    assert "info@example.com" not in email.evidence


def test_http_form_and_mixed_content():
    form = '<form action="http://forms.example/send" method="post"></form>'
    assert insecure_form_targets(form, "http://www.example.com/")
    page = """
    <script src="http://cdn.example/app.js"></script>
    <img src="http://images.example/logo.png" alt="Site logo">
    """
    mixed = mixed_content_items(page, "https://www.example.com/")
    assert ("script", "http://cdn.example/app.js", "High") in [(tag, url, level) for tag, url, level in mixed]
    assert any(level == "Medium" for _tag, _url, level in mixed)
    assert mixed_content_items(page, "http://www.example.com/") == []
    findings = content_findings([("https://www.example.com/", page + form)])
    checks = {finding.check for finding in findings}
    assert "mixed-content" in checks
    assert "insecure-form" in checks


def test_pdf_and_docx_metadata_values_are_not_returned():
    from watson.fixture_site import build_docx, build_pdf

    pdf = build_pdf(AUTHOR)
    docx = build_docx(AUTHOR)
    assert AUTHOR.encode() in pdf
    pdf_fields = pdf_metadata_fields(pdf)
    docx_fields = docx_metadata_fields(docx)
    assert "Author" in pdf_fields
    assert "creator" in docx_fields
    assert AUTHOR not in repr(pdf_fields)
    assert AUTHOR not in repr(docx_fields)
    assert pdf_metadata_fields(b"%PDF-1.4 /Author ()") == set()


def test_redact_and_excel_formula():
    assert redact("Email office@example.com today") == "Email [redacted-email] today"
    assert excel_safe("=cmd|' /C calc'!A0").startswith("'")
    assert excel_safe("Calendar") == "Calendar"


def test_reserved_names_are_not_contacted_and_rate_is_one_per_second():
    assert is_nonresolving_host("old-sponsor.invalid")
    assert is_nonresolving_host("cdn.example")
    assert not is_nonresolving_host("example.com")
    assert not is_nonresolving_host("localhost")
    assert polite_interval(1) == 1
    assert polite_interval(2) == 0.5
    assert polite_interval(1, crawl_delay=5) == 5


def test_rate_limiter_uses_the_supplied_clock():
    class Clock:
        def __init__(self):
            self.now_value = 0.0
            self.slept = []

        def now(self):
            return self.now_value

        def sleep(self, seconds):
            self.slept.append(seconds)
            self.now_value += seconds

    clock = Clock()
    limiter = RateLimiter(1, sleep=clock.sleep, now=clock.now)
    limiter.wait()
    limiter.wait()
    assert clock.slept == [1]
