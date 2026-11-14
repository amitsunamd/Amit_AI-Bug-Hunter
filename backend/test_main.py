import pytest
from main import validate_url

def test_rejects_file_scheme():
    with pytest.raises(ValueError):
        validate_url("file:///etc/passwd")

def test_rejects_localhost():
    with pytest.raises(ValueError):
        validate_url("http://localhost")

def test_rejects_private_ip():
    with pytest.raises(ValueError):
        validate_url("http://192.168.1.10")

def test_rejects_cross_host_redirect():
    with pytest.raises(ValueError):
        validate_url("https://other.example/path", "example.com")

def test_rejects_custom_port():
    with pytest.raises(ValueError):
        validate_url("https://example.com:8080")


from pydantic import ValidationError
from main import ScanRequest, add_unique_issue


def test_scan_page_limit_defaults_to_thirty():
    request = ScanRequest(url="https://example.com", authorized=True)
    assert request.max_pages == 30


def test_scan_page_limit_cannot_exceed_one_hundred():
    with pytest.raises(ValidationError):
        ScanRequest(url="https://example.com", authorized=True, max_pages=101)


def test_scan_page_limit_must_be_positive():
    with pytest.raises(ValidationError):
        ScanRequest(url="https://example.com", authorized=True, max_pages=0)


def test_duplicate_finding_collects_affected_pages():
    findings = []
    seen = set()
    add_unique_issue(findings, seen, "low", "Security headers",
                     "Missing referrer-policy", "Missing header",
                     "Set the header", "https://example.com/")
    add_unique_issue(findings, seen, "low", "Security headers",
                     "Missing referrer-policy", "Missing header",
                     "Set the header", "https://example.com/about")
    assert len(findings) == 1
    assert findings[0]["affected_urls"] == [
        "https://example.com/", "https://example.com/about"
    ]


from main import redact_url


def test_redacts_sensitive_download_query_parameters():
    url = "https://example.com/download/?key=private123&file=public.pdf&access_token=abc"
    safe = redact_url(url)
    assert "private123" not in safe
    assert "abc" not in safe
    assert "file=public.pdf" in safe
    assert "key=%5BREDACTED%5D" in safe



from main import normalize_crawl_url, page_family, content_fingerprint
from bs4 import BeautifulSoup


def test_normalizer_removes_tracking_but_keeps_meaningful_query():
    normalized = normalize_crawl_url("https://example.com/search?utm_source=news&page=2&q=finance#top")
    assert normalized == "https://example.com/search?page=2&q=finance"


def test_page_family_groups_pagination_but_keeps_other_filters():
    first = page_family("https://example.com/list?ssf_paged=1&type=company")
    later = page_family("https://example.com/list?type=company&ssf_paged=902")
    other_filter = page_family("https://example.com/list?type=person&ssf_paged=2")
    assert first == later
    assert first != other_filter


def test_content_fingerprint_ignores_whitespace_and_case():
    one = BeautifulSoup("<p>Hello   World</p>", "html.parser")
    two = BeautifulSoup("<p>hello\nworld</p>", "html.parser")
    assert content_fingerprint(one) == content_fingerprint(two)


def test_findings_include_confidence_and_evidence():
    findings = []
    add_unique_issue(findings, set(), "medium", "Availability",
                     "Page returned HTTP 404", "Observed HTTP 404 response",
                     "Restore the page", "https://example.com/missing")
    assert findings[0]["confidence"] == "high"
    assert findings[0]["evidence"] == "Observed HTTP 404 response"
