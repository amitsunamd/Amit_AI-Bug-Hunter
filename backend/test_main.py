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
