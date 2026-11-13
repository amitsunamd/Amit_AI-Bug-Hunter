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
