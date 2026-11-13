from __future__ import annotations
import ipaddress
import socket
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="AI Bug Hunter API", version="0.1.0",
              description="Consent-based, non-invasive website checks.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)
TIMEOUT = 8
MAX_LINKS = 20
UA = "Amit-AI-Bug-Hunter/0.1 (authorized non-invasive checker)"

class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    authorized: bool = False

def validate_url(raw: str, expected_host: str | None = None) -> str:
    p = urlparse(raw.strip())
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Enter a valid public HTTP(S) URL.")
    if p.port not in (None, 80, 443):
        raise ValueError("Custom ports are not supported.")
    host = p.hostname.rstrip(".").lower()
    if expected_host and host != expected_host:
        raise ValueError("Cross-host redirects are blocked.")
    if host == "localhost" or host.endswith((".local", ".internal")):
        raise ValueError("Local network targets are blocked.")
    try:
        ips = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            ips = {ipaddress.ip_address(x[4][0]) for x in
                   socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ValueError("Hostname could not be resolved.") from exc
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError("Private or non-public IP addresses are blocked.")
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))

def safe_get(url: str, host: str) -> requests.Response:
    current = validate_url(url, host)
    session = requests.Session()
    session.headers["User-Agent"] = UA
    for _ in range(4):
        r = session.get(current, timeout=TIMEOUT, allow_redirects=False)
        if r.status_code not in (301, 302, 303, 307, 308):
            return r
        loc = r.headers.get("Location")
        if not loc:
            return r
        current = validate_url(urljoin(current, loc), host)
    raise ValueError("Too many redirects.")

def issue(out, severity, category, title, details, fix):
    out.append({"severity": severity, "category": category, "title": title,
                "details": details, "recommendation": fix})

@app.get("/")
def root():
    return {"name": "AI Bug Hunter API", "status": "online", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}

@app.post("/api/scan")
def scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(400, "Confirm that you own this site or have permission to test it.")
    try:
        parsed = urlparse(req.url.strip())
        if not parsed.hostname:
            raise ValueError("Enter a complete URL such as https://example.com")
        host = parsed.hostname.rstrip(".").lower()
        target = validate_url(req.url, host)
        response = safe_get(target, host)
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(400, str(exc)) from exc

    issues = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    status = response.status_code
    if status >= 500:
        issue(issues, "high", "Availability", f"Server returned HTTP {status}",
              "The server returned a 5xx response.", "Review server logs and upstream services.")
    elif status >= 400:
        issue(issues, "medium", "Availability", f"Page returned HTTP {status}",
              "The requested page returned an error status.", "Check the URL and server routing.")

    checks = {
        "content-security-policy": ("medium", "Define a suitable Content-Security-Policy."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Set a privacy-conscious Referrer-Policy."),
        "strict-transport-security": ("medium", "Enable HSTS after confirming HTTPS works."),
    }
    for header, (severity, fix) in checks.items():
        if header not in headers:
            issue(issues, severity, "Security headers", f"Missing {header}",
                  "The response did not include this common security header.",
                  fix)

    html = "text/html" in headers.get("content-type", "").lower()
    soup = BeautifulSoup(response.text[:1500000] if html else "", "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if html and not title:
        issue(issues, "low", "HTML quality", "Page title missing",
              "No non-empty HTML title was found.", "Add a descriptive title element.")
    if html and not soup.find("meta", attrs={"name": "description"}):
        issue(issues, "info", "SEO", "Meta description missing",
              "No meta description was found.", "Add a concise description if appropriate.")
    if html:
        for img in soup.find_all("img"):
            if not img.has_attr("alt"):
                issue(issues, "low", "Accessibility", "Image missing alt attribute",
                      "At least one image has no alt attribute.",
                      "Add descriptive alt text or an empty alt for decorative images.")
                break
        for form in soup.find_all("form"):
            passwords = form.find_all("input", attrs={"type": "password"})
            method = (form.get("method") or "get").lower()
            if passwords and target.startswith("http://"):
                issue(issues, "high", "Transport security", "Password form on HTTP",
                      "A password field appears on a non-HTTPS page.",
                      "Serve authentication pages over HTTPS only.")
            if passwords and method == "get":
                issue(issues, "high", "Form security", "Password form uses GET",
                      "A password form appears to use the GET method.",
                      "Use POST over HTTPS for credential submission.")
        if target.startswith("https://"):
            for el in soup.find_all(src=True):
                if str(el.get("src", "")).startswith("http://"):
                    issue(issues, "medium", "Mixed content", "HTTP resource on HTTPS page",
                          "At least one resource uses an insecure HTTP URL.",
                          "Load page resources over HTTPS.")
                    break

    links, seen = [], set()
    for a in soup.find_all("a", href=True):
        candidate = urljoin(target, a["href"])
        cp = urlparse(candidate)
        if cp.hostname and cp.hostname.lower().rstrip(".") == host and cp.scheme in ("http", "https"):
            try:
                candidate = validate_url(candidate, host)
            except ValueError:
                continue
            if candidate not in seen:
                links.append(candidate)
                seen.add(candidate)
        if len(links) >= MAX_LINKS:
            break

    link_results = []
    for link in links:
        try:
            r = safe_get(link, host)
            link_results.append({"url": link, "status": r.status_code})
            if r.status_code >= 400:
                issue(issues, "low", "Broken link", f"Same-site link returned HTTP {r.status_code}",
                      link, "Update the link or restore the destination.")
        except (ValueError, requests.RequestException) as exc:
            link_results.append({"url": link, "error": str(exc)})

    counts = Counter(x["severity"] for x in issues)
    return {
        "target": target, "http_status": status, "page_title": title,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total_issues": len(issues), "high": counts["high"],
                    "medium": counts["medium"], "low": counts["low"],
                    "info": counts["info"], "links_checked": len(link_results)},
        "issues": issues, "links": link_results,
        "limitations": [
            "Basic non-invasive checks only; not a penetration test.",
            "Only a small sample of same-host links is checked.",
            "Heuristic findings require manual verification.",
            "Only scan systems you own or are explicitly authorized to test."
        ]
    }
