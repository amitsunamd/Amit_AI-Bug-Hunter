from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import time
from collections import Counter, deque
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="AI Bug Hunter API",
    version="0.2.0",
    description="Consent-based, bounded, non-invasive website checks.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)

TIMEOUT = 7
MAX_BODY_BYTES = 1_500_000
DEFAULT_MAX_PAGES = 30
HARD_MAX_PAGES = 100
CRAWL_DELAY = 0.12
UA = "Amit-AI-Bug-Hunter/0.2 (authorized non-invasive checker)"


class CrossHostRedirectBlocked(ValueError):
    """A redirect was intentionally not followed because it leaves the scan host."""
    def __init__(self, source: str, destination: str):
        super().__init__("Cross-host redirects are blocked.")
        self.source = source
        self.destination = destination


TRACKING_QUERY_KEYS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "mc_cid", "mc_eid"}
PAGINATION_QUERY_KEYS = {"page", "paged", "p", "ssf_paged", "offset", "start", "page_num", "page_number"}
MAX_PAGES_PER_FAMILY = 5


def normalize_crawl_url(raw: str) -> str:
    """Normalize URL identity without discarding meaningful application parameters."""
    p = urlparse(raw)
    query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in TRACKING_QUERY_KEYS]
    query.sort(key=lambda pair: (pair[0].lower(), pair[1]))
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urlunparse((p.scheme.lower(), p.netloc.lower(), path, "", urlencode(query), ""))


def page_family(raw: str) -> str:
    """Group pagination variants of one path while retaining non-pagination query identity."""
    p = urlparse(normalize_crawl_url(raw))
    query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in PAGINATION_QUERY_KEYS]
    return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(query), ""))


def content_fingerprint(soup: BeautifulSoup) -> str:
    text = re.sub(r"\\s+", " ", soup.get_text(" ", strip=True)).lower()
    return hashlib.sha256(text[:20000].encode("utf-8", errors="ignore")).hexdigest()


SENSITIVE_QUERY_KEYS = {
    "key", "token", "access_token", "refresh_token", "api_key", "apikey",
    "secret", "password", "passwd", "signature", "sig", "session",
    "sessionid", "auth", "authorization", "code",
}


def redact_url(raw: str) -> str:
    """Keep useful URL context while hiding likely secrets in query parameters."""
    try:
        parts = urlparse(raw)
        safe_query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.lower() in SENSITIVE_QUERY_KEYS or any(
                marker in key.lower() for marker in ("token", "secret", "password", "signature")
            ):
                value = "[REDACTED]"
            safe_query.append((key, value))
        return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params,
                           urlencode(safe_query), ""))
    except Exception:
        return "[URL REDACTED]"


class ScanRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    authorized: bool = False
    max_pages: int = Field(default=DEFAULT_MAX_PAGES, ge=1, le=HARD_MAX_PAGES)


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
            ips = {
                ipaddress.ip_address(x[4][0])
                for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror as exc:
            raise ValueError("Hostname could not be resolved.") from exc
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError("Private or non-public IP addresses are blocked.")
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def safe_get(url: str, host: str) -> requests.Response:
    current = validate_url(url, host)
    redirect_chain = []
    session = requests.Session()
    session.headers["User-Agent"] = UA
    for _ in range(4):
        current = validate_url(current, host)
        redirect_chain.append(redact_url(current))
        response = session.get(
            current, timeout=TIMEOUT, allow_redirects=False, stream=True
        )
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            if not location:
                response._content = b""
                response._content_consumed = True
                response.close()
                return response
            response.close()
            redirected = urljoin(current, location)
            try:
                current = validate_url(redirected, host)
            except ValueError as exc:
                if "Cross-host redirects are blocked" in str(exc):
                    raise CrossHostRedirectBlocked(current, redact_url(redirected)) from exc
                raise
            continue
        # Bound memory use even when a target returns a very large page.
        chunks = []
        size = 0
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                remaining = MAX_BODY_BYTES - size
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                size += min(len(chunk), remaining)
                if size >= MAX_BODY_BYTES:
                    break
            response._content = b"".join(chunks)
            response._content_consumed = True
        finally:
            response.close()
        response._bughunter_redirect_chain = redirect_chain
        return response
    raise ValueError("Too many redirects.")


def issue(out, severity, category, title, details, fix, url=None):
    out.append({
        "severity": severity,
        "category": category,
        "title": title,
        "details": details,
        "recommendation": fix,
        "url": url,
    })


def add_unique_issue(out, seen, severity, category, title, details, fix, url):
    key = (severity, category, title)
    if key in seen:
        for existing in out:
            if (existing["severity"], existing["category"], existing["title"]) == key:
                safe_url = redact_url(url) if url else None
                if safe_url and safe_url not in existing.setdefault("affected_urls", []):
                    existing["affected_urls"].append(safe_url)
                return
    seen.add(key)
    item = {
        "severity": severity, "category": category, "title": title,
        "details": details, "recommendation": fix, "url": redact_url(url) if url else None,
        "affected_urls": [redact_url(url)] if url else [],
        "confidence": "high" if category in {"Availability", "Security headers", "Cookie security", "Transport security"} else ("medium" if severity in {"high", "medium", "low"} else "low"),
        "evidence": details,
    }
    out.append(item)


def page_audit(response, page_url, issues, seen):
    headers = {k.lower(): v for k, v in response.headers.items()}
    status = response.status_code
    if status >= 500:
        add_unique_issue(issues, seen, "high", "Availability",
            f"Server returned HTTP {status}", "The server returned a 5xx response.",
            "Review server logs and upstream services.", page_url)
    elif status >= 400:
        add_unique_issue(issues, seen, "medium", "Availability",
            f"Page returned HTTP {status}", "The requested page returned an error status.",
            "Check the URL and server routing.", page_url)

    checks = {
        "content-security-policy": ("medium", "Define a suitable Content-Security-Policy."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Set a privacy-conscious Referrer-Policy."),
        "strict-transport-security": ("medium", "Enable HSTS after confirming HTTPS works."),
    }
    for header, (severity, fix) in checks.items():
        if header == "strict-transport-security" and not page_url.startswith("https://"):
            continue
        if header not in headers:
            add_unique_issue(issues, seen, severity, "Security headers",
                f"Missing {header}", "The response did not include this common security header.",
                fix, page_url)

    csp = headers.get("content-security-policy", "")
    if csp:
        csp_lower = csp.lower()
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            add_unique_issue(issues, seen, "medium", "Content Security Policy",
                "CSP allows unsafe script execution",
                "The Content-Security-Policy contains unsafe-inline or unsafe-eval. This can weaken script injection protections; verify whether the directive is required.",
                "Prefer nonce- or hash-based script allowances and remove unsafe-eval where possible.",
                page_url)
        if "default-src" not in csp_lower and "script-src" not in csp_lower:
            add_unique_issue(issues, seen, "low", "Content Security Policy",
                "CSP has no default-src or script-src directive",
                "A policy exists but does not define a clear default or script source restriction.",
                "Review the policy and define restrictive default-src and script-src directives.",
                page_url)

    set_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, "headers") else []
    for cookie in set_cookies:
        lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()[:80]
        if page_url.startswith("https://") and "secure" not in lower:
            add_unique_issue(issues, seen, "low", "Cookie security",
                "Cookie missing Secure attribute",
                f"The response sets cookie '{cookie_name}' without a Secure attribute.",
                "Set Secure on cookies that should only be sent over HTTPS.", page_url)
        if "httponly" not in lower:
            add_unique_issue(issues, seen, "low", "Cookie security",
                "Cookie missing HttpOnly attribute",
                f"The response sets cookie '{cookie_name}' without HttpOnly.",
                "Set HttpOnly on session and other sensitive cookies not needed by JavaScript.", page_url)
        if "samesite" not in lower:
            add_unique_issue(issues, seen, "low", "Cookie security",
                "Cookie missing SameSite attribute",
                f"The response sets cookie '{cookie_name}' without SameSite.",
                "Set an appropriate SameSite=Lax or Strict attribute; use None only when cross-site use is required and Secure is set.",
                page_url)

    if headers.get("access-control-allow-origin", "").strip() == "*":
        add_unique_issue(issues, seen, "low", "CORS",
            "CORS allows every origin",
            "The response advertises Access-Control-Allow-Origin: *. This may be intentional for public resources but should be reviewed for sensitive endpoints.",
            "Restrict allowed origins to trusted sites when the endpoint returns user-specific or sensitive data.",
            page_url)

    if headers.get("server"):
        add_unique_issue(issues, seen, "info", "Information disclosure",
            "Server technology banner is exposed",
            "The response includes a Server header. This is not automatically a vulnerability but may disclose implementation details.",
            "Consider minimizing unnecessary version details in server response headers.", page_url)
    if headers.get("x-powered-by"):
        add_unique_issue(issues, seen, "info", "Information disclosure",
            "X-Powered-By header is exposed",
            "The response includes an X-Powered-By header that may reveal application technology.",
            "Remove unnecessary technology-identifying response headers.", page_url)

    is_html = "text/html" in headers.get("content-type", "").lower()
    soup = BeautifulSoup(response.text if is_html else "", "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if is_html and not title:
        add_unique_issue(issues, seen, "low", "HTML quality", "Page title missing",
            "No non-empty HTML title was found.", "Add a descriptive title element.", page_url)
    if is_html and not soup.find("meta", attrs={"name": "description"}):
        add_unique_issue(issues, seen, "info", "SEO", "Meta description missing",
            "No meta description was found.", "Add a concise page-specific description if appropriate.", page_url)
    if is_html:
        for img in soup.find_all("img"):
            if not img.has_attr("alt"):
                add_unique_issue(issues, seen, "low", "Accessibility", "Image missing alt attribute",
                    "At least one image has no alt attribute.",
                    "Add descriptive alt text or an empty alt for decorative images.", page_url)
                break
        for form in soup.find_all("form"):
            passwords = form.find_all("input", attrs={"type": "password"})
            method = (form.get("method") or "get").lower()
            action = urljoin(page_url, form.get("action") or page_url)
            if passwords and page_url.startswith("http://"):
                add_unique_issue(issues, seen, "high", "Transport security", "Password form on HTTP",
                    "A password field appears on a non-HTTPS page.",
                    "Serve authentication pages over HTTPS only.", page_url)
            if passwords and method == "get":
                add_unique_issue(issues, seen, "high", "Form security", "Password form uses GET",
                    "A password form appears to use the GET method.",
                    "Use POST over HTTPS for credential submission.", page_url)
            if passwords and urlparse(action).scheme == "http":
                add_unique_issue(issues, seen, "high", "Transport security", "Password form submits over HTTP",
                    "A password form action points to an insecure HTTP URL.",
                    "Submit credentials only to an HTTPS endpoint.", page_url)
        if page_url.startswith("https://"):
            for el in soup.find_all(src=True):
                if str(el.get("src", "")).strip().lower().startswith("http://"):
                    add_unique_issue(issues, seen, "medium", "Mixed content",
                        "HTTP resource on HTTPS page",
                        "At least one resource uses an insecure HTTP URL.",
                        "Load page resources over HTTPS.", page_url)
                    break
    return soup, title


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
        first_response = safe_get(target, host)
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(400, str(exc)) from exc

    issues = []
    seen_issues = set()
    links_seen = set()
    pages_seen = set()
    canonical_seen = {}
    fingerprint_seen = {}
    family_counts = Counter()
    queue = deque([(target, None)])
    page_results = []
    first_title = ""
    first_status = first_response.status_code
    first_content_type = first_response.headers.get("Content-Type", "")

    while queue and len(pages_seen) < req.max_pages:
        page_url, source_page = queue.popleft()
        page_key = normalize_crawl_url(page_url)
        if page_key in pages_seen:
            continue
        family = page_family(page_url)
        if family_counts[family] >= MAX_PAGES_PER_FAMILY:
            continue
        family_counts[family] += 1
        pages_seen.add(page_key)
        try:
            response = first_response if page_url == target else safe_get(page_url, host)
            soup, title = page_audit(response, page_url, issues, seen_issues)
            redirect_chain = getattr(response, "_bughunter_redirect_chain", [redact_url(page_url)])
            if len(redirect_chain) > 1:
                add_unique_issue(issues, seen_issues, "info", "Redirect analysis",
                    "Same-host redirect chain observed",
                    "The request followed " + str(len(redirect_chain) - 1) + " same-host redirect(s): " + " → ".join(redirect_chain),
                    "Review whether each redirect is necessary and update internal links to point directly to the final URL.", page_url)
            if response.status_code >= 400 and source_page:
                add_unique_issue(issues, seen_issues, "medium" if response.status_code < 500 else "high", "Broken link",
                    f"Internal link returned HTTP {response.status_code}",
                    "A same-host link discovered on " + redact_url(source_page) + " returned HTTP " + str(response.status_code) + ".",
                    "Restore the destination, correct the link, or add an intentional redirect to the correct page.", page_url)
            if page_url == target:
                first_title = title
            page_results.append({"url": redact_url(page_url), "status": response.status_code, "title": title,
                                 "redirect_chain": redirect_chain if len(redirect_chain) > 1 else []})
            canonical = soup.find("link", rel=lambda value: value and "canonical" in ([x.lower() for x in value] if isinstance(value, list) else str(value).lower().split()))
            if canonical and canonical.get("href"):
                canonical_url = urljoin(page_url, canonical["href"])
                try:
                    canonical_url = normalize_crawl_url(validate_url(canonical_url, host))
                    prior = canonical_seen.get(canonical_url)
                    if prior and prior != page_key:
                        add_unique_issue(issues, seen_issues, "info", "Duplicate content",
                            "Multiple pages declare the same canonical URL",
                            "This page and " + redact_url(prior) + " declare the same canonical destination.",
                            "Confirm that the canonical URL is intentional and that duplicate pages should be consolidated for indexing.", page_url)
                    else:
                        canonical_seen[canonical_url] = page_key
                except ValueError:
                    pass
            fingerprint = content_fingerprint(soup)
            if fingerprint and len(soup.get_text(" ", strip=True)) >= 180:
                prior_page = fingerprint_seen.get(fingerprint)
                if prior_page and prior_page != page_key:
                    add_unique_issue(issues, seen_issues, "info", "Duplicate content",
                        "Near-identical page text detected",
                        "The visible text fingerprint matches another crawled page: " + redact_url(prior_page) + ". This may be a legitimate duplicate or template page.",
                        "Compare both pages and use canonical tags or unique page content where appropriate.", page_url)
                else:
                    fingerprint_seen[fingerprint] = page_key
            for anchor in soup.find_all("a", href=True):
                candidate = urljoin(page_url, anchor["href"])
                cp = urlparse(candidate)
                if not cp.hostname or cp.hostname.lower().rstrip(".") != host:
                    continue
                if cp.scheme not in ("http", "https"):
                    continue
                try:
                    candidate = validate_url(candidate, host)
                except ValueError:
                    continue
                # Drop fragments and avoid crawling common non-page assets.
                path = urlparse(candidate).path.lower()
                if path.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
                                  ".pdf", ".zip", ".gz", ".mp4", ".mp3", ".css", ".js",
                                  ".ico", ".woff", ".woff2", ".ttf")):
                    continue
                candidate_key = normalize_crawl_url(candidate)
                if candidate_key not in links_seen:
                    links_seen.add(candidate_key)
                    if candidate_key not in pages_seen and len(pages_seen) + len(queue) < req.max_pages:
                        queue.append((candidate, page_url))
            time.sleep(CRAWL_DELAY)
        except CrossHostRedirectBlocked as redirect_error:
            add_unique_issue(
                issues, seen_issues, "info", "Scan limitation",
                "Cross-host redirect not followed",
                "This page redirects to a different hostname. The scanner intentionally stopped at the host boundary; this does not by itself indicate a broken link or vulnerability.",
                "Open the page in a normal browser and verify the final destination. If the destination is expected and trusted, record it as an external redirect rather than a scanner failure.",
                page_url,
            )
            page_results.append({
                "url": redact_url(page_url),
                "note": "Cross-host redirect blocked; destination not followed",
                "redirect_destination": redirect_error.destination,
            })
        except (ValueError, requests.RequestException) as exc:
            page_results.append({"url": redact_url(page_url), "error": str(exc)})

    counts = Counter(x["severity"] for x in issues)
    return {
        "target": redact_url(target),
        "http_status": first_status,
        "page_title": first_title,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "pages_checked": len([x for x in page_results if "status" in x]),
        "max_pages": req.max_pages,
        "pages": page_results,
        "summary": {
            "total_issues": len(issues), "high": counts["high"],
            "medium": counts["medium"], "low": counts["low"],
            "info": counts["info"], "links_checked": len(page_results),
            "pages_checked": len([x for x in page_results if "status" in x]),
            "duplicate_url_candidates_skipped": max(0, len(links_seen) - len(pages_seen)),
            "page_families_limited": sum(1 for count in family_counts.values() if count >= MAX_PAGES_PER_FAMILY),
        },
        "crawl_policy": {"max_pages_per_path_family": MAX_PAGES_PER_FAMILY, "pagination_aware": True, "tracking_parameters_removed": sorted(TRACKING_QUERY_KEYS)},

        "issues": issues,
        "links": page_results,
        "limitations": [
            "Bounded, non-invasive crawl of same-host HTML pages only.",
            "Maximum page count is capped at 100 and response bodies at 1.5 MB per page.",
            "Cookie, CORS and header observations require manual context and may be intentional.",
            "No exploitation, brute force, login bypass, authenticated testing or destructive requests are performed.",
            "This is not a penetration test; findings are heuristic indicators requiring manual validation.",
            "Only scan systems you own or are explicitly authorized to assess.",
        ],
    }
