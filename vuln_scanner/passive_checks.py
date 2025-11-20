from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from .logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class HeaderIssue:
    header: str
    message: str
    severity: str


@dataclass
class CookieIssue:
    name: str
    message: str
    severity: str


@dataclass
class UrlIssues:
    url: str
    header_issues: List[HeaderIssue] = field(default_factory=list)
    cookie_issues: List[CookieIssue] = field(default_factory=list)
    tls_issues: List[str] = field(default_factory=list)
    exposed_dirs: List[str] = field(default_factory=list)


def check_security_headers(url: str, resp: requests.Response) -> List[HeaderIssue]:
    headers = {k.lower(): v for k, v in resp.headers.items()}
    issues: List[HeaderIssue] = []

    if "content-security-policy" not in headers:
        issues.append(
            HeaderIssue(
                header="Content-Security-Policy",
                message="Missing Content-Security-Policy header (helps mitigate XSS).",
                severity="medium",
            )
        )

    if "x-frame-options" not in headers:
        issues.append(
            HeaderIssue(
                header="X-Frame-Options",
                message="Missing X-Frame-Options header (clickjacking protection).",
                severity="low",
            )
        )

    if "x-content-type-options" not in headers:
        issues.append(
            HeaderIssue(
                header="X-Content-Type-Options",
                message="Missing X-Content-Type-Options header (MIME sniffing).",
                severity="low",
            )
        )

    if "referrer-policy" not in headers:
        issues.append(
            HeaderIssue(
                header="Referrer-Policy",
                message="Missing Referrer-Policy header (leaks of sensitive URLs).",
                severity="low",
            )
        )

    if "strict-transport-security" not in headers and url.startswith("https://"):
        issues.append(
            HeaderIssue(
                header="Strict-Transport-Security",
                message="Missing HSTS header on HTTPS endpoint.",
                severity="medium",
            )
        )

    return issues


def check_cookies(resp: requests.Response) -> List[CookieIssue]:
    issues: List[CookieIssue] = []
    for cookie in resp.cookies:
        if not cookie.secure:
            issues.append(
                CookieIssue(
                    name=cookie.name,
                    message="Cookie missing Secure flag (should be HTTPS-only).",
                    severity="medium",
                )
            )
        if "httponly" not in (cookie._rest.keys() if hasattr(cookie, "_rest") else {}):  # type: ignore[attr-defined]
            issues.append(
                CookieIssue(
                    name=cookie.name,
                    message="Cookie missing HttpOnly flag (helps mitigate XSS stealing cookies).",
                    severity="medium",
                )
            )
    return issues


def check_tls(url: str, resp: requests.Response) -> List[str]:
    # We rely on the HTTP library's TLS validation settings (verify parameter).
    # Advanced TLS analysis (cipher suites, protocol versions) would require
    # lower-level access and is beyond this safe baseline implementation.
    issues: List[str] = []
    if url.startswith("http://"):
        issues.append("Connection is over HTTP, not HTTPS. Consider enforcing TLS.")
    return issues


EXPOSED_PATTERNS = [
    "/.git/",
    "/.svn/",
    "/backup/",
    "/old/",
    "/phpinfo.php",
]


def check_exposed_directories(url: str, content: str) -> List[str]:
    findings: List[str] = []
    lower = content.lower()
    if "Index of /" in content and "<title>Index of" in content:
        findings.append("Auto-indexing directory listing detected.")

    for pattern in EXPOSED_PATTERNS:
        if pattern in url:
            findings.append(f"URL appears to reference potentially sensitive path: {pattern}")

    # Content-based heuristics kept intentionally conservative and generic.
    if " /.git/" in lower or " /.svn/" in lower:
        findings.append("Page content references VCS metadata directories (.git/.svn).")

    return findings


def run_passive_checks(crawl_responses: Dict[str, requests.Response]) -> List[UrlIssues]:
    all_issues: List[UrlIssues] = []

    for url, resp in crawl_responses.items():
        ui = UrlIssues(url=url)
        try:
            ui.header_issues = check_security_headers(url, resp)
            ui.cookie_issues = check_cookies(resp)
            ui.tls_issues = check_tls(url, resp)
            ui.exposed_dirs = check_exposed_directories(url, resp.text or "")
        except Exception as exc:  # non-fatal
            logger.warning("Error running passive checks on %s: %s", url, exc)
        all_issues.append(ui)

    return all_issues
