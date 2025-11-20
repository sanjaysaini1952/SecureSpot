from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
from urllib.parse import urljoin, urlparse

import requests

from .config import ScanConfig
from .logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class SensitivePathFinding:
    path: str
    url: str
    status_code: int
    description: str = ""


@dataclass
class SensitivePathResults:
    findings: List[SensitivePathFinding] = field(default_factory=list)


SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/server-status",
    "/phpinfo.php",
    "/admin/",
    "/admin/login",
    "/login",
    "/.env",
    "/config.php",
]


def probe_sensitive_paths(config: ScanConfig, session: requests.Session) -> SensitivePathResults:
    """Gently probe a small, fixed set of common sensitive paths.

    This is intentionally conservative: it only performs a single GET per
    candidate path using the already-configured session and timeout, and it
    does not brute-force or enumerate large wordlists.
    """

    results = SensitivePathResults()

    base = config.target_url.rstrip("/") + "/"
    parsed_base = urlparse(base)
    if not parsed_base.scheme.startswith("http"):
        return results

    for path in SENSITIVE_PATHS:
        url = urljoin(base, path.lstrip("/"))
        try:
            resp = session.get(
                url,
                timeout=config.request_timeout,
                allow_redirects=config.follow_redirects,
                verify=config.verify_tls,
            )
        except Exception as exc:
            logger.debug("Error probing sensitive path %s: %s", url, exc)
            continue

        if resp.status_code in (200, 301, 302, 307, 308):
            desc = "Potentially interesting path is accessible. Inspect manually."
            results.findings.append(
                SensitivePathFinding(
                    path=path,
                    url=url,
                    status_code=resp.status_code,
                    description=desc,
                )
            )

    return results
