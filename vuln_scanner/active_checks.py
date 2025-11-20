from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import bs4
import requests

from .logging_utils import get_logger


logger = get_logger(__name__)


@dataclass
class ReflectionFinding:
    url: str
    parameter: str
    reflected: bool
    context_snippet: str = ""


@dataclass
class ActiveCheckResults:
    reflections: List[ReflectionFinding] = field(default_factory=list)


SAFE_MARKER = "SVS_REFLECTION_TEST_12345"


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def _find_reflection(marker: str, html: str) -> str:
    idx = html.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - 40)
    end = min(len(html), idx + len(marker) + 40)
    return html[start:end]


def detect_reflections(url: str, resp: requests.Response, session: requests.Session) -> List[ReflectionFinding]:
    """Detect harmless input reflection in responses.

    This does NOT attempt to exploit XSS; it only checks whether a benign
    marker value is reflected back in the page when used as a query parameter.
    """

    if "html" not in resp.headers.get("Content-Type", "").lower():
        return []

    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        # Try a generic param if none exist
        params = ["q"]

    findings: List[ReflectionFinding] = []

    for p in params:
        test_url = _inject_param(url, p, SAFE_MARKER)
        try:
            test_resp = session.get(test_url, timeout=10, allow_redirects=True, verify=resp.raw is not None)
        except Exception as exc:
            logger.debug("Error requesting %s for reflection test: %s", test_url, exc)
            continue

        if SAFE_MARKER in (test_resp.text or ""):
            snippet = _find_reflection(SAFE_MARKER, test_resp.text or "")
            findings.append(
                ReflectionFinding(
                    url=test_url,
                    parameter=p,
                    reflected=True,
                    context_snippet=snippet,
                )
            )

    return findings


def run_active_checks(crawl_responses: Dict[str, requests.Response], session: requests.Session) -> ActiveCheckResults:
    results = ActiveCheckResults()

    for url, resp in crawl_responses.items():
        try:
            reflections = detect_reflections(url, resp, session)
            results.reflections.extend(reflections)
        except Exception as exc:
            logger.warning("Error running active checks on %s: %s", url, exc)

    return results
