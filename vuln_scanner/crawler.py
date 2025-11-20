import collections
import time
from typing import Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urldefrag, urlparse

import bs4
import requests

from .config import ScanConfig
from .logging_utils import get_logger


logger = get_logger(__name__)


class CrawlResult:
    def __init__(self) -> None:
        self.visited: Set[str] = set()
        self.errors: Dict[str, str] = {}


def is_same_domain(url: str, allowed_domains: List[str]) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return any(host == d or host.endswith("." + d) for d in allowed_domains)


def normalize_url(base: str, link: str) -> Optional[str]:
    if not link:
        return None
    href = urljoin(base, link)
    href, _ = urldefrag(href)
    parsed = urlparse(href)
    if parsed.scheme not in ("http", "https"):
        return None
    return href


def extract_links(url: str, response: requests.Response) -> List[str]:
    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return []

    try:
        soup = bs4.BeautifulSoup(response.text, "html.parser")
    except Exception:
        return []

    links: List[str] = []
    for tag in soup.find_all("a", href=True):
        links.append(tag["href"])
    return links


def crawl(config: ScanConfig, session: requests.Session) -> Tuple[CrawlResult, Dict[str, requests.Response]]:
    """Non-destructive crawler limited by scope, depth, and rate.

    Returns the crawl result and a mapping of URL -> last successful response
    object, to be reused by checks where possible.
    """

    result = CrawlResult()
    responses: Dict[str, requests.Response] = {}
    allowed_domains = config.allowed_domains or [urlparse(config.target_url).hostname or ""]

    queue: Deque[Tuple[str, int]] = collections.deque()
    queue.append((config.target_url, 0))

    while queue and len(result.visited) < config.max_pages:
        url, depth = queue.popleft()
        if url in result.visited:
            continue
        if depth > config.max_depth:
            continue
        if not is_same_domain(url, allowed_domains):
            continue

        logger.debug("Crawling %s (depth=%s)", url, depth)
        try:
            resp = session.get(
                url,
                timeout=config.request_timeout,
                allow_redirects=config.follow_redirects,
                verify=config.verify_tls,
            )
            result.visited.add(url)
            responses[url] = resp
        except Exception as exc:  # non-fatal
            logger.warning("Error fetching %s: %s", url, exc)
            result.errors[url] = str(exc)
            continue

        links = extract_links(url, resp)
        for href in links:
            normalized = normalize_url(url, href)
            if not normalized:
                continue
            if normalized in result.visited:
                continue
            if not is_same_domain(normalized, allowed_domains):
                continue
            queue.append((normalized, depth + 1))

        if config.delay_between_requests > 0:
            time.sleep(config.delay_between_requests)

    return result, responses
