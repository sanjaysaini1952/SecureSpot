from __future__ import annotations

from typing import Dict

import requests

from .active_checks import ActiveCheckResults, run_active_checks
from .auth import build_session
from .config import ScanConfig
from .crawler import CrawlResult, crawl
from .logging_utils import get_logger
from .passive_checks import UrlIssues, run_passive_checks
from .path_checks import SensitivePathResults, probe_sensitive_paths
from .reporting import build_report, write_html_report, write_json_report


logger = get_logger(__name__)


def run_scan(config: ScanConfig) -> Dict:
    """Run a full, *non-destructive* scan.

    This function performs:
    - Scoped, rate-limited crawling
    - Passive checks (headers, cookies, TLS, exposed directories)
    - Safe active checks (reflection detection only)
    It does not perform any form of exploitation.
    """

    session: requests.Session = build_session(config)

    logger.info("Starting crawl of %s", config.target_url)
    crawl_result, responses = crawl(config, session)

    logger.info("Running passive checks on %d pages", len(responses))
    passive_results: list[UrlIssues] = run_passive_checks(responses)

    logger.info("Running safe active checks on %d pages", len(responses))
    active_results: ActiveCheckResults = run_active_checks(responses, session)

    logger.info("Probing common sensitive paths on target host")
    sensitive_paths: SensitivePathResults = probe_sensitive_paths(config, session)

    report = build_report(config, crawl_result, passive_results, active_results, sensitive_paths)

    if config.output_json:
        logger.info("Writing JSON report to %s", config.output_json)
        write_json_report(report, config.output_json)

    if config.output_html:
        logger.info("Writing HTML report to %s", config.output_html)
        write_html_report(report, config.output_html)

    return report
