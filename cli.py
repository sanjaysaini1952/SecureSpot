import argparse

from vuln_scanner.config import ScanConfig
from vuln_scanner.logging_utils import setup_logging
from vuln_scanner.scanner import run_scan


def parse_args() -> ScanConfig:
    parser = argparse.ArgumentParser(
        description=(
            "SecureSpot - safe, authorized-only website vulnerability scanner. "
            "Use only against systems for which you have explicit permission."
        )
    )
    parser.add_argument("target", help="Target URL to scan (must be within your authorized scope)")
    parser.add_argument(
        "--allowed-domain",
        action="append",
        dest="allowed_domains",
        default=None,
        help="Domain allowed for crawling (can be given multiple times). Defaults to target's domain.",
    )
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (not recommended)")
    parser.add_argument("--username", help="HTTP basic auth username", default=None)
    parser.add_argument("--password", help="HTTP basic auth password", default=None)
    parser.add_argument("--cookie", help="Raw Cookie header value for authenticated sessions", default=None)
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--json-out", default="scan_report.json", help="Path to JSON report (default: scan_report.json)")
    parser.add_argument("--html-out", default="scan_report.html", help="Path to HTML report (default: scan_report.html)")

    args = parser.parse_args()

    cfg = ScanConfig(
        target_url=args.target,
        allowed_domains=args.allowed_domains or [],
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        request_timeout=args.timeout,
        delay_between_requests=args.delay,
        verify_tls=not args.no_verify_tls,
        auth_username=args.username,
        auth_password=args.password,
        auth_cookie=args.cookie,
        log_level=args.log_level,
        output_json=args.json_out,
        output_html=args.html_out,
    )

    return cfg


def main() -> None:
    cfg = parse_args()

    # Critical safety reminder before any action
    print(
        "[NOTICE] This tool is for authorized security testing only. "
        "Ensure you have explicit permission to scan the target and its scope."
    )

    setup_logging(cfg.log_level)
    run_scan(cfg)


if __name__ == "__main__":
    main()
