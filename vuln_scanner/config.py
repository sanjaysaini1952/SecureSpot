from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    target_url: str
    allowed_domains: List[str]
    max_depth: int = 2
    max_pages: int = 100
    request_timeout: int = 10
    concurrent_requests: int = 4
    delay_between_requests: float = 0.5
    user_agent: str = "SecureSpot/1.0 (defensive security; non-destructive)"
    verify_tls: bool = True
    follow_redirects: bool = True
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_cookie: Optional[str] = None
    respect_robots_txt: bool = True
    log_level: str = "INFO"
    output_json: str = "scan_report.json"
    output_html: str = "scan_report.html"
    extra_headers: dict = field(default_factory=dict)


def build_default_config(target_url: str) -> ScanConfig:
    return ScanConfig(target_url=target_url, allowed_domains=[])
