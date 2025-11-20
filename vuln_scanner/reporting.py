from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from .active_checks import ActiveCheckResults
from .config import ScanConfig
from .crawler import CrawlResult
from .passive_checks import UrlIssues
from .path_checks import SensitivePathResults


def _serialize(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_serialize(o) for o in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


def build_report(
    config: ScanConfig,
    crawl_result: CrawlResult,
    passive_results: list[UrlIssues],
    active_results: ActiveCheckResults,
    sensitive_paths: SensitivePathResults,
) -> Dict[str, Any]:
    return {
        "meta": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "target_url": config.target_url,
            "max_depth": config.max_depth,
            "max_pages": config.max_pages,
        },
        "crawl": {
            "visited_count": len(crawl_result.visited),
            "visited": sorted(crawl_result.visited),
            "errors": crawl_result.errors,
        },
        "passive_checks": _serialize(passive_results),
        "active_checks": _serialize(active_results),
        "sensitive_paths": _serialize(sensitive_paths),
    }


def write_json_report(report: Dict[str, Any], path: str) -> None:
    p = Path(path)
    p.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_html_report(report: Dict[str, Any], path: str) -> None:
    p = Path(path)

    # Minimal, static HTML report for safe viewing.
    html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>SecureSpot Scan Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    h1, h2, h3 {{ color: #333; }}
    pre {{ background: #f6f6f6; padding: 1rem; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; font-size: 0.9rem; }}
    th {{ background: #f0f0f0; text-align: left; }}
    .severity-low {{ color: #4a7; }}
    .severity-medium {{ color: #e9a100; }}
    .severity-high {{ color: #d33; }}
    .section {{ margin-bottom: 2rem; }}
  </style>
</head>
<body>
  <h1>SecureSpot Scan Report</h1>
  <div class=\"section\">
    <h2>Meta</h2>
    <p><strong>Target:</strong> {report['meta']['target_url']}</p>
    <p><strong>Generated at (UTC):</strong> {report['meta']['generated_at']}</p>
    <p><strong>Max depth:</strong> {report['meta']['max_depth']} | <strong>Max pages:</strong> {report['meta']['max_pages']}</p>
  </div>

  <div class=\"section\">
    <h2>Crawl Summary</h2>
    <p><strong>Visited pages:</strong> {report['crawl']['visited_count']}</p>
    <details>
      <summary>Visited URLs</summary>
      <pre>{"\n".join(report['crawl']['visited'])}</pre>
    </details>
    <details>
      <summary>Errors</summary>
      <pre>{json.dumps(report['crawl']['errors'], indent=2)}</pre>
    </details>
  </div>

  <div class=\"section\">
    <h2>Passive Checks</h2>
"""

    for ui in report.get("passive_checks", []):
        html += f"""
    <div class=\"section\">
      <h3>URL: {ui['url']}</h3>
      <h4>Security Headers</h4>
      <table>
        <tr><th>Header</th><th>Severity</th><th>Message</th></tr>
"""
        for hi in ui.get("header_issues", []):
            html += f"<tr><td>{hi['header']}</td><td class='severity-{hi['severity']}'>{hi['severity']}</td><td>{hi['message']}</td></tr>"
        html += "</table>\n      <h4>Cookies</h4>\n      <table>\n        <tr><th>Name</th><th>Severity</th><th>Message</th></tr>"
        for ci in ui.get("cookie_issues", []):
            html += f"<tr><td>{ci['name']}</td><td class='severity-{ci['severity']}'>{ci['severity']}</td><td>{ci['message']}</td></tr>"
        html += "</table>\n      <h4>TLS / Transport</h4>\n      <ul>"
        for ti in ui.get("tls_issues", []):
            html += f"<li>{ti}</li>"
        html += "</ul>\n      <h4>Exposed Directories / Paths</h4>\n      <ul>"
        for ed in ui.get("exposed_dirs", []):
            html += f"<li>{ed}</li>"
        html += "</ul>\n    </div>"

    html += """
  <div class=\"section\">
    <h2>Safe Active Checks (Reflections)</h2>
    <table>
      <tr><th>URL</th><th>Parameter</th><th>Reflected</th><th>Context Snippet</th></tr>
"""

    for rf in report.get("active_checks", {}).get("reflections", []):
        snippet = (rf.get("context_snippet") or "").replace("<", "&lt;").replace(">", "&gt;")
        html += f"<tr><td>{rf['url']}</td><td>{rf['parameter']}</td><td>{'yes' if rf['reflected'] else 'no'}</td><td><pre>{snippet}</pre></td></tr>"

    html += """
    </table>
  </div>

  <div class=\"section\">
    <h2>Sensitive Path Probing Results</h2>
    <table>
      <tr><th>Path</th><th>URL</th><th>Status Code</th><th>Description</th></tr>
"""

    for fp in report.get("sensitive_paths", {}).get("findings", []):
        html += f"<tr><td>{fp['path']}</td><td>{fp['url']}</td><td>{fp['status_code']}</td><td>{fp.get('description', '')}</td></tr>"

    html += """
    </table>
  </div>
</body>
</html>
"""

    p.write_text(html, encoding="utf-8")
