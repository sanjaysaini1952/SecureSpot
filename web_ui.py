"""Simple local web UI for the SecureSpot vulnerability scanner.

Run with:
    python web_ui.py

Then open:
    http://127.0.0.1:5000/

Use ONLY against systems where you have explicit, written permission.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, redirect, render_template_string, request, url_for

from vuln_scanner.config import ScanConfig
from vuln_scanner.logging_utils import setup_logging
from vuln_scanner.scanner import run_scan


app = Flask(__name__)


INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>SecureSpot UI</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; }
    label { display: block; margin-top: 0.5rem; }
    input[type=text], input[type=number], input[type=password] {
      width: 320px; padding: 0.3rem; margin-top: 0.2rem;
    }
    .small { width: 100px; }
    button { margin-top: 1rem; padding: 0.4rem 0.8rem; }
    .notice { background: #fff6d5; padding: 0.8rem; border: 1px solid #e0c96a; margin-bottom: 1rem; }
    .section { margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <h1>SecureSpot - Safe Vulnerability Scanner</h1>
  <div class=\"notice\">
    <strong>Authorized use only.</strong> Use this tool only on systems where you have
    explicit, written permission from the owner.
  </div>

  <form method=\"post\" action=\"{{ url_for('start_scan') }}\">
    <div class=\"section\">
      <h2>Target</h2>
      <label>Target URL
        <input type=\"text\" name=\"target_url\" required placeholder=\"https://example.com\" />
      </label>
      <label>Allowed domain(s) (comma-separated, optional)
        <input type=\"text\" name=\"allowed_domains\" placeholder=\"example.com,app.example.com\" />
      </label>
    </div>

    <div class=\"section\">
      <h2>Crawl limits</h2>
      <label>Max depth
        <input class=\"small\" type=\"number\" name=\"max_depth\" value=\"2\" min=\"0\" />
      </label>
      <label>Max pages
        <input class=\"small\" type=\"number\" name=\"max_pages\" value=\"50\" min=\"1\" />
      </label>
      <label>Delay between requests (seconds)
        <input class=\"small\" type=\"number\" step=\"0.1\" name=\"delay\" value=\"0.5\" min=\"0\" />
      </label>
    </div>

    <div class=\"section\">
      <h2>Authentication (optional)</h2>
      <label>Username
        <input type=\"text\" name=\"username\" />
      </label>
      <label>Password
        <input type=\"password\" name=\"password\" />
      </label>
      <label>Cookie header
        <input type=\"text\" name=\"cookie\" placeholder=\"SESSIONID=...\" />
      </label>
    </div>

    <div class=\"section\">
      <h2>Output</h2>
      <label>JSON report path
        <input type=\"text\" name=\"json_out\" value=\"scan_report.json\" />
      </label>
      <label>HTML report path
        <input type=\"text\" name=\"html_out\" value=\"scan_report.html\" />
      </label>
    </div>

    <button type=\"submit\">Start scan</button>
  </form>

  {% if last_report %}
  <div class=\"section\">
    <h2>Last report</h2>
    <p>Last HTML report: <a href=\"{{ url_for('view_report') }}\" target=\"_blank\">open report</a></p>
  </div>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index() -> str:
    html_out = request.args.get("html_out", "scan_report.html")
    last_report = Path(html_out).exists()
    return render_template_string(INDEX_TEMPLATE, last_report=last_report)


@app.route("/scan", methods=["POST"])
def start_scan():
    target_url = request.form.get("target_url", "").strip()
    allowed_raw = request.form.get("allowed_domains", "").strip()
    allowed_domains = [d.strip() for d in allowed_raw.split(",") if d.strip()] if allowed_raw else []

    max_depth = int(request.form.get("max_depth", 2))
    max_pages = int(request.form.get("max_pages", 50))
    delay = float(request.form.get("delay", 0.5))

    username = request.form.get("username") or None
    password = request.form.get("password") or None
    cookie = request.form.get("cookie") or None

    json_out = request.form.get("json_out", "scan_report.json")
    html_out = request.form.get("html_out", "scan_report.html")

    cfg = ScanConfig(
        target_url=target_url,
        allowed_domains=allowed_domains,
        max_depth=max_depth,
        max_pages=max_pages,
        delay_between_requests=delay,
        auth_username=username,
        auth_password=password,
        auth_cookie=cookie,
        output_json=json_out,
        output_html=html_out,
        request_timeout=10,
        verify_tls=True,
        follow_redirects=True,
        log_level="INFO",
    )

    setup_logging(cfg.log_level)

    print(
        "[NOTICE] This tool is for authorized security testing only. "
        "Ensure you have explicit permission to scan the target and its scope."
    )

    run_scan(cfg)

    return redirect(url_for("index", html_out=html_out))


@app.route("/report")
def view_report():
    html_out = request.args.get("html_out", "scan_report.html")
    path = Path(html_out)
    if not path.exists():
        return "Report not found. Run a scan first.", 404
    # Serve static HTML contents directly.
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    # Designed for local use only
    app.run(host="127.0.0.1", port=5000, debug=False)
