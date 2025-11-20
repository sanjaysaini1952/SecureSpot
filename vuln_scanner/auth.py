from typing import Dict, Optional

import requests

from .config import ScanConfig


def build_session(config: ScanConfig) -> requests.Session:
    """Build a configured requests.Session with safe defaults.

    This session is used for all HTTP requests by the scanner.
    """

    session = requests.Session()

    headers: Dict[str, str] = {
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    headers.update(config.extra_headers)
    session.headers.update(headers)

    if config.auth_username and config.auth_password:
        session.auth = (config.auth_username, config.auth_password)

    if config.auth_cookie:
        session.headers["Cookie"] = config.auth_cookie

    return session


def apply_additional_auth(session: requests.Session, method: str, value: str) -> None:
    """Placeholder for extensible auth mechanisms (API keys, tokens, etc.).

    This function intentionally avoids any automatic brute forcing or guessing
    of credentials. All authentication data must be explicitly provided.
    """

    method = method.lower()
    if method == "header":
        name, _, token = value.partition(":")
        if name and token:
            session.headers[name.strip()] = token.strip()
    elif method == "bearer":
        session.headers["Authorization"] = f"Bearer {value.strip()}"
