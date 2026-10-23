#!/usr/bin/env python3
"""
API Security Framework — authorized BOLA (Broken Object Level Authorization) checks.

This utility runs a small, configurable set of non-destructive API authorization
tests against endpoints and test identities that you own or are authorized to assess.
It can use a JSON test plan, send requests with distinct user tokens, and compare
responses for cross-user object access. It does not discover endpoints or create
accounts. Use synthetic test data and dedicated test credentials only.

Important: Run only in a staging/test environment with written authorization.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "APISecurityFramework/1.0 (authorized BOLA validation)"

def load_plan(path: Path) -> dict:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Test plan not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON test plan: {exc}") from exc
    if not isinstance(plan, dict):
        raise SystemExit("Test plan must be a JSON object.")
    if not isinstance(plan.get("tests"), list):
        raise SystemExit("Test plan must contain a 'tests' array.")
    return plan

def safe_url(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be a complete http(s) URL")
    # Accept only relative paths to avoid accidentally sending credentials to another host.
    if urlparse(path).scheme or path.startswith("//"):
        raise ValueError("Each test path must be relative to base_url.")
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

def request_json(url: str, token: str | None, method: str = "GET",
                 timeout: float = DEFAULT_TIMEOUT) -> dict:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, method=method, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read(1_000_000)
            return {"status": response.status, "headers": dict(response.headers.items()),
                    "body": body.decode("utf-8", errors="replace"), "error": None}
    except HTTPError as exc:
        body = exc.read(1_000_000)
        return {"status": exc.code, "headers": dict(exc.headers.items()),
                "body": body.decode("utf-8", errors="replace"), "error": f"HTTP {exc.code}"}
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": None, "headers": {}, "body": "", "error": str(exc)}

def body_fingerprint(body: str) -> str:
    """Return a normalized fingerprint for reporting; does not print response bodies."""
    import hashlib
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest() if body else ""

def run_test(base_url: str, test: dict, tokens: dict[str, str], timeout: float) -> dict:
    test_id = str(test.get("id", "unnamed-test"))
    path = str(test.get("path", ""))
    method = str(test.get("method", "GET")).upper()
    owner = str(test.get("owner_identity", "user_a"))
    other = str(test.get("other_identity", "user_b"))
    if method not in {"GET", "HEAD"}:
        return {"id": test_id, "status": "SKIPPED", "reason": "Only GET and HEAD are supported by this safe template."}
    if owner not in tokens or other not in tokens:
        return {"id": test_id, "status": "SKIPPED", "reason": "Both identities must have test tokens configured."}
    url = safe_url(base_url, path)
    owner_response = request_json(url, tokens[owner], method, timeout)
    other_response = request_json(url, tokens[other], method, timeout)

    # Potential signal only: if the resource owner can read it but the other identity
    # also receives a successful response, review whether that access is intended.
    owner_ok = owner_response["status"] is not None and 200 <= owner_response["status"] < 300
    other_ok = other_response["status"] is not None and 200 <= other_response["status"] < 300
    if owner_ok and other_ok:
        status = "REVIEW_POSSIBLE_BOLA"
        explanation = (
            "Both identities received a successful response for the configured object. "
            "Confirm the second identity is not authorized to access this object; shared or public resources can be legitimate."
        )
    elif owner_ok and not other_ok:
        status = "EXPECTED_ACCESS_CONTROL_SIGNAL"
        explanation = "Owner identity succeeded while the second identity did not receive a 2xx response."
    else:
        status = "INCONCLUSIVE"
        explanation = "Owner request did not succeed, so this test cannot determine cross-user object access."

    return {
        "id": test_id,
        "path": path,
        "method": method,
        "owner_identity": owner,
        "other_identity": other,
        "owner_status": owner_response["status"],
        "other_status": other_response["status"],
        "owner_body_sha256": body_fingerprint(owner_response["body"]),
        "other_body_sha256": body_fingerprint(other_response["body"]),
        "status": status,
        "explanation": explanation,
        "note": "Response bodies are not included in the report; verify authorization semantics manually."
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Run authorized, non-destructive BOLA checks from a JSON test plan.")
    parser.add_argument("--base-url", required=True, help="Base URL of an authorized test/staging API.")
    parser.add_argument("--plan", default="test_plan.example.json", help="JSON test plan.")
    parser.add_argument("--output", default="api_security_report.json", help="Output JSON report.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout in seconds.")
    parser.add_argument("--token-a-env", default="API_TEST_TOKEN_A", help="Environment variable for identity A token.")
    parser.add_argument("--token-b-env", default="API_TEST_TOKEN_B", help="Environment variable for identity B token.")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive.")
    token_a = os.environ.get(args.token_a_env, "")
    token_b = os.environ.get(args.token_b_env, "")
    if not token_a or not token_b:
        parser.error(f"Set both {args.token_a_env} and {args.token_b_env} environment variables to dedicated test tokens.")
    try:
        base = args.base_url.rstrip("/") + "/"
        # Validate base and test paths before making requests.
        if urlparse(base).scheme not in {"http", "https"} or not urlparse(base).netloc:
            parser.error("--base-url must be a complete http(s) URL.")
        plan = load_plan(Path(args.plan))
        results = [run_test(base, item, {"user_a": token_a, "user_b": token_b}, args.timeout)
                   for item in plan["tests"] if isinstance(item, dict)]
    except ValueError as exc:
        parser.error(str(exc))
    report = {
        "tool": "API Security Framework",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_url": base,
        "test_count": len(results),
        "results": results,
        "limitations": [
            "A successful response for two identities is only a review signal, not proof of BOLA.",
            "Use dedicated test accounts and synthetic objects in staging.",
            "Only GET and HEAD methods are supported by this template.",
            "Response bodies are not included in the report."
        ]
    }
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    for item in results:
        print(f"[{item.get('status', 'UNKNOWN')}] {item.get('id')}: {item.get('explanation', item.get('reason', ''))}")
    print(f"Report written to {Path(args.output).resolve()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
