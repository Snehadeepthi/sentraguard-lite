#!/usr/bin/env python3
"""SentraGuard Lite CLI - one command:

    python cli.py analyze --input sample_request.json --output out.json

Reads a request JSON file, calls POST /analyze on the running API and writes
the JSON response to the output file. Standard library only (no installs).

API URL: --api-url, else $API_BASE_URL, else http://localhost:8000
Exit codes: 0 success, 1 error (bad file, API unreachable, API rejected input)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_API_URL = "http://localhost:8000"


class CliError(Exception):
    """Expected, user-facing failure."""


def read_request(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CliError(f"input file not found: {path}")
    except json.JSONDecodeError as exc:
        raise CliError(f"input file is not valid JSON ({path}: line {exc.lineno}, col {exc.colno})")
    if not isinstance(data, dict):
        raise CliError("input JSON must be an object with prompt / context_docs / metadata")
    return data


def post_json(url: str, payload: dict, timeout: float) -> tuple[int, dict]:
    """POST JSON and return (status_code, parsed_body). Isolated for testing."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # 4xx / 5xx still carry a JSON body
        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except ValueError:
            return exc.code, {"error": {"code": "http_error", "message": str(exc)}}
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise CliError(f"could not reach API at {url}: {getattr(exc, 'reason', exc)}. Is it running?")


def cmd_analyze(args: argparse.Namespace) -> int:
    payload = read_request(Path(args.input))
    url = args.api_url.rstrip("/") + "/analyze"
    status, body = post_json(url, payload, args.timeout)

    if status != 200:
        err = body.get("error", {}) if isinstance(body, dict) else {}
        msg = f"API returned {status}: {err.get('message', body)}"
        for d in err.get("details", []):
            msg += f"\n  - {d.get('field')}: {d.get('message')}"
        raise CliError(msg)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    # Short, non-sensitive summary on stdout (no prompt text).
    print(f"decision={body['decision']} risk_score={body['risk_score']} "
          f"risk_tags={','.join(body['risk_tags']) or '-'} -> {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="SentraGuard Lite CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("analyze", help="analyze a request JSON file via the running API")
    p.add_argument("--input", required=True, help="path to request JSON")
    p.add_argument("--output", required=True, help="path to write the response JSON")
    p.add_argument("--api-url", default=os.getenv("API_BASE_URL", DEFAULT_API_URL),
                   help="API base URL (default: $API_BASE_URL or %(default)s)")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    p.set_defaults(func=cmd_analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
