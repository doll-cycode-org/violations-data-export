#!/usr/bin/env python3
"""
Quick connectivity test: auth, then call the violations endpoint with no
filters at all, to isolate whether 404s are about the path or the query
params. Reuses auth/env handling from export_violations.py.

Usage:
    python3 test_violations_endpoint.py
"""
import json

from export_violations import BASE_URL, VIOLATIONS_PATH, _request, get_access_token
import os


def main():
    client_id = os.environ.get("CYCODE_CLIENT_ID")
    client_secret = os.environ.get("CYCODE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit("CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET must be set (env or .env).")

    print(f"BASE_URL={BASE_URL}")
    print(f"VIOLATIONS_PATH={VIOLATIONS_PATH}")

    token = get_access_token(client_id, client_secret)
    print("Got token.")

    resp = _request("GET", VIOLATIONS_PATH, token=token, params={"page_size": 1})
    print("Success. Response keys:", list(resp.keys()))
    print(json.dumps(resp, indent=2)[:2000])


if __name__ == "__main__":
    main()
