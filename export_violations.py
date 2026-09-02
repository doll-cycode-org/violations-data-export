#!/usr/bin/env python3
"""
Daily export of open Cycode SecretDetection violations to CSV.

Filters:
  - status: Open
  - category: SecretDetection
  - tags: verified-by-ai OR exist-in-latest-code
  - branches: main OR master
  - severity: any

Auth: client-credentials flow. Reads CYCODE_CLIENT_ID / CYCODE_CLIENT_SECRET
from the environment, exchanges them for a bearer token, then paginates the
violations endpoint.

NOTE: the token endpoint path/response shape and the exact violations path
below are based on the public v4 API surface as of this writing. If your
tenant's auth call 404s or the response doesn't contain a token field, check
the "Personal Access Tokens" / API docs in the Cycode UI (Settings > API
tokens) and adjust TOKEN_PATH / VIOLATIONS_PATH / the token field name in
get_access_token() accordingly -- both are isolated at the top so this is a
one-line fix.

Usage:
    python3 export_violations.py

Credentials are read from the environment, falling back to a .env file
(KEY=VALUE per line, next to this script unless ENV_FILE is set) for any
variable not already set in the environment. Real environment variables
always take precedence over the .env file.

Concurrency: violations are fetched one HTTP request chain per severity value
(Critical/High/Medium/Low/Info/NotAvailable) in parallel threads -- each
chain still paginates sequentially via next_page_token, but the 5 severities
run concurrently. All CSV writing happens once at the end, after every
severity has finished, so partial/interleaved writes are never a concern.

Env vars / .env keys:
    CYCODE_CLIENT_ID       (required)
    CYCODE_CLIENT_SECRET   (required)
    CYCODE_BASE_URL        (default: https://api.cycode.com)
    OUTPUT_DIR             (default: ./exports)
    ENV_FILE                (default: .env next to this script)
    LOG_LEVEL               (default: INFO)
    MAX_WORKERS              (default: number of severities, currently 5)
"""
import csv
import datetime
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


def load_dotenv(path):
    """Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.
    Never overrides a variable already present in the real environment."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            os.environ.setdefault(key, value)


_default_env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(os.environ.get("ENV_FILE", _default_env_file))

BASE_URL = os.environ.get("CYCODE_BASE_URL", "https://api.cycode.com").rstrip("/")
TOKEN_PATH = os.environ.get("CYCODE_TOKEN_PATH", "/api/v1/auth/api-token")
VIOLATIONS_PATH = os.environ.get("CYCODE_VIOLATIONS_PATH", "/v4/violations")

CATEGORY = "SecretDetection"
STATUS = "Open"
BRANCHES = ["main", "master"]
# NOTE: "verified-by-ai" (kebab-case) is the current tag value and is what
# matches live violations in this tenant today. "Verified by AI" (title
# case, spaces) is a legacy/pre-rename value -- rare (seen once in ~15.8k
# rows of historical export data vs. ~15.8k for the kebab-case form) and a
# live API query for it currently returns 0 results in this tenant, but
# it's included in the OR-list anyway since it costs nothing and guards
# against older/un-migrated detections or other tenants still carrying it.
TAGS = ["verified-by-ai", "Verified by AI", "exist-in-latest-code"]
PAGE_SIZE = 100

# Violations are queried one severity at a time so each can be fetched
# concurrently. "NotAvailable" is intentionally excluded -- it shouldn't
# occur for Open SecretDetection violations, and surfacing it as a bucket
# tends to raise questions from customers rather than convey anything real.
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
)
log = logging.getLogger("export_violations")

FIELDS = [
    "detection_source_policy_name",
    "detection_severity",
    "detection_status",
    "detection_category",
    "detection_tags",
    "detection_type",
    "detection_risk_score_severity",
    "detection_provider",
    "detection_correlation_message",
    "detection_created_date",
    "detection_id",
    "detection_labels",
    "detection_risk_score",
    "detection_source_entity_name",
    "detection_source_entity_type",
    "detection_source_policy_type",
    "detection_status_updated_at",
    "detection_sub_category_v2",
    "detection_updated_date",
    "detection_detection_details.organization_name",
    "detection_detection_details.repository_name",
    "detection_detection_details.line",
    "detection_detection_details.commit_id",
    "detection_detection_details.file_name",
    "detection_detection_details.file_url",
    "detection_detection_details.location_type",
    "detection_detection_details.branch_name",
    "detection_detection_details.repository_url",
    "detection_detection_details.sha512",
    "detection_detection_details.author_email",
    "detection_detection_details.author_name",
    "detection_detection_details.committed_at",
    "detection_detection_details.infra_provider",
    "detection_detection_details.provider",
    "detection_detection_details.cloud_provider",
]

# Fields with no known source in the API response as of this writing --
# always written empty. Documented here rather than silently dropped.
UNMAPPED_FIELDS = [
    "detection_detection_details.location_type",
    "detection_detection_details.infra_provider",
    "detection_detection_details.cloud_provider",
]


def _request(method, path, *, token=None, params=None, json_body=None):
    url = BASE_URL + path
    if params:
        query = urllib.parse.urlencode(params, doseq=True)
        url = f"{url}?{query}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        log.debug("%s %s -> 200 (%.2fs)", method, url, time.monotonic() - start)
        return body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log.error("%s %s -> %s (%.2fs)", method, url, e.code, time.monotonic() - start)
        raise SystemExit(f"HTTP {e.code} calling {url}: {body}")


def get_access_token(client_id, client_secret):
    log.info("Requesting access token from %s%s", BASE_URL, TOKEN_PATH)
    resp = _request(
        "POST",
        TOKEN_PATH,
        json_body={"ClientId": client_id, "Secret": client_secret},
    )
    token = resp.get("token") or resp.get("access_token") or resp.get("Token")
    if not token:
        raise SystemExit(
            f"Could not find a token field in auth response: {resp!r}\n"
            "Check TOKEN_PATH and the expected response shape."
        )
    log.info("Access token acquired.")
    return token


def fetch_violations_for_severity(token, severity):
    """Paginate the violations endpoint for a single severity value.
    Pagination within a severity is sequential (each page depends on the
    previous page's next_page_token); severities themselves are fetched
    concurrently by the caller."""
    items = []
    next_page_token = None
    page_num = 0
    while True:
        params = {
            "category": CATEGORY,
            "status": STATUS,
            "branches": BRANCHES,
            "tags": TAGS,
            "severity": [severity],
            "page_size": PAGE_SIZE,
        }
        if next_page_token:
            params["next_page_token"] = next_page_token
        page = _request("GET", VIOLATIONS_PATH, token=token, params=params)
        page_items = page.get("items", [])
        page_num += 1
        log.info(
            "severity=%s page=%d fetched=%d running_total=%d",
            severity, page_num, len(page_items), len(items) + len(page_items),
        )
        items.extend(page_items)
        next_page_token = page.get("next_page_token")
        if not next_page_token or not page_items:
            break
    return items


def fetch_all_violations(token, max_workers=None):
    max_workers = max_workers or len(SEVERITIES)
    all_items = []
    log.info(
        "Fetching violations for %d severities concurrently (max_workers=%d): %s",
        len(SEVERITIES), max_workers, ", ".join(SEVERITIES),
    )
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="sev") as pool:
        future_to_severity = {
            pool.submit(fetch_violations_for_severity, token, sev): sev
            for sev in SEVERITIES
        }
        for future in as_completed(future_to_severity):
            severity = future_to_severity[future]
            try:
                items = future.result()
            except Exception:
                log.exception("Failed fetching severity=%s", severity)
                raise
            log.info("Completed severity=%s total=%d", severity, len(items))
            all_items.extend(items)
    return all_items


def g(d, k):
    v = d.get(k)
    return v if v is not None else ""


def violation_to_row(v):
    dd = v.get("detection_details", {}) or {}
    return [
        g(v, "source_policy_name"),
        g(v, "severity"),
        g(v, "status"),
        g(v, "category"),
        json.dumps(v.get("tags", []), ensure_ascii=False),
        g(v, "type"),
        g(v, "risk_score_severity"),
        g(v, "provider"),
        g(v, "correlation_message"),
        g(v, "created_date"),
        g(v, "detection_id"),
        json.dumps(v.get("labels", []), ensure_ascii=False),
        g(v, "risk_score"),
        g(v, "source_entity_name"),
        g(v, "source_entity_type"),
        g(v, "source_policy_type"),
        g(v, "status_updated_at"),
        g(v, "sub_category_v2"),
        g(v, "updated_date"),
        g(dd, "organization_name"),
        g(dd, "repository_name"),
        g(dd, "line"),
        g(dd, "commit_id"),
        g(dd, "file_name"),
        g(dd, "file_url"),
        g(dd, "location_type"),
        g(dd, "branch_name"),
        g(dd, "repository_url"),
        g(dd, "sha512"),
        g(dd, "author_email"),
        g(dd, "author_name"),
        g(dd, "committed_at"),
        g(dd, "infra_provider"),
        g(dd, "provider"),
        g(dd, "cloud_provider"),
    ]


def main():
    start = time.monotonic()
    client_id = os.environ.get("CYCODE_CLIENT_ID")
    client_secret = os.environ.get("CYCODE_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit("CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET must be set in the environment.")

    output_dir = os.environ.get("OUTPUT_DIR", "./exports")
    os.makedirs(output_dir, exist_ok=True)
    today = datetime.date.today().isoformat()
    out_path = os.path.join(output_dir, f"cycode-open-secret-detections-{today}.csv")

    max_workers = int(os.environ.get("MAX_WORKERS", len(SEVERITIES)))

    token = get_access_token(client_id, client_secret)
    violations = fetch_all_violations(token, max_workers=max_workers)

    dupes = len(violations) - len({v.get("detection_id") for v in violations})
    if dupes:
        log.warning("%d duplicate detection_id(s) across severity buckets", dupes)

    log.info("Writing %d rows to %s", len(violations), out_path)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        for v in violations:
            writer.writerow(violation_to_row(v))

    elapsed = time.monotonic() - start
    log.info("Wrote %d rows to %s in %.2fs", len(violations), out_path, elapsed)
    if UNMAPPED_FIELDS:
        log.info(
            "Columns with no source field in the API response (always empty): %s",
            ", ".join(UNMAPPED_FIELDS),
        )


if __name__ == "__main__":
    main()
