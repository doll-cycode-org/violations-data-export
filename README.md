# Cycode Violations Export

Daily export of open Cycode Secret Detection violations to CSV.

## What it queries

- **Status:** Open
- **Category:** SecretDetection
- **Tags:** `verified-by-ai` OR `Verified by AI` OR `exist-in-latest-code`
- **Branches:** `main` OR `master`
- **Severity:** any (Critical, High, Medium, Low, Info) — `NotAvailable` is intentionally excluded; it shouldn't occur for Open SecretDetection violations and tends to raise customer questions if it shows up

## Setup

1. Get a Cycode API client ID / secret (Cycode UI → Settings → API Tokens).
2. Create a `.env` file next to `export_violations.py`:
   ```
   CYCODE_CLIENT_ID=...
   CYCODE_CLIENT_SECRET=...
   ```
   `.env` is gitignored — never commit it.
3. Run it:
   ```
   python3 export_violations.py
   ```

No third-party dependencies — stdlib only (`urllib`, `csv`, `logging`, `concurrent.futures`).

## Output

Writes `./exports/cycode-open-secret-detections-YYYY-MM-DD.csv` (one file per day; re-running the same day overwrites that day's file). Override the directory with `OUTPUT_DIR`.

Columns match the original manual Cycode "Discovery" export format, e.g. `detection_id`, `detection_severity`, `detection_detection_details.repository_name`, etc. `detection_tags` and `detection_labels` are written as JSON-array strings, matching that format.

## Running it daily

Point cron (or your scheduler of choice) at it, e.g.:
```
0 6 * * * cd /path/to/violations-data-export && /usr/bin/python3 export_violations.py >> /path/to/violations-data-export/export.log 2>&1
```
The script itself doesn't schedule anything — it's a single run per invocation.

## Configuration (env vars / `.env` keys)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `CYCODE_CLIENT_ID` | Yes | — | |
| `CYCODE_CLIENT_SECRET` | Yes | — | |
| `CYCODE_BASE_URL` | No | `https://api.cycode.com` | |
| `OUTPUT_DIR` | No | `./exports` | |
| `ENV_FILE` | No | `.env` next to the script | |
| `LOG_LEVEL` | No | `INFO` | `DEBUG` also logs every successful HTTP call with timing |
| `MAX_WORKERS` | No | `5` (number of severities) | Thread pool size for concurrent severity fetches |
| `CYCODE_TOKEN_PATH` | No | `/api/v1/auth/api-token` | Only needed if your tenant's auth path differs |
| `CYCODE_VIOLATIONS_PATH` | No | `/v4/violations` | Only needed if your tenant's endpoint path differs |

Real environment variables always take precedence over `.env`.

## How it fetches data (concurrency)

Violations are fetched **one HTTP call chain per severity value**, running concurrently in a thread pool (`ThreadPoolExecutor`, size = `MAX_WORKERS`). Within a single severity, pages are still fetched sequentially, since each page's request depends on the previous page's `next_page_token` — only the 5 severities run in parallel with each other. All results are held in memory and the CSV is written once at the end, after every severity thread has finished, so there's no risk of a partial or interleaved file if one thread is slower than another.

The script logs progress per page (`severity=X page=N fetched=... running_total=...`) and a summary per severity as each completes, plus total row count and elapsed time at the end.

## Considerations / known gaps

- **`detection_detection_details.location_type`, `.infra_provider`, `.cloud_provider`** — these three columns exist in the original CSV format but have no corresponding field anywhere in the Secret Detection violation API response (checked against live sample data). They're always written empty rather than dropped, so the column set stays stable for downstream consumers.
- **Tag matching is OR, not AND.** The Cycode API's `tags` filter parameter is a union (OR) across the values given, confirmed empirically (`verified-by-ai` alone: 107 matches; `exist-in-latest-code` alone: 159; both together: 179 — consistent with a union, not an intersection which would be ≤107).
- **Two tag spellings for "verified by AI".** `verified-by-ai` (kebab-case) is the current, common value (~15.8k occurrences in a historical bulk export). `Verified by AI` (title case, spaces) is a legacy/pre-rename value — seen exactly once in that same historical export, and a live API query for it currently returns 0 results in this tenant. Both are included in the `tags` OR-list to be safe; see the comment above `TAGS` in the script.
- **Duplicate detection across severities.** Splitting the query by severity assumes each violation has exactly one severity value. The script computes a `detection_id`-based duplicate count after fetching and logs a warning if it's ever nonzero — this would only happen if that assumption breaks (e.g. a violation's severity changes mid-run between two severity queries). No dedup is silently applied; the raw duplicate count is only logged, not removed, so investigate if you see the warning.
- **No retry/backoff.** A single failed HTTP call (network blip, rate limit, transient 5xx) aborts the whole run via `SystemExit`/exception propagation from the failing thread. Fine for a daily cron job you can just re-run, but worth knowing if this gets wired into something less tolerant of a full-run failure.
- **Token is fetched once per run**, not cached across runs. Each invocation does a fresh client-credentials exchange.
- **Endpoint paths were reverse-engineered**, not pulled from official docs (no network access from the environment that wrote this script). `TOKEN_PATH` and `CYCODE_VIOLATIONS_PATH`/`CYCODE_TOKEN_PATH` are overridable via env var specifically so this can be fixed without a code change if Cycode changes or if your tenant differs.
- **No pagination cap.** If your tenant's matching violation count grows very large, a single severity's fetch loop will keep paging until `next_page_token` is empty — there's no upper bound on request count or runtime today.

## Files

- `export_violations.py` — the export script (this is what you run/schedule).
- `test_violations_endpoint.py` — connectivity smoke test: authenticates and calls the violations endpoint with only `page_size=1` and no other filters, useful for isolating "is my path/auth wrong" from "is one of my filter params wrong" when debugging.
