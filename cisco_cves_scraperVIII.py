
"""
===========================================================
Cisco CVE → Jira Ingestion Script
===========================================================

PURPOSE
-------
This script pulls recent (last 3 months) Cisco-related CVEs from the NVD
(National Vulnerability Database) API and prepares them
as Jira-ready issue objects.

FEATURES
--------
- Uses the official NVD CVE 2.0 API (authoritative source)
- Limits results to the last 3 months
- Filters to CRITICAL and HIGH severity CVEs only
- Adds CVSS score and severity into the Jira description
- Handles pagination safely
- Deduplicates CVEs across runs
- Produces Jira-ready JSON output
- Safe to run repeatedly (idempotent)

This script does NOT:
- Scrape Cisco’s website
- Create Jira tickets directly
- Require third-party Python libraries
"""

import json
import time
import os
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

# =========================================================
# Configuration
# =========================================================

# Base endpoint for the NVD CVE 2.0 API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# HTTP headers for the API request
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}

# Jira configuration (used only for output formatting)
JIRA_PROJECT_KEY = "SEC"

# Output file that stores Jira-ready issues
# This file is also used for deduplication
OUTPUT_FILE = "jira_cisco_issues.json"

# Pagination and rate-limiting controls
RESULTS_PER_PAGE = 50
SLEEP_BETWEEN_CALLS = 2

# =========================================================
# Date Range: Last 3 Months
# =========================================================

NOW = datetime.now(timezone.utc)
THREE_MONTHS_AGO = NOW - timedelta(days=90)

PUB_START_DATE = THREE_MONTHS_AGO.strftime("%Y-%m-%dT%H:%M:%S.000Z")
PUB_END_DATE = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")

# =========================================================
# Fetch One Page of Cisco CVEs
# =========================================================

def fetch_cisco_cves(start_index, retries=3, delay=5):
    """
    Fetch a single page of Cisco-related CVEs from NVD.

    - Uses keywordSearch=Cisco for reliable vendor coverage
    - Applies a 3-month publication date filter
    - Supports pagination via startIndex
    - Retries automatically on transient failures
    """

    params = {
        "keywordSearch": "Cisco",
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
        "pubStartDate": PUB_START_DATE,
        "pubEndDate": PUB_END_DATE,
    }

    url = NVD_API_URL + "?" + urlencode(params)
    req = Request(url, headers=HEADERS)

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception:
            if attempt == retries:
                raise
            print(f"NVD unavailable (attempt {attempt}/{retries}), retrying...")
            time.sleep(delay)

# =========================================================
# Convert CVE → Jira Issue Object
# =========================================================

def cve_to_jira_issue(cve):
    """
    Convert a single CVE record into a Jira-ready issue payload.

    Filters applied here:
    - Must have CVSS v3.1 scoring
    - Must be CRITICAL or HIGH severity

    Enrichment:
    - CVSS score and severity added to description
    """

    metrics = cve.get("metrics", {})

    # Skip CVEs without CVSS v3.1 scoring
    if "cvssMetricV31" not in metrics:
        return None

    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
    severity = cvss_data.get("baseSeverity", "MEDIUM")
    cvss_score = cvss_data.get("baseScore")

    # Only keep high-impact vulnerabilities
    if severity not in ("CRITICAL", "HIGH"):
        return None

    priority_map = {
        "CRITICAL": "Highest",
        "HIGH": "High",
    }

    description_text = (
        f"CVSS Score: {cvss_score}\n"
        f"Severity: {severity}\n\n"
        f"{cve.get('descriptions', [{}])[0].get('value')}"
    )

    return {
        "cve_id": cve.get("id"),
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "issuetype": {"name": "Bug"},
            "summary": f"Cisco vulnerability: {cve.get('id')}",
            "description": description_text,
            "priority": {
                "name": priority_map.get(severity, "Medium")
            }
        }
    }

# =========================================================
# Load Existing CVEs (Deduplication)
# =========================================================

def load_existing_cve_ids():
    """
    Load previously processed CVE IDs from the output file.
    This prevents duplicate Jira issues across runs.
    """

    if not os.path.exists(OUTPUT_FILE):
        return set()

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        issues = json.load(f)

    return {issue["cve_id"] for issue in issues if "cve_id" in issue}

# =========================================================
# Main Control Flow
# =========================================================

def main():
    """
    Main execution logic:
    1. Load existing CVEs for deduplication
    2. Page through NVD results
    3. Convert qualifying CVEs to Jira issues
    4. Append new issues to output file
    """

    existing_cves = load_existing_cve_ids()
    print(f"Loaded {len(existing_cves)} existing CVEs")

    new_issues = []
    start_index = 0
    total_results = None

    while True:
        data = fetch_cisco_cves(start_index)

        if total_results is None:
            total_results = data.get("totalResults", 0)

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if not cve_id or cve_id in existing_cves:
                continue

            issue = cve_to_jira_issue(cve)
            if issue:
                new_issues.append(issue)

        start_index += RESULTS_PER_PAGE
        print(f"Processed {min(start_index, total_results)} / {total_results}")
        time.sleep(SLEEP_BETWEEN_CALLS)

        if start_index >= total_results:
            break

    print(f"Found {len(new_issues)} new Cisco CRITICAL/HIGH CVEs")

    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            existing_issues = json.load(f)
    else:
        existing_issues = []

    existing_issues.extend(new_issues)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(existing_issues, f, indent=2)

    print(f"Saved {len(existing_issues)} total Jira issues to {OUTPUT_FILE}")

# =========================================================
# Entrypoint
# =========================================================

if __name__ == "__main__":
    main()
