
import json
import time
import os
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

# -----------------------------
# Configuration
# -----------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}

JIRA_PROJECT_KEY = "SEC"
OUTPUT_FILE = "jira_cisco_issues.json"

RESULTS_PER_PAGE = 50
SLEEP_BETWEEN_CALLS = 2


# -----------------------------
# Date range: last 3 months
# -----------------------------

NOW = datetime.now(timezone.utc)
THREE_MONTHS_AGO = NOW - timedelta(days=90)

PUB_START_DATE = THREE_MONTHS_AGO.strftime("%Y-%m-%dT%H:%M:%S.000Z")
PUB_END_DATE = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")



# -----------------------------
# Fetch one page of CVEs
# -----------------------------

def fetch_cisco_cves(start_index, retries=3, delay=5):
    
    params = {
        "keywordSearch": "Cisco",
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
        "pubStartDate": PUB_START_DATE,
        "pubEndDate": PUB_END_DATE
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


# -----------------------------
# CVE → Jira Issue
# -----------------------------

def cve_to_jira_issue(cve):
    metrics = cve.get("metrics", {})
    severity = "MEDIUM"

    if "cvssMetricV31" in metrics:
        severity = metrics["cvssMetricV31"][0]["cvssData"].get(
            "baseSeverity", "MEDIUM"
        )

    priority_map = {
        "CRITICAL": "Highest",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low"
    }

    return {
        "cve_id": cve.get("id"),
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "issuetype": {"name": "Bug"},
            "summary": f"Cisco vulnerability: {cve.get('id')}",
            "description": cve.get("descriptions", [{}])[0].get("value"),
            "priority": {
                "name": priority_map.get(severity, "Medium")
            }
        }
    }


# -----------------------------
# Load existing CVEs
# -----------------------------

def load_existing_cve_ids():
    if not os.path.exists(OUTPUT_FILE):
        return set()

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        issues = json.load(f)

    return {issue["cve_id"] for issue in issues if "cve_id" in issue}


# -----------------------------
# Main
# -----------------------------

def main():
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

            new_issues.append(cve_to_jira_issue(cve))

        start_index += RESULTS_PER_PAGE
        print(f"Processed {min(start_index, total_results)} / {total_results}")
        time.sleep(SLEEP_BETWEEN_CALLS)

        if start_index >= total_results:
            break

    print(f"Found {len(new_issues)} new Cisco CVEs")

    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            existing_issues = json.load(f)
    else:
        existing_issues = []

    existing_issues.extend(new_issues)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(existing_issues, f, indent=2)

    print(f"Saved {len(existing_issues)} total Jira issues to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
