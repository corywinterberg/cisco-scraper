
import json
import time
from urllib.request import urlopen, Request
from urllib.parse import urlencode

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}

# -------------------------
# Fetch with retry logic
# -------------------------
def fetch(params, retries=3, delay=5):
    """
    Call the NVD API and retry on temporary failures (503s).
    """
    url = BASE_URL + "?" + urlencode(params)
    req = Request(url, headers=HEADERS)

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            if attempt == retries:
                raise
            print(f"NVD unavailable (attempt {attempt}/{retries}), retrying...")
            time.sleep(delay)


def get_cisco_cves(results_per_page=50):
    """
    Query NVD for Cisco-related CVEs.
    """
    params = {
        "keywordSearch": "Cisco",
        "resultsPerPage": results_per_page
    }
    return fetch(params)


# -------------------------
# Convert CVEs → Jira issues
# -------------------------
def cve_to_jira_issue(cve):
    """
    Convert a single CVE record into a Jira issue payload.
    """
    metrics = cve.get("metrics", {})
    cvss = None
    severity = "Medium"  # default

    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "Medium")

    # Simple severity → Jira priority mapping
    priority_map = {
        "CRITICAL": "Highest",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low"
    }

    return {
        "fields": {
            # 🔴 CHANGE THIS to your Jira project key
            "project": {"key": "SEC"},

            # 🔴 CHANGE THIS if you want Task / Bug / Story
            "issuetype": {"name": "Bug"},

            # Jira issue title
            "summary": f"Cisco vulnerability: {cve.get('id')}",

            # Jira issue description (plain text for now)
            "description": cve.get("descriptions", [{}])[0].get("value"),

            # Jira priority
            "priority": {
                "name": priority_map.get(severity, "Medium")
            },

            # Optional custom fields (examples)
            # These require custom field IDs in Jira
            # "customfield_12345": cve.get("id"),        # CVE ID
            # "customfield_12346": cvss,                 # CVSS score
        }
    }


def build_jira_issues(data):
    """
    Convert all Cisco CVEs into Jira issue objects.
    """
    issues = []

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        issues.append(cve_to_jira_issue(cve))

    return issues


# -------------------------
# Main
# -------------------------
def main():
    data = get_cisco_cves()
    issues = build_jira_issues(data)

    print(f"Prepared {len(issues)} Jira issues")

    # Write Jira-ready JSON to file
    with open("jira_cisco_issues.json", "w", encoding="utf-8") as f:
        json.dump(issues, f, indent=2)

    print("Saved jira_cisco_issues.json")


if __name__ == "__main__":
    main()

