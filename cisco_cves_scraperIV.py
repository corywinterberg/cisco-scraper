
# Built‑in modules used for:
# - csv: writing output to a CSV file
# - json: decoding JSON responses from the API
# - time: (currently unused, but commonly used for rate‑limiting APIs)
import csv
import json
import time

# urllib is part of Python’s standard library and lets us make HTTP requests
from urllib.request import urlopen, Request
from urllib.parse import urlencode


# Base endpoint for the NVD CVE 2.0 API
# This is a real, supported REST API provided by NIST
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# HTTP headers sent with every request
# User‑Agent helps avoid basic bot blocking
# Accept tells the API we expect JSON back
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}



def fetch(params, retries=3, delay=5):
    """
    Fetch data from the NVD API with basic retry logic.
    This handles temporary 503 errors (rate limiting / maintenance).
    """

    url = BASE_URL + "?" + urlencode(params)
    req = Request(url, headers=HEADERS)

    for attempt in range(1, retries + 1):
        try:
            with urlopen(req) as r:
                return json.loads(r.read().decode("utf-8"))

        except Exception as e:
            # If this was our last attempt, raise the error
            if attempt == retries:
                raise

            print(
                f"NVD unavailable (attempt {attempt}/{retries}). "
                f"Retrying in {delay} seconds..."
            )
            time.sleep(delay)



def get_cisco_cves(results_per_page=50):
    """
    Builds the query parameters for Cisco‑related CVEs
    and calls the fetch() function.
    """

    params = {
        # Simple keyword search across CVE metadata
        "keywordSearch": "Cisco",

        # How many results the API should return in one call
        "resultsPerPage": results_per_page
    }

    return fetch(params)


def extract_rows(data):
    """
    Takes the raw JSON response from NVD and converts it into
    a list of clean, flat rows suitable for CSV output.
    """

    rows = []

    # Loop through each vulnerability returned by the API
    for vuln in data.get("vulnerabilities", []):

        # Each vulnerability has a "cve" object
        cve = vuln.get("cve", {})

        # CVSS and severity live under the "metrics" section
        metrics = cve.get("metrics", {})

        cvss = None
        severity = None

        # Prefer CVSS v3.1 if it exists (most modern CVEs use this)
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

        # Build a single flat row for this CVE
        rows.append({
            "cve_id": cve.get("id"),
            "severity": severity,
            "cvss": cvss,
            "published": cve.get("published"),
            "updated": cve.get("lastModified"),

            # Descriptions is a list — we take the first one
            "description": cve.get("descriptions", [{}])[0].get("value")
        })

    return rows


def main():
    """
    Main control flow:
    1. Pull Cisco CVEs from NVD
    2. Normalize the data
    3. Write results to CSV
    """

    # Step 1: Call the NVD API
    data = get_cisco_cves()

    # Step 2: Convert raw JSON into rows
    rows = extract_rows(data)

    print(f"Found {len(rows)} Cisco CVEs from NVD")

    # Step 3: Write the results to a CSV file
    with open("cisco_cves.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "cve_id",
                "severity",
                "cvss",
                "published",
                "updated",
                "description"
            ]
        )

        # Write CSV header row
        writer.writeheader()

        # Write one row per CVE
        writer.writerows(rows)

    print("Saved cisco_cves.csv")


# Standard Python entry‑point check
# This ensures main() only runs when the script is executed directly
if __name__ == "__main__":
    main()
