import requests
import pandas as pd

BASE = "https://sec.cloudapps.cisco.com/security/center"
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}

# -------- Step 1: Get vulnerability list --------
list_url = f"{BASE}/publicationListing.x"

params = {
    "product": "Cisco",
    "sort": "-day_sir",
    "limit": 50,   # adjust / paginate as needed
    "offset": 0
}

resp = requests.get(list_url, headers=HEADERS, params=params)
resp.raise_for_status()

print(resp.status_code)
print(resp.headers.get("Content-Type"))
print(resp.text[:500])
exit()

data = resp.json()

advisories = data.get("advisories", [])
print(f"Found {len(advisories)} advisories")

results = []

# -------- Step 2: Fetch each advisory detail --------
for adv in advisories:
    advisory_id = adv.get("advisoryId")
    if not advisory_id:
        continue

    detail_url = f"{BASE}/publicationDetail.x"
    detail_resp = requests.get(
        detail_url,
        headers=HEADERS,
        params={"advisoryId": advisory_id}
    )
    detail_resp.raise_for_status()
    detail = detail_resp.json()

    results.append({
        "advisory_id": advisory_id,
        "title": detail.get("advisoryTitle"),
        "severity": detail.get("sir"),
        "cvss": detail.get("cvssScore"),
        "cves": ", ".join(detail.get("cves", [])),
        "published": detail.get("firstPublished"),
        "updated": detail.get("lastUpdated"),
        "summary": detail.get("summary")
    })

# -------- Export --------
df = pd.DataFrame(results)
df.to_csv("cisco_vulnerabilities.csv", index=False)

print("Saved cisco_vulnerabilities.csv")