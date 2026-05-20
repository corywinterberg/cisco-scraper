
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import pandas as pd
import time

START_URL = (
    "https://sec.cloudapps.cisco.com/security/center/"
    "publicationListing.x?product=Cisco&sort=-day_sir"
)

results = []

with sync_playwright() as p:
    browser = p.firefox.launch(headless=True)
    page = browser.new_page()
    page.goto(START_URL, timeout=60000)

    # Wait for advisories to render
    page.wait_for_selector("a[href*='advisory']", timeout=60000)

    # Collect advisory links
    links = page.eval_on_selector_all(
        "a[href*='advisory']",
        "els => [...new Set(els.map(e => e.href))]"
    )

    print(f"Found {len(links)} advisories")

    for url in links:
        page.goto(url, timeout=60000)
        time.sleep(1)

        soup = BeautifulSoup(page.content(), "html.parser")

        def find_value(label):
            span = soup.find("span", string=label)
            return span.find_next("span").get_text(strip=True) if span else None

        record = {
            "url": url,
            "title": soup.find("h1").get_text(strip=True) if soup.find("h1") else None,
            "severity": find_value("Severity"),
            "cvss": find_value("CVSS Score"),
            "cves": find_value("CVE"),
            "published": find_value("First Published"),
            "updated": find_value("Last Updated"),
        }

        results.append(record)

    browser.close()

# Export
df = pd.DataFrame(results)
df.to_csv("cisco_vulnerabilities.csv", index=False)

print("Saved cisco_vulnerabilities.csv")
