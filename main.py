
import requests

url = "https://sec.cloudapps.cisco.com/security/center/publicationService.x"

params = {
    "product": "Cisco",
    "offset": 0
}

response = requests.get(url, params=params)
data = response.json()

for item in data.get("advisories", []):
    print(item.get("advisoryTitle"), item.get("publicationDate"))
