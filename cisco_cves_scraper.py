import requests #Brings in requests library which lets python call API and send HTTP requests

url = "https://sec.cloudapps.cisco.com/security/center/publicationService.x" #API 

params = {              #query parameters
    "product": "Cisco",
    "offset": 0
}

response = requests.get(url, params=params) #sends GET request to API for my
data = response.json()


for item in data: #loop to get title and date
    print(item.get("title"), item.get("firstPublished"))

