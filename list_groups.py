import config
import json
import requests
from dotenv import load_dotenv

load_dotenv()

objects_to_list = ["groups", "contacts"]

url = "https://www.wasenderapi.com/api/groups"
headers = {
    "Authorization": f"Bearer {config.WASENDER_API_TOKEN}"
}
response = requests.get(url, headers=headers)
print(json.dumps(response.json(),ensure_ascii=False,indent=4))