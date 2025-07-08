import config
import requests
from dotenv import load_dotenv

load_dotenv()

url = "https://www.wasenderapi.com/api/groups"
headers = {
    "Authorization": f"Bearer {config.WASENDER_API_TOKEN}"
}
response = requests.get(url, headers=headers)
print(response.json())