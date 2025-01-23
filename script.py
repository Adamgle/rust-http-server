from asyncio import sleep
import requests
from pprint import pprint
import json


body = {"value": "Python", "id": 123}

# This should work, but it doesn't
response = requests.post("http://127.0.0.1:5000/database/data.json", json=body)

pprint(response.text)
