import requests
from pprint import pprint
import string

URL_BASE = "http://localhost:5000/"
URL_REDIRECT = "http://127.0.0.1:5000/"
# This is maximum payload size that you can send, assuming UTF-8 encoding takes 1 bytes per character
# that would 7950 bytes, thought that is indicated by the client, server says this is


def test_post(URL: string):
    print(f"{URL}database/data.json")
    response = requests.post(
        f"{URL}database/data.json",
        json={
            "value": "100" * 100000000,
            "id": 123,
        },
    )
    response.connection.config
    print("payload: ", len(("100" * 100000000)))
    pprint(
        {
            "message": response.text,
            "status_code": response.status_code,
            "is_redirect": response.is_redirect,
            "is_permanent_redirect": response.is_permanent_redirect,
        },
        sort_dicts=False,
    )


def test_get(URL: string):
    response = requests.get(URL)

    pprint(
        {
            "status_code": response.status_code,
            "is_redirect": response.is_redirect,
            "is_permanent_redirect": response.is_permanent_redirect,
        },
        sort_dicts=False,
    )

    if response.status_code == 200:
        pprint(response.text)


for i in range(10):
    # test_get(URL_BASE)
    test_post(URL_REDIRECT)
    # test_get(URL_REDIRECT)
