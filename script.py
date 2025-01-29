import requests
from pprint import pprint
import string
import socket

URL_BASE = "http://localhost:5000/"
URL_REDIRECT = "http://127.0.0.1:5000/"
# This is maximum payload size that you can send, assuming UTF-8 encoding takes 1 bytes per character
# that would 7950 bytes, thought that is indicated by the client, server says this is


def test_post(URL: string, payload: string):
    print(f"{URL}database/data.json")

    response = requests.post(
        f"{URL}database/data.json",
        json={
            "value": payload,
            "id": 123,
        },
    )

    # pprint(
    #     {
    #         "message": response.text,
    #         "status_code": response.status_code,
    #         "is_redirect": response.is_redirect,
    #         "is_permanent_redirect": response.is_permanent_redirect,
    #     },
    #     sort_dicts=False,
    # )

    return response.status_code


def write_note(payload: str):
    with open("./public/note.txt", mode="w+") as f:
        f.write(payload)


def tests():
    tests = dict()

    def test_post(path: string, payload: string):
        response = requests.post(URL_BASE + path, json={"value": payload, "id": 123})

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

    def test_get(path: str):
        response = requests.get(
            URL_BASE + path,
            # headers={"Accept": "text/plain", "User-Agent": "Mozilla/5.0\n\r"},
        )

        pprint(response.request.headers)
        pprint(response.status_code)

    payload = "A" * pow(10, 1)

    def send_custom():
        import socket

        # Target server and port
        host = "localhost"
        port = 5000

        # Craft the malicious HTTP request
        request = (
            "GET /database/data.json HTTP/1.1\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            f"Host: {host}:{42069}\r\n"
            "X-Custom-Header: valid-value\r\n"
            "Injected-Header: malicious-value\r\n\r\n"
        )

        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(request.encode())  # Send the malicious request
            response = s.recv(4096)  # Receive the response

        pprint(response)

        print(response.decode())  # Print the server's response

    tests["GET"] = [
        [
            # test_get("note.txt"),
            # send_custom() if i % 2 == 0 else None,
            test_post("database/data.json", payload),
        ]
        for i in range(10)
    ]
    
    # tests["CUSTOM"] = send_custom()

    return tests


pprint(tests())
# write_note("A" * pow(10, 9))
