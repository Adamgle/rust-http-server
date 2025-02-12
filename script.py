import collections
import json
import requests
from pprint import pprint
import string
import socket
import functools
import threading
import typing
import time

URL_BASE = "http://localhost:5000/"
URL_REDIRECT = "http://127.0.0.1:5000/"


def write_note(payload: str):
    with open("./public/note.txt", mode="w+") as f:
        f.write(payload)


def tests():
    tests = collections.defaultdict(list)

    build_payload: typing.Callable[[int, str], str] = lambda id, payload: json.dumps(
        {"id": id, "value": payload}
    )

    def test_post(path: string, payload: string):
        response = requests.post(URL_BASE + path, json={"value": payload, "id": 123})

        return response.status_code

    def test_get(path: str):
        response = requests.get(
            URL_BASE + path,
        )

        return response.status_code

    def send_custom(id: int, request: typing.Union["POST", "GET"]):
        # Target server and port
        host = "localhost"
        port = 5000

        # Craft the malicious HTTP request
        # NOTE: THIS IS NOT HEADER INJECTION YOU DUMB F'C

        POST_payload = build_payload(id, "A" * pow(10, 1))

        POST_request = (
            "POST /database/tasks.json HTTP/1.1\r\n"
            f"Content-Length: {len(POST_payload)}\r\n"
            "Content-Type: application/json\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            f"Host: {host}:{42069}\r\n"
            "X-Custom-Header: valid-value\r\n"
            "Injected-Header: malicious-value\r\n\r\n"
            f"{POST_payload}"
        )

        GET_request = (
            "GET /database/tasks.json HTTP/1.1\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            f"Host: {host}:{42069}\r\n"
            "X-Custom-Header: valid-value\r\n"
            "Injected-Header: malicious-value\r\n"
            "\r\n"
        )

        def create_socket(request: string):  # Create a socket connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(request.encode())
                data = s.recv(1024)

                return data.decode("utf-8")

        return "200" in (
            create_socket(POST_request)
            if request == "POST"
            else create_socket(GET_request)
        )

    def run():
        for i in range(100):
            keys = ["POST", "GET", "CUSTOM"]
            for key in keys:
                for _ in range(1):
                    tests[key].append(
                        test_get("database/tasks.json")
                        if key == "GET"
                        else (
                            test_post("database/tasks.json", payload)
                            if key == "POST"
                            else send_custom()
                        )
                    )

                if all([x == 200 for x in tests[key]]):
                    print(f"{key}: All requests were successful")

    def run_multithreaded(callback, **kwargs):
        threads = []
        results = []

        id = 0

        def worker(callback, **kwargs):
            nonlocal id

            thread_results = []

            for _ in range(100):
                id += 1
                thread_results.append(callback(id, kwargs["request"]))

            results.extend(thread_results)
            # print(f"Thread results: {thread_results}")

        for _ in range(10):  # Create 10 threads
            thread = threading.Thread(
                target=worker,
                kwargs={"callback": callback, **kwargs},
            )
            threads.append(thread)
            thread.start()

        for idx, thread in enumerate(threads):
            thread.join()
            if all(results):
                print(
                    f"All requests of {idx} thread were successful: request count: {len(results)}"
                )

        return results

    start_time = time.time()
    results = run_multithreaded(send_custom, request="POST")
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution time: {execution_time:.2f} seconds")
    print(f"Average time per request: {(execution_time / len(results)):.4f} seconds")
    # send_custom(1, "POST")

    return tests


pprint(tests())
