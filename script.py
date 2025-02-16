# Code in this file is a shenanigan, foolishness. Take it with a grain of salt, don't ya.

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

    def send_custom(id: int, request: typing.Union["POST", "GET"], path: string):
        # Target server and port
        host = "localhost"
        port = 5000

        # Craft the malicious HTTP request
        # NOTE: THIS IS NOT HEADER INJECTION YOU DUMB F'C

        POST_payload = build_payload(id, "A" * pow(10, 1))

        POST_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Content-Length: {len(POST_payload)}\r\n"
            "Content-Type: application/json\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            f"Host: {host}:{42069}\r\n"
            "X-Custom-Header: valid-value\r\n"
            f"Injected-Header: malicious-value{"x" * 1024}\r\n\r\n"
            f"{POST_payload}"
        )

        GET_request = (
            f"GET {path} HTTP/1.1\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            f"Host: {host}:{42069}\r\n"
            "X-Custom-Header: valid-value\r\n"
            "Injected-Header: malicious-value\r\n"
            "\r\n"
        )

        size = (
            len(GET_request.encode("utf-8"))
            if request == "GET"
            else len(POST_request.encode("utf-8"))
        )
        print("Sending request of size: ", size)

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

    def run_multithreaded(callback, threads_count=10, requests_per_thread=100, **kwargs):
        threads = []
        results = []

        id = 0

        def worker(callback, **kwargs):
            nonlocal id

            thread_results = []

            for _ in range(requests_per_thread):
                id += 1

                thread_results.append(callback(id, **kwargs))
            results.extend(thread_results)
            # print(f"Thread results: {thread_results}")

        for _ in range(threads_count):  # Create 10 threads
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

    def run_benchmark(callback, **kwargs):
        import os

        if "count" not in kwargs:
            kwargs["count"] = 1

        log_entry = [
            f"Running {kwargs['count']} requests at {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}"
        ]

        if "request" not in kwargs or "path" not in kwargs:
            raise ValueError("Request and path must be provided")

        log_entry.append(f"Running: {kwargs['request']} {kwargs['path']}")

        current_directory = os.getcwd()

        full_path = os.path.join(
            current_directory, "public", kwargs["path"].removeprefix("/")
        )

        log_entry.append(f"File size of: {os.path.getsize(full_path)} bytes")

        with open("benchmark.log", "a+") as f:
            total = 0

            for count in range(kwargs["count"]):
                start_time = time.time()

                results = callback(request=kwargs["request"], path=kwargs["path"])
                end_time = time.time()

                execution_time = end_time - start_time

                print(f"Execution time: {execution_time:.2f} seconds")
                print(
                    f"Average time per request: {(execution_time / len(results)):.4f} seconds"
                )

                total += execution_time

            log_entry.append(
                f"Average execution time: {total / kwargs['count']:.2f} seconds\n\n"
            )

            f.write("\n".join(log_entry))

    run_benchmark(
        functools.partial(run_multithreaded, callback=send_custom, threads_count=1, requests_per_thread=1),
        request="POST",
        path="/database/tasks.json",
        count=1,
    )


tests()
