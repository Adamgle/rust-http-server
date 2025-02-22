# Code in this file is a shenanigan, foolishness. Take it with a grain of salt, don't ya.

import collections
import functools
import json
import requests
from pprint import pprint
import socket
import threading
import typing
import time
import os

URL_BASE = "http://localhost:5000/"
URL_REDIRECT = "http://127.0.0.1:5000/"


def write_note(payload: str):
    with open("./public/note.txt", mode="w+") as f:
        f.write(payload)


def build_payload(id: int, payload: str) -> str:
    return json.dumps({"id": id, "value": payload})


def test_post(path: str, payload: str) -> int:
    response = requests.post(URL_BASE + path, json={"value": payload, "id": 123})
    return response.status_code


def test_get(path: str) -> int:
    response = requests.get(URL_BASE + path)
    return response.status_code


inject_size = 1


def send_custom(id: int, request: str, path: str) -> bool:
    host = "localhost"
    port = 5000

    POST_payload = build_payload(id, "A" * 1024)

    # We do not need that, it was made for testing of a buffered data that could not be fit into the buffer
    # as that would overflow the inner buffer of the BufReader, but it seems to work fine.
    injected = f"malicious-value{'x' * inject_size}"

    POST_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Content-Length: {len(POST_payload)}\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        f"Host: {host}:{port}\r\n"
        "X-Custom-Header: valid-value\r\n"
        f"Injected-Header: {injected}\r\n\r\n"
        f"{POST_payload}"
    )

    # injected_header_size = len(injected.encode("utf-8"))
    # keys_size = 0

    # for line in POST_request.splitlines()[1:]:
    #     if line == "":
    #         break

    #     keys_size += 1

    # print(keys_size)
    # print("\033[93mInjected header size: ", injected_header_size, "\033[0m")

    GET_request = (
        f"GET {path} HTTP/1.1\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        f"Host: {host}:{port}\r\n"
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

    def create_socket(request: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(request.encode())
            # If the response would be greater than 1024 bytes that would be flawed
            data = s.recv(1024)

            return data.decode("utf-8")

    # That return a response, although be careful as this only returns the first 1024 bytes of the response
    response = (
        create_socket(POST_request) if request == "POST" else create_socket(GET_request)
    )

    # response_injected_header_size, response_keys_size = response.split(";")

    # if (
    #     int(response_injected_header_size) != injected_header_size
    #     or int(response_keys_size) != keys_size
    # ):
    #     raise ValueError(
    #         f"Response does not match the injected header size: {response_injected_header_size} != {injected_header_size} or {response_keys_size} != {keys_size}"
    #     )

    return {
        "payload_size": size,
        "status": "200" in response,
    }


def run_multithreaded(callback, threads_count=10, requests_per_thread=100, **kwargs):
    threads = []
    results: list[bool] = []
    request_size = 0
    id = 0

    def worker(callback, **kwargs):
        nonlocal id
        nonlocal request_size
        thread_results = []

        for _ in range(requests_per_thread):
            id += 1
            result = callback(id, **kwargs)
            request_size = result["payload_size"] if request_size == 0 else request_size
            thread_results.append(result["status"] if "status" in result else result)

        results.extend(thread_results)

    for _ in range(threads_count):
        thread = threading.Thread(
            target=worker, kwargs={"callback": callback, **kwargs}
        )
        threads.append(thread)
        thread.start()

    for idx, thread in enumerate(threads):
        thread.join()
        if all(results):
            print(
                f"All requests of {idx} thread were successful: request count: {len(results)}"
            )
        else:
            print(
                f"Thread {idx} had failed requests, failed requests: {results.count(False)}"
            )

    return {"results": results, "request_size": request_size}


def run_benchmark(callback, **kwargs):
    # 'count' is the number of benchmarks to run, and then it will take the average of all the runs.
    if "count" not in kwargs:
        kwargs["count"] = 1

    callback_keywords = callback.keywords

    thread_count, request_per_thread = (
        callback_keywords["threads_count"]
        if "threads_count" in callback_keywords
        else None
    ), (
        callback_keywords["requests_per_thread"]
        if "requests_per_thread" in callback_keywords
        else None
    )

    log_entry = [
        f"Running {kwargs['count']} benchmarks {f"on {thread_count} threads, making {request_per_thread} requests per thread, total of {kwargs['count'] * thread_count * request_per_thread} requests, at" if all(prop is not None for prop in [thread_count, request_per_thread]) else "at"} {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}"
    ]

    if "request" not in kwargs or "path" not in kwargs:
        raise ValueError("request and path must be provided")

    log_entry.append(f"Running: {kwargs['request']} {kwargs['path']}")

    full_path = os.path.join(os.getcwd(), "public", kwargs["path"].removeprefix("/"))

    log_entry.append(f"File size of: {os.path.getsize(full_path)} bytes")

    # Payload size includes headers and body, if any, so technically it cannot be None,
    # though anything is possible and that is peak production code.
    payload_size = None

    with open("benchmark.log", "a+") as f:
        total = 0
        for _ in range(kwargs["count"]):
            start_time = time.time()
            result = callback(request=kwargs["request"], path=kwargs["path"])
            results = result["results"] if "results" in result else None

            payload_size = result["request_size"] if "request_size" in result else None

            end_time = time.time()
            execution_time = end_time - start_time

            total += execution_time

        print(f"Execution time: {execution_time:.2f} seconds")

        req_count = (
            kwargs["count"] * thread_count * request_per_thread
            if all(prop is not None for prop in [thread_count, request_per_thread])
            else kwargs["count"]
        )

        # if results:
        #     raise ValueError("No results were returned")

        print(f"Average time per request: {(execution_time / req_count):.4f} seconds")

        log_entry.append(f"Payload size: {payload_size} bytes")
        if payload_size and thread_count and request_per_thread:
            log_entry.append(
                "Payload transferred: {:.2f} MB".format(
                    (payload_size * thread_count * request_per_thread * kwargs["count"])
                    / 1024
                    / 1024
                )
            )
            log_entry.append(
                f"Average time per request: {(total / (kwargs['count'] * thread_count * request_per_thread)):.4f} seconds"
            )

        log_entry.append(
            f"Average execution time: {total / kwargs['count']:.2f} seconds\n\n"
        )

        f.write("\n".join(log_entry))


def tests():
    global inject_size

    # for i in range(100000):
    # inject_size += 1

    # send_custom(1, "POST", "/database/tasks.json")
    # send_custom(1, "GET", "/database/tasks.json")

    run_benchmark(
        functools.partial(
            run_multithreaded,
            callback=send_custom,
            threads_count=15,
            requests_per_thread=100,
        ),
        request="POST",
        path="/database/tasks.json",
        count=5,
    )


tests()
