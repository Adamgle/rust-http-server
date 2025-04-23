# Code in this file is a shenanigans, foolishness.

import functools
import json
import os
import pprint
import socket
import threading
import time
from typing import Callable, List, Optional, TypedDict, Any
from enum import Enum
import typing
import matplotlib.pyplot as plt
import numpy as np
import requests

URL_BASE = "http://localhost:5000/"
DEFAULT_PORT = 5000
NOTE_FILE_PATH = "./public/note.txt"


class HttpHeaders:
    def __init__(self, headers: dict[str, str]):
        self.headers = headers

    def __getitem__(self, key: str) -> str:
        return self.headers.get(key, "")

    def __setitem__(self, key: str, value: str) -> None:
        self.headers[key] = value

    def get_headers(self) -> dict[str, str]:
        return self.headers


class HttpRequest(HttpHeaders):
    def __init__(self, method: str, path: str, headers: dict[str, str]):
        super().__init__(headers)
        self.method = method
        self.path = path

    def __str__(self) -> str:
        return f"{self.method} {self.path} HTTP/1.1\r\n" + "\r\n".join(
            [f"{k}: {v}" for k, v in self.headers.items()]
        )


headers_dict = {
    "User-Agent": "Mozilla/5.0",
    "Host": f"localhost:{DEFAULT_PORT}",
}

headers = HttpHeaders(headers_dict)

request = HttpRequest(
    method="GET",
    path="/",
    headers=headers_dict,
)


print(request.get_headers())


class SendResult(TypedDict):
    payload_size: int
    status: bool


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


def write_note(payload: str) -> None:
    with open(NOTE_FILE_PATH, "w+", encoding="utf-8") as f:
        f.write(payload)


def build_payload(id: int, value: str) -> str:
    return json.dumps({"id": id, "value": value})


def test_post(path: str, payload: str) -> int:
    response = requests.post(URL_BASE + path, json={"value": payload, "id": 123})
    return response.status_code


def test_get(path: str) -> int:
    response = requests.get(URL_BASE + path)
    return response.status_code


SendCustomCallable = Callable[[str, str, Optional[str], Optional[str]], SendResult]


def send_custom(
    request: HttpMethod = HttpMethod.GET,
    path: str = "/",
    payload: Optional[str] = None,
    host: str = "localhost",
    inject_size: int = 1,
    **kwargs,
) -> SendResult:
    injected_header = f"malicious-value{'x' * inject_size}"

    response_timestamps: Optional[List[float]] = kwargs.get("response_timestamps", None)

    match request:
        case HttpMethod.POST:
            headers = (
                f"POST {path} HTTP/1.1\r\n"
                f"Content-Length: {len(payload) if payload else 0}\r\n"
                "Content-Type: application/json\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                f"Host: {host}:{DEFAULT_PORT}\r\n"
                "X-Custom-Header: valid-value\r\n"
                f"Injected-Header{injected_header}: {injected_header}\r\n\r\n"
                f"{payload if payload else ''}"
            )
        case HttpMethod.GET:
            headers = (
                f"GET {path} HTTP/1.1\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                f"Host: {host}:{DEFAULT_PORT}\r\n"
                "X-Custom-Header: valid-value\r\n"
                f"Injected-Header: {injected_header}\r\n\r\n"
            )
        case _:
            headers = (
                f"{request.value} {path} HTTP/1.1\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                f"Host: {host}:{DEFAULT_PORT}\r\n"
                "X-Custom-Header: valid-value\r\n"
                f"Injected-Header: {injected_header}\r\n\r\n"
                f"{payload if payload else ''}"
            )

    def create_socket(message: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, DEFAULT_PORT))
            s.sendall(message.encode())

            response = s.recv(1024).decode()
            s.close()

            return response

    response = create_socket(headers)

    if response:
        if response_timestamps is not None:
            response_timestamps.append(time.time())

    return {
        "payload_size": len(headers.encode()),
        "status": "200" in response,
    }


def run_multithreaded(
    callback: SendCustomCallable,
    threads_count: int = 10,
    requests_count: int = 100,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Executes a callback function, presumably `send_custom` in current implementation, but could be anything that is making a request, in multiple threads.
    Makes n requests distributes across m threads, meaning one thread makes n/m requests.
    requests_count must be divisible by threads_count.
    Args:
        callback (SendCustomCallable): The function to be executed by each thread. Must accept keyword arguments and return a dict with "payload_size" and "status" keys.
        threads_count (int, optional): Number of threads to spawn. Defaults to 10.
        requests_count (int, optional): Number of requests distributes across thread to perform. Defaults to 100.
        **kwargs (Any): Additional keyword arguments to pass to the callback function.
    Returns:
        dict[str, Any]: A dictionary containing:
            - "results": List of boolean status results from all requests.
            - "request_size": The payload size from the first callback result.
    Notes:
        - The function prints the number of failures after each thread completes.
        - The "request_size" is determined from the first callback invocation.
    """

    if requests_count % threads_count != 0:
        raise ValueError("requests_count must be divisible by threads_count.")

    results: list[bool] = []
    request_size: int = 0
    thread_list = []

    # response_timestamps: Optional[List[time.time]] = kwargs.get(
    #     "response_timestamp", None
    # )

    def worker() -> None:
        nonlocal request_size
        thread_results: list[bool] = []

        for _ in range(requests_count // threads_count):
            # Invokes send_custom presumably

            result = callback(**kwargs)

            if request_size == 0:
                request_size = result["payload_size"]
            thread_results.append(result["status"])

        results.extend(thread_results)

    for _ in range(threads_count):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
        thread.start()

    for idx, thread in enumerate(thread_list):
        thread.join()
        print(f"Thread {idx} done. Failures: {results.count(False)}")

    return {"results": results, "request_size": request_size}


def run_benchmark(
    callback: SendCustomCallable,
    count: int = 1,
    request: HttpMethod = HttpMethod.GET,
    path: str = "/",
    response_timestamps: List[float] = [],
) -> None:
    """Runs n benchmarks on a given path and request. Default's to one benchmark on "/" path with 'GET'.

    Args:
        callback (SendCustomCallable): Currently it runs on run_multithreaded function that runs send_custom, but ideally it could run on anything,
        preferably on raw socket as benchmarking with requests library is a shenanigan.
        count (int, optional): Count of benchmarks to run. Defaults to 1.
        request (str, HttpMethod): Http method. Defaults to "GET".
        path (str, optional): Path to run. Defaults to "/".
    """

    file_path = os.path.join("public", path.lstrip("/"))
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # arguments of the run_multithreaded built with functools.partial
    callback_args = callback.keywords

    print(callback_args)

    threads_count, requests_count = (
        callback_args["threads_count"],
        callback_args["requests_count"],
    )

    print(
        f"Threads count: {threads_count} Requests per thread: {requests_count // threads_count} "
    )

    log_entry: list[str] = [
        f"Running {count} benchmarks on {threads_count} threads, making {requests_count // threads_count} requests per thread, at {timestamp}",
        f"Running: {request} {path}",
    ]

    try:
        file_size = os.path.getsize(file_path)
    except FileNotFoundError:
        file_size = -1
        raise FileNotFoundError("File not found. Please check the path.")

    log_entry.append(f"File path: {file_path} (Size: {file_size} bytes)")

    total_time = 0.0
    payload_size = None

    for i in range(count):
        start = time.time()

        benchmark_response_timestamps: List[float] = [start]

        result = callback(
            request=request,
            path=path,
            response_timestamps=benchmark_response_timestamps,
        )

        response_timestamps.append([ts - start for ts in benchmark_response_timestamps])

        end = time.time()
        total_time += end - start
        payload_size = result.get("request_size", 0)

    average_time = total_time / count
    log_entry.append(f"Payload size: {payload_size} bytes")
    log_entry.append(f"Average execution time: {average_time:.4f} seconds\n")

    # plot_response_timestamps(response_timestamps)

    with open("benchmark.log", "a", encoding="utf-8") as f:
        f.write("\n".join(log_entry) + "\n")

    print("\n".join(log_entry))


def plot_response_timestamps(timestamps: List[List[float]]) -> None:
    timestamps = np.array(timestamps, dtype=np.float64)

    plt.figure(figsize=(10, 6))
    plt.xlabel("Request Number")
    plt.ylabel("Time since thread start (seconds)")
    plt.title("Response Timestamps per Thread")
    plt.grid()

    for i, ts in enumerate(timestamps):
        plt.plot(ts, marker=".", label=f"Benchmark {i + 1}")

    timestamps_avg = np.mean(timestamps, axis=0)
    xs = np.arange(len(timestamps_avg))
    slope, intercept = np.polyfit(xs, timestamps_avg, 1)
    print("Current slope: ", slope)

    plt.plot(timestamps_avg, marker="x", linestyle="--", label="Average benchmark")

    # Those are average slopes of the linear approximation using polyfit on GET 
    # request wih small payload size.

    # count = 5, requests_count = 1000, threads_count = 10
    multi_slope = 0.0004328727698983177
    # count = 5, requests_count = 1000, threads_count = 1

    single_slope = 0.00069040234219954
    plt.plot(xs, single_slope * xs, label="Single thread", linestyle="--")
    plt.plot(xs, multi_slope * xs, label="Multi thread", linestyle="--")

    plt.legend(title="Legend")
    plt.show()


def main():
    run_benchmark(
        callback=functools.partial(
            run_multithreaded,
            callback=send_custom,
            threads_count=1,
            requests_count=100,
            payload=build_payload(123, "test"),
        ),
        request=HttpMethod.POST,
        path="/database/tasks.json",
        count=1,
    )


if __name__ == "__main__":
    main()
