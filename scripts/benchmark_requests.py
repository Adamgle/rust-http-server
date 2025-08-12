# Code in this file is a shenanigans, foolishness.

import collections
import functools
import json
import os
import pprint
import re
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, TypedDict, Any
from enum import Enum
import typing
import matplotlib.pyplot as plt
import numpy as np
import requests
import random
import secrets
import uuid

from urllib.parse import quote

URL_BASE = "http://localhost:5000/"
DEFAULT_PORT = 5000
NOTE_FILE_PATH = "./public/note.txt"


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


def build_task(value: str) -> str:
    return json.dumps({"value": value})


def test_post(path: str, payload: str) -> int:
    response = requests.post(URL_BASE + path, json={"value": payload, "id": 123})
    return response.status_code


def test_get(path: str) -> int:
    response = requests.get(URL_BASE + path)
    return response.status_code


SendCustomCallable = Callable[..., SendResult]


def send_custom(
    request: HttpMethod = HttpMethod.GET,
    path: str = "/",
    payload: Optional[str] = None,
    host: str = "localhost",
    inject_size: int = 1,
    sessionId: str = "",
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
                f"{f'Cookie: sessionId={sessionId}\r\n' if sessionId else ''}"
                f"Host: {host}:{DEFAULT_PORT}\r\n"
                "X-Custom-Header: valid-value\r\n"
                f"Injected-Header{injected_header}: {injected_header}\r\n\r\n"
                f"{payload if payload else ''}"
            )
        case HttpMethod.GET:
            headers = (
                f"GET {path} HTTP/1.1\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                f"{f'Cookie: sessionId={sessionId}\r\n' if sessionId else ''}"
                f"Host: {host}:{DEFAULT_PORT}\r\n"
                "X-Custom-Header: valid-value\r\n"
                f"Injected-Header: {injected_header}\r\n\r\n"
            )
        case _:
            headers = (
                f"{request.value} {path} HTTP/1.1\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                f"Host: {host}:{DEFAULT_PORT}\r\n"
                f"{f'Cookie: sessionId={sessionId}\r\n' if sessionId else ''}"
                "X-Custom-Header: valid-value\r\n"
                f"Injected-Header: {injected_header}\r\n\r\n"
                f"{payload if payload else ''}"
            )

    def create_socket(message: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((host, DEFAULT_PORT))
                s.sendall(message.encode())

                response = []

                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break

                    response.extend(chunk)

                # , errors='ignore'
                return bytes(response).decode("utf-8")
            except OSError as e:
                print(f"Socket error: {e}")
                return "500"

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
    plot_results: bool = True,
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
        plot_results (bool, optional): Whether to plot response timestamps. Defaults to True.
        **kwargs (Any): Additional keyword arguments to pass to the callback function.
    Returns:
        dict[str, Any]: A dictionary containing:
            - "results": List of boolean status results from all requests.
            - "request_size": The payload size from the first callback result.
            - "response_timestamps": List of timestamp lists for each thread.
    Notes:
        - The function prints the number of failures after each thread completes.
        - The "request_size" is determined from the first callback invocation.
    """

    if requests_count % threads_count != 0:
        raise ValueError("requests_count must be divisible by threads_count.")

    results: list[bool] = []
    request_size: int = 0
    thread_list = []
    all_response_timestamps: List[List[float]] = []
    start_time = time.time()

    def worker() -> None:
        nonlocal request_size, start_time

        thread_results: list[bool] = []
        thread_timestamps: List[float] = [start_time]

        for _ in range(requests_count // threads_count):
            # Add response_timestamps to kwargs for this thread
            # kwargs_with_timestamps = kwargs.copy()
            kwargs["response_timestamps"] = thread_timestamps

            result = callback(**kwargs)

            if request_size == 0:
                request_size = result["payload_size"]

            thread_results.append(result["status"])

        # Convert absolute timestamps to relative timestamps from start
        relative_timestamps = [ts - start_time for ts in thread_timestamps]
        all_response_timestamps.append(relative_timestamps)
        results.extend(thread_results)

    for i in range(threads_count):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
        thread.start()

    for idx, thread in enumerate(thread_list):
        thread.join()
        print(f"Thread {idx} done. Failures: {results.count(False)}")

    # Plot results if requested
    if plot_results:
        plot_response_timestamps(all_response_timestamps)

    return {
        "results": results,
        "request_size": request_size,
        "response_timestamps": all_response_timestamps,
    }


def run_benchmark(
    callback: SendCustomCallable,
    count: int = 1,
    request: HttpMethod = HttpMethod.GET,
    path: str = "/",
    response_timestamps: List[List[float]] = [],
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
    callback_args = callback.keywords  # type: ignore

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
        # raise FileNotFoundError("File not found. Please check the path.")

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

    plot_response_timestamps(response_timestamps)

    with open("benchmarks/benchmark.log", "a", encoding="utf-8") as f:
        f.write("\n".join(log_entry) + "\n")

    print("\n".join(log_entry))


# TODO: This could happen on DatabaseWAL execution, or other side effects that will trigger substantial difference
# between the adjacent requests in time. Defaults to 10ms, which is 0.01 seconds, anything exceeding 10ms would be considered a performance loss.
def determine_performance_loss(
    # timestamps: List[float],
    timestamps: List[List[float]],
    threshold: float = 0.01,
) -> Dict[int, List[float]]:
    benchmarks = dict()

    for idx, ts in enumerate(timestamps):
        # Results that outperform the threshold
        benchmarks[idx + 1] = [
            (i + 1, ts[i + 1] - ts[i])
            for i in range(len(ts) - 1)
            if ts[i + 1] - ts[i] > threshold
        ]

    return benchmarks


def plot_response_timestamps(timestamps: List[List[float]]) -> None:
    timestamps_array = np.array(timestamps, dtype=np.float64)

    plt.figure(figsize=(10, 6))
    plt.xlabel("Request Number")
    plt.ylabel("Time since thread start (seconds)")
    plt.title("Response Timestamps per Thread")
    plt.grid()

    # for i, ts in enumerate(timestamps):
    #     plt.plot(ts, marker=".", label=f"Thread {i + 1}")

    timestamps_avg = np.mean(timestamps_array, axis=0)
    xs = np.arange(len(timestamps_avg))

    # slope, intercept = np.polyfit(xs, timestamps_avg, deg=1)
    a, b, c = np.polyfit(xs, timestamps_avg, deg=2)

    # print("Current slope: ", slope)
    print("Polynomial x^2 coefficients: ", a, b, c)

    print(f"Average timestamps: {timestamps_avg} | timestamps: {timestamps}")

    plt.plot(timestamps_avg, marker="x", linestyle="--", label="Average benchmark")

    # Those are average slopes of the linear approximation using polyfit on GET
    # request wih small payload size.

    # count = 5, requests_count = 1000, threads_count = 10
    multi_slope = 0.0004328727698983177

    # count = 5, requests_count = 1000, threads_count = 1
    single_slope = 0.00069040234219954

    # 2 * 7.064454015189068e-08 => slope of the polynomial approximation at some x
    # count = 1, threads_count = 10, requests_count = 10000, empty db
    quadratic_approx = (
        7.064454015189068e-08 * xs**2
        + 0.00035391819927912033 * xs
        + 0.07135582499828524
    )

    current_fit = a * xs**2 + b * xs + c

    plt.plot(xs, single_slope * xs, label="Single thread", linestyle="--")
    plt.plot(xs, multi_slope * xs, label="Multi thread", linestyle="--")
    # plt.plot(xs, slope * xs, label="Current slope (linear fit)", linestyle="--")
    plt.plot(xs, quadratic_approx, label="Multi threaded quadratic fit", linestyle="--")
    plt.plot(
        xs,
        current_fit,
        label="Current fit (quadratic approximation)",
        linestyle="--",
    )

    plt.legend(title="Legend")

    pprint.pprint(determine_performance_loss(timestamps))

    plt.show()


def main():
    run_multithreaded(
        callback=send_custom,
        path="/database/tasks.json",
        payload=build_task("a" * (1024 * 1024)),
        sessionId="b9b88ce5-7027-4d64-b6f3-f3b6aeb980b3",
        threads_count=10,
        requests_count=100
    )
    
    # send_custom(
    #     request=HttpMethod.POST,
    #     path="/database/tasks.json",
    #     payload=build_task("a" * (1024 * 1024 * 24)),
    #     sessionId="b9b88ce5-7027-4d64-b6f3-f3b6aeb980b3",
    # )


if __name__ == "__main__":
    main()
