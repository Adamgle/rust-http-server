import collections
from typing import *  # type: ignore
import re
import pprint
import csv
import os
import datetime

LOG_FILE: str = "./logs/logs.log"
LOG_HISTORY: str = "./logs/history_logs.json"


# Parses logs from the current session and from the history
def parse_logs(
    log_file: str = LOG_FILE, log_history: str = LOG_HISTORY
) -> Dict[datetime.datetime, Dict[datetime.datetime, str]]:
    entries: Dict[datetime.datetime, Dict[datetime.datetime, str]] = (
        collections.defaultdict(dict)
    )

    return entries


def get_borrowed_owned_conversions(
    log_file: str = LOG_FILE,
) -> DefaultDict[Tuple[str, str], List[str]]:
    """
    Extract benchmarking logs for API type conversions between borrowed and owned contexts.

    This function parses logs that record Rust context type conversions for route handling.
    It focuses on conversions between `Owned` and borrowed (`'ctx`) variants, including:

    - `OwnedRouteHandlerContext` → `RouteHandlerContext<'ctx>`
    - `RouteHandlerContext<'ctx>` → `OwnedRouteHandlerContext`
    - `OwnedRouteContext` → `RouteContext<'ctx>`
    - `RouteContext<'ctx>` → `OwnedRouteContext`

    Returns
    -------
    list
        A list of parsed conversion records, each representing one logged conversion event.

    NOTE
    ----

    **The function is mostly useless, as any in this file.**

    """

    with open(log_file, "r", encoding="utf-8") as f:
        lines = [
            line.strip()
            for line in f.readlines()
            if "INFO" in line and "Converted" in line
        ]

    conversions = collections.defaultdict(list)

    for line in lines:
        # Converted RouteContext to OwnedRouteContext took: 17 µs

        words = line[line.index("Converted") :].split(" ")
        src = words[1]
        dst = words[3]
        duration = words[-2:]
        conversions[(src, dst)].append(duration)

    # Create CSV files for each conversion type

    # Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    # Write individual CSV files for each conversion type

    for (src, dst), durations in conversions.items():
        filename = f"output/{src}_to_{dst}_conversions.csv"
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Duration", "Unit"])
            for duration in durations:
                writer.writerow([duration[0], duration[1]])

    # Write summary CSV with all conversions
    with open(
        "output/conversion_summary.csv", "w", newline="", encoding="utf-8"
    ) as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Source", "Destination", "Count", "Avg_Duration", "Unit"])
        for (src, dst), durations in conversions.items():
            count = len(durations)
            if count > 0:
                # Assuming all durations have same unit for averaging
                avg_duration = sum(float(d[0]) for d in durations) / count
                unit = durations[0][1] if durations else ""
                writer.writerow([src, dst, count, f"{avg_duration:.2f}", unit])

    return conversions


if __name__ == "__main__":
    conversions = get_borrowed_owned_conversions()

    maxes = {
        key: {
            "size": len(data),
            "max": f"{sum(data) / len(data):.1f}",
            "count": max(data),
        }
        for key, data in [
            (key, [float(d[0]) for d in data]) for key, data in conversions.items()
        ]
    }

    pprint.pprint(maxes)
