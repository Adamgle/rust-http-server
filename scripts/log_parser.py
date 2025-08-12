import collections
from typing import *  # type: ignore
import re
import pprint
import csv
import os

import os
import json
from datetime import datetime
from pathlib import Path


LOG_FILE: str = "./logs/logs.log"
LOG_HISTORY: str = "./logs/history_logs.json"


class LogEntry:
    # %Y-%m-%d %H:%M:%S%.3f
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

    def __init__(self, timestamp: datetime, level: str, source: str, message: str):
        self.timestamp = timestamp
        self.level = level
        self.source = source
        self.message = message

    def __hash__(self):
        return hash((self.timestamp, self.level, self.source))

    def __repr__(self):
        return f"LogEntry(timestamp={self.timestamp}, level={self.level}, source={self.source}, message={self.message})"

    @staticmethod
    def from_string(label: str, message: str) -> "LogEntry":
        # Example log entry format: [2023-03-15 12:34:56.789][INFO][source.rs] Log message

        parts = label.split(" ")
        timestamp, level, source = parts[:2], parts[2], parts[3]

        timestamp = datetime.strptime(" ".join(timestamp), LogEntry.DATE_FORMAT)

        return LogEntry(timestamp, level, source, message)


def parse_current_logs(log_file: str = LOG_FILE) -> DefaultDict[str, List[LogEntry]]:
    logs_path = Path(log_file)

    if not logs_path.exists():
        return collections.defaultdict(list)

    with logs_path.open("r", encoding="utf-8") as f:
        logs = f.read()

    if not logs:
        return collections.defaultdict(list)

    entries: List[LogEntry] = []

    lines = enumerate(logs.splitlines())
    entry: Optional[LogEntry] = None

    for idx, line in lines:
        left = line.find("[")
        right = line.find("]")

        if left != -1 and right != -1:
            label_str = line[left + 1 : right].strip()
            label_parts = label_str.split(" ")

            # Extract time, level, source from label parts
            time_part = "".join(label_parts[0:2]) if len(label_parts) >= 2 else None
            level = label_parts[2] if len(label_parts) > 2 else None
            source = label_parts[3] if len(label_parts) > 3 else None

            time_obj = None
            if time_part:
                try:
                    time_obj = datetime.strptime(time_part, LogEntry.DATE_FORMAT)
                except ValueError:
                    pass

            if (
                time_obj is not None
                and level is not None
                and source is not None
                and " " not in level
                and ".rs" in source
            ):
                try:
                    source_path = Path(source).relative_to(Path.cwd())
                except ValueError:
                    source_path = Path(source)

                source_str = str(source_path)

                # If we have a previous entry, append it to entries before starting a new one
                if entry is not None and idx > 0:
                    entries.append(entry)

                # Start new entry
                entry = LogEntry(
                    timestamp=time_obj,
                    level=level,
                    source=source_str,
                    message=line[right + 1 :].lstrip(),
                )
                continue

        # If no new entry header found, append to current entry message (multiline log)
        if entry is not None:
            # Append the entire line with a newline for readability if needed
            entry.message += "\n" + line

    # Append last buffered entry if exists
    if entry is not None:
        entries.append(entry)

    return collections.defaultdict(
        list,
        {
            datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"): entries,
        },
    )


# Parses logs from the current session and from the history
def parse_logs(
    log_file: str = LOG_FILE, log_history: str = LOG_HISTORY
) -> DefaultDict[str, List[LogEntry]]:
    current = parse_current_logs(log_file)

    with open(log_history, "r", encoding="utf-8") as f:
        history: Dict[str, Dict[str, str]] = json.load(f)

    for time, entries in history.items():
        for label, message in entries.items():
            entry = LogEntry.from_string(label, message)
            current[time].append(entry)

    return current


def get_borrowed_owned_conversions(
    logs: DefaultDict[str, List[LogEntry]],
    log_file: str = LOG_FILE,
) -> DefaultDict[str, DefaultDict[Tuple[str, str], List[str]]]:
    """
    Extract benchmarking logs for API type conversions between borrowed and owned contexts.

    This function parses logs that record Rust context type conversions for route handling.
    It focuses on conversions between `Owned` and borrowed (`'ctx`) variants, including:

    - `OwnedRouteHandlerContext` → `RouteHandlerContext<'ctx>`
    - `RouteHandlerContext<'ctx>` → `OwnedRouteHandlerContext`
    - `OwnedRouteContext` → `RouteContext<'ctx>`
    - `RouteContext<'ctx>` → `OwnedRouteContext`

    NOTE
    ----

    **The function is mostly useless and utterly insane, as any in this file.**

    """
    conversions: collections.defaultdict[
        str, collections.defaultdict[Tuple[str, str], List[str]]
    ] = collections.defaultdict(lambda: collections.defaultdict(list))

    for time, logs_data in logs.items():
        entries: collections.defaultdict[Tuple[str, str], List[str]] = (
            collections.defaultdict(list)
        )

        for log in logs_data:
            # Converted RouteContext to OwnedRouteContext took: 17 µs

            if log.level != "INFO" or "Converted" not in log.message:
                continue

            words = [
                e.strip()
                for e in log.message[log.message.index("Converted") :].split(" ")
            ]

            src = words[1]
            dst = words[3]
            duration = words[-2:]

            assert len(duration) == 2, "Duration should have two parts"
            duration = " ".join(duration)

            entries[(src, dst)].append(duration)

        conversions[time] = entries

    return conversions


if __name__ == "__main__":
    logs = parse_logs()

    conversions: collections.defaultdict[
        str, collections.defaultdict[Tuple[str, str], List[str]]
    ] = get_borrowed_owned_conversions(logs)

    maxes: DefaultDict[str, DefaultDict[Tuple[str, str], Dict[str, str]]] = (
        collections.defaultdict(lambda: collections.defaultdict(dict))
    )

    for time, conversion_data in conversions.items():
        for (src, dst), durations in conversion_data.items():
            numeric_durations = [float(d.split()[0]) for d in durations]
            if numeric_durations:
                maxes[time][(src, dst)] = {
                    "size": str(len(numeric_durations)),
                    "avg": f"{sum(numeric_durations) / len(numeric_durations):.1f}",
                    "max": str(max(numeric_durations)),
                }

    # Write to CSV spreadsheet
    csv_file = "./logs/conversions_stats.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write header
        writer.writerow(
            [
                "Time",
                "Source Type",
                "Destination Type",
                "Count",
                "Average (µs)",
                "Max (µs)",
            ]
        )

        # Write data rows
        for time, conversion_data in maxes.items():
            for (src, dst), stats in conversion_data.items():
                writer.writerow(
                    [time, src, dst, stats["size"], stats["avg"], stats["max"]]
                )

    print(f"CSV file saved to: {csv_file}")

    pprint.pprint(maxes)
