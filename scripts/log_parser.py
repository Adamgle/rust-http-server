import collections
from typing import *  # type: ignore
import pprint
import csv

import os
import json
from datetime import datetime
from pathlib import Path
import pandas as pd

LOG_FILE: str = "./logs/logs.log"
LOG_HISTORY: str = "./logs/history_logs.json"


class LogEntry:
    # %Y-%m-%d %H:%M:%S.%.3f
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

    def __init__(self, timestamp: datetime, level: str, source: str, message: str):
        self.timestamp = timestamp
        self.level = level
        self.source = source
        self.message = message

    # def __hash__(self):
    # return hash((self.timestamp, self.level, self.source))

    def __repr__(self):
        return f"LogEntry(timestamp={self.timestamp}, level={self.level}, source={self.source}, message={self.message})"

    @staticmethod
    def from_string(label: str, message: str) -> "LogEntry":
        # Example log entry format: [2023-03-15 12:34:56.789][INFO][source.rs] Log message

        parts = label.split(" ")
        timestamp, level, source = parts[:2], parts[2], parts[3]

        timestamp = datetime.strptime(" ".join(timestamp), LogEntry.DATE_FORMAT)

        return LogEntry(timestamp, level, source, message)


class Logs:
    def __init__(self):
        self.data: DefaultDict[str, List[LogEntry]] = Logs.parse_logs()

    @staticmethod
    # Parses logs already sitting in the logs.log file.
    def parse_current_logs(
        log_file: str = LOG_FILE,
    ) -> DefaultDict[str, List[LogEntry]]:
        logs_path = Path(log_file)

        if not logs_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_file}")

        with logs_path.open("r", encoding="utf-8") as f:
            logs = f.read()

        if not logs:
            print("[INFO] Log file for current session is empty")
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

                if len(label_parts) != 4:
                    if entry:
                        entry.message += "\n" + line
                    continue

                # Extract time, level, source from label parts
                time_part = " ".join(label_parts[0:2])
                level = label_parts[2]
                # Doing source = label_parts[3:] would be better to account for spaces in the file name.
                source = " ".join(label_parts[3:])

                time_obj = None

                if time_part:
                    try:
                        time_obj = datetime.strptime(time_part, LogEntry.DATE_FORMAT)
                    except ValueError:
                        if entry:
                            entry.message += "\n" + line
                        continue

                if time_obj is not None and " " not in level and ".rs" in source:
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

        if not entries:
            raise ValueError(
                "No valid log entries found, even thought the log file was not empty."
            )

        return collections.defaultdict(
            list,
            {
                datetime.now().strftime(LogEntry.DATE_FORMAT): entries,
            },
        )

    # Parses logs from the current session and from the history
    @staticmethod
    def parse_logs(
        log_file: str = LOG_FILE, log_history: str = LOG_HISTORY
    ) -> DefaultDict[str, List[LogEntry]]:
        current = Logs.parse_current_logs(log_file)

        with open(log_history, "r", encoding="utf-8") as f:
            history: Dict[str, Dict[str, str]] = json.load(f)

        for time, entries in history.items():
            for label, message in entries.items():
                entry = LogEntry.from_string(label, message)
                current[time].append(entry)

        return current

    @staticmethod
    # Takes benchmarking logs of any, uses whatever is left after the measurement as the key, hoping it is unique.
    def extract_benchmarking_logs(
        logs: DefaultDict[str, List[LogEntry]],
    ) -> DefaultDict[str, DefaultDict[str, List[str]]]:
        benchmarking_logs: DefaultDict[str, DefaultDict[str, List[str]]] = (
            collections.defaultdict(lambda: collections.defaultdict(list))
        )

        for time, entries in logs.items():
            for entry in entries:
                splitter = "took: "
                if entry.level == "INFO" and splitter in entry.message:

                    idx = entry.message.index(splitter)
                    key, measurement = (
                        entry.message[:idx].strip(),
                        entry.message[idx + (len(splitter) - 1) :].strip(),
                    )

                    if " " not in measurement:
                        # Some measurements might not be splitted with space, we will walk the string until we will fail to find a digit or "." or ","
                        for i, char in enumerate(measurement):
                            if not (char.isdigit() or char in {".", ","}):
                                measurement = measurement[:i] + " " + measurement[i:]

                                break

                    if " " not in measurement:
                        # If we still don't have a space, we will just use the whole string
                        raise ValueError(
                            "Measurement is not valid, space not found as a separator."
                        )

                    benchmarking_logs[time][key].append(measurement)

        return benchmarking_logs

    @staticmethod
    def create_benchmarking_csv(
        benchmarking_logs: DefaultDict[str, DefaultDict[str, List[str]]],
    ) -> None:
        MAX_COLS = 16384 - 2  # reserve 2 columns for "Time" and "Key"

        rows = []

        for time, entries in benchmarking_logs.items():
            for key, measurements in entries.items():
                row = [time, key] + measurements[:MAX_COLS]
                rows.append(row)

        if not rows:
            raise Exception("No rows found; possibly no benchmarking logs available.")

        # Determine column names
        max_measurements = max(len(r) - 2 for r in rows)
        col_names = ["Time", "Key"] + [
            f"Measurement {i+1}" for i in range(max_measurements)
        ]

        # Convert to DataFrame
        df1 = pd.DataFrame(rows, columns=col_names)

        summations = []

        for r in rows:
            row = [f"{r[0]} - {r[1]}"]

            assert len(r) >= 3

            # Take last measurement and extract the unit, all units are the same
            unit = r[-1].split(" ")[-1]
            values = map(
                float, (measurement.strip().split(" ")[0] for measurement in r[2:])
            )

            row.append(f"{sum(values)} {unit}")

            assert len(row) == 2, "Row should have exactly two elements"

            summations.append(row)

        # Sort alphabetically by Key
        df1 = df1.sort_values(by="Key")
        df2 = pd.DataFrame(summations, columns=["Time - Key", "Total Duration"])

        file = "./logs/benchmarking_stats.xlsx"

        with pd.ExcelWriter(file) as writer:
            df1.to_excel(writer, sheet_name="Table 1", index=False)
            df2.to_excel(writer, sheet_name="Table 2", index=False)

        print(f"Excel file saved to: {file} ")


class BorrowedOwnedConversion:
    @staticmethod
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

    @staticmethod
    def get_maxes_borrowed_owned_conversions(
        logs: DefaultDict[str, List[LogEntry]],
    ) -> DefaultDict[str, DefaultDict[Tuple[str, str], Dict[str, str]]]:
        conversions: collections.defaultdict[
            str, collections.defaultdict[Tuple[str, str], List[str]]
        ] = BorrowedOwnedConversion.get_borrowed_owned_conversions(logs)

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

        return maxes

    @staticmethod
    def create_maxes_csv(
        benchmarking_logs: DefaultDict[
            str, DefaultDict[Tuple[str, str], Dict[str, str]]
        ],
    ) -> None:
        csv_file = "./logs/structured/borrowed_owned_conversions_maxes.csv"
        os.makedirs(os.path.dirname(csv_file), exist_ok=True)

        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow(
                ["Time", "Source", "Destination", "Count", "Average", "Max"]
            )

            # Write data rows
            for time, conversion_data in benchmarking_logs.items():
                for (src, dst), stats in conversion_data.items():
                    writer.writerow(
                        [time, src, dst, stats["size"], stats["avg"], stats["max"]]
                    )

        print(f"Borrowed/Owned conversions CSV file saved to: {csv_file}")


if __name__ == "__main__":
    logs = Logs()

    maxes = BorrowedOwnedConversion.get_maxes_borrowed_owned_conversions(logs.data)
    # BorrowedOwnedConversion.create_maxes_csv(maxes)
    pprint.pprint(maxes)

    benchmarking_logs = Logs.extract_benchmarking_logs(logs.data)
    Logs.create_benchmarking_csv(benchmarking_logs)
