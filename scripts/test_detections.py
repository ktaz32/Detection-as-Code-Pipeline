import json
from datetime import datetime, timedelta
from pathlib import Path


POSITIVE_DIR = Path("tests/positive")
NEGATIVE_DIR = Path("tests/negative")


def load_json(path: Path) -> dict:
    """
    Load a JSON test file and return it as a Python dictionary.
    """
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def parse_timestamp(value):
    """
    Parse an ISO 8601 timestamp.

    Supports timestamps ending in Z by converting them to a
    UTC-aware datetime value.
    """
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError:
        return None


def matches_det_001(event: dict) -> bool:
    """
    DET-001 — Encoded PowerShell Execution

    Detects PowerShell execution using encoded-command arguments.
    """

    image = str(event.get("Image", "")).lower()
    command_line = str(event.get("CommandLine", "")).lower()

    powershell_images = (
        "\\powershell.exe",
        "\\pwsh.exe",
        "powershell.exe",
        "pwsh.exe",
    )

    encoded_indicators = (
        " -enc ",
        " -enc:",
        " -encodedcommand ",
        " -encodedcommand:",
        " /enc ",
        " /encodedcommand ",
    )

    image_match = any(
        image.endswith(executable)
        for executable in powershell_images
    )

    command_match = any(
        indicator in command_line
        for indicator in encoded_indicators
    )

    return image_match and command_match


def matches_det_002(event: dict) -> bool:
    """
    DET-002 — Suspicious PowerShell Download Cradle

    Detects PowerShell command lines containing common
    remote-content retrieval techniques.
    """

    image = str(event.get("Image", "")).lower()
    command_line = str(event.get("CommandLine", "")).lower()

    powershell_images = (
        "\\powershell.exe",
        "\\pwsh.exe",
        "powershell.exe",
        "pwsh.exe",
    )

    download_indicators = (
        "invoke-webrequest",
        "iwr ",
        "downloadstring",
        "downloadfile",
        "webclient",
        "start-bitstransfer",
        "curl ",
        "wget ",
    )

    image_match = any(
        image.endswith(executable)
        for executable in powershell_images
    )

    command_match = any(
        indicator in command_line
        for indicator in download_indicators
    )

    return image_match and command_match


def matches_det_003(data: dict) -> bool:
    """
    DET-003 — Multiple Failed Windows Logons

    Detects at least five Event ID 4625 failures against
    the same user from the same source IP within five minutes.
    """

    events = data.get("events", [])

    if not isinstance(events, list):
        return False

    failed_logons = [
        event
        for event in events
        if event.get("EventID") == 4625
    ]

    if len(failed_logons) < 5:
        return False

    grouped_events = {}

    for event in failed_logons:
        user = str(
            event.get("TargetUserName", "")
        ).strip().lower()

        source_ip = str(
            event.get("IpAddress", "")
        ).strip().lower()

        timestamp = parse_timestamp(
            event.get("TimeCreated")
        )

        if not user or not source_ip or timestamp is None:
            continue

        key = (user, source_ip)

        grouped_events.setdefault(
            key,
            [],
        ).append(timestamp)

    threshold = 5
    window = timedelta(minutes=5)

    for timestamps in grouped_events.values():

        if len(timestamps) < threshold:
            continue

        timestamps.sort()

        for start_index in range(len(timestamps)):

            count = 1

            for current_index in range(
                start_index + 1,
                len(timestamps),
            ):

                time_difference = (
                    timestamps[current_index]
                    - timestamps[start_index]
                )

                if time_difference <= window:
                    count += 1
                else:
                    break

                if count >= threshold:
                    return True

    return False


def matches_det_004(data: dict) -> bool:
    """
    DET-004 — Successful Logon After Repeated Failures

    Detects at least five failed Event ID 4625 logons
    against the same user from the same source IP within
    five minutes, followed by Event ID 4624 successful
    authentication from the same user and source.

    The successful authentication must occur after the
    failures and no more than five minutes after the first
    failure in the correlated sequence.
    """

    events = data.get("events", [])

    if not isinstance(events, list):
        return False

    grouped_events = {}

    for event in events:

        event_id = event.get("EventID")

        if event_id not in (4624, 4625):
            continue

        user = str(
            event.get("TargetUserName", "")
        ).strip().lower()

        source_ip = str(
            event.get("IpAddress", "")
        ).strip().lower()

        timestamp = parse_timestamp(
            event.get("TimeCreated")
        )

        if not user or not source_ip or timestamp is None:
            continue

        key = (user, source_ip)

        grouped_events.setdefault(
            key,
            [],
        ).append(
            {
                "event_id": event_id,
                "timestamp": timestamp,
            }
        )

    failure_threshold = 5
    correlation_window = timedelta(minutes=5)

    for event_group in grouped_events.values():

        event_group.sort(
            key=lambda item: item["timestamp"]
        )

        failures = [
            item
            for item in event_group
            if item["event_id"] == 4625
        ]

        successes = [
            item
            for item in event_group
            if item["event_id"] == 4624
        ]

        if len(failures) < failure_threshold:
            continue

        if not successes:
            continue

        for start_index in range(len(failures)):

            correlated_failures = []

            first_failure_time = failures[
                start_index
            ]["timestamp"]

            for current_index in range(
                start_index,
                len(failures),
            ):

                current_failure = failures[
                    current_index
                ]

                time_difference = (
                    current_failure["timestamp"]
                    - first_failure_time
                )

                if time_difference <= correlation_window:
                    correlated_failures.append(
                        current_failure
                    )
                else:
                    break

            if (
                len(correlated_failures)
                < failure_threshold
            ):
                continue

            last_failure_time = (
                correlated_failures[-1][
                    "timestamp"
                ]
            )

            for success in successes:

                success_time = success[
                    "timestamp"
                ]

                success_after_failures = (
                    success_time
                    > last_failure_time
                )

                success_within_window = (
                    success_time
                    - first_failure_time
                    <= correlation_window
                )

                if (
                    success_after_failures
                    and success_within_window
                ):
                    return True

    return False


DETECTIONS = {
    "DET-001": matches_det_001,
    "DET-002": matches_det_002,
    "DET-003": matches_det_003,
    "DET-004": matches_det_004,
}


def run_tests():
    """
    Run all positive and negative detection tests.

    Positive tests must match.
    Negative tests must not match.
    """

    failures = 0
    tests_run = 0

    print()
    print("=" * 60)
    print("Detection-as-Code Test Suite")
    print("=" * 60)
    print()

    for detection_id, matcher in DETECTIONS.items():

        print("-" * 60)
        print(detection_id)
        print("-" * 60)

        positive_files = sorted(
            POSITIVE_DIR.glob(
                f"{detection_id}*.json"
            )
        )

        negative_files = sorted(
            NEGATIVE_DIR.glob(
                f"{detection_id}*.json"
            )
        )

        if not positive_files:
            print(
                f"[FAIL] No positive test files found for "
                f"{detection_id}"
            )
            failures += 1

        if not negative_files:
            print(
                f"[FAIL] No negative test files found for "
                f"{detection_id}"
            )
            failures += 1

        for path in positive_files:

            tests_run += 1

            try:
                test_data = load_json(path)
                result = matcher(test_data)

            except Exception as error:
                print(
                    f"[FAIL] Positive test error: "
                    f"{path}"
                )
                print(
                    f"       {error}"
                )
                failures += 1
                continue

            if result:
                print(
                    f"[PASS] Positive test matched: "
                    f"{path}"
                )
            else:
                print(
                    f"[FAIL] Positive test did not match: "
                    f"{path}"
                )
                failures += 1

        for path in negative_files:

            tests_run += 1

            try:
                test_data = load_json(path)
                result = matcher(test_data)

            except Exception as error:
                print(
                    f"[FAIL] Negative test error: "
                    f"{path}"
                )
                print(
                    f"       {error}"
                )
                failures += 1
                continue

            if not result:
                print(
                    f"[PASS] Negative test did not match: "
                    f"{path}"
                )
            else:
                print(
                    f"[FAIL] Negative test incorrectly matched: "
                    f"{path}"
                )
                failures += 1

        print()

    print("=" * 60)
    print("Test Summary")
    print("=" * 60)

    print(f"Tests run: {tests_run}")
    print(f"Failures:  {failures}")

    if failures:
        print()
        print(
            f"FAILED: {failures} test(s) failed."
        )
        raise SystemExit(1)

    print()
    print(
        "SUCCESS: All detection tests passed."
    )


if __name__ == "__main__":
    run_tests()