import json
from pathlib import Path

POSITIVE_DIR = Path("tests/positive")
NEGATIVE_DIR = Path("tests/negative")


def matches_det_001(event: dict) -> bool:
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

    image_match = any(image.endswith(x) for x in powershell_images)
    command_match = any(x in command_line for x in encoded_indicators)

    return image_match and command_match


def matches_det_002(event: dict) -> bool:
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

    image_match = any(image.endswith(x) for x in powershell_images)
    command_match = any(x in command_line for x in download_indicators)

    return image_match and command_match


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def run_tests():
    failures = 0

    print("\nDET-001 — Encoded PowerShell Detection Tests\n")

    for path in sorted(POSITIVE_DIR.glob("DET-001*.json")):
        event = load_json(path)
        result = matches_det_001(event)

        if result:
            print(f"[PASS] Positive test matched: {path}")
        else:
            print(f"[FAIL] Positive test did not match: {path}")
            failures += 1

    for path in sorted(NEGATIVE_DIR.glob("DET-001*.json")):
        event = load_json(path)
        result = matches_det_001(event)

        if not result:
            print(f"[PASS] Negative test did not match: {path}")
        else:
            print(f"[FAIL] Negative test incorrectly matched: {path}")
            failures += 1

    print()

    if failures:
        print(f"FAILED: {failures} test(s)")
        raise SystemExit(1)

    print("SUCCESS: All DET-001 tests passed.")


if __name__ == "__main__":
    run_tests()