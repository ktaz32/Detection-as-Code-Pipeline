from pathlib import Path
import sys
import yaml

DETECTION_DIR = Path("detections")

REQUIRED_FIELDS = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "level",
}


def validate_rule(path: Path) -> list[str]:
    errors = []

    try:
        with path.open("r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
    except Exception as exc:
        return [f"YAML parse error: {exc}"]

    if not isinstance(rule, dict):
        return ["Rule must contain a YAML mapping/object"]

    missing = REQUIRED_FIELDS - rule.keys()

    if missing:
        errors.append(
            f"Missing required field(s): {', '.join(sorted(missing))}"
        )

    logsource = rule.get("logsource")
    if not isinstance(logsource, dict):
        errors.append("logsource must be a mapping")

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append("detection must be a mapping")
    elif "condition" not in detection:
        errors.append("detection.condition is missing")

    tags = rule.get("tags", [])
    if tags and not isinstance(tags, list):
        errors.append("tags must be a list")

    return errors


def main():
    rule_files = sorted(DETECTION_DIR.rglob("*.yml"))

    if not rule_files:
        print("[FAIL] No Sigma rules found")
        sys.exit(1)

    failures = 0

    print("\nSigma Rule Validation\n")

    for path in rule_files:
        errors = validate_rule(path)

        if errors:
            failures += 1
            print(f"[FAIL] {path}")

            for error in errors:
                print(f"       - {error}")

        else:
            print(f"[PASS] {path}")

    print()

    if failures:
        print(f"FAILED: {failures} Sigma rule(s) invalid")
        sys.exit(1)

    print(f"SUCCESS: {len(rule_files)} Sigma rule(s) validated.")


if __name__ == "__main__":
    main()