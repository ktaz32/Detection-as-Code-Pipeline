# Detection Test Fixtures

The test suite uses synthetic JSON telemetry to verify expected detection behavior.

## Positive fixtures

Files in `positive/` represent telemetry that **must trigger** the corresponding detection.

## Negative fixtures

Files in `negative/` represent benign or non-matching telemetry that **must not trigger** the corresponding detection.

Each detection ID must have at least one positive and one negative fixture. `scripts/test_detections.py` fails the CI run when required fixtures are missing.

Current coverage: **10 positive + 10 negative = 20 behavioral tests**.

Run locally with:

```bash
python scripts/test_detections.py
```
