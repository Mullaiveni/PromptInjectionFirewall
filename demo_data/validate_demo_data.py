from __future__ import annotations

import json
import mimetypes
from pathlib import Path

from pif_gateway.config import Settings
from pif_gateway.detector import inspect_segments
from pif_gateway.extractors import ExtractionError, extract_segments
from pif_gateway.policy import evaluate_policy


DATA_DIRECTORY = Path(__file__).parent
MEDIA_TYPES = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".eml": "message/rfc822",
    ".json": "application/json",
    ".md": "text/markdown",
    ".py": "text/x-python",
}


def media_type_for(path: Path) -> str:
    return MEDIA_TYPES.get(path.suffix.lower()) or (
        mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    )


def validate() -> int:
    manifest = json.loads((DATA_DIRECTORY / "manifest.json").read_text("utf-8"))
    settings = Settings.from_env()
    failures: list[str] = []
    skipped: list[str] = []

    print(f"{'FILE':45} {'EXPECTED':20} {'ACTUAL':20} RESULT")
    print("-" * 98)
    for entry in manifest["generated_files"]:
        path = DATA_DIRECTORY / entry["file"]
        expected = entry["expected_action"]
        try:
            segments = extract_segments(
                path.read_bytes(),
                media_type_for(path),
                path.name,
            )
        except ExtractionError as exc:
            if entry.get("requires") == "Tesseract OCR" and "Tesseract" in str(exc):
                skipped.append(path.name)
                print(f"{path.name:45} {expected:20} {'SKIPPED':20} OCR unavailable")
                continue
            failures.append(f"{path.name}: extraction failed: {exc}")
            print(f"{path.name:45} {expected:20} {'ERROR':20} {exc}")
            continue

        findings = inspect_segments(segments, settings)
        decision = evaluate_policy(segments, findings, settings)
        actual = decision.action.value
        passed = actual == expected
        print(
            f"{path.name:45} {expected:20} {actual:20} "
            f"{'PASS' if passed else 'FAIL'}"
        )
        if not passed:
            failures.append(f"{path.name}: expected {expected}, got {actual}")

    print()
    print(
        f"Validated {len(manifest['generated_files']) - len(skipped)} files; "
        f"{len(skipped)} skipped; {len(failures)} failed."
    )
    if skipped:
        print("Skipped OCR files: " + ", ".join(skipped))
    if failures:
        print("\nFailures:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(validate())
