"""Generates the synchronous client from the asynchronous one.

Usage: python scripts/unasync.py [--check]

With --check, nothing is written and the exit code is 1 if the synchronous client is out of date.
"""

import re
import subprocess
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "pyfederation"
SOURCE = PACKAGE / "async_client.py"
TARGET = PACKAGE / "client.py"

HEADER = "# Generated from async_client.py by scripts/unasync.py, do not edit.\n"

SUBSTITUTIONS = [
    (r"\basync def\b", "def"),
    (r"\basync with\b", "with"),
    (r"\basync for\b", "for"),
    (r"\bawait ", ""),
    (r"\bAsync(?=[A-Z])", ""),
    (r"\bAsynchronous\b", "Synchronous"),
    (r"\baclose\b", "close"),
    (r"\baread\b", "read"),
    (r"\baiter_bytes\b", "iter_bytes"),
    (r"\b__aenter__\b", "__enter__"),
    (r"\b__aexit__\b", "__exit__"),
]


def generate() -> str:
    code = SOURCE.read_text(encoding="utf-8")
    for pattern, replacement in SUBSTITUTIONS:
        code = re.sub(pattern, replacement, code)

    formatted = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--stdin-filename", str(TARGET), "-"],
        input=HEADER + code,
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
    )
    return formatted.stdout


def main() -> int:
    code = generate()

    if "--check" in sys.argv[1:]:
        if TARGET.read_text(encoding="utf-8") != code:
            print(f"{TARGET.name} is out of date, run scripts/unasync.py", file=sys.stderr)
            return 1
        return 0

    TARGET.write_text(code, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
