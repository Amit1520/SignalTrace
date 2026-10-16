"""
Run this from your project root (same place you run uvicorn from):

    python diagnose_timezone.py

It imports your ACTUAL installed backend.shared.humanize module -- not a
copy, not a test -- and calls it directly with the exact kind of value
backend/incidents/correlator.py passes it (a naive datetime, representing
UTC, matching your real incident: ~11:47 UTC = ~5:17 PM IST).

This isolates two possibilities:
  - If this prints "around 11 AM"  -> the deployed code itself is still
    wrong (old file, or the fix didn't apply as expected). Send me the
    output and I'll look at the actual file on disk.
  - If this prints "around 5 PM"   -> the code is correct. The incidents
    you're checking in the UI were correlated BEFORE this fix was loaded,
    and their Chronology text is permanently frozen from that moment --
    nothing further to fix in the code; you need a genuinely new incident,
    correlated after this script confirms the code is right.
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from backend.shared.humanize import format_hour_from_timestamp
except ImportError as error:
    print(f"COULD NOT IMPORT backend.shared.humanize: {error}")
    print("Check that backend/shared/__init__.py and backend/shared/humanize.py both exist.")
    sys.exit(1)

print("Imported from:", format_hour_from_timestamp.__module__)
import backend.shared.humanize as humanize_module
print("File on disk:", humanize_module.__file__)
print()

# The exact case correlator.py hits: a naive datetime (no tzinfo at all),
# representing 11:47 UTC -- which is 5:17 PM IST.
naive_utc_timestamp = datetime(2026, 10, 1, 11, 47, 0)

result = format_hour_from_timestamp(naive_utc_timestamp)
print(f"Input:  naive datetime {naive_utc_timestamp} (represents 11:47 UTC / 5:17 PM IST)")
print(f"Output: {result}")
print()

if result == "around 5 PM":
    print("CORRECT. The deployed code handles this case properly.")
    print("Any incident still showing the wrong hour was correlated BEFORE")
    print("this fix was loaded into a running server process.")
elif result == "around 11 AM":
    print("STILL WRONG. The deployed humanize.py does not have the naive-datetime fix.")
    print("Check the file path printed above -- is it the file you think it is?")
else:
    print(f"UNEXPECTED RESULT: {result!r}")
    print("Paste this whole output back for diagnosis.")