#!/usr/bin/env python3
"""
Repairs the security_headers_scanner ID-float bug (see score_analyzer.py
_load_results_as_dataframe, fixed to cast Id/ID/ETER_ID to str before concat).

Poland's headers results carry a purely-numeric "Id" column. Every other
country uses an alphanumeric "ETER_ID" instead, so once every country's
per-file DataFrame was concatenated into one, pandas back-filled the missing
"Id" for non-Polish rows with NaN — which silently promotes the WHOLE "Id"
column to float64, turning e.g. "120" into "120.0" for every single Polish
institution (not just ones with genuinely missing data). That string then
got copied verbatim into ETER_ID, breaking the dashboard's by-ID merge
against every other scanner's clean integer IDs for Poland.

Purely cosmetic/format corruption — no data loss, no rescan needed. This
strips the spurious ".0" suffix from purely-numeric ID/ETER_ID/Id values.

Usage:
    python scripts/repair_headers_id_float.py <file1.csv> [file2.csv ...]
"""
import csv
import re
import sys
from pathlib import Path

ID_COLS = ("ETER_ID", "ID", "Id")
_FLOAT_INT_RE = re.compile(r"^\d+\.0$")


def repair_file(path):
    path = Path(path)
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    fixed = 0
    for row in rows:
        for col in ID_COLS:
            v = row.get(col)
            if v and _FLOAT_INT_RE.match(v.strip()):
                row[col] = v.strip()[:-2]
                fixed += 1

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return {"path": str(path), "total_rows": len(rows), "values_fixed": fixed}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for arg in sys.argv[1:]:
        result = repair_file(arg)
        print(f"{result['path']}: total_rows={result['total_rows']} values_fixed={result['values_fixed']}")
