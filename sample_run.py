#!/usr/bin/env python3
"""CLI sample run — writes JSON/CSV under sample_output/."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app import FINDING_CSV_FIELDS, make_csv_writer, run_scan, sanitize_csv_cell

OUT = Path(__file__).resolve().parent / "sample_output"


def main() -> None:
    p = argparse.ArgumentParser(description="Domain & Brand Alert sample run")
    p.add_argument("--brand", default="Northwind Bakery")
    p.add_argument("--domain", default="northwind-bakery.test")
    p.add_argument("--mode", choices=("auto", "live", "demo"), default="auto")
    p.add_argument("--lookalike-limit", type=int, default=40)
    args = p.parse_args()

    result = run_scan(args.brand, args.domain, mode=args.mode, lookalike_limit=args.lookalike_limit)
    OUT.mkdir(parents=True, exist_ok=True)

    json_path = OUT / "last_scan.json"
    csv_path = OUT / "last_scan.csv"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        fields = FINDING_CSV_FIELDS
        w = make_csv_writer(fh, fieldnames=fields)
        w.writeheader()
        for f in result.get("findings") or []:
            w.writerow({k: sanitize_csv_cell(f.get(k, "")) for k in fields})

    counts = result.get("counts") or {}
    print(f"Mode: {result.get('mode')}")
    print(f"Domain: {result.get('domain')} | Brand: {result.get('brand')}")
    print(f"Findings: total={counts.get('total')} high={counts.get('high')} warn={counts.get('warn')} info={counts.get('info')}")
    for n in result.get("notes") or []:
        print(f"Note: {n}")
    print(f"Wrote {json_path}")
    print(f"Wrote {csv_path}")


if __name__ == "__main__":
    main()
