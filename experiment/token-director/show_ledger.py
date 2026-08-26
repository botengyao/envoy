#!/usr/bin/env python3
"""Render the Token Director's ledger as a table."""
import json
import sys

HEADER = (f"{'#':<4} {'hop':>6} {'model':<28} {'fr':<4} "
          f"{'in':>6} {'out':>6} {'total':>6} {'est':>6} {'drift':>6} "
          f"{'status':<9} {'cost($)':>9}")


def main(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        print("(ledger empty)")
        return 0

    print(HEADER)
    print("-" * len(HEADER))
    totals = {"in": 0, "out": 0, "cost": 0.0}
    for r in rows:
        drift = r["estimated_total"] - r["total_tokens"]
        print(f"{r['id']:<4} {r['hop']:>6} {r['model']:<28} "
              f"{'sse' if r['streaming'] else 'json':<4} "
              f"{r['input_tokens']:>6} {r['output_tokens']:>6} {r['total_tokens']:>6} "
              f"{r['estimated_total']:>6} {drift:>+6} "
              f"{r['extraction_status']:<9} {r['cost_usd']:>9.6f}")
        totals["in"] += r["input_tokens"]
        totals["out"] += r["output_tokens"]
        totals["cost"] += r["cost_usd"]
    print("-" * len(HEADER))
    print(f"{len(rows)} settled   input={totals['in']}  output={totals['out']}  "
          f"cost=${totals['cost']:.6f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/token-director/ledger.jsonl"))
