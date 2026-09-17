import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pkx.compiler import table


def fmt(flows):
    return "; ".join(("->" if s == "I" else "<-") + " " + ",".join(t) if t else ("->" if s == "I" else "<-") + " _" for s, t in flows)


def main():
    total = 0
    rows = table()
    for row in rows:
        assert row["full_inclusion"], row["dh"]
        assert row["compact_inclusion"], row["dh"]
        assert row["kem_flows"] == row["lower_bound"], row["dh"]
        total += row["assignments"]
        print(f"{row['dh']:6s} dh_flows={row['dh_flows']} comps={','.join(row['components']):12s} kem_flows={row['kem_flows']} lower_bound={row['lower_bound']} target={row['target_flows']} | {fmt(row['compiled'])}")
    print(f"predicate inclusion verified for {len(rows)} patterns, both roles, {total} assignments per mode")


if __name__ == "__main__":
    main()
