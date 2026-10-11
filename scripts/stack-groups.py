#!/usr/bin/env python3
"""stack-groups.py -- normalise call stacks and group the ones that recur.

A backtrace is the cheapest runtime evidence there is: it turns "this event
happened" into "these functions ran to produce it". Grouping backtraces is
how a hot path and a rare path separate, and how two observations are shown to
have gone through the same code.

With symbols stripped, the honest form is `module+0xoffset`. That is not a
deficiency to work around -- it is what the evidence supports, and a name
invented from proximity to a string is worse than no name.

Input is one stack per line, frames separated by ';', or a JSON array of
arrays. Both formats appear in real traces.

  stack-groups.py stacks.txt
  stack-groups.py stacks.txt --top 15 --detail
  stack-groups.py stacks.txt --map-file maps.txt --resolve
  stack-groups.py good.txt bad.txt --compare

Examples
--------
  gdb -p PID -batch -ex 'thread apply all bt' 2>/dev/null | stack-groups.py -
  stack-groups.py stacks.json --json
  stack-groups.py before.txt after.txt --compare --first-divergence
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _runtimelib as R  # noqa: E402


def load_stacks(path: str) -> tuple:
    """Read stacks from a file: JSON arrays, or one stack per line."""
    try:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path, "r", errors="replace") as fh:
                text = fh.read()
    except OSError as e:
        return None, [f"cannot read {path}: {e}"]

    if not text.strip():
        return None, [f"{path} is empty; there are no stacks to group"]

    stripped = text.strip()
    if stripped[0] in "[{":
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError as e:
            return None, [f"{path} looks like JSON but does not parse: {e}"]
        stacks = []
        for item in (doc if isinstance(doc, list) else doc.get("stacks", [])):
            if isinstance(item, list):
                stacks.append([f if isinstance(f, str) else str(f)
                               for f in item])
            elif isinstance(item, dict):
                frames = item.get("frames")
                if isinstance(frames, list):
                    stacks.append([f if isinstance(f, str) else
                                   f.get("address", str(f)) for f in frames])
            elif isinstance(item, str):
                stacks.append([f for f in item.split(";")])
        if stacks:
            return stacks, []
        return None, [f"{path} contains no usable stacks"]

    # Two shapes arrive here. A ';' separated line is one stack. A gdb
    # backtrace is several lines, and its stack ends at the frame index
    # restarting at #0 -- which is also what makes a blank-line separator
    # unnecessary and the frame index the reliable boundary.
    stacks: list = []
    current: list = []
    saw_frame_index = False
    for line in stripped.splitlines():
        s = line.strip()
        if not s:
            if current:
                stacks.append(current)
                current = []
            continue
        indexed = bool(re.match(r"^#\d+\s", s))
        if s.startswith("#") and not indexed:
            continue
        if indexed:
            saw_frame_index = True
            if re.match(r"^#0\b", s) and current:
                stacks.append(current)
                current = []
        if ";" in s and not indexed:
            # A ';' separated line is a whole stack by itself.
            if current:
                stacks.append(current)
                current = []
            stacks.append([f.strip() for f in s.split(";") if f.strip()])
            continue
        current.append(s)
    if current:
        stacks.append(current)
    if not stacks and saw_frame_index:
        return None, [f"{path} looks like a backtrace but produced no frames"]
    return stacks, []


def render_groups(g: dict, args) -> str:
    L = ["=" * 78, "CALL STACK GROUPS", "=" * 78]
    L.append(f"stacks read  : {g['total_stacks']}")
    L.append(f"distinct     : {g['distinct_stacks']}")
    L.append(f"comparison   : {g.get('comparison')}")
    L.append("")
    L.append(f"{'count':>6} {'freq':>7}  {'label':<22} leaf")
    for grp in g["groups"][:args.top]:
        L.append(f"{grp['count']:>6} {grp['frequency']:>6.1%}  "
                 f"{grp['label']:<22} {grp['leaf']}")
        if args.detail:
            for i, f in enumerate(grp["frames"][:args.detail]):
                L.append(f"{'':>6} {'':>7}    [{i}] {f}")
            if grp.get("modules"):
                L.append(f"{'':>6} {'':>7}    modules: "
                         f"{', '.join(grp['modules'])}")
    L.append("")
    L.append(f"note: {g['note']}")
    return "\n".join(L)


def render_compare(c: dict) -> str:
    L = ["=" * 78, "STACK COMPARISON", "=" * 78]
    L.append(f"group A : {c['a_total']} stacks, {c['a_groups']} distinct")
    L.append(f"group B : {c['b_total']} stacks, {c['b_groups']} distinct")
    L.append("")
    if c["only_in_a"]:
        L.append(f"only in A ({len(c['only_in_a'])}):")
        for k in c["only_in_a"][:args_limit(c)]:
            L.append(f"  - {k[:110]}")
        L.append("")
    if c["only_in_b"]:
        L.append(f"only in B ({len(c['only_in_b'])}):")
        for k in c["only_in_b"][:args_limit(c)]:
            L.append(f"  + {k[:110]}")
        L.append("")
    if not c["only_in_a"] and not c["only_in_b"]:
        L.append("the same set of stacks appears in both.")
        L.append("")
    L.append("frequency differences on shared stacks:")
    L.append(f"{'count A':>8} {'count B':>8}  stack")
    for row in c["frequency_differences"][:args_limit(c)]:
        L.append(f"{row['count_a']:>8} {row['count_b']:>8}  {row['key'][:88]}")
    L.append("")
    L.append(f"note: {c['note']}")
    return "\n".join(L)


def args_limit(c: dict) -> int:
    return c.get("limit", 15)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Normalise and group call stacks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("stacks", nargs="?",
                   help="stacks file ('-' for stdin)")
    p.add_argument("--compare", metavar="OTHER", default=None,
                   help="compare against a second stacks file")
    p.add_argument("--map-file", default=None,
                   help="a saved maps file, so --resolve can resolve frames")
    p.add_argument("--resolve", action="store_true",
                   help="resolve frame addresses through the memory map")
    p.add_argument("--top", type=int, default=15,
                   help="groups to show (default 15)")
    p.add_argument("--detail", type=int, default=0,
                   help="print this many frames per group")
    p.add_argument("--limit", type=int, default=15,
                   help="max rows in a comparison (default 15)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if not args.stacks and not args.compare:
        p.error("give a stacks file, or --compare with two files")
    if not args.stacks and args.compare:
        args.stacks = args.compare

    resolver = None
    if args.map_file:
        try:
            with open(args.map_file, "r", errors="replace") as fh:
                regions = R.classify_regions(R.parse_maps(fh.read()))
            resolver = R.Resolver(regions)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    stacks, problems = load_stacks(args.stacks)
    if stacks is None:
        for p_ in problems:
            print(f"error: {p_}", file=sys.stderr)
        return 2

    # Group each raw stack into its frame dicts first.
    parsed = [R.parse_stack("; ".join(s) if isinstance(s, list) else s)
              for s in stacks]
    parsed = [p_ for p_ in parsed if p_]

    groups = R.group_stacks(parsed, limit=args.top,
                            resolver=resolver if args.resolve else None)

    out = {"source": args.stacks, "problems": problems, **groups}

    if args.compare:
        other, oproblems = load_stacks(args.compare)
        if other is None:
            print(f"error: {'; '.join(oproblems)}", file=sys.stderr)
            return 2
        oparsed = [R.parse_stack("; ".join(s) if isinstance(s, list) else s)
                   for s in other]
        oparsed = [p_ for p_ in oparsed if p_]
        bgroups = R.group_stacks(oparsed, limit=10_000,
                                 resolver=resolver if args.resolve else None)
        akeys = {g["key"] for g in R.group_stacks(
            parsed, limit=10_000,
            resolver=resolver if args.resolve else None)["groups"]}
        bkeys = {g["key"] for g in bgroups["groups"]}
        acounts = {g["key"]: g["count"] for g in R.group_stacks(
            parsed, limit=10_000,
            resolver=resolver if args.resolve else None)["groups"]}
        bcounts = {g["key"]: g["count"] for g in bgroups["groups"]}

        freq = []
        for k in sorted(set(akeys) & set(bkeys)):
            if acounts[k] != bcounts[k]:
                freq.append({"key": k, "count_a": acounts[k],
                             "count_b": bcounts[k],
                             "delta": bcounts[k] - acounts[k]})
        freq.sort(key=lambda r: -abs(r["delta"]))

        out["comparison"] = {
            "a_total": len(parsed), "a_groups": len(akeys),
            "b_total": len(oparsed), "b_groups": len(bkeys),
            "only_in_a": sorted(akeys - bkeys),
            "only_in_b": sorted(bkeys - akeys),
            "frequency_differences": freq,
            "limit": args.limit,
            "note": "a stack present in one run and absent in the other is a "
                    "stronger finding than a frequency difference, which may "
                    "only reflect a different number of samples",
        }

    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    if "comparison" in out:
        print(render_compare(out["comparison"]))
        print()
    print(render_groups(out, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())