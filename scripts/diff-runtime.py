#!/usr/bin/env python3
"""diff-runtime.py -- compare two runtime traces and locate the first divergence.

Two runs of the same input rarely produce identical event streams. The
question is where they first differ, because everything after that point may
be a consequence of one earlier difference.

  normal vs modified      what a patch changed
  working vs crashing      where the crash begins
  old version vs new       which event moved first
  feature off vs on        what the feature actually does
  input A vs input B       what a control is sensitive to

Timestamps are excluded from comparison by default. Two runs of the same input
do not align on wall-clock time, so including them would report a divergence
at the first event every time and tell you nothing.

  diff-runtime.py baseline.json modified.json
  diff-runtime.py working.json crashing.json --detail
  diff-runtime.py v1.json v2.json --keys type,address,caller
  diff-runtime.py a.json b.json --json

Examples
--------
  diff-runtime.py baseline.json patched.json --detail
  diff-runtime.py ok.json crash.json --keys type,address --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _runtimelib as R  # noqa: E402


def load(path: str):
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return None, [f"cannot read {path}: {e}"]
    if not text.strip():
        return None, [f"{path} is empty; an empty trace has no events to "
                      f"compare and is not the same as a trace with none"]
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return (events, []) if events else (None, [f"{path} is not JSON or JSONL"])
    if isinstance(doc, dict):
        doc = doc.get("events", doc.get("records"))
    if not isinstance(doc, list):
        return None, [f"{path} must hold an array of events"]
    return doc, []


def aligned_rows(a, b, keys, start, span):
    n = max(len(a), len(b))
    rows = []
    for i in range(max(0, start), min(n, start + span)):
        ea = a[i] if i < len(a) else None
        eb = b[i] if i < len(b) else None
        ka = tuple(str(ea.get(k)) if ea and ea.get(k) is not None else None
                   for k in keys) if ea else None
        kb = tuple(str(eb.get(k)) if eb and eb.get(k) is not None else None
                   for k in keys) if eb else None
        rows.append({
            "index": i,
            "match": ka is not None and ka == kb,
            "a": {k: ea.get(k) for k in keys
                  if ea and ea.get(k) is not None} if ea else None,
            "b": {k: eb.get(k) for k in keys
                  if eb and eb.get(k) is not None} if eb else None,
        })
    return rows


def render(d: dict, args) -> str:
    L = ["=" * 78, "RUNTIME TRACE DIFF", "=" * 78]
    L.append(f"A : {d['a']}  ({d['length_a']} events)")
    L.append(f"B : {d['b']}  ({d['length_b']} events)")
    L.append(f"compared: {', '.join(d['compared_keys'])}")
    L.append("")
    L.append(f"  {d['note']}")
    L.append("")

    if d["identical"]:
        L.append("identical on the compared keys.")
        L.append("")
        L.append("  Agreement here is about which events happened, not about")
        L.append("  state. Two runs can perform the same events with different")
        L.append("  values and be functionally wrong. Compare observable state")
        L.append("  as well; see state-diff.py.")
        return "\n".join(L)

    L.append(f"first divergence at index {d['first_divergence_index']}  "
             f"(kind: {d['kind']})")
    div = d.get("divergence") or {}
    if div.get("explanation"):
        L.append("")
        L.append(f"  {div['explanation']}")
    if div.get("differing_fields"):
        L.append(f"  differing fields: {', '.join(div['differing_fields'])}")
    L.append("")
    L.append(f"  A[{d['first_divergence_index']}]: "
             f"{json.dumps(div.get('side_a'), sort_keys=True, default=str)}")
    L.append(f"  B[{d['first_divergence_index']}]: "
             f"{json.dumps(div.get('side_b'), sort_keys=True, default=str)}")
    L.append("")

    if args.detail:
        first = d["first_divergence_index"] or 0
        start = max(0, first - args.context)
        L.append("-" * 78)
        L.append(f"ALIGNED VIEW  (indices {start}..{start + args.context * 2})")
        L.append("-" * 78)
        for row in aligned_rows(d["_a"], d["_b"], d["compared_keys"], start,
                                args.context * 2 + 1):
            mark = "=" if row["match"] else ("<<<" if row["index"] == first
                                             else "*")
            L.append(f"  {row['index']:>5} {mark:^4} "
                     f"A={json.dumps(row['a'], sort_keys=True, default=str)}")
            L.append(f"        {'':^4} "
                     f"B={json.dumps(row['b'], sort_keys=True, default=str)}")
        L.append("")

    if "downstream_event_mismatches" in d:
        L.append("-" * 78)
        L.append("DOWNSTREAM")
        L.append("-" * 78)
        L.append(f"  further event mismatches: "
                 f"{d['downstream_event_mismatches']}")
        for row in d.get("downstream_first_five", []):
            L.append(f"    index {row['index']}: A={row['side_a']} "
                     f"B={row['side_b']}")
        L.append("")
        L.append(f"  {d['interpretation']}")
        L.append("")
        L.append("  Investigate the first divergence. The rest is a cascade")
        L.append("  until a test says otherwise.")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Compare two runtime traces and find the first divergence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("a", help="baseline trace")
    p.add_argument("b", help="comparison trace")
    p.add_argument("--keys", default=None,
                   help="comma-separated fields to compare "
                        "(default type,module,address,tid,size,symbol)")
    p.add_argument("--context", type=int, default=3,
                   help="events shown either side of the divergence "
                        "(default 3)")
    p.add_argument("--detail", action="store_true",
                   help="print an aligned view around the divergence")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    a, pa = load(args.a)
    b, pb = load(args.b)
    if a is None or b is None:
        print(f"error: {'; '.join(pa + pb)}", file=sys.stderr)
        return 2

    keys = [k.strip() for k in args.keys.split(",")] if args.keys else None
    d = R.diff_runs(a, b, keys=keys, first_only=False)
    d["a"] = args.a
    d["b"] = args.b
    d["_a"], d["_b"] = a, b

    if args.json:
        printable = {k: v for k, v in d.items() if not k.startswith("_")}
        print(json.dumps(printable, indent=2, default=str))
    else:
        print(render(d, args))
    return 0 if not d["identical"] else 0


if __name__ == "__main__":
    sys.exit(main())