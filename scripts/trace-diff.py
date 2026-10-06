#!/usr/bin/env python3
"""trace-diff.py -- locate the first divergence between two traces.

When a reimplementation is compared against the original, almost everything
after the first difference is downstream of that difference. Chasing the last
mismatch in a log means chasing consequences. The first mismatch is where the
investigation belongs.

  original        A -> B -> C -> D -> F
  reimplementation A -> B -> C -> E -> F

                       ^ the first divergence. D versus E is the question;
                         F matching is not evidence that F is correct.

Two input formats are accepted, and the two sides need not match: one event
per line (what a debugger or a logging hook produces) or a JSON array (what an
instrumented build produces).

Examples
--------
  trace-diff.py original.log reimpl.log
  trace-diff.py orig.json mine.json --context 4
  trace-diff.py orig.log mine.log --detail --json
  trace-diff.py --label original - < reimpl.log
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _reconlib as R  # noqa: E402


def load(path: str, label: str, use_stdin: bool) -> tuple:
    """Read one trace. Returns (label, events, error)."""
    try:
        if use_stdin:
            text = sys.stdin.read()
        else:
            if not os.path.isfile(path):
                return label, [], f"no such file: {path}"
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as e:
        return label, [], str(e)

    if not text.strip():
        return label, [], f"{path} is empty; an empty trace has no events to " \
                          f"compare and cannot be treated as matching"
    try:
        return label, R.parse_trace(text), None
    except ValueError as e:
        return label, [], f"{path}: {e}"


def render(d: dict, args) -> str:
    L = []
    add = L.append
    add("=" * 74)
    add("TRACE COMPARISON  (first divergence, not last)")
    add("=" * 74)
    add(f"side A : {d['side_a']['label']}   {d['length_a']} event(s)")
    add(f"side B : {d['side_b']['label']}   {d['length_b']} event(s)")
    add(f"comparing: {d.get('comparison', 'label and arguments')}")
    add("")

    if d["identical"]:
        add(f"identical: both traces have {d['length_a']} matching event(s).")
        add("")
        add(f"  {d.get('note', '')}")
        add("  Compare the observable state as well; see state-diff.py.")
        add("")
        return "\n".join(L)

    ctx = args.context
    first = d["first_divergence_index"]
    if first is None:
        first = d["common_prefix_length"]

    add(f"events in agreement : {d['common_prefix_length']}")
    add(f"first divergence at : {first}  (0-based index)")
    add(f"kind                : {d['kind']}")
    add("")

    start = max(0, first - ctx)
    end_a = min(d["length_a"], first + ctx + 1)
    end_b = min(d["length_b"], first + ctx + 1)

    add("-" * 74)
    add("ALIGNED VIEW")
    add("-" * 74)
    add(f"{'idx':>6}  {d['side_a']['label'][:26]:<26}  "
        f"{d['side_b']['label'][:26]:<26}  ")
    for i in range(start, max(end_a, end_b)):
        la = d["events_a"][i]["label"] if i < d["length_a"] else None
        lb = d["events_b"][i]["label"] if i < d["length_b"] else None
        if i == first:
            mark = f" <<< first divergence ({d['kind']})"
        elif la is None or lb is None:
            mark = " (missing on one side)"
        else:
            mark = " ="
        add(f"{i:>6}  {(la or '-'):<26}  {(lb or '-'):<26}  {mark}")
        if args.detail:
            # The canonical key is shown rather than the raw value, so a type
            # difference (2 vs "2") is visible instead of looking identical.
            if i < d["length_a"]:
                ka = R.event_detail(d["events_a"][i])
                if ka is not None:
                    add(f"         A: {ka}")
            if i < d["length_b"]:
                kb = R.event_detail(d["events_b"][i])
                if kb is not None:
                    add(f"         B: {kb}")
    add("")

    div = d.get("divergence") or {}
    add("-" * 74)
    add("THE QUESTION")
    add("-" * 74)
    if div.get("explanation"):
        add(f"  {div['explanation']}")
    else:
        add(f"  side A: {div.get('side_a')}")
        add(f"  side B: {div.get('side_b')}")
    add("")
    add("  Everything after this index is unverified. A later agreement may")
    add("  mean the two implementations really do converge there, or it may")
    add("  mean the divergence was absorbed; the trace cannot distinguish")
    add("  those, and only comparing observable state at the matching points")
    add("  can.")
    add("")
    add("  Next: identify why side A does what it does, not what side B")
    add("  should be changed to match. One of the two is the specification")
    add("  and the other is not, and the divergence alone does not say which.")
    add("")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Find the first divergence between two traces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("trace_a", help="first trace ('-' for stdin)")
    p.add_argument("trace_b", help="second trace")
    p.add_argument("--label-a", default=None, help="name for side A")
    p.add_argument("--label-b", default=None, help="name for side B")
    p.add_argument("--context", type=int, default=3,
                   help="events shown either side of the divergence "
                        "(default 3)")
    p.add_argument("--detail", action="store_true",
                   help="show event details (arguments, values) when present")
    p.add_argument("--labels-only", action="store_true",
                   help="compare event names only, ignoring arguments. Use "
                        "when one side carries no argument data; otherwise "
                        "the default compares names and arguments, because "
                        "matching calls with different arguments is not "
                        "agreement")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    label_a = args.label_a or args.trace_a
    label_b = args.label_b or args.trace_b
    la, ea, err_a = load(args.trace_a, label_a, args.trace_a == "-")
    lb, eb, err_b = load(args.trace_b, label_b, args.trace_b == "-")

    for err in (err_a, err_b):
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2

    diff = R.first_divergence(ea, eb, include_detail=args.detail,
                             labels_only=args.labels_only)
    diff["side_a"] = {"label": la, "path": args.trace_a}
    diff["side_b"] = {"label": lb, "path": args.trace_b}
    diff["events_a"] = ea
    diff["events_b"] = eb

    if args.json:
        printable = {k: v for k, v in diff.items()
                     if k not in ("events_a", "events_b")}
        printable["aligned"] = [
            {"index": i,
             "a": ea[i]["label"] if i < len(ea) else None,
             "b": eb[i]["label"] if i < len(eb) else None,
             "match": R.event_key(ea[i], args.labels_only) ==
                      R.event_key(eb[i], args.labels_only)}
            for i in range(max(len(ea), len(eb)))]
        print(json.dumps(printable, indent=2, default=str))
    else:
        print(render(diff, args))

    # Identical is a legitimate outcome, not a failure; a divergence is the
    # interesting result and is also not an error. Both exit 0 so the tool
    # composes in a script without the caller special-casing it.
    return 0


if __name__ == "__main__":
    sys.exit(main())