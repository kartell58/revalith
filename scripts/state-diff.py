#!/usr/bin/env python3
"""state-diff.py -- compare observable state between two runs.

Differential testing needs a specification. There is only one candidate for it:
the original. This tool compares an observable snapshot from the original
against one from the reimplementation and reports where they disagree.

The discipline it enforces is the one that matters: a divergence is not a
bug report, it is a question. One of the two sides is the specification and
the other is not, and the divergence alone does not say which. Every numeric
divergence is therefore reported with candidate causes and the test that would
settle each -- never with a suggested edit.

Both snapshots are JSON objects; nested objects and arrays are flattened to
dotted paths, so a field that stops being reported is a divergence rather than
a silent absence.

Examples
--------
  state-diff.py original.json reimpl.json
  state-diff.py original.json reimpl.json --first-only
  state-diff.py frame0180-a.json frame0180-b.json --tolerance 0.5
  state-diff.py a.json b.json --numeric-only --json
  state-diff.py a.json b.json --keys position,velocity,state
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _reconlib as R  # noqa: E402

# Candidate causes, keyed by the substring that triggers them. Each is a
# hypothesis about the mechanism, phrased so it can be tested rather than
# applied. See _reconlib.NUMERIC_CAUSE_PATTERNS for the long-form text.
CAUSE_HINTS = [
    ("fixed-point rounding",
     "an integer scaled by a fixed factor loses its low bits. A difference of "
     "one unit usually means the reimplementation rounds where the original "
     "truncates, or applies the scale at a different point in the expression."),
    ("integration order",
     "accumulating in a different order gives a different result. Which order "
     "the original uses is observable from the order of its writes."),
    ("collision resolution",
     "a collision pass applied in a different order, or skipped on one side, "
     "leaves positions consistent within each side but not equal."),
    ("division vs shift",
     "a divide and a shift by a power of two agree for non-negative values "
     "and disagree for negative ones; test whether the value can be negative."),
    ("float vs fixed-point",
     "the two representations drift apart as magnitude grows, so the "
     "divergence should grow with the value."),
    ("overflow or wraparound",
     "a result exceeding the field width wraps. A difference equal to the "
     "field range points here."),
    ("saturation or clamp",
     "a clamp makes both sides agree below the limit and diverge above it; "
     "test the limit itself."),
    ("sign or width mismatch",
     "signedness or width differences disagree only on particular values; "
     "test the boundary values explicitly."),
    ("unit or scale mismatch",
     "the values differ by a constant factor, which indicates a conversion "
     "applied in a different place."),
]


def load_state(path: str):
    """Return (state, error, note, is_sequence).

    ``state`` is the object to compare. A JSON array of per-frame snapshots is
    accepted; by default the last element is compared, since that is the state
    both runs reached. ``is_sequence`` lets the caller do element-wise
    comparison instead.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return None, f"cannot read {path}: {e}", None, False
    if not text.strip():
        return None, f"{path} is empty; there is no state to compare", None, False
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"{path} is not valid JSON: {e}", None, False

    if isinstance(doc, list):
        if not doc:
            return None, (f"{path} contains an empty list; nothing to "
                          f"compare"), None, True
        bad = [i for i, x in enumerate(doc) if not isinstance(x, dict)]
        if bad:
            return (None,
                    f"{path}: element(s) {bad[:5]} are not objects; a "
                    f"sequence snapshot must be an array of objects",
                    None, True)
        note = (f"compared the last of {len(doc)} element(s) by default; "
                f"use --all-elements to compare the sequence element-wise")
        return doc[-1], None, note, True

    if not isinstance(doc, dict):
        return None, (f"{path} must contain an object or an array of "
                      f"objects"), None, False
    return doc, None, None, False


def load_sequence(path: str):
    """Load a JSON array of objects for element-wise comparison."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.loads(fh.read())
    except OSError as e:
        return None, f"cannot read {path}: {e}"
    except json.JSONDecodeError as e:
        return None, f"{path} is not valid JSON: {e}"
    if isinstance(doc, dict):
        return None, (f"{path} is an object, not a sequence; drop "
                      f"--all-elements to compare it directly")
    if not isinstance(doc, list):
        return None, f"{path} must contain an array for --all-elements"
    if not doc:
        return None, f"{path} contains an empty array"
    bad = [i for i, x in enumerate(doc) if not isinstance(x, dict)]
    if bad:
        return None, f"{path}: element(s) {bad[:5]} are not objects"
    return doc, None


def diff_sequence(a, b, tolerance: float, limit: int) -> dict:
    """Compare two sequences element-wise and locate where they part.

    For a per-frame snapshot this answers the question that matters most:
    *which frame* did they stop agreeing at. Divergence in the final frame is
    a symptom; the first frame that differs is where the cause is.
    """
    n = min(len(a), len(b))
    per_index = []
    first_diff = None
    for i in range(n):
        d = R.diff_observations(a[i], b[i], tolerance=tolerance)
        count = d["divergent_fields"]
        per_index.append({"index": i, "divergent_fields": count,
                          "fields": [f["field"] for f in d["fields"]]})
        if count and first_diff is None:
            first_diff = i

    result = {
        "mode": "element-wise",
        "length_original": len(a),
        "length_reimpl": len(b),
        "compared_elements": n,
        "first_divergent_element": first_diff,
        "length_mismatch": len(a) != len(b),
        "per_element": per_index,
    }
    if first_diff is not None:
        d = R.diff_observations(a[first_diff], b[first_diff], tolerance=tolerance)
        for f in d["fields"]:
            causes = [c for c in (f.get("candidate_causes") or [])
                      if isinstance(c, dict) and c.get("detail")]
            if not causes:
                causes = hints_for(f, f["field"])
            f["candidate_causes"] = causes
        result["first_divergence"] = d
        result["interpretation"] = (
            f"element {first_diff} is the first to disagree. Later elements "
            f"are consequences of it: fix this one before reading the rest. "
            f"(an index is positional, not a frame number -- check whether "
            f"the snapshot carries its own frame identifier.)")
    else:
        result["interpretation"] = (
            "every compared element agrees at this tolerance")
    return result


def hints_for(field: dict, path: str) -> list:
    """Rank candidate causes for a divergence by what the numbers show."""
    out = []
    delta = field.get("delta")
    va, vb = field.get("value_a"), field.get("value_b")
    low = path.lower()

    for cause, detail in CAUSE_HINTS:
        score = 0
        if cause == "off-by-one at a discrete step":
            continue
        if cause == "fixed-point rounding":
            if delta is not None and abs(delta) == 1:
                score = 3
            if any(t in low for t in ("pos", "vel", "coord", "scale",
                                      "frac", "fixed")):
                score = max(score, 2)
        elif cause == "unit or scale mismatch":
            if (isinstance(va, (int, float)) and va and
                    isinstance(vb, (int, float))):
                ratio = vb / va
                if abs(ratio - round(ratio)) < 1e-9 and round(ratio) not in (0, 1):
                    score = 3
        elif cause == "collision resolution":
            if any(t in low for t in ("pos", "hit", "collision", "bounds",
                                      "rect", "aabb")):
                score = 2
        elif cause == "integration order":
            if any(t in low for t in ("vel", "acc", "delta", "sum")):
                score = 2
        elif cause == "overflow or wraparound":
            if delta is not None and isinstance(va, (int, float)):
                for width in (8, 16, 32, 64):
                    limit = 1 << (width - 1)
                    if abs(delta) == limit or abs(delta) == (limit << 1):
                        score = 3
        elif cause == "saturation or clamp":
            if any(t in low for t in ("clamp", "sat", "max", "min",
                                      "limit", "speed")):
                score = 2
        elif cause == "float vs fixed-point":
            if (isinstance(va, float) and isinstance(vb, (int, float))
                    and isinstance(va, float) and isinstance(vb, int)):
                score = 2
            if va and vb and isinstance(va, (int, float)) and \
                    isinstance(vb, (int, float)) and va != 0:
                rel = abs(delta or 0) / abs(va)
                if rel < 1e-3 and abs(va) > 1000:
                    score = 2
        elif cause == "sign or width mismatch":
            if field.get("kind") == "type":
                score = 3
            if isinstance(va, int) and isinstance(vb, int) and \
                    not isinstance(va, bool):
                if (va < 0) != (vb < 0) and abs(va - vb) > abs(va) + abs(vb):
                    score = 3
        elif cause == "division vs shift":
            if delta is not None and isinstance(va, int) and \
                    isinstance(vb, int) and va > 0 and vb >= 0:
                if va in (2, 4, 8, 16, 256, 360, 65536) and vb != va:
                    score = 1
        if score:
            out.append({"cause": cause, "detail": detail,
                        "why": f"the divergence at '{path}' is consistent "
                               f"with this; the numbers alone do not "
                               f"distinguish it from the others"})
    if delta is not None and abs(delta) == 1:
        out.append({
            "cause": "off-by-one at a discrete step",
            "detail": "the values differ by exactly one, the signature of a "
                      "rounding-mode or inclusive/exclusive boundary "
                      "difference",
            "why": f"'{path}' differs by exactly 1",
        })
    return out


def _restrict(objs, wanted):
    """Keep only fields whose flattened path matches one of ``wanted``."""
    out = []
    for obj in objs:
        flat = R.flatten(obj)
        out.append({k: v for k, v in flat.items()
                    if any(k == w or k.startswith(w + ".") or k.startswith(w + "[")
                           for w in wanted)})
    return out


def render_sequence(d: dict, args) -> str:
    L = []
    add = L.append
    add("=" * 74)
    add("OBSERVABLE STATE COMPARISON  (element-wise)")
    add("=" * 74)
    add(f"original      : {d['original']}")
    add(f"reimpl        : {d['reimpl']}")
    add(f"elements      : {d['length_original']} vs {d['length_reimpl']} "
        f"({d['compared_elements']} compared)")
    if d.get("tolerance"):
        add(f"tolerance     : {d['tolerance']}")
    add("")
    if d["length_mismatch"]:
        add("the sequences have different lengths, which is itself a "
            "divergence:")
        add(f"  original has {d['length_original']} element(s), reimpl has "
            f"{d['length_reimpl']}")
        add("")
    fde = d["first_divergent_element"]
    if fde is None:
        add("every compared element agrees at this tolerance.")
        add("")
        add(f"  {d['interpretation']}")
        add("")
        return "\n".join(L)

    add(f"first divergent element: {fde}   "
        f"({d['per_element'][fde]['divergent_fields']} field(s))")
    add("")
    add(f"  {d['interpretation']}")
    add("")
    add("-" * 74)
    add("ELEMENT COUNTS (divergent fields per element)")
    add("-" * 74)
    for row in d["per_element"][:args.limit]:
        mark = " <<< first divergence" if row["index"] == fde else ""
        add(f"  {row['index']:>6}  {row['divergent_fields']:>3} divergent"
            f"{mark}")
    add("")
    add("-" * 74)
    add("THE FIRST DIVERGENCE IN DETAIL")
    add("-" * 74)
    add(f"original      : {d['original']}[{fde}]")
    add(f"reimpl        : {d['reimpl']}[{fde}]")
    fd = d["first_divergence"]
    add(f"fields read   : {fd['compared_fields']}")
    add("")
    for f in fd["fields"][:args.limit]:
        add(f"  {f['field']}")
        add(f"      original      : {f['value_a']!r}")
        add(f"      reimpl        : {f['value_b']!r}")
        if "delta" in f:
            add(f"      delta         : {f['delta']:+.10g}")
        if f.get("explanation"):
            add(f"      note          : {f['explanation']}")
        causes = f.get("candidate_causes") or []
        if causes:
            add("      candidate causes:")
            for c in causes:
                add(f"        - {c['cause']}")
                add(f"            {c['detail']}")
        add("")
    add(f"  {fd['method']}")
    add("")
    return "\n".join(L)


def render(d: dict, args) -> str:
    L = []
    add = L.append
    add("=" * 74)
    add("OBSERVABLE STATE COMPARISON")
    add("=" * 74)
    add(f"original      : {d['original']}")
    add(f"reimpl        : {d['reimpl']}")
    add(f"fields read   : {d['compared_fields']}")
    add(f"divergent     : {d['divergent_fields']}")
    if d.get("tolerance"):
        add(f"  tolerance     : {d['tolerance']}")
        add(f"                {d['note']}")
    for n in (d.get("notes") or []):
        add(f"  note          : {n}")
    add("")

    if d["identical"]:
        add("no divergence found at the tolerance used.")
        add("")
        add("This is a statement about the fields compared, at this point in")
        add("the run, at this tolerance. It is not a statement that the")
        add("implementations are equivalent: untested inputs, later frames and")
        add("unobserved side effects are not covered by a snapshot match.")
        add("")
        return "\n".join(L)

    add("-" * 74)
    add("DIVERGENCES")
    add("-" * 74)
    for f in d["fields"][:args.limit]:
        add(f"  {f['field']}")
        add(f"      original      : {f['value_a']!r}")
        add(f"      reimpl        : {f['value_b']!r}")
        if "delta" in f:
            add(f"      delta         : {f['delta']:+.10g}"
                + (f"  (relative {f['delta']/f['value_a']:+.4g})"
                   if isinstance(f["value_a"], (int, float)) and
                   f["value_a"] else ""))
        add(f"      kind          : {f['kind']}")
        if f.get("explanation"):
            add(f"      note          : {f['explanation']}")
        causes = f.get("candidate_causes") or hints_for(f, f["field"])
        if causes:
            add("      candidate causes (none of these is the answer yet):")
            for c in causes:
                add(f"        - {c['cause']}")
                add(f"            {c['detail']}")
        add("")

    add("-" * 74)
    add("WHAT TO DO WITH THIS")
    add("-" * 74)
    add(f"  {d['method']}")
    add("")
    add("  Work the divergence with the most discriminating cause first. For")
    add("  a numeric divergence that means finding the two input values where")
    add("  the implementations disagree and reading what the original does")
    add("  with them, not adjusting a constant until the output matches: a")
    add("  constant that makes one frame agree is not evidence about the")
    add("  next frame.")
    add("")
    add("  Record the resolution in the ledger (recon-ledger.py), with the")
    add("  test that settled it, before moving to the next divergence.")
    add("")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Compare observable state between two runs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("original", help="state snapshot from the original")
    p.add_argument("reimpl", help="state snapshot from the reimplementation")
    p.add_argument("--tolerance", type=float, default=0.0,
                   help="absolute difference below which two numbers are "
                        "treated as equal (default 0: exact)")
    p.add_argument("--first-only", action="store_true",
                   help="report only the first divergent field")
    p.add_argument("--numeric-only", action="store_true",
                   help="skip fields where either side is not a number")
    p.add_argument("--keys", default=None,
                   help="comma-separated field names or prefixes to compare "
                        "(e.g. position,velocity)")
    p.add_argument("--all-elements", action="store_true",
                   help="treat each input as a sequence of snapshots and "
                        "locate the first element that disagrees, rather "
                        "than comparing only the last")
    p.add_argument("--limit", type=int, default=20,
                   help="max divergences shown (default 20)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.tolerance < 0:
        print("error: --tolerance cannot be negative", file=sys.stderr)
        return 2

    if args.all_elements:
        a, err_a = load_sequence(args.original)
        if err_a:
            print(f"error: {err_a}", file=sys.stderr)
            return 2
        b, err_b = load_sequence(args.reimpl)
        if err_b:
            print(f"error: {err_b}", file=sys.stderr)
            return 2
        if args.keys:
            wanted = [k.strip() for k in args.keys.split(",") if k.strip()]
            a = _restrict(a, wanted)
            b = _restrict(b, wanted)
        d = diff_sequence(a, b, args.tolerance, args.limit)
        d["original"] = args.original
        d["reimpl"] = args.reimpl
        if args.json:
            print(json.dumps(d, indent=2, default=str))
        else:
            print(render_sequence(d, args))
        return 0

    a, err_a, note_a, _ = load_state(args.original)
    if err_a:
        print(f"error: {err_a}", file=sys.stderr)
        return 2
    b, err_b, note_b, _ = load_state(args.reimpl)
    if err_b:
        print(f"error: {err_b}", file=sys.stderr)
        return 2

    if args.keys:
        wanted = [k.strip() for k in args.keys.split(",") if k.strip()]
        a = _restrict([a], wanted)[0]
        b = _restrict([b], wanted)[0]

    d = R.diff_observations(a, b, tolerance=args.tolerance,
                            first_only=args.first_only,
                            numeric_only=args.numeric_only)
    notes = [n for n in (note_a, note_b) if n]
    if notes:
        d["notes"] = notes
    for f in d["fields"]:
        # numeric_causes also returns an "observed" row carrying the measured
        # delta; that is the measurement, not a candidate cause, so it is
        # dropped here and the measurement is rendered separately.
        causes = [c for c in (f.get("candidate_causes") or [])
                  if isinstance(c, dict) and c.get("detail")]
        f["candidate_causes"] = causes or hints_for(f, f["field"])
    d["original"] = args.original
    d["reimpl"] = args.reimpl

    if args.json:
        print(json.dumps(d, indent=2, default=str))
    else:
        print(render(d, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())