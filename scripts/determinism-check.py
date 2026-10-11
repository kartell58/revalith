#!/usr/bin/env python3
"""determinism-check.py -- establish whether a target is deterministic on an input.

Differential testing compares a reimplementation against the original. That
comparison only means something if the original produces the same observation
twice: run it, take one snapshot from each side, and any difference may be the
reimplementation's fault, the original's non-determinism, or the input changing
underneath both. The first of those is a finding. The second is a property of
the target. The third invalidates the experiment.

So this runs before any of the differential tooling, and its verdict is a
precondition, not a result.

What it does NOT do is name a cause. "position.y differs between run 2 and
run 3" is a measurement. "the clock is not stubbed" is a hypothesis, and the
tool lists what to check rather than asserting what is true.

Two inputs:

  --traces a.json b.json c.json   observations already collected
  --run "CMD" --times N           run a command N times, read JSON on stdout

Agreement across N runs is evidence, not proof. The sample count is recorded
in the output for that reason: three runs that agree leave open a divergence
that only appears on the hundredth.

Exit codes:
  0  deterministic on these runs and this input
  1  not deterministic, or not enough runs to tell
  2  usage or input error

Examples
--------
  determinism-check.py run1.json run2.json run3.json
  determinism-check.py run*.json --tolerance 0.5 --json
  determinism-check.py --run "./game --headless --dump" --times 5
  determinism-check.py run1.json run2.json --keys position,state
"""
import argparse
import json
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _reconlib as R  # noqa: E402

# What to check when something varies. These are places a target commonly
# picks up variation, phrased as places to look rather than as causes, because
# naming a cause from a differing value would be exactly the inference this
# skill exists to refuse.
VARIATION_SOURCES = [
    ("frame or iteration counter",
     "a counter that advances between runs is not divergence, it is the run "
     "number. Either compare at a fixed counter, or subtract it."),
    ("wall clock",
     "time(), clock_gettime(), GetTickCount and friends. Compare two runs "
     "and every one of them differs; that is not a finding about the target."),
    ("random source",
     "an unseeded or time-seeded RNG. Fix the seed, or record it, or the "
     "runs are not comparable at all."),
    ("thread scheduling",
     "an ordering difference between threads shows up as a value that is "
     "stable for a while and then flips. More runs find it; fewer miss it."),
    ("address-space layout",
     "ASLR moves pointers, so any recorded address varies. Record offsets "
     "from a module base instead, which is what normalize-address.py "
     "produces."),
    ("uninitialised memory",
     "a field that is read before it is written varies with whatever was on "
     "the stack or heap. It is a bug in the target and worth reporting, "
     "not noise to average away."),
    ("external input",
     "a file, a socket, the environment. If it changed between runs, the "
     "experiment changed and neither side is at fault."),
]


def load_observation(path):
    """Return (flattened, error). A missing or broken file is not fatal."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return None, f"cannot read {path}: {e}"
    if not text.strip():
        return None, f"{path} is empty; that is not an observation"
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"{path} is not valid JSON: {e}"
    if not isinstance(doc, (dict, list)):
        return None, (f"{path} must contain an object or an array of objects, "
                      f"not a bare {type(doc).__name__}")
    if isinstance(doc, list):
        bad = [i for i, x in enumerate(doc) if not isinstance(x, dict)]
        if bad:
            return None, (f"{path}: element(s) {bad[:5]} are not objects")
    flat = R.flatten(doc)
    if not flat:
        return None, f"{path} flattened to nothing; there is nothing to compare"
    return flat, None


def same_value(a, b, tolerance):
    """Equality, with a tolerance for numbers.

    Comparing floating point for exact equality is the right default here: the
    question is whether the target produced the same observation twice, and a
    tolerance is a decision the caller makes deliberately, not a default that
    hides drift.
    """
    if tolerance > 0 and isinstance(a, (int, float)) and not isinstance(a, bool) \
            and isinstance(b, (int, float)) and not isinstance(b, bool):
        return abs(float(a) - float(b)) <= tolerance
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return a == b


def collect_runs(args):
    """Return (runs, errors). One bad run is reported, never fatal to the rest."""
    runs, errors = [], []

    if args.run:
        for i in range(1, args.times + 1):
            try:
                proc = subprocess.run(
                    shlex.split(args.run), capture_output=True, text=True,
                    timeout=args.timeout, cwd=args.cwd or None)
            except subprocess.TimeoutExpired:
                errors.append(f"run {i}: timed out after {args.timeout}s")
                continue
            except OSError as e:
                errors.append(f"run {i}: cannot execute: {e}")
                break
            if proc.returncode != 0:
                tail = (proc.stderr or "").strip().splitlines()
                detail = tail[-1] if tail else f"exit {proc.returncode}"
                errors.append(f"run {i}: failed ({detail})")
                continue
            try:
                doc = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                errors.append(f"run {i}: stdout is not valid JSON ({e}); a "
                              f"determinism check needs structured output")
                continue
            runs.append((f"run{i}", R.flatten(doc)))
    else:
        for path in args.traces:
            flat, err = load_observation(path)
            if err:
                errors.append(err)
            else:
                runs.append((os.path.basename(path), flat))

    return runs, errors


def analyse(runs, tolerance, keys):
    """Compare every run against the first. Returns the structured report."""
    base_name, base = runs[0]
    paths = set()
    for _, flat in runs:
        paths |= set(flat)
    if keys:
        wanted = set()
        for k in keys:
            wanted |= {p for p in paths
                       if p == k or p.startswith(k + ".") or f"[{k}" in p}
        paths = wanted

    stable, varying, absent = [], [], []
    for path in sorted(paths):
        present = [(name, flat[path]) for name, flat in runs if path in flat]
        missing = [name for name, flat in runs if path not in flat]
        if missing:
            absent.append({"field": path, "absent_in": missing})
            continue
        first = present[0][1]
        if all(same_value(first, v, tolerance) for _, v in present[1:]):
            stable.append(path)
            continue
        values = [v for _, v in present]
        entry: dict = {"field": path, "values_by_run": dict(present)}
        numbers = [v for v in values
                   if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if len(numbers) == len(values) and len(set(numbers)) > 1:
            entry["numeric"] = True
            entry["min"] = min(numbers)
            entry["max"] = max(numbers)
            entry["spread"] = max(numbers) - min(numbers)
        else:
            entry["numeric"] = False
            entry["distinct_values"] = len({json.dumps(v, sort_keys=True,
                                                       default=str)
                                             for v in values})
        varying.append(entry)

    return {
        "baseline": base_name,
        "runs": len(runs),
        "run_names": [n for n, _ in runs],
        "deterministic": not varying and not absent,
        "stable_field_count": len(stable),
        "stable_fields": stable,
        "varying_fields": varying,
        "fields_absent_in_some_runs": absent,
        "tolerance": tolerance,
        "sources_to_check": VARIATION_SOURCES,
        "note": "agreement across these runs is evidence, not proof: the "
                "sample count is above, and a divergence that appears only "
                "on the hundredth run is still a divergence",
    }


def render(report, errors, args) -> str:
    out = []
    verdict = "DETERMINISTIC" if report["deterministic"] else "NOT DETERMINISTIC"
    if report["runs"] < 2:
        verdict = "UNDETERMINED"
    out.append(f"{verdict}  ({report['runs']} run(s), baseline "
               f"{report['baseline']})")
    out.append("")
    out.append(f"  stable fields           {report['stable_field_count']}")
    out.append(f"  varying fields          {len(report['varying_fields'])}")
    out.append(f"  absent in some runs     "
               f"{len(report['fields_absent_in_some_runs'])}")
    out.append("")

    if report["varying_fields"]:
        out.append("varying:")
        for f in report["varying_fields"][:args.limit]:
            if f.get("numeric"):
                out.append(f"  - {f['field']}: {f['min']} .. {f['max']} "
                           f"(spread {f['spread']})")
            else:
                vals = list(f["values_by_run"].values())
                shown = ", ".join(repr(v)[:40] for v in vals[:4])
                if len(vals) > 4:
                    shown += ", ..."
                out.append(f"  - {f['field']}: {shown}")
        if len(report["varying_fields"]) > args.limit:
            out.append(f"  ... and {len(report['varying_fields']) - args.limit}"
                       f" more")
        out.append("")

    if report["fields_absent_in_some_runs"]:
        out.append("reported by some runs only:")
        for f in report["fields_absent_in_some_runs"][:args.limit]:
            out.append(f"  - {f['field']}  missing from: "
                       f"{', '.join(f['absent_in'])}")
        out.append("")
        out.append("  a field that stops being reported is a divergence too, "
                   "and an easier one to miss.")
        out.append("")

    if report["varying_fields"] or report["fields_absent_in_some_runs"]:
        out.append("places variation usually comes from -- a list of where to "
                   "look, not a")
        out.append("diagnosis of what happened here:")
        for name, _ in report["sources_to_check"]:
            out.append(f"  - {name}")
        out.append("")
        out.append("  Differentiate them before comparing against a "
                   "reimplementation:")
        out.append("  a difference that a second run of the original also "
                   "produces is not the")
        out.append("  reimplementation's fault, and chasing it there wastes "
                   "the difference.")
        out.append("")

    if errors:
        out.append("problems:")
        for e in errors:
            out.append(f"  ! {e}")
        out.append("")

    out.append(report["note"])
    return "\n".join(out)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Establish whether a target is deterministic on an input.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("traces", nargs="*",
                   help="observation files, each a JSON object or an array of "
                        "objects (at least two)")
    p.add_argument("--run", default=None,
                   help="command to run repeatedly; it must print one JSON "
                        "observation on stdout")
    p.add_argument("--times", type=int, default=3,
                   help="how many times to run --run (default 3)")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="per-run timeout in seconds (default 60)")
    p.add_argument("--cwd", default=None, help="working directory for --run")
    p.add_argument("--tolerance", type=float, default=0.0,
                   help="allow this much difference on numeric fields; "
                        "default is exact equality")
    p.add_argument("--keys", default=None,
                   help="comma-separated fields to restrict the check to")
    p.add_argument("--limit", type=int, default=20,
                   help="maximum varying fields to print (default 20)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.run and args.traces:
        print("error: give either observations or --run, not both", file=sys.stderr)
        return 2
    if not args.run and len(args.traces) < 2:
        print("error: determinism needs at least two observations; pass two "
              "or more files, or --run with --times", file=sys.stderr)
        return 2
    if args.times < 2 and args.run:
        print("error: --times must be at least 2", file=sys.stderr)
        return 2
    if args.run and not args.run.strip():
        print("error: --run is empty", file=sys.stderr)
        return 2

    keys = [k.strip() for k in args.keys.split(",")] if args.keys else None

    runs, errors = collect_runs(args)
    if len(runs) < 2:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"error: got {len(runs)} usable run(s); determinism cannot be "
              f"established from fewer than two", file=sys.stderr)
        return 2

    report = analyse(runs, args.tolerance, keys)
    report["errors"] = errors
    report["command"] = args.run

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render(report, errors, args))

    if errors and len(runs) < len(args.traces):
        # Some inputs were unreadable, so the verdict covers fewer runs than
        # the caller supplied. Say so rather than reporting a clean result.
        print("warning: this verdict ignores the observations listed under "
              "'problems'; re-run with those fixed before relying on it",
              file=sys.stderr)

    return 0 if report["deterministic"] else 1


if __name__ == "__main__":
    sys.exit(main())