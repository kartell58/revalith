#!/usr/bin/env python3
"""runtime-events.py -- validate, summarise and correlate runtime events.

A runtime investigation produces a stream of events, and the stream is where
this skill's discipline is hardest to keep. Two events near each other in
time are not one causing the other, and a hook that fires on every call
reports far more than the process did.

This tool validates event records against the schema, summarises what was
observed, and offers the correlations that are cheap to compute. It refuses to
emit a causal claim: `caused_by` without a recorded experiment is rejected,
because that is the field where an inference would be laundered into a fact.

It accepts JSON arrays, ``{"events": [...]}``, and JSON Lines, so a trace from
any tool can be fed in unchanged.

  runtime-events.py events.json --validate
  runtime-events.py events.json --summarize
  runtime-events.py events.json --type memory_write --thread 4821
  runtime-events.py events.json --write-to 0x7ffd1a2b0410 --map-file maps.txt
  runtime-events.py events.json --modules

Examples
--------
  runtime-events.py events.json --validate --json
  runtime-events.py events.json --summarize
  runtime-events.py events.json --syscalls
  runtime-events.py events.json --write-to 0x7ffd1a2b0410 --map-file maps.txt
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _runtimelib as R  # noqa: E402


def load_events(path: str) -> tuple:
    """Read events from JSON, {"events": [...]}, or JSON Lines."""
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return None, [f"cannot read {path}: {e}"]
    if not text.strip():
        return None, [f"{path} is empty; there are no events to analyse"]

    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        # JSON Lines is the common shape for a trace, and it is worth
        # supporting rather than asking the reader to convert it first.
        events = []
        bad = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            events.append(obj)
        if events:
            problems = []
            if bad:
                problems.append(f"{bad} line(s) were not valid JSON and were "
                                f"skipped")
            return events, problems
        return None, [f"{path} is neither valid JSON nor JSON Lines"]

    if isinstance(doc, dict):
        doc = doc.get("events", doc.get("records"))
    if not isinstance(doc, list):
        return None, [f"{path} must contain an array of events, or an object "
                      f"with an 'events' array"]
    if not doc:
        return None, [f"{path} contains an empty event list"]
    return doc, []


def summarise(events: list) -> dict:
    by_type: dict = {}
    by_thread: dict = {}
    by_module: dict = {}
    timestamps = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        t = ev.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
        tid = ev.get("tid") or ev.get("thread")
        if tid is not None:
            by_thread[str(tid)] = by_thread.get(str(tid), 0) + 1
        if ev.get("module"):
            by_module[ev["module"]] = by_module.get(ev["module"], 0) + 1
        ts = ev.get("timestamp")
        if isinstance(ts, (int, float)):
            timestamps.append(ts)

    span = None
    if len(timestamps) >= 2:
        span = max(timestamps) - min(timestamps)

    return {
        "total": len(events),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "by_thread": dict(sorted(by_thread.items(),
                                 key=lambda kv: -kv[1])),
        "by_module": dict(sorted(by_module.items(), key=lambda kv: -kv[1])),
        "threads_observed": len(by_thread),
        "modules_observed": len(by_module),
        "time_span": span,
        "note": "counts of recorded events, not of operations performed: "
                "instrumentation decides what is recorded, so a type absent "
                "here may still have happened",
    }


def filter_events(events: list, args) -> list:
    out = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if args.type and ev.get("type") not in args.type:
            continue
        if args.thread and str(ev.get("tid") or ev.get("thread")) not in args.thread:
            continue
        if args.module and ev.get("module") not in args.module:
            continue
        if args.address is not None:
            a = R.normalize_address_text(ev.get("address"))
            if a != args.address:
                continue
        out.append(ev)
    return out


def render_validation(report: dict, problems: list) -> str:
    L = ["=" * 78, "RUNTIME EVENT VALIDATION", "=" * 78]
    for p in problems:
        L.append(f"  note: {p}")
    L.append(f"events checked : {report['count']}")
    L.append(f"valid           : {report['valid']}")
    L.append("")
    if report["by_type"]:
        L.append("by type:")
        for t, n in report["by_type"].items():
            L.append(f"  {n:>5}  {t}")
        L.append("")
    if report["problems"]:
        L.append(f"{len(report['problems'])} problem(s):")
        for p in report["problems"][:60]:
            L.append(f"  event[{p['index']}]: {p['problem']}")
        if len(report["problems"]) > 60:
            L.append(f"  ... {len(report['problems']) - 60} more")
        L.append("")
        L.append("The checks that matter most:")
        L.append("  a memory event without 'size' cannot be reproduced by "
                 "anyone else")
        L.append("  'verified' or 'high' confidence without evidence is an "
                 "assertion")
        L.append("  'caused_by' without an experiment is an inference "
                 "presented as a cause")
    else:
        L.append("no problems: every event satisfies the schema and carries "
                 "the evidence its claims require")
    return "\n".join(L)


def render_summary(s: dict) -> str:
    L = ["=" * 78, "RUNTIME EVENT SUMMARY", "=" * 78]
    L.append(f"events           : {s['total']}")
    L.append(f"threads observed : {s['threads_observed']}")
    L.append(f"modules observed : {s['modules_observed']}")
    if s["time_span"] is not None:
        L.append(f"time span        : {s['time_span']}")
    L.append("")
    L.append("by type:")
    for t, n in s["by_type"].items():
        L.append(f"  {n:>6}  {t}")
    L.append("")
    if s["by_thread"]:
        L.append("by thread (tid):")
        for t, n in list(s["by_thread"].items())[:20]:
            L.append(f"  {n:>6}  {t}")
        L.append("")
    if s["by_module"]:
        L.append("by module:")
        for m, n in s["by_module"].items():
            L.append(f"  {n:>6}  {m}")
        L.append("")
    L.append(f"note: {s['note']}")
    return "\n".join(L)


def render_provenance(p: dict) -> str:
    L = ["=" * 78, f"PROVENANCE  {p['address']}", "=" * 78]
    L.append(f"events touching it : {p['events']}")
    L.append(f"writes / reads      : {p.get('write_count')} / "
             f"{p.get('read_count')}")
    if p.get("threads"):
        L.append(f"threads            : {', '.join(p['threads'])}")
    L.append(f"thread agreement   : {p.get('thread_agreement')}")
    L.append(f"confidence         : {p.get('confidence')}")
    L.append("")
    if p.get("note"):
        L.append(f"  ! {p['note']}")
        L.append("")
    if p["status"] == "no_events":
        L.append(f"  {p['note']}")
        L.append("")
        L.append(f"  alias hypothesis: {p.get('alias_hypothesis')}")
        return "\n".join(L)

    fw = p.get("first_write")
    if fw:
        L.append(f"first write (event {fw['index']}): {fw['classification']}")
        L.append(f"  value {fw['value']}  basis {fw['basis']}")
        L.append(f"  {fw['caveat']}")
        L.append("")
    per = p.get("periodic")
    if per:
        L.append(f"write cadence: {per['classification']} "
                 f"(most common interval {per['most_common_interval']}, "
                 f"{per['share_of_that_interval']:.0%} of intervals)")
        L.append(f"  {per['caveat']}")
        L.append("")
    if p.get("missing_stages"):
        L.append(f"stages with no evidence: {', '.join(p['missing_stages'])}")
        L.append("  a missing stage is a gap in the trace, not an absence of "
                 "behaviour")
        L.append("")
    L.append("provenance stages (stage assignment is a reading, not an "
             "observation):")
    for stage, rows in p["stages"].items():
        L.append(f"  {stage}:")
        for r in rows[:6]:
            L.append(f"    t={r['timestamp']} tid={r['tid']} "
                     f"{r['type']} value={r['value']} caller={r['caller']}")
    return "\n".join(L)


def render_syscalls(c: dict) -> str:
    L = ["=" * 78, "SYSCALLS", "=" * 78]
    L.append(f"observed : {c['syscalls_observed']} "
             f"({c['distinct']} distinct)")
    L.append("")
    for name, rec in c["by_name"].items():
        L.append(f"  {name}: {rec['count']}"
                 + (f"  threads {', '.join(rec['threads'])}"
                    if rec.get("threads") else "")
                 + ("  [structural]" if rec["structural"] else ""))
    L.append("")
    if c["readings"]:
        L.append("readings (each needs the thing it names before it is more "
                 "than a reading):")
        for r in c["readings"]:
            L.append(f"  {r['syscall']}: {r['reading']}")
            if r.get("requires"):
                L.append(f"      needs: {r['requires']}")
    L.append("")
    L.append(f"note: {c['note']}")
    return "\n".join(L)


def render_modules(m: dict) -> str:
    L = ["=" * 78, "MODULE LOAD ORDER", "=" * 78]
    L.append(f"loaded : {m['loaded_count']}")
    L.append("")
    for entry in m["load_order"]:
        L.append(f"  {entry['order']:>3}. {entry['module']}"
                 f"  t={entry['timestamp']}  base={entry['base']}  "
                 f"by={entry['loaded_by']}")
    if m.get("unloaded"):
        L.append("")
        L.append(f"unloaded later: {', '.join(m['unloaded'])}")
    L.append("")
    L.append(f"note: {m['note']}")
    L.append(f"caveat: {m['caveat']}")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Validate and summarise runtime event records.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("events", help="JSON array, {\"events\": [...]}, or JSONL")
    p.add_argument("--validate", action="store_true",
                   help="check every event against the schema")
    p.add_argument("--summarize", action="store_true",
                   help="counts by type, thread and module")
    p.add_argument("--syscalls", action="store_true",
                   help="group syscalls and offer readings of them")
    p.add_argument("--modules", action="store_true",
                   help="module load order, and what was loaded at runtime")
    p.add_argument("--write-to", type=lambda x: int(x, 0), default=None,
                   help="build the provenance chain for this address")
    p.add_argument("--type", action="append", default=[],
                   choices=R.EVENT_TYPES, help="filter by type (repeatable)")
    p.add_argument("--thread", action="append", default=[],
                   help="filter by tid or thread name (repeatable)")
    p.add_argument("--module", action="append", default=[],
                   help="filter by module (repeatable)")
    p.add_argument("--address", type=lambda x: int(x, 0), default=None,
                   help="filter by event address")
    p.add_argument("--map-file", default=None,
                   help="a saved maps file, so write-to can resolve modules")
    p.add_argument("--pid", default=None)
    p.add_argument("--self", action="store_true")
    p.add_argument("--smaps", action="store_true")
    p.add_argument("--limit", type=int, default=40,
                   help="max rows per section (default 40)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    events, problems = load_events(args.events)
    if events is None:
        print(f"error: {'; '.join(problems)}", file=sys.stderr)
        return 2

    sections = {
        "validation": R.validate_events(events),
        "summary": summarise(events),
        "syscalls": R.correlate_syscalls(events),
        "modules": R.module_load_chain(events),
    }

    resolver = None
    if args.write_to is not None:
        if args.map_file:
            try:
                with open(args.map_file, "r", errors="replace") as fh:
                    regions = R.classify_regions(R.parse_maps(fh.read()))
                resolver = R.Resolver(regions)
            except OSError as e:
                problems.append(f"cannot read the map file: {e}")
        elif args.pid or args.self:
            resolver, prov = R.load_resolver(
                "self" if args.self else args.pid, None, use_smaps=args.smaps)
            if resolver is None:
                problems.append(prov.get("error", "no memory map"))
        sections["provenance"] = R.build_provenance(
            events, args.write_to, resolver)

    filtered = filter_events(events, args) if (args.type or args.thread or
                                               args.module or
                                               args.address is not None) else None
    if filtered is not None:
        sections["filtered"] = {"matched": len(filtered),
                                "events": filtered[:args.limit]}

    out = {"source": args.events, "problems": problems, **sections}

    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(render_validation(out["validation"], problems))
    if args.summarize or not (args.validate or args.write_to or args.syscalls
                              or args.modules):
        print()
        print(render_summary(out["summary"]))
    if args.syscalls:
        print()
        print(render_syscalls(out["syscalls"]))
    if args.modules:
        print()
        print(render_modules(out["modules"]))
    if "provenance" in sections:
        print()
        print(render_provenance(sections["provenance"]))
    if filtered is not None:
        print()
        print("-" * 78)
        print(f"FILTERED: {len(filtered)} of {len(events)} events match")
        for ev in filtered[:args.limit]:
            print(f"  {json.dumps(ev, sort_keys=True)}")
    return 0 if out["validation"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())