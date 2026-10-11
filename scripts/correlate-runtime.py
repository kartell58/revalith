#!/usr/bin/env python3
"""correlate-runtime.py -- join runtime observations to static ones.

This is the bridge between the static world and the runtime one, and the step
where a wrong load bias turns into a whole investigation reading the wrong
bytes. A runtime address means nothing on its own: it becomes a function, a
section and a file offset only after the module map and the segment table have
been walked, and this tool walks them.

It also does the correlation work that is cheap and reliable: which threads
ran which functions, which memory each function touched, which syscalls
clustered together, and what a divergence between two runs looks like when the
runs are runtime traces rather than static artefacts.

Two rules it will not break.

**Correlation is not causation.** Two events near each other in time are not
one causing the other. A function executing and a field changing, with nothing
between them, is a *candidate* relationship. Causality needs an experiment, and
the tool marks the distinction rather than resolving it.

**A missing observation is a gap in the trace.** Not the absence of behaviour.

  correlate-runtime.py events.json --map-file maps.txt --binary ./libfoo.so
  correlate-runtime.py events.json --write-to 0x7ffd1a2b0410 --map-file maps.txt
  correlate-runtime.py events.json --threads --map-file maps.txt
  correlate-runtime.py a.json b.json --diff --first

Examples
--------
  correlate-runtime.py events.json --map-file maps.txt --binary libfoo.so --json
  correlate-runtime.py events.json --write-to 0x7ffd00002020 --map-file maps.txt
  correlate-runtime.py a.json b.json --diff
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _runtimelib as R  # noqa: E402

# Commands to run the static tools this tool substitutes for. Its job is
# correlation, not disassembly; a disassembler does disassembly.
STATIC_COMMANDS = (
    ("readelf -hSsWd --dyn-syms", "headers, sections, dynamic, symbols"),
    ("llvm-readobj --file-headers --sections --dyn-symbols", "same, clearer"),
    ("objdump -d", "disassembly"),
    ("nm -D --defined-only", "dynamic symbols"),
    ("strings -a -t x", "strings with offsets"),
)


def load_events(path: str):
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return None, [f"cannot read {path}: {e}"]
    if not text.strip():
        return None, [f"{path} is empty"]
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


def load_resolver(args):
    """Build a Resolver from whatever the caller supplied."""
    import _binlib as B
    regions = None
    problems = []

    if args.map_file:
        try:
            with open(args.map_file, "r", errors="replace") as fh:
                regions = R.parse_maps(fh.read())
        except OSError as e:
            return None, [f"cannot read {args.map_file}: {e}"]
        if not regions:
            return None, [f"{args.map_file} parsed to zero regions"]
        if args.smaps_file:
            try:
                with open(args.smaps_file, "r", errors="replace") as fh:
                    R.apply_vmflags(regions, R.parse_smaps_vmflags(fh.read()))
            except OSError as e:
                problems.append(f"smaps unreadable: {e}")
    elif args.pid or args.self:
        regions, prov = R.load_resolver(
            "self" if args.self else args.pid, None, use_smaps=args.smaps)
        if regions is None:
            return None, [prov.get("error", "no memory map")]
        for s in prov.get("sources", []):
            if "unavailable" in s:
                problems.append(s)
    else:
        return None, []

    R.classify_regions(regions)
    binaries, bproblems = {}, []
    for path in (args.binary or []):
        try:
            binaries[os.path.basename(path)] = B.load(path)
        except Exception as e:                    # noqa: BLE001
            bproblems.append(f"{path}: {type(e).__name__}: {e}")
    problems.extend(bproblems)
    return R.Resolver(regions, None, binaries), problems


def thread_table(events, resolver) -> dict:
    """Which thread did what. The first question about concurrency.

    A thread that appears once is not a worker; a thread that appears in every
    trace point is doing something structural. Neither is concluded here --
    the counts are reported and the reading is left to the analyst.
    """
    threads: dict = {}
    for ev in events:
        tid = ev.get("tid") or ev.get("thread")
        if tid is None:
            continue
        key = str(tid)
        t = threads.setdefault(key, {"tid": key, "events": 0, "types": {},
                                     "modules": set(), "calls": [], "first": None,
                                     "last": None})
        t["events"] += 1
        etype = ev.get("type", "?")
        t["types"][etype] = t["types"].get(etype, 0) + 1
        if ev.get("module"):
            t["modules"].add(ev["module"])
        if etype == "call":
            t["calls"].append(ev.get("caller") or ev.get("symbol")
                              or ev.get("address"))
        ts = ev.get("timestamp")
        if isinstance(ts, (int, float)):
            t["first"] = ts if t["first"] is None else min(t["first"], ts)
            t["last"] = ts if t["last"] is None else max(t["last"], ts)

    out = []
    for t in threads.values():
        span = (t["last"] - t["first"]) if t["first"] is not None else None
        dominant = max(t["types"].items(), key=lambda kv: kv[1])
        out.append({
            "tid": t["tid"],
            "events": t["events"],
            "dominant_activity": dominant[0],
            "dominant_share": round(dominant[1] / t["events"], 3),
            "modules": sorted(t["modules"]) or None,
            "distinct_callers": len(set(c for c in t["calls"] if c)),
            "first_timestamp": t["first"],
            "last_timestamp": t["last"],
            "span": span,
            "label": ("worker candidate" if t["events"] >= 5 and
                      dominant[1] / t["events"] >= 0.6 else
                      ("short-lived or occasional" if t["events"] < 5 else
                       "mixed activity")),
            "caveat": "a 'worker candidate' is a frequency observation, not a "
                      "role: a thread that spins in a busy loop looks identical "
                      "to one doing real work until you see what it touches",
        })
    out.sort(key=lambda x: -x["events"])
    return {
        "threads": out,
        "note": "frequency does not establish role. A busy thread may be "
                "computing, spinning on a futex, or repainting; only the "
                "memory it touches and the calls it makes distinguish them",
    }


def write_to_table(events, address: int, resolver) -> dict:
    """Who writes and reads one address. The provenance chain.

    Built by ordering the events that touch the address and classifying each
    by what it is. Every classification is labelled, because "the first write
    is initialisation" is only true if no earlier read was recorded -- and an
    uninstrumented path would break that.
    """
    return R.build_provenance(events, address, resolver)


def build_report(events, resolver, args, problems) -> dict:
    report: dict = {
        "source": args.events,
        "problems": problems,
        "event_count": len(events),
        "schema_validation": R.validate_events(events),
        "capabilities": R.probe_capabilities(),
    }

    if resolver is not None:
        # Resolve every address the events carry. This is where a wrong load
        # bias would show up, so the warnings travel with the result.
        resolved = []
        seen = set()
        for ev in events:
            addr = R.normalize_address_text(ev.get("address"))
            if addr is None or addr in seen:
                continue
            seen.add(addr)
            n = resolver.normalize(addr)
            n["event_type"] = ev.get("type")
            resolved.append(n)
        report["addresses"] = {
            "distinct": len(resolved),
            "resolved_ok": sum(1 for n in resolved if n["status"] == "ok"),
            "partial": sum(1 for n in resolved if n["status"] == "partial"),
            "unresolved": sum(1 for n in resolved if n["status"] == "unresolved"),
            "records": resolved[:args.limit],
            "note": "a file offset is only reported when the module's binary "
                    "was supplied and parsed; the segment table is what "
                    "decides it, and runtime-minus-base is not a file offset",
        }
        # Static calls this tool did not make, so the reader knows where the
        # real static analysis happens.
        binaries = sorted({m.name for m in resolver.modules if m.binary_info})
        report["modules"] = [m.to_dict() for m in resolver.modules]
        report["static_tools_not_invoked"] = [
            {"command": c, "provides": d}
            for c, d in STATIC_COMMANDS]
        report["binaries_available_to_tool"] = binaries
    else:
        report["addresses"] = None

    if args.threads or not (args.write_to or args.diff):
        report["thread_table"] = thread_table(events, resolver)

    if args.write_to is not None:
        report["provenance"] = write_to_table(events, args.write_to, resolver)

    if args.syscalls:
        report["syscalls"] = R.correlate_syscalls(events)

    if args.modules:
        report["modules_loaded"] = R.module_load_chain(events)

    return report


def render(report: dict, args) -> str:
    L = ["=" * 78, "RUNTIME / STATIC CORRELATION", "=" * 78]
    L.append(f"source : {report['source']}")
    L.append(f"events : {report['event_count']}")
    for p in report["problems"]:
        L.append(f"warning: {p}")
    L.append("")

    v = report["schema_validation"]
    L.append(f"schema: {v['valid']}/{v['count']} valid"
             + (f", {v['problem_count']} problem(s)" if v["problems"] else ""))
    L.append("")

    if report.get("addresses"):
        a = report["addresses"]
        L.append("-" * 78)
        L.append("ADDRESSES  (module-relative, ELF vaddr, file offset)")
        L.append("-" * 78)
        L.append(f"distinct {a['distinct']}: "
                 f"{a['resolved_ok']} ok, {a['partial']} partial, "
                 f"{a['unresolved']} unresolved")
        L.append("")
        L.append(f"{'status':<11} {'module':<20} {'rel':<10} {'file offset':<12} "
                 f"section/symbol")
        for n in a["records"]:
            sym = n.get("symbol") or n.get("section") or ""
            L.append(f"{n['status']:<11} {(n.get('module') or '-'):<20} "
                     f"{(n.get('module_relative') or '-'):<10} "
                     f"{(n.get('file_offset') or '-'):<12} {sym}")
        L.append("")
        L.append(f"  {a['note']}")
        L.append("")

    if report.get("thread_table"):
        L.append("-" * 78)
        L.append("THREADS")
        L.append("-" * 78)
        t = report["thread_table"]
        L.append(f"{'tid':<10} {'events':>7} {'dominant':<16} {'share':>6}  label")
        for row in t["threads"]:
            L.append(f"{row['tid']:<10} {row['events']:>7} "
                     f"{row['dominant_activity']:<16} "
                     f"{row['dominant_share']:>6.0%}  {row['label']}")
        L.append("")
        L.append(f"  {t['note']}")
        L.append("")

    if report.get("provenance"):
        p = report["provenance"]
        L.append("-" * 78)
        L.append(f"PROVENANCE  {p['address']}")
        L.append("-" * 78)
        L.append(f"events {p['events']}, writes {p.get('write_count')}, "
                 f"reads {p.get('read_count')}")
        if p.get("threads"):
            L.append(f"threads {', '.join(p['threads'])}  "
                     f"agreement={p.get('thread_agreement')}")
        if p.get("note"):
            L.append(f"  ! {p['note']}")
        fw = p.get("first_write")
        if fw:
            L.append(f"first write: {fw['classification']} "
                     f"(value {fw['value']}, basis {fw['basis']})")
            L.append(f"  {fw['caveat']}")
        per = p.get("periodic")
        if per:
            L.append(f"cadence: {per['classification']} "
                     f"(interval {per['most_common_interval']}, "
                     f"{per['share_of_that_interval']:.0%})")
            L.append(f"  {per['caveat']}")
        if p.get("missing_stages"):
            L.append(f"stages without evidence: "
                     f"{', '.join(p['missing_stages'])}")
        for stage, rows in (p.get("stages") or {}).items():
            L.append(f"  {stage}:")
            for r in rows[:8]:
                L.append(f"    t={r['timestamp']} tid={r['tid']} "
                         f"{r['type']} value={r['value']} caller={r['caller']}")
        L.append("")

    if report.get("syscalls"):
        s = report["syscalls"]
        L.append("-" * 78)
        L.append("SYSCALLS")
        L.append("-" * 78)
        for name, rec in s["by_name"].items():
            L.append(f"  {name}: {rec['count']}")
        for r in s["readings"][:12]:
            L.append(f"  reading {r['syscall']}: {r['reading']}")
            if r.get("requires"):
                L.append(f"      needs: {r['requires']}")
        L.append(f"  {s['note']}")
        L.append("")

    if report.get("modules_loaded"):
        m = report["modules_loaded"]
        L.append("-" * 78)
        L.append("MODULE LOAD ORDER")
        L.append("-" * 78)
        for e in m["load_order"]:
            L.append(f"  {e['order']:>3}. {e['module']} t={e['timestamp']} "
                     f"base={e['base']} by={e['loaded_by']}")
        L.append(f"  {m['note']}")
        L.append(f"  caveat: {m['caveat']}")
        L.append("")

    if report.get("static_tools_not_invoked"):
        L.append("-" * 78)
        L.append("STATIC ANALYSIS THIS TOOL DID NOT DO")
        L.append("-" * 78)
        for t_ in report["static_tools_not_invoked"]:
            L.append(f"  {t_['command']:<48} {t_['provides']}")
        L.append("  These are what a static analysis needs; run them yourself.")
        L.append("")

    if report.get("capabilities"):
        c = report["capabilities"]
        L.append("-" * 78)
        L.append("RUNTIME CAPABILITIES HERE")
        L.append("-" * 78)
        for name, cap in c["capabilities"].items():
            L.append(f"  {cap['state']:<12} {name:<18} {cap['gives']}")
        L.append(f"  {c['privilege_note']}")
        L.append("")

    return "\n".join(L)


def render_diff(d: dict) -> str:
    L = ["=" * 78, "RUNTIME DIFF  (two traces)", "=" * 78]
    L.append(f"A : {d['length_a']} events")
    L.append(f"B : {d['length_b']} events")
    L.append(f"compared keys: {', '.join(d['compared_keys'])}")
    L.append("")
    if d["identical"]:
        L.append("identical on the compared keys")
        L.append(f"  {d['note']}")
        L.append("")
        L.append("  Agreement is not equivalence: it says nothing about state,")
        L.append("  only about which events happened.")
        return "\n".join(L)
    L.append(f"first divergence at index {d['first_divergence_index']}  "
             f"(kind: {d['kind']})")
    L.append("")
    div = d.get("divergence") or {}
    if div.get("explanation"):
        L.append(f"  {div['explanation']}")
    L.append(f"  A: {json.dumps(div.get('side_a'), sort_keys=True, default=str)}")
    L.append(f"  B: {json.dumps(div.get('side_b'), sort_keys=True, default=str)}")
    if div.get("differing_fields"):
        L.append(f"  differing fields: {', '.join(div['differing_fields'])}")
    L.append("")
    if "downstream_event_mismatches" in d:
        L.append(f"  {d['downstream_event_mismatches']} further event "
                 f"mismatches follow")
        L.append(f"  {d['interpretation']}")
    L.append("")
    L.append(f"  {d['note']}")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Correlate runtime events with static analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("events", help="runtime event records")
    p.add_argument("--map-file", default=None,
                   help="a saved /proc/<pid>/maps")
    p.add_argument("--smaps-file", default=None)
    p.add_argument("--pid", default=None)
    p.add_argument("--self", action="store_true")
    p.add_argument("--smaps", action="store_true")
    p.add_argument("--binary", action="append", default=[],
                   help="the module's file, enabling file offsets (repeatable)")
    p.add_argument("--write-to", type=lambda x: int(x, 0), default=None,
                   help="provenance chain for this address")
    p.add_argument("--threads", action="store_true",
                   help="which thread did what")
    p.add_argument("--syscalls", action="store_true")
    p.add_argument("--modules", action="store_true",
                   help="module load order")
    p.add_argument("--diff", default=None,
                   help="a second event file to diff against")
    p.add_argument("--limit", type=int, default=40,
                   help="max rows per section (default 40)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.diff:
        a_events, pa = load_events(args.events)
        b_events, pb = load_events(args.diff)
        if a_events is None or b_events is None:
            print(f"error: {'; '.join(pa + pb)}", file=sys.stderr)
            return 2
        d = R.diff_runs(a_events, b_events)
        d["note"] = ("timestamps are excluded: two runs of the same input do "
                     "not align on wall-clock time, and including them would "
                     "report a divergence at every event")
        d["a"] = args.events
        d["b"] = args.diff
        print(json.dumps(d, indent=2, default=str) if args.json
              else render_diff(d))
        return 0

    events, problems = load_events(args.events)
    if events is None:
        print(f"error: {'; '.join(problems)}", file=sys.stderr)
        return 2

    resolver, rproblems = load_resolver(args)
    problems.extend(rproblems)
    if args.map_file or args.pid or args.self:
        if resolver is None:
            print(f"error: {'; '.join(rproblems)}", file=sys.stderr)
            return 2

    report = build_report(events, resolver, args, problems)
    print(json.dumps(report, indent=2, default=str) if args.json
          else render(report, args))
    return 0 if report["schema_validation"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())