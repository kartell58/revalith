#!/usr/bin/env python3
"""recon-ledger.py -- manage the reconstruction ledger.

The ledger is the record of what has been reconstructed, how far, and on what
evidence. Its purpose is narrow and mechanical: stop an old hypothesis from
being read later as an established fact.

Every entry carries a status. Every status demands something:

  observed / hypothesized / reconstructed   need evidence
  verified                                  needs a test that could have failed
  confidence                                may not exceed what the status supports
  refuted                                   needs a record of what refuted it

`validate` enforces those rules, and `stats` answers the question that
matters most when picking up an old project: which assumptions is the rest of
the reconstruction standing on?

Examples
--------
  recon-ledger.py init ./reconstruction
  recon-ledger.py add ./reconstruction functions 0x8120 \\
      --evidence "called once per frame" "reads +0x08" \\
      --hypothesis "per-frame state update" --confidence low
  recon-ledger.py update ./reconstruction functions 0x8120 \\
      --status reconstructed --confidence high
  recon-ledger.py list ./reconstruction functions --status hypothesized
  recon-ledger.py show ./reconstruction 0x8120
  recon-ledger.py validate ./reconstruction
  recon-ledger.py stats ./reconstruction --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _reconlib as R  # noqa: E402

# Every ledger file starts as a valid, empty document. An empty ledger is
# valid; an absent one is not, because its absence is indistinguishable from
# having never started.
def seed_doc(category: str) -> dict:
    return {
        "schema_version": R.SCHEMA_VERSION,
        "category": category,
        "kind": R.LEDGER_KINDS[category],
        "count": 0,
        "entries": [],
    }


def cmd_init(args) -> int:
    os.makedirs(args.ledger, exist_ok=True)
    created, existing = [], []
    for cat in R.LEDGER_KINDS:
        path = os.path.join(args.ledger, f"{cat}.json")
        if os.path.exists(path) and not args.force:
            existing.append(cat)
            continue
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(seed_doc(cat), fh, indent=2)
            fh.write("\n")
        created.append(cat)
    if args.json:
        print(json.dumps({"ledger": args.ledger, "created": created,
                          "already_present": existing}, indent=2))
    else:
        print(f"ledger: {args.ledger}")
        for cat in created:
            print(f"  created  {cat}.json")
        for cat in existing:
            print(f"  kept     {cat}.json  (use --force to overwrite)")
    return 0


def cmd_add(args) -> int:
    try:
        entry = R.new_entry(
            name=args.name,
            kind=R.LEDGER_KINDS[args.category],
            status=args.status,
            confidence=args.confidence,
            evidence=args.evidence,
            hypothesis=args.hypothesis,
            tests=args.tests,
            observed_behavior=args.behavior,
            next_test=args.next_test,
            notes=args.note,
            supporting_observations=args.supporting,
            contradicting=args.contradicting,
            source=args.source,
            avoid=args.avoid,
            refuted_by=args.refuted_by,
            address=args.address,
            related_functions=args.related_functions,
            related_data=args.related_data,
            related_structures=args.related_structures,
        )
    except Exception as e:                      # noqa: BLE001
        print(f"error: could not build entry: {e}", file=sys.stderr)
        return 1

    # Reopening a refuted idea is legitimate; reopening it silently is what
    # wastes a day. The question is not "is this forbidden" but "is there
    # something new", so a match demands --new-evidence rather than a refusal.
    ledger = R.Ledger(args.ledger)
    reopened: list = []
    if args.category != "dead_ends" and os.path.isdir(ledger.root):
        try:
            reopened = R.find_reopened_dead_ends(
                entry, ledger.read("dead_ends"), args.new_evidence)
        except R.LedgerError:
            reopened = []
    blocking = [h for h in reopened if not h["has_new_evidence"]]
    if blocking and not args.force:
        print("error: this entry reopens a recorded dead end, and nothing "
              "records what is new:", file=sys.stderr)
        for h in blocking:
            print(f"  - {h['dead_end']}: {h['matched_because']}", file=sys.stderr)
            if h.get("refuted_by"):
                print(f"      refuted by: {h['refuted_by']}", file=sys.stderr)
            if h.get("avoid"):
                print(f"      recorded as: {h['avoid']}", file=sys.stderr)
        print("\nIf the test was inadequate, the tool was missing, or the code "
              "changed, record that in --new-evidence. If the idea really is "
              "dead, add the evidence that settled it instead.",
              file=sys.stderr)
        return 1

    problems = R.validate_entry(entry, R.LEDGER_KINDS[args.category])
    # Refuse to store an entry that would misrepresent its own state. A
    # ledger that accepts contradictions is worse than no ledger.
    fatal = [p for p in problems if "exceeds what status" not in p
             and "status 'verified' requires" not in p]
    if fatal and not args.allow_invalid:
        print(f"error: entry is not valid:", file=sys.stderr)
        for p in fatal:
            print(f"  - {p}", file=sys.stderr)
        print("\nProvide the missing evidence or tests, or pass "
              "--allow-invalid to record it anyway with the problems "
              "attached.", file=sys.stderr)
        return 1

    try:
        ledger.add(args.category, entry)
    except R.LedgerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if problems:
        entry["validation_problems"] = problems
        ledger.write(args.category, ledger.read(args.category))

    if args.json:
        print(json.dumps({"added": entry, "problems": problems,
                          "reopens_dead_end": reopened}, indent=2))
    else:
        print(f"added {args.category}/{args.name}  status={args.status}")
        if problems:
            print("recorded with problems:")
            for p in problems:
                print(f"  ! {p}")
        for h in reopened:
            note = "" if h["has_new_evidence"] else " (forced)"
            print(f"  note: reopens dead end '{h['dead_end']}'{note}")
    return 0


def cmd_update(args) -> int:
    ledger = R.Ledger(args.ledger)
    changes = {}
    for field, value in (("status", args.status),
                         ("confidence", args.confidence),
                         ("hypothesis", args.hypothesis),
                         ("next_test", args.next_test),
                         ("source", args.source),
                         ("avoid", args.avoid),
                         ("notes", args.note)):
        if value is not None:
            changes[field] = value
    for field, values in (("evidence", args.evidence),
                          ("tests", args.tests)):
        if values:
            changes[field] = values
    if args.contradicting:
        changes["contradicting"] = args.contradicting
    if args.supporting:
        changes["supporting_observations"] = args.supporting
    if args.refuted_by:
        changes["refuted_by"] = args.refuted_by
    if args.contradiction_resolved:
        changes["contradiction_resolved"] = args.contradiction_resolved

    if not changes:
        print("error: nothing to change; pass at least one of --status, "
              "--confidence, --evidence, --tests, --hypothesis, --note, "
              "--source, --supporting, --contradicting, --refuted-by, "
              "--avoid", file=sys.stderr)
        return 2

    try:
        entry, problems = ledger.update(args.category, args.name, changes)
    except R.LedgerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"entry": entry, "problems": problems}, indent=2))
    else:
        print(f"updated {args.category}/{args.name}")
        for k, v in changes.items():
            shown = v if not isinstance(v, list) else f"{len(v)} item(s)"
            print(f"  {k}: {shown}")
        if problems:
            print("problems:")
            for p in problems:
                print(f"  ! {p}")
    return 0


def cmd_list(args) -> int:
    ledger = R.Ledger(args.ledger)
    try:
        entries = ledger.read(args.category)
    except R.LedgerError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    rows = []
    for e in entries:
        if args.status and e.get("status") != args.status:
            continue
        if args.confidence and e.get("confidence") != args.confidence:
            continue
        if args.grep:
            blob = json.dumps(e).lower()
            if args.grep.lower() not in blob:
                continue
        rows.append(e)

    if args.json:
        print(json.dumps({"ledger": args.ledger,
                          "category": args.category,
                          "count": len(rows),
                          "entries": [R.summarise_entry(e) for e in rows]},
                         indent=2))
        return 0

    if not rows:
        print(f"no entries in {args.category}.json match"
              + (f" status={args.status}" if args.status else ""))
        return 0

    print(f"{len(rows)} of {len(entries)} entries in {args.category}.json")
    print()
    w = max(len(str(e.get('name'))) for e in rows)
    w = min(w, 44)
    for e in rows:
        print(f"  {str(e.get('name'))[:w]:<{w}}  "
              f"{str(e.get('status') or '?'):<24} "
              f"{str(e.get('confidence') or '-'):<10} "
              f"ev={len(e.get('evidence') or [])} "
              f"tst={len(e.get('tests') or [])}")
        hyp = e.get("hypothesis")
        if hyp and args.verbose:
            print(f"      {hyp}")
    return 0


def cmd_show(args) -> int:
    ledger = R.Ledger(args.ledger)
    matches = ledger.find(args.name)
    if not matches:
        print(f"error: no entry named '{args.name}' in {args.ledger}",
              file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([{"category": c, "entry": e} for c, e in matches],
                         indent=2))
        return 0
    for cat, e in matches:
        print(f"=== {cat}.json ===")
        for key in ("name", "kind", "status", "confidence", "source", "address",
                    "hypothesis", "observed_behavior", "notes", "avoid",
                    "contradiction_resolved", "refuted_by"):
            if e.get(key):
                print(f"  {key:<18} {e[key]}")
        for key in ("evidence", "supporting_observations", "tests",
                    "contradicting", "related_functions", "related_data",
                    "related_structures"):
            vals = e.get(key)
            if vals:
                print(f"  {key}:")
                for v in vals:
                    print(f"    - {v}")
        problems = R.validate_entry(e, R.LEDGER_KINDS[cat])
        if problems:
            print("  validation:")
            for p in problems:
                print(f"    ! {p}")
        hist = e.get("history")
        if hist:
            print(f"  history ({len(hist)} change(s)):")
            for h in hist[-5:]:
                print(f"    {h['changes']}")
        print()
    return 0


def cmd_validate(args) -> int:
    ledger = R.Ledger(args.ledger)
    report = ledger.validate()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"ledger: {report['ledger']}")
        print(f"entries checked : {report['checked']}")
        print(f"valid           : {report['valid']}")
        c = report["counts"]
        print(f"established     : {c['established']}")
        print(f"assumed         : {c['assumed']}")
        print(f"refuted         : {c['refuted']}")
        if report["problems"]:
            print()
            print(f"{len(report['problems'])} problem(s):")
            for p in report["problems"]:
                who = p["entry"] or p["category"]
                print(f"  {who}: {p['problem']}")
        else:
            print("\nno problems: every entry's status is supported by its "
                  "evidence and tests")
        if report["load_bearing"]:
            print()
            print("assumed elements that other entries depend on:")
            for lb in report["load_bearing"]:
                print(f"  {lb['name']}  status={lb['status']} "
                      f"confidence={lb['confidence']} "
                      f"referenced_by={lb['referenced_by_count']}")
                print(f"      {lb['risk']}")
    return 0 if report["ok"] else 1


def cmd_stats(args) -> int:
    ledger = R.Ledger(args.ledger)
    entries = [e for _, e in ledger.all_entries()]
    by_status: dict = {}
    by_conf: dict = {}
    by_kind: dict = {}
    for e in entries:
        by_status[e.get("status", "?")] = by_status.get(e.get("status", "?"), 0) + 1
        by_conf[e.get("confidence", "-")] = by_conf.get(e.get("confidence", "-"), 0) + 1
        by_kind[e.get("kind", "?")] = by_kind.get(e.get("kind", "?"), 0) + 1
    fv = R.facts_vs_hypotheses(entries)

    if args.json:
        print(json.dumps({"ledger": args.ledger, "total": len(entries),
                          "by_status": by_status, "by_confidence": by_conf,
                          "by_kind": by_kind, **fv}, indent=2))
        return 0

    print(f"ledger: {args.ledger}")
    print(f"total entries : {len(entries)}")
    print()
    print("by status:")
    for s in R.STATUSES:
        n = by_status.get(s, 0)
        bar = "#" * min(n, 40)
        print(f"  {s:<26} {n:>4}  {bar}")
    print()
    print("by confidence:")
    for c in R.CONFIDENCES:
        print(f"  {c:<26} {by_conf.get(c, 0):>4}")
    unconf = by_conf.get("-", 0)
    if unconf:
        print(f"  {'(none recorded)':<26} {unconf:>4}")
    print()
    print("by kind:")
    for k in sorted(by_kind):
        print(f"  {k:<26} {by_kind[k]:>4}")
    print()
    if fv["load_bearing_assumptions"]:
        print("assumed elements other reconstructions depend on:")
        for lb in fv["load_bearing_assumptions"]:
            print(f"  {lb['name']}  ({lb['status']}, {lb['confidence']}) "
                  f"referenced by {lb['referenced_by_count']} entry/entries")
        print()
        print(f"  {fv['note']}")
    else:
        print("nothing assumed is load-bearing: every hypothesis is either "
              "settled or unreferenced")
    return 0


def cmd_gaps(args) -> int:
    """What the ledger cannot yet answer.

    The counter-question to `stats`. Stats says what has been found, which
    makes a long investigation feel finished; this says what has not, which is
    what decides the next hour of work.
    """
    ledger = R.Ledger(args.ledger)
    if not ledger.exists():
        print(f"error: no ledger at {args.ledger}; run `init` first",
              file=sys.stderr)
        return 1
    report = R.gaps(ledger)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        counts = report["counts"]
        print(f"ledger: {report['ledger']}")
        print(f"  entries                 {counts['entries']}")
        print(f"  dead ends recorded      {counts['dead_ends']}")
        print()
        for key, title in (
                ("missing_tests", "claims a status its tests do not support"),
                ("unactionable_hypotheses",
                 "hypotheses with nothing that could settle them"),
                ("unresolved_contradictions",
                 "evidence against a claim with no recorded answer"),
                ("load_bearing_assumptions",
                 "assumptions the rest of the work stands on")):
            items = report[key]
            print(f"{title} ({len(items)}):")
            for item in items:
                name = item.get("name")
                cat = item.get("category")
                detail = item.get("why") or item.get("risk") or ""
                print(f"  - {name}" + (f"  [{cat}]" if cat else "")
                      + (f"  -- {detail}" if detail else ""))
            if not items:
                print("  (none)")
            print()
        if report["empty_categories"]:
            print("categories never asked (empty is not answered):")
            for cat in report["empty_categories"]:
                print(f"  - {cat}")
            print()
        if report["unsourced_entries"]:
            print(f"entries with no recorded source ({len(report['unsourced_entries'])}):"
                  " the layer that produced the evidence is unknown")
            for item in report["unsourced_entries"][:20]:
                print(f"  - {item.get('name')}  [{item.get('category')}]")
            if len(report["unsourced_entries"]) > 20:
                print(f"  ... and {len(report['unsourced_entries']) - 20} more")
            print()
        print(report["note"])

    return 0 if report["clear"] or not args.strict else 1


def cmd_render(args) -> int:
    """Render the readable project-state files from the ledger.

    Generated, never hand-edited: a second store of the same facts is how a
    session ends up contradicting the ledger, with nothing noticing.
    """
    ledger = R.Ledger(args.ledger)
    if not ledger.exists():
        print(f"error: no ledger at {args.ledger}; run `init` first",
              file=sys.stderr)
        return 1
    files = R.render_state(ledger)

    if args.stdout:
        if args.category and args.category not in files:
            print(f"error: nothing is rendered as '{args.category}'; "
                  f"renderable: {', '.join(sorted(files))}", file=sys.stderr)
            return 1
        name = args.category if args.category else "investigation-state.md"
        print(files[name], end="")
        return 0

    try:
        os.makedirs(args.output, exist_ok=True)
    except OSError as e:
        print(f"error: cannot create {args.output}: {e}", file=sys.stderr)
        return 1

    written = []
    for name, text in sorted(files.items()):
        path = os.path.join(args.output, name)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as e:
            # One unwritable file must not abandon the rest of the render.
            print(f"warning: could not write {path}: {e}", file=sys.stderr)
            continue
        written.append(name)

    if args.json:
        print(json.dumps({"output": args.output, "written": written,
                          "skipped": sorted(set(files) - set(written))},
                         indent=2))
    else:
        print(f"rendered {len(written)} file(s) to {args.output}")
        for name in written:
            print(f"  {name}")
        skipped = sorted(set(files) - set(written))
        for name in skipped:
            print(f"  SKIPPED {name}")
    return 0 if len(written) == len(files) else 1


def main() -> int:
    p = argparse.ArgumentParser(
        description="Manage the reconstruction ledger.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("command",
                   choices=["init", "add", "update", "list", "show",
                            "validate", "stats", "gaps", "render"],
                   help="init creates the ledger files; add/update change "
                        "them; list/show/validate/stats read them; gaps "
                        "reports what is still open; render writes the "
                        "readable project-state files from the ledger")
    p.add_argument("ledger", help="path to the reconstruction directory")
    # Neither positional carries argparse `choices`: for 'show' the second
    # positional is an entry name, and a name like 0x8120 would be rejected as
    # an invalid category. Categories are validated in main() instead, where
    # the command is known.
    p.add_argument("category", nargs="?",
                   help="ledger category: " + ", ".join(sorted(R.LEDGER_KINDS)))
    p.add_argument("name", nargs="?",
                   help="entry name (add, update)")
    p.add_argument("--status", choices=R.STATUSES, default=None)
    p.add_argument("--confidence", choices=R.CONFIDENCES, default=None)
    p.add_argument("--source", choices=R.SOURCES, default=None,
                   help="which layer produced the evidence: one of "
                        + ", ".join(R.SOURCES))
    p.add_argument("--avoid", default=None,
                   help="what not to do next; required on a dead end, which "
                        "without it is history rather than guidance")
    p.add_argument("--new-evidence", default=None,
                   help="what changed since a recorded dead end refuted "
                        "this; reopening one without this is refused")
    p.add_argument("--contradiction-resolved", default=None,
                   help="how a recorded contradiction was answered")
    p.add_argument("--evidence", action="append", default=[],
                   help="an observation, with where it was seen "
                        "(repeatable)")
    p.add_argument("--tests", action="append", default=[],
                   help="a test that could have failed (repeatable)")
    p.add_argument("--next-test", default=None,
                   help="what would settle this entry; recording it does not "
                        "claim the test was run")
    p.add_argument("--supporting", action="append", default=[],
                   help="an observation the claim rests on, as distinct from "
                        "--evidence which records what was seen (repeatable)")
    p.add_argument("--contradicting", action="append", default=[],
                   help="an observation that argues against this entry "
                        "(repeatable). Recording one alongside status "
                        "'verified' is refused unless you say how it was "
                        "resolved")
    p.add_argument("--hypothesis", default=None)
    p.add_argument("--behavior", default=None,
                   help="what was actually observed happening")
    p.add_argument("--note", default=None)
    p.add_argument("--address", default=None, help="e.g. 0x8120")
    p.add_argument("--refuted-by", default=None)
    p.add_argument("--related-functions", action="append", default=[])
    p.add_argument("--related-data", action="append", default=[])
    p.add_argument("--related-structures", action="append", default=[])
    p.add_argument("--allow-invalid", action="store_true",
                   help="record an entry that fails validation, attaching "
                        "the problems to it")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing ledger files (init), or record "
                        "an entry that reopens a dead end (add)")
    p.add_argument("--strict", action="store_true",
                   help="exit 1 when gaps remain (gaps)")
    p.add_argument("-o", "--output", default="./project-state",
                   help="directory to render into (render)")
    p.add_argument("--stdout", action="store_true",
                   help="print one rendered file instead of writing "
                        "(render; name it as the category argument)")
    p.add_argument("--grep", default=None, help="substring filter (list)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show hypotheses (list)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    needs_category = args.command in ("add", "update", "list")
    if needs_category and not args.category:
        p.error(f"'{args.command}' requires a category: "
                f"{', '.join(sorted(R.LEDGER_KINDS))}")
    if needs_category and args.category not in R.LEDGER_KINDS:
        p.error(f"unknown ledger '{args.category}'; expected one of: "
                f"{', '.join(sorted(R.LEDGER_KINDS))}")
    if args.command == "show":
        # argparse fills positionals left to right, so for 'show' the name
        # lands in the category slot. 'show' searches every ledger and takes
        # no category, so the value is moved across and the slot cleared.
        args.name = args.category or args.name
        args.category = None
    needs_name = args.command in ("add", "update", "show")
    if needs_name and not args.name:
        p.error(f"'{args.command}' requires an entry name")

    if args.command == "add" and not args.status:
        args.status = "unknown"

    return {
        "init": cmd_init,
        "add": cmd_add,
        "update": cmd_update,
        "list": cmd_list,
        "show": cmd_show,
        "validate": cmd_validate,
        "stats": cmd_stats,
        "gaps": cmd_gaps,
        "render": cmd_render,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())