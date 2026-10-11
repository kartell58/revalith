#!/usr/bin/env python3
"""memory-map.py -- read a process memory map and classify it.

A memory map answers questions that no static view can: what the process
actually loaded, which regions are writable, where its heap is, and whether a
library appeared at runtime rather than being linked. It is the first thing
to look at when a static analysis and a trace disagree about what is running.

Classification is only as strong as its basis. A region is called a heap
because the kernel labelled it `[heap]`, because `smaps` reports `mg`, or
because it grew between two samples -- never because it is anonymous and
writable, which is what most heuristics settle for.

Live process, or a saved map for offline work:

  memory-map.py 1234                        # read /proc/1234/maps
  memory-map.py 1234 --smaps               # add the kernel's VmFlags
  memory-map.py --map-file saved.maps       # no process needed
  memory-map.py 1234 --watch 2             # two samples, to see growth
  memory-map.py 1234 --json                # for other tools

Examples
--------
  memory-map.py --self
  memory-map.py 1234 --watch 2 --sleep 1.5
  memory-map.py --map-file maps.txt --modules-only
  memory-map.py --map-file maps.txt --region 0x7f1a40000000 --json
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _runtimelib as R  # noqa: E402


def read_maps(pid: str, use_smaps: bool) -> tuple:
    """Read maps (and optionally smaps) for a pid. Returns (regions, notes)."""
    notes = []
    text, err = R.read_proc_file(pid, "maps")
    if err:
        return None, {"error": err, "sources": notes}
    regions = R.parse_maps(text)
    if not regions:
        return None, {"error": "maps parsed to zero regions; the read may "
                                "have been truncated",
                      "sources": notes}
    notes.append(f"maps: {len(regions)} regions")
    if use_smaps:
        stext, serr = R.read_proc_file(pid, "smaps")
        if stext and not serr:
            flags = R.parse_smaps_vmflags(stext)
            R.apply_vmflags(regions, flags)
            notes.append(f"smaps: VmFlags for {len(flags)} regions")
        else:
            notes.append(f"smaps unavailable: {serr or 'empty'}. Region "
                         f"classification loses the kernel's own hints, so "
                         f"every heap and stack claim stays an inference")
    return regions, {"sources": notes}


def load_from_file(path: str, smaps_path: str = None) -> tuple:
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        return None, {"error": f"cannot read {path}: {e}"}
    regions = R.parse_maps(text)
    if not regions:
        return None, {"error": f"{path} parsed to zero regions; is it a "
                                f"/proc/<pid>/maps file?"}
    notes = [f"map file: {path} ({len(regions)} regions)"]
    if smaps_path:
        try:
            with open(smaps_path, "r", errors="replace") as fh:
                flags = R.parse_smaps_vmflags(fh.read())
            R.apply_vmflags(regions, flags)
            notes.append(f"smaps file: {smaps_path} "
                         f"({len(flags)} VmFlags)")
        except OSError as e:
            notes.append(f"smaps file unreadable: {e}")
    return regions, {"sources": notes}


def apply_growth(old: list, new: list) -> list:
    """Record how much each region grew between two samples.

    Growth is evidence for a heap or a stack and for nothing else, which is
    why it is recorded as a number rather than as a conclusion.
    """
    index = {(r.start, r.end): r for r in old}
    for r in new:
        prev = index.get((r.start, r.end))
        if prev is not None:
            r.growth = r.size - prev.size
        else:
            r.notes.append("region did not exist in the earlier sample")
    return new


def summarise(regions: list) -> dict:
    by_class: dict = {}
    by_basis: dict = {}
    total = 0
    anon = 0
    for r in regions:
        by_class[r.classification] = by_class.get(r.classification, 0) + 1
        by_basis[r.basis] = by_basis.get(r.basis, 0) + 1
        total += r.size
        if r.anonymous:
            anon += r.size
    return {
        "regions": len(regions),
        "total_bytes": total,
        "anonymous_bytes": anon,
        "file_backed_bytes": total - anon,
        "by_classification": dict(sorted(by_class.items(),
                                         key=lambda kv: -kv[1])),
        "by_basis": dict(sorted(by_basis.items(), key=lambda kv: -kv[1])),
    }


def render(report: dict, args) -> str:
    L = []
    add = L.append
    add("=" * 78)
    add("MEMORY MAP")
    add("=" * 78)
    target = report.get("target")
    add(f"target   : {target}")
    add(f"sources  : {'; '.join(report.get('sources', []))}")
    for w in report.get("warnings", []):
        add(f"warning  : {w}")
    if report.get("error"):
        add(f"error    : {report['error']}")
        add("")
        add("  Nothing was concluded. A memory map that could not be read is")
        add("  not an empty memory map, and the two must not be confused.")
        add("")
        return "\n".join(L)

    s = report["summary"]
    add("")
    add("-" * 78)
    add("SUMMARY")
    add("-" * 78)
    add(f"regions          : {s['regions']}")
    add(f"total mapped     : {s['total_bytes']:,} bytes")
    add(f"  file-backed    : {s['file_backed_bytes']:,}")
    add(f"  anonymous      : {s['anonymous_bytes']:,}")
    add("")
    add("by classification (how many regions, and on what basis):")
    for cls, n in list(s["by_classification"].items())[:14]:
        add(f"  {n:>4}  {cls}")
    add("")
    add("by basis:")
    basis_meaning = {
        "kernel_named": "the kernel labelled the region",
        "kernel_hint": "VmFlags from smaps",
        "file_backed": "a file backs it",
        "observed": "read from the kernel, no further reading needed",
        "observed_growth": "it grew between samples",
        "inferred": "consistent with a class, nothing more",
        "unknown": "not determined",
    }
    for b, n in s["by_basis"].items():
        add(f"  {n:>4}  {b:<18} {basis_meaning.get(b, '')}")

    if args.modules_only:
        add("")
        add("-" * 78)
        add("MODULES  (file-backed; grouped by file, not by address range)")
        add("-" * 78)
        for m in report["modules"]:
            add(f"  {m['base']}  {m['name']}  size {m['size']:,}")
            add(f"        load bias {m['load_bias']}  basis {m['load_bias_basis']}")
            for p in m.get("paths", []):
                add(f"        {p}")
            for w in m.get("load_bias_warnings") or []:
                add(f"        ! {w}")
        add("")
        return "\n".join(L)

    add("")
    add("-" * 78)
    add("REGIONS")
    add("-" * 78)
    regions = report["regions"]
    if args.region is not None:
        regions = [r for r in regions
                   if int(r["start"], 16) <= args.region < int(r["end"], 16)]
        if not regions:
            add(f"  0x{args.region:x} is not inside any region of this map")
            add("")
            return "\n".join(L)
        add(f"  filtered to those containing 0x{args.region:x}")
        add("")

    if args.classification:
        regions = [r for r in regions if args.classification in r["classification"]]

    for r in regions[:args.limit]:
        add(f"  {r['start']}-{r['end']}  {r['permissions']}  "
            f"{r['size']:>10,}  {r['classification']}")
        add(f"      basis      : {r['basis']}"
            + (f"  ({r['basis_detail']})" if r.get("basis_detail") else ""))
        add(f"      confidence : {r['confidence']}")
        if r.get("pathname"):
            add(f"      path       : {r['pathname']}")
        add(f"      file offset: {r['file_offset']}"
            + (f"   inode {r['inode']}" if r.get("inode") else ""))
        if r.get("vmflags"):
            add(f"      VmFlags    : {r['vmflags']}")
        if r.get("growth_bytes") is not None:
            g = r["growth_bytes"]
            add(f"      growth     : {g:+,} bytes between samples")
        for n in r.get("notes") or []:
            add(f"      note       : {n}")

    if len(regions) > args.limit:
        add(f"  ... {len(regions) - args.limit} more region(s) not shown "
            f"(--limit {args.limit})")

    add("")
    add("-" * 78)
    add("MODULES  (file-backed; grouped by file, not by address range)")
    add("-" * 78)
    for m in report["modules"]:
        add(f"  {m['base']}  {m['name']}  size {m['size']:,}")
        add(f"        load bias {m['load_bias']}  basis {m['load_bias_basis']}")
        for p in m.get("paths", []):
            add(f"        {p}")
        for w in m.get("load_bias_warnings") or []:
            add(f"        ! {w}")

    add("")
    add("-" * 78)
    add("READING THIS MAP")
    add("-" * 78)
    add("  A library here that is absent from the executable's DT_NEEDED was")
    add("  loaded at runtime. Static analysis of the executable alone cannot")
    add("  reach it.")
    add("")
    add("  An anonymous executable region is a fact. Calling it JIT, an")
    add("  unpacker or a patcher is a reading, and the report does not make it")
    add("  for you.")
    add("")
    add("  A module whose load bias could not be derived, or whose mappings")
    add("  disagree, will not translate runtime addresses to file offsets")
    add("  correctly. Use normalize-address.py and read its warnings.")
    add("")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read and classify a process memory map.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("pid", nargs="?",
                   help="process id, or 'self' for this process")
    p.add_argument("--self", action="store_true",
                   help="inspect this process (same as `self`)")
    p.add_argument("--map-file", default=None,
                   help="read a saved /proc/<pid>/maps instead of a live "
                        "process; nothing needs to be running")
    p.add_argument("--smaps-file", default=None,
                   help="a saved smaps to take VmFlags from")
    p.add_argument("--smaps", action="store_true",
                   help="also read /proc/<pid>/smaps for VmFlags")
    p.add_argument("--watch", type=int, default=0, metavar="N",
                   help="take N samples, N seconds apart, and record growth")
    p.add_argument("--sleep", type=float, default=1.0,
                   help="seconds between --watch samples (default 1.0)")
    p.add_argument("--region", type=lambda x: int(x, 0), default=None,
                   help="show only the region containing this address")
    p.add_argument("--classification", default=None,
                   help="filter by classification substring")
    p.add_argument("--modules-only", action="store_true",
                   help="show modules and the summary, not every region")
    p.add_argument("--limit", type=int, default=200,
                   help="max regions to print (default 200)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    pid = "self" if (args.self or (args.pid or "").lower() == "self") \
        else args.pid
    if not pid and not args.map_file:
        p.error("give a pid, --self, or --map-file")

    warnings: list = []
    samples = args.watch if args.watch > 1 else 1

    first = None
    for i in range(samples):
        if args.map_file:
            regions, prov = load_from_file(args.map_file, args.smaps_file)
        else:
            regions, prov = read_maps(pid, args.smaps)
        if regions is None:
            report = {"target": args.map_file or f"pid {pid}",
                      "error": prov.get("error"), "sources": prov.get("sources", []),
                      "warnings": warnings}
            print(json.dumps(report, indent=2) if args.json
                  else render(report, args))
            return 2
        # Only genuine caveats are warnings; the provenance lines are already
        # reported under "sources" and repeating them there is noise.
        for s in prov.get("sources", []):
            if "unavailable" in s or "unreadable" in s or "hint" in s:
                warnings.append(s)
        if i == 0:
            first = regions
        elif i == samples - 1:
            regions = apply_growth(first, regions)
        if i < samples - 1:
            time.sleep(args.sleep)

    R.classify_regions(regions)
    modules = R.build_modules(regions)
    for m in modules:
        R.derive_load_bias(m)

    report = {
        "target": args.map_file or f"pid {pid}",
        "sources": prov.get("sources", []),
        "warnings": warnings,
        "summary": summarise(regions),
        "regions": [r.to_dict() for r in regions],
        "modules": [m.to_dict() for m in modules],
        "notes": [
            "classification carries a basis; a region without a basis is "
            "reported as unknown rather than guessed",
            "modules are grouped by file, so one library appears once even "
            "when it maps at several file offsets",
        ],
    }

    print(json.dumps(report, indent=2, default=str) if args.json
          else render(report, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())