#!/usr/bin/env python3
"""normalize-address.py -- translate runtime addresses into every space.

This is the bridge between the static world and the runtime one, and the
single most common source of confidently wrong conclusions in memory analysis.

    runtime address  ->  module  ->  module-relative  ->  ELF vaddr
                                                           ->  file offset
                                                            ->  symbol

`runtime_address - module_base` is **not** a file offset. A module maps at
several file offsets, the lowest of which is usually the header page rather
than the code; ASLR moves everything; and the segment table decides the rest.
This script walks PT_LOAD and says so when it cannot translate, rather than
producing a number that looks right.

It can compare a runtime address against a static one directly, which is the
check worth doing before reading any bytes:

  normalize-address.py 0x7f1a40001234 --map-file maps.txt --lib /lib/libfoo.so
  normalize-address.py 0x2a4c0 --static 0x2a4c0 --map-file maps.txt
  normalize-address.py 0x7f1a40001234 --resolve-to 0x2a4c0 --map-file maps.txt

Examples
--------
  memory-map.py --self -o /dev/null >/dev/null      # see the map first
  normalize-address.py --pid self 0x7f00
  normalize-address.py 0x7f1a40001234 --map-file maps.txt --lib libfoo.so
  normalize-address.py 0x2a4c0 --static 0x2a4c0 --map-file maps.txt --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _runtimelib as R  # noqa: E402


def load_binaries(paths: list) -> tuple:
    """Parse the binaries the caller named, keyed by basename.

    A binary the caller did not name is left unresolved on purpose: reporting
    a file offset for a module whose segment table was never read would be
    exactly the guess this tool exists to avoid.
    """
    import _binlib as B
    binaries, problems = {}, []
    for path in paths:
        try:
            binaries[os.path.basename(path)] = B.load(path)
        except Exception as e:                   # noqa: BLE001
            problems.append(f"{path}: {type(e).__name__}: {e}")
    return binaries, problems


def build(args) -> tuple:
    """Assemble a Resolver from whatever the caller supplied."""
    problems = []
    regions = None

    if args.map_file:
        try:
            with open(args.map_file, "r", errors="replace") as fh:
                regions = R.parse_maps(fh.read())
        except OSError as e:
            return None, None, [f"cannot read {args.map_file}: {e}"]
        if not regions:
            return None, None, [f"{args.map_file} parsed to zero regions"]
        if args.smaps_file:
            try:
                with open(args.smaps_file, "r", errors="replace") as fh:
                    R.apply_vmflags(regions,
                                    R.parse_smaps_vmflags(fh.read()))
            except OSError as e:
                problems.append(f"smaps unreadable: {e}")
    else:
        pid = "self" if args.self else args.pid
        regions, prov = R.load_resolver(pid, None, use_smaps=args.smaps)
        if regions is None:
            return None, None, [prov.get("error", "no memory map")]
        for s in prov.get("sources", []):
            if "unavailable" in s:
                problems.append(s)
        regions = [r for r in regions]

    R.classify_regions(regions)
    modules = R.build_modules(regions)

    if args.lib:
        wanted = set(args.lib)
        modules = [m for m in modules
                   if m.name in wanted or
                   any(os.path.basename(p) in wanted for p in m.paths)]
        if not modules:
            return None, None, [
                f"no module matching {sorted(wanted)} in the map; available: "
                f"{', '.join(sorted(m.name for m in R.build_modules(regions)))}"]

    binaries, bproblems = load_binaries(args.binary or [])
    problems.extend(bproblems)
    resolver = R.Resolver(regions, modules, binaries)
    return resolver, regions, problems


def compare(resolver: R.Resolver, static_addr: int) -> dict:
    """Translate a static address to where it lives at runtime.

    The inverse direction, and the one that catches a wrong load bias before
    it misleads a whole investigation.
    """
    out: dict = {"static_address": f"0x{static_addr:x}", "status": "unresolved",
                 "runtime_address": None, "module": None, "warnings": []}

    # Find the module whose parsed binary contains the static address.
    for m in resolver.modules:
        info = m.binary_info
        if info is None or m.load_bias is None:
            continue
        if m.contains(static_addr + m.load_bias):
            rt = static_addr + m.load_bias
            if any(r.contains(rt) for r in m.regions):
                out["status"] = "ok"
                out["module"] = m.name
                out["runtime_address"] = f"0x{rt:x}"
                out["module_relative"] = f"0x{m.relative(rt):x}"
                out["load_bias"] = f"0x{m.load_bias:x}"
                out["file_offset"] = info.vaddr_to_offset(static_addr)
                out["file_offset"] = (f"0x{out['file_offset']:x}"
                                      if out["file_offset"] is not None
                                      else None)
                sec = info.section_for(static_addr)
                out["section"] = sec.name if sec else None
                return out

    out["warnings"].append(
        "no module with a parsed binary contains this static address. Either "
        "the binary was not supplied with --binary, or the address is not a "
        "virtual address in any of them")
    return out


def render(records: list, args) -> str:
    L = []
    add = L.append
    add("=" * 78)
    add("ADDRESS NORMALISATION")
    add("=" * 78)
    add(f"source  : {args.map_file or ('pid self' if args.self else f'pid {args.pid}')}")
    if args.binary:
        add(f"binaries: {', '.join(args.binary)}")
    for p in records.get("problems", []):
        add(f"warning : {p}")
    add("")
    add("  runtime - module base is NOT a file offset. The translation below")
    add("  walks the segment table. Where it could not, it says so.")
    add("")

    for n in records["records"]:
        add("-" * 78)
        if n.get("error"):
            add("record")
            add("-" * 78)
            add(f"  error: {n['error']}")
            add("")
            continue
        add(f"runtime {n['runtime_address']}")
        add("-" * 78)
        if n.get("status") == "error":
            add(f"  error: {n['error']}")
            continue
        region = n.get("region") or {}
        add(f"  status          : {n['status']}")
        add(f"  region          : {region.get('start', '?')} {region.get('perms', '')} "
            f"{region.get('classification', '')} ({region.get('basis', '?')})")
        add(f"  module          : {n.get('module') or 'none'}")
        add(f"  module-relative : {n.get('module_relative') or '-'}")
        add(f"  ELF vaddr       : {n.get('elf_vaddr') or '-'}")
        add(f"  file offset     : {n.get('file_offset') or '-'}")
        if n.get("bss_offset"):
            add(f"  bss offset      : {n['bss_offset']}  (past filesz: no file "
                f"offset exists)")
        add(f"  section         : {n.get('section') or '-'}"
            + (f" +{n['section_offset']}" if n.get("section_offset") else ""))
        add(f"  symbol          : {n.get('symbol') or '-'}")
        if n.get("segment"):
            s = n["segment"]
            add(f"  segment         : offset {s['offset']} filesz {s['filesz']} "
                f"memsz {s['memsz']}")
        add(f"  confidence      : {n.get('confidence')}")
        for w in n.get("warnings", []):
            add(f"  ! {w}")
        add("")

    for c in records.get("comparisons", []):
        add("-" * 78)
        add(f"static 0x{c['static_address']}  ->  runtime")
        add("-" * 78)
        add(f"  status          : {c['status']}")
        add(f"  runtime address : {c.get('runtime_address') or '-'}")
        add(f"  module          : {c.get('module') or '-'}")
        add(f"  module-relative : {c.get('module_relative') or '-'}")
        add(f"  file offset     : {c.get('file_offset') or '-'}")
        add(f"  section         : {c.get('section') or '-'}")
        for w in c.get("warnings", []):
            add(f"  ! {w}")
        add("")
    return "\n".join(L)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Translate runtime addresses into module-relative, ELF and "
                    "file spaces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("addresses", nargs="*",
                   help="runtime addresses, e.g. 0x7f1a40001234")
    p.add_argument("--pid", default=None, help="process id to read")
    p.add_argument("--self", action="store_true",
                   help="use this process's map")
    p.add_argument("--map-file", default=None,
                   help="a saved /proc/<pid>/maps; no process needed")
    p.add_argument("--smaps-file", default=None)
    p.add_argument("--smaps", action="store_true")
    p.add_argument("--lib", action="append", default=[],
                   help="restrict to these module names (repeatable)")
    p.add_argument("--binary", action="append", default=[],
                   help="the file for a module, enabling file offsets "
                        "(repeatable). Without it a file offset is not "
                        "reported, because the segment table was never read")
    p.add_argument("--static", type=lambda x: int(x, 0), default=None,
                   help="also translate this static address to runtime")
    p.add_argument("--resolve-to", type=lambda x: int(x, 0), default=None,
                   help="report where this static offset lands at runtime")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if not args.map_file and not args.pid and not args.self:
        p.error("give --pid, --self, or --map-file")
    if not args.addresses and args.static is None and args.resolve_to is None:
        p.error("give at least one runtime address, --static, or --resolve-to")

    resolver, _regions, problems = build(args)
    if resolver is None:
        out = {"problems": problems,
               "records": [{"error": p} for p in problems]}
        print(json.dumps(out, indent=2) if args.json else render(out, args))
        print("error: no usable memory map, so no address was translated",
              file=sys.stderr)
        return 2

    bad = []
    records = []
    for a in args.addresses:
        record = resolver.normalize_text(a)
        records.append(record)
    if bad:
        problems.extend(bad)
        print("error: " + "; ".join(bad), file=sys.stderr)
        return 2

    comparisons = []
    if args.static is not None:
        comparisons.append(compare(resolver, args.static))
    if args.resolve_to is not None:
        comparisons.append(compare(resolver, args.resolve_to))

    out = {"problems": problems, "records": records,
           "comparisons": comparisons}
    print(json.dumps(out, indent=2, default=str) if args.json
          else render(out, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())