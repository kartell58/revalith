#!/usr/bin/env python3
"""elf-summary.py -- print a structured overview of a binary.

Reports format, architecture, entrypoint, sections, segments, dependencies and
symbol counts for ELF, PE/COFF and Mach-O using only the Python standard
library. Anything that cannot be determined is printed as "unknown" with the
reason, never guessed.

Examples
--------
  elf-summary.py ./target                     # human-readable summary
  elf-summary.py ./target --sections          # include the section table
  elf-summary.py ./target --symbols imports   # list imported symbols
  elf-summary.py ./target --json              # machine-readable output
  elf-summary.py ./app.apk                   # APK: lists contained members
"""
import argparse
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _binlib as B  # noqa: E402

UNKNOWN = "unknown"


def _fmt_addr(v):
    return "unknown" if v is None else f"0x{v:x}"


def summarize(path, args):
    fmt = B.sniff(path)

    # Container formats: describe the payload instead of pretending to parse.
    if fmt.startswith(("APK", "JAR", "zip")):
        return container_summary(path, fmt, args)

    info = B.load(path)
    out = {
        "file": path,
        "size_bytes": os.path.getsize(path),
        "sha256": B.hash_file(path) if args.hash else None,
        "format": info.fmt,
        "architecture": info.arch or UNKNOWN,
        "bits": info.bits if info.bits else UNKNOWN,
        "endianness": info.endian or UNKNOWN,
        "image_base": _fmt_addr(info.imagebase),
        "entrypoint": _fmt_addr(info.entrypoint),
        "entrypoint_rva": _fmt_addr(info.extra.get("entry_rva"))
        if info.fmt == "PE" else None,
        "stripped": info.stripped,
        "position_independent": info.is_pie,
        "build_id": info.build_id,
        "soname": info.soname or UNKNOWN,
        "needed": info.needed,
        "notes": info.notes,
        "counts": {
            "sections": len(info.sections),
            "segments": len(info.segments),
            "symbols_total": len(info.symbols),
            "symbols_dynamic": len(info.dyn_symbols()),
            "symbols_static": len(info.static_symbols()),
            "exports": len(info.exports()),
            "imports": len(info.imports()),
            "functions": len(info.functions()),
        },
        "format_details": {k: v for k, v in info.extra.items()
                           if k not in ("data_directories",)},
        "sections": [s.to_dict() for s in info.sections] if args.sections else None,
        "segments": [s.to_dict() for s in info.segments] if args.sections else None,
    }
    if args.symbols:
        out["symbol_listing"] = _symbol_listing(info, args.symbols)
    return out


def _symbol_listing(info, kinds):
    def matches(s):
        if "exports" in kinds and s in info.exports():
            return True
        if "imports" in kinds and s in info.imports():
            return True
        return False

    exports = {id(s) for s in info.exports()}
    imports = {id(s) for s in info.imports()}
    rows = []
    for s in info.symbols:
        if not s.name:
            continue
        role = ("export" if id(s) in exports else
                "import" if id(s) in imports else "local")
        if not matches(s):
            continue
        rows.append({"name": s.name, "role": role, "value": _fmt_addr(s.value),
                     "size": s.size, "type": s.type, "bind": s.bind,
                     "table": s.table})
    rows.sort(key=lambda r: r["name"])
    if args.limit:
        rows = rows[:args.limit]
    return rows


def container_summary(path, fmt, args):
    """APK / JAR / zip: report members so the agent knows what to extract."""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        native = [n for n in names if n.endswith(".so")]
        dex = [n for n in names if n.endswith(".dex")]
        classes = [n for n in names if n.endswith(".class")]
        manifest = "AndroidManifest.xml" in names
    return {
        "file": path,
        "size_bytes": os.path.getsize(path),
        "sha256": B.hash_file(path) if args.hash else None,
        "format": fmt,
        "container_note": (
            "This is a zip container, not a directly parseable binary. "
            "Extract the members you need and run the analysis on those."),
        "android_manifest": manifest,
        "counts": {
            "members": len(names),
            "dex": len(dex),
            "native_libs": len(native),
            "classes": len(classes),
        },
        "dex_members": dex,
        "native_libs": native,
        "extraction_hint": (
            "unzip -o -d out/ " + path) if names else None,
    }


def render(d):
    if d.get("format", "").startswith(("APK", "JAR", "zip")):
        lines = [
            f"file            : {d['file']}",
            f"size            : {d['size_bytes']} bytes",
            f"format          : {d['format']}",
            f"android manifest: {d['android_manifest']}",
            f"members         : {d['counts']['members']} "
            f"(dex {d['counts']['dex']}, .so {d['counts']['native_libs']}, "
            f"class {d['counts']['classes']})",
        ]
        if d["dex_members"]:
            lines.append("dex members     : " + ", ".join(d["dex_members"][:10]))
        if d["native_libs"]:
            lines.append("native libs     : " + ", ".join(d["native_libs"][:10]))
        lines.append("")
        lines.append(d["container_note"])
        lines.append(f"extract with    : {d['extraction_hint']}")
        return "\n".join(lines)

    c = d["counts"]
    lines = [
        f"file          : {d['file']}",
        f"size          : {d['size_bytes']} bytes"
        + (f"   sha256 {d['sha256']}" if d["sha256"] else ""),
        f"format        : {d['format']}",
        f"architecture  : {d['architecture']}  {d['bits']}-bit  "
        f"{d['endianness']}-endian",
        f"image base    : {d['image_base']}",
        f"entrypoint    : {d['entrypoint']}"
        + (f"  (rva {d['entrypoint_rva']})" if d.get("entrypoint_rva") else ""),
        f"stripped      : {d['stripped']}",
        f"PIE/ASLR      : {d['position_independent']}",
        f"build-id      : {d['build_id'] or UNKNOWN}",
        f"soname        : {d['soname']}",
        "",
        f"dependencies  : {len(d['needed'])}",
    ]
    lines += [f"  - {n}" for n in d["needed"]] or ["  none recorded"]
    lines += [
        "",
        f"counts        : sections {c['sections']}  segments {c['segments']}  "
        f"symbols {c['symbols_total']} (dyn {c['symbols_dynamic']}, "
        f"static {c['symbols_static']})",
        f"                exports {c['exports']}  imports {c['imports']}  "
        f"functions {c['functions']}",
    ]
    if d["notes"]:
        lines += ["", "notes         :"] + [f"  - {n}" for n in d["notes"]]
    fd = d.get("format_details") or {}
    if fd:
        lines += ["", "format details:"]
        for k in sorted(fd):
            v = fd[k]
            if v not in (None, [], {}):
                lines.append(f"  {k}: {v}")
    if d.get("sections"):
        lines += ["", "sections:"]
        lines.append(f"  {'name':<28} {'addr':>12} {'offset':>10} "
                     f"{'size':>10}  flags   entropy")
        for s in d["sections"]:
            lines.append(f"  {s['name'] or '-':<28} {_fmt_addr(s['addr']):>12} "
                         f"{s['offset']:>10} {s['size']:>10}  "
                         f"{s['flags']:#x}  {s['entropy']}")
        lines.append("")
        lines.append("  high entropy (>7.0) often means compressed/encrypted data")
    if d.get("segments"):
        lines += ["", "segments:"]
        lines.append(f"  {'type':<16} {'vaddr':>12} {'offset':>10} "
                     f"{'filesz':>10} {'memsz':>10}")
        for s in d["segments"]:
            lines.append(f"  {s['type']:<16} {_fmt_addr(s['vaddr']):>12} "
                         f"{s['offset']:>10} {s['filesz']:>10} {s['memsz']:>10}")
    if d.get("symbol_listing"):
        lines += ["", "symbols:"]
        lines.append(f"  {'role':<8} {'value':>14} {'size':>7}  name")
        for s in d["symbol_listing"]:
            lines.append(f"  {s['role']:<8} {s['value']:>14} {s['size']:>7}  "
                         f"{s['name']}")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(
        description="Summarize a binary's format, layout and symbols.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("file", help="binary to inspect")
    p.add_argument("--sections", action="store_true",
                   help="include the section and segment tables")
    p.add_argument("--symbols", nargs="*", choices=["imports", "exports"],
                   default=None,
                   help="list symbols by role (default: both when given)")
    p.add_argument("--limit", type=int, default=200,
                   help="max symbols to list (default 200)")
    p.add_argument("--hash", action="store_true",
                   help="compute the SHA-256 of the file")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    if not os.path.exists(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 2
    if os.path.isdir(args.file):
        print(f"error: {args.file} is a directory", file=sys.stderr)
        return 2

    try:
        data = summarize(args.file, args)
    except B.ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"error: permission denied reading {args.file}: {e}",
              file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(render(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())