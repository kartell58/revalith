#!/usr/bin/env python3
"""universal-dump.py -- evidence-oriented triage of an unknown target.

An orchestrator, not an analyser. It walks a target, identifies files by
content, collects network indicators with provenance, delegates to external
tools when they exist, and produces a report that ranks what to investigate
next based on observed evidence.

It deliberately does NOT reimplement Ghidra, radare2, IL2CPP dumpers or
specialised format parsers. Detection and delegation are its job.

Design rules that this tool holds itself to:

  * Identify by content first; the extension is corroboration, not proof.
  * An unidentified file is ``unknown`` with its evidence, never guessed.
  * High entropy alone never yields "encrypted". It raises a hypothesis.
  * Every indicator carries the file and offset it came from; when the
    offset cannot be determined it is ``null``, never invented.
  * Missing external tools are recorded, not fatal. One bad file never
    aborts the run.
  * No network access. Everything works offline.

Examples
--------
  universal-dump.py ./app.apk                        # full triage
  universal-dump.py ./lib -o /tmp/dump --depth full   # a whole tree
  universal-dump.py ./app.apk --extract               # extract first
  universal-dump.py ./game --il2cpp-tool Il2CppDumper # record the dumper
  universal-dump.py ./app.apk --json                 # report.json to stdout
  universal-dump.py ./target --quiet                 # less console noise
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "dumpers"))

import _binlib as B          # noqa: E402
import _tools                # noqa: E402
from dumpers import _android, _archives, _assets, _binaries, _formats, \
    _indicators, _report, _unity  # noqa: E402

TEXT_CATEGORIES = {"text", "config", "javascript", "json", "xml", "html"}
BINARY_EXTS = (".so", ".dll", ".dylib", ".exe", ".o", ".a", ".elf", ".dex")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}


def log(msg, quiet=False):
    if not quiet:
        print(msg, file=sys.stderr)


def iter_targets(target: str):
    """Yield (absolute_path, relative_label) for every file under target.

    For a single-file target the label is the basename, so reports read
    ``libfoo.so`` rather than a bare ``.``.
    """
    if os.path.isfile(target):
        yield target, os.path.basename(target)
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            yield full, os.path.relpath(full, target)


def main():
    p = argparse.ArgumentParser(
        description="Evidence-oriented triage orchestrator for unknown targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("target", help="file, directory, APK, AAB or archive")
    p.add_argument("-o", "--out", default=None,
                   help="output directory (default: <target>-dump)")
    p.add_argument("--depth", choices=["quick", "binaries", "full"],
                   default="full",
                   help="quick=metadata only, binaries=+binaries and archives, "
                        "full=+string scan of every scannable file")
    p.add_argument("--extract", action="store_true",
                   help="extract archives before analysing their contents")
    p.add_argument("--max-string-bytes", type=int, default=4 * 1024 * 1024,
                   help="per-file string scan limit in bytes (default 4 MiB)")
    p.add_argument("--max-files", type=int, default=20000,
                   help="maximum files to process (default 20000)")
    p.add_argument("--il2cpp-tool", default=None,
                   help="force a specific IL2CPP dumper instead of "
                        "auto-selecting the first available one")
    p.add_argument("--il2cpp-timeout", type=int, default=600,
                   help="seconds allowed for an external dumper (default 600)")
    p.add_argument("--no-hash", action="store_true",
                   help="skip file hashing (faster, less comparable)")
    p.add_argument("--tools-only", action="store_true",
                   help="only report which tools are available, then exit")
    p.add_argument("--json", action="store_true",
                   help="write report.json to stdout as well")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="suppress progress output")
    args = p.parse_args()

    if not os.path.exists(args.target):
        print(f"error: no such file or directory: {args.target}",
              file=sys.stderr)
        return 2

    # ---- tool discovery first: nothing below assumes a tool exists ----
    tool_report = _tools.discover()
    log(f"tools found: {len(tool_report.found)}; "
        f"missing: {len(tool_report.missing)}", args.quiet)

    if args.tools_only:
        if args.json:
            print(json.dumps(tool_report.to_dict(), indent=2))
        else:
            print(f"{'group':<16} {'status':<10} detail")
            for group in sorted(set(_tools.TOOL_GROUPS)):
                if group in tool_report.found:
                    ver = tool_report.versions.get(group)
                    print(f"{group:<16} {'available':<10} "
                          f"{tool_report.found[group]} {ver or ''}")
                else:
                    print(f"{group:<16} {'MISSING':<10} "
                          f"tried: {', '.join(_tools.TOOL_GROUPS[group])}")
            print(f"\nMissing tools change coverage, not correctness. The "
                  f"bundled parsers are stdlib-only and work regardless.")
        return 0

    outdir = args.out or f"{args.target.rstrip(os.sep)}-dump"
    report = _report.new_report(args.target, tool_report)

    # ---- classify the top-level target --------------------------------
    top_fmt = B.sniff(args.target)
    report["target"]["sniffed_format"] = top_fmt
    report["target"]["type"] = _target_type(args.target, top_fmt)
    log(f"target type: {report['target']['type']}", args.quiet)

    # ---- optional pre-extraction --------------------------------------
    work_root = args.target
    if args.extract and os.path.isfile(args.target):
        dest = os.path.join(outdir, "extracted")
        log(f"extracting {args.target} -> {dest}", args.quiet)
        res = _archives.extract_all(args.target, dest, fmt=top_fmt)
        if res.get("error"):
            _report.add_warning(report, "extract", res["error"])
            for n in res.get("notes", []):
                _report.add_warning(report, "extract", n)
        else:
            report["target"]["extracted_to"] = dest
            report["target"]["extraction"] = res
            work_root = dest
            if res["extracted"] == 0:
                _report.add_warning(
                    report, "extract",
                    "nothing was extracted; analysing the container itself")
                work_root = args.target

    # ---- catalogue every file -----------------------------------------
    log("catalogueing files...", args.quiet)
    catalogue: list = []
    all_paths = []
    for full, label in iter_targets(work_root):
        all_paths.append((full, label))
        if len(catalogue) >= args.max_files:
            _report.add_warning(
                report, "catalogue",
                f"stopped after --max-files={args.max_files}; the rest of the "
                f"tree was not examined")
            break
        try:
            rec = _assets.catalogue_file(full, root=work_root,
                                         do_hash=not args.no_hash)
            rec["path"] = label          # single-file targets read better
            rec["_abs"] = full
            rec["_label"] = label
            catalogue.append(rec)
        except OSError as e:
            catalogue.append({"path": label, "size": None,
                              "format": "unknown",
                              "error": f"{type(e).__name__}: {e}",
                              "_abs": full, "_label": label})
    report["files"]["catalogue"] = catalogue
    report["files"]["count"] = len(catalogue)
    report["files"]["total_bytes"] = sum(r.get("size") or 0 for r in catalogue)
    report["files"]["summary"] = _assets.summarise(catalogue)

    # ---- android ------------------------------------------------------
    android_recs = [r for r in catalogue
                    if r.get("format") == "zip" and _looks_android(r)]
    for rec in android_recs[:5]:
        log(f"android container: {rec['path']}", args.quiet)
        a = _android.analyse_apk(rec["_abs"], extract_to=None)
        a["path"] = rec["path"]
        a["observations"] = _android.apk_observations(a)
        report["android"] = a
        if a.get("error"):
            _report.add_warning(report, "android", a["error"])
        for w in a.get("warnings", [])[:10]:
            _report.add_warning(report, "android", w)
        for ind in a.get("indicators", []):
            pass  # merged below via the indicator collector
        break

    # ---- binaries -----------------------------------------------------
    bin_catalogue = [r for r in catalogue
                     if _is_binary(r)]
    if args.depth in ("binaries", "full"):
        log(f"triaging {len(bin_catalogue)} binaries...", args.quiet)
        for rec in bin_catalogue[:400]:
            try:
                b = _binaries.triage(rec["_abs"], want_relocs=True,
                                     want_strings=False)
            except Exception as e:      # noqa: BLE001
                _report.add_warning(report, "binaries",
                                    f"{rec['path']}: {type(e).__name__}: {e}")
                continue
            b["path"] = rec["path"]
            report["binaries"].append(b)
            if b.get("error"):
                _report.add_warning(report, "binaries",
                                    f"{rec['path']}: {b['error']}")
            for w in b.get("warnings", [])[:5]:
                _report.add_warning(report, "binaries",
                                    f"{rec['path']}: {w}")

    # architectures observed across binaries
    archs = []
    for b in report["binaries"]:
        a = b.get("architecture")
        if a and a != "unknown" and a not in archs:
            archs.append(a)
    if report.get("android"):
        archs = sorted(set(archs) | set(report["android"].get("abis") or []))
    report["target"]["architectures"] = archs

    # ---- archives -----------------------------------------------------
    arc_catalogue = [r for r in catalogue
                     if _formats.is_probably_archive(r.get("format", ""))]
    for rec in arc_catalogue[:200]:
        try:
            arc = _archives.inspect(rec["_abs"], fmt=rec.get("format"))
        except Exception as e:          # noqa: BLE001
            _report.add_warning(report, "archives",
                                f"{rec['path']}: {type(e).__name__}: {e}")
            continue
        arc.path = rec["path"]
        names = [m.name for m in arc.members]
        interesting = (_archives.interesting_members(names)
                       if names else {})
        entry = arc.to_dict()
        entry["interesting"] = interesting
        report["archives"].append(entry)
        if not arc.readable and arc.notes:
            for n in arc.notes[:3]:
                _report.add_warning(report, "archives", f"{rec['path']}: {n}")

    # ---- unity / il2cpp ------------------------------------------------
    log("checking for Unity / IL2CPP indicators...", args.quiet)
    member_names = []
    for arc in report["archives"]:
        for m in arc.get("members", []):
            member_names.append(m["name"])
    unity = _unity.detect_from_names(member_names)
    if unity.get("detected"):
        log(f"Unity detected: il2cpp={unity['il2cpp']}", args.quiet)
        # Metadata may be an extracted file, or still only an archive member.
        meta_candidates = [r for r in catalogue
                           if os.path.basename(r["path"]).lower()
                           == "global-metadata.dat"]
        meta_abs = None
        meta_label = None
        if meta_candidates:
            meta_abs = meta_candidates[0]["_abs"]
            meta_label = meta_candidates[0]["path"]
        else:
            # Pull the metadata out of the container so it can be probed and
            # handed to a dumper; without extraction we could only name it.
            member = next(
                (n for n in member_names
                 if os.path.basename(n).lower() == "global-metadata.dat"), None)
            if member:
                extracted = _extract_member(args.target, member,
                                           os.path.join(outdir, "unity"))
                if extracted:
                    meta_abs, meta_label = extracted
                else:
                    _report.add_warning(
                        report, "unity",
                        f"metadata member {member} found but could not be "
                        f"extracted; its format was not probed")
        if meta_abs:
            meta = _unity.probe_metadata(meta_abs)
            meta["path"] = meta_label
            unity["metadata"] = meta
            log(f"  metadata: status={meta['status']} "
                f"standard_magic={meta['standard_magic']}", args.quiet)
        else:
            unity["metadata"] = None
        il2cpp_bin = None
        for r in catalogue:
            if os.path.basename(r["path"]).lower().startswith("libil2cpp"):
                il2cpp_bin = r["_abs"]
                break
        if meta_abs and il2cpp_bin:
            unity["dumper"] = _unity.delegate(
                meta_abs, il2cpp_bin, os.path.join(outdir, "unity", "il2cpp"),
                tool_report=tool_report, timeout=args.il2cpp_timeout,
                max_tool=args.il2cpp_tool)
        elif meta_abs:
            unity["dumper"] = {
                "attempted": False,
                "error": "metadata found but no IL2CPP binary was located "
                         "on disk; extract the container first so the dumper "
                         "can be given both inputs"}
        else:
            unity["dumper"] = {
                "attempted": False,
                "error": "no global-metadata.dat found, so no dumper was run"}
        unity["version_hints"] = _unity.version_hints(
            member_names, search_root=work_root if os.path.isdir(work_root)
            else None)
    report["unity"] = unity

    # ---- indicators ----------------------------------------------------
    if args.depth == "full":
        log("scanning for strings and network indicators...", args.quiet)
    scan_list = []
    for rec in catalogue:
        fmt = rec.get("format", "")
        cat = rec.get("category")
        size = rec.get("size") or 0
        if fmt in ("elf", "pe", "macho", "macho-fat", "dex", "text", "json",
                   "xml", "javascript", "html", "sqlite", "ar", "wasm") or \
                cat in ("binary", "text", "config", "android"):
            scan_list.append(rec)
        elif size and size <= 512 * 1024 and cat == "other":
            scan_list.append(rec)
    all_inds = []
    scanned = 0
    not_scanned = 0
    all_strings: list = []
    for rec in scan_list:
        if args.depth != "full" and rec.get("category") == "text":
            not_scanned += 1
            continue
        if (rec.get("size") or 0) == 0:
            not_scanned += 1
            continue
        try:
            res = _indicators.scan_file(rec["_abs"], min_len=5,
                                        limit=args.max_string_bytes)
        except OSError as e:
            not_scanned += 1
            continue
        if res.get("error"):
            _report.add_warning(report, "strings",
                                f"{rec['path']}: {res['error']}")
            not_scanned += 1
            continue
        scanned += 1
        if res.get("partial"):
            report["coverage"]["partial_scan_files"].append({
                "path": rec["path"], "scanned": res["bytes_scanned"],
                "size": res.get("total_size")})
        for s in res["strings"]:
            all_strings.append({"text": s["text"],
                                "offset": f"0x{s['offset']:x}",
                                "encoding": s["encoding"],
                                "source": rec["path"]})
        all_inds.extend(res["indicators"])

    if report.get("android"):
        for ind in report["android"].get("indicators", []):
            all_inds.append(ind)

    all_inds = _indicators.dedupe(all_inds)
    report["indicators"]["summary"] = _indicators.summarise(all_inds)
    buckets = {"url": "urls", "domain": "domains", "ipv4": "ipv4",
               "ipv6": "ipv6", "api_path": "api_paths"}
    for kind, key in buckets.items():
        vals = [i.to_dict() for i in all_inds if i.kind == kind]
        report["indicators"][key] = vals
    ports = {}
    for i in all_inds:
        if i.port:
            ports.setdefault(str(i.port), []).append(i.value)
    report["indicators"]["ports"] = [
        {"port": int(p), "seen_on": sorted(set(v))[:5]}
        for p, v in sorted(ports.items(), key=lambda kv: int(kv[0]))]
    report["indicators"]["note"] = (
        "each entry carries source and offset; offsets are null where they "
        "could not be determined")

    report["coverage"]["files_scanned_for_strings"] = scanned
    report["coverage"]["files_not_scanned"] = not_scanned
    report["coverage"]["notes"].append(
        f"depth={args.depth}: 'quick' skips binaries and string scanning, "
        f"'binaries' skips string scanning of text files")
    if args.no_hash:
        report["coverage"]["notes"].append(
            "hashing disabled via --no-hash: results are not comparable "
            "against other dumps by hash")

    # ---- write artefacts ------------------------------------------------
    os.makedirs(outdir, exist_ok=True)
    _report.build_priorities(report)

    sdir = os.path.join(outdir, "strings")
    _report.write_lines(
        os.path.join(sdir, "all.txt"),
        [f"{s['offset']}  {s['encoding']:<8} {s['source']}  {s['text']}"
         for s in all_strings[:200000]],
        header="# offset  encoding  source  text\n")
    for key, kind in (("urls", "url"), ("domains", "domain"),
                      ("ips", None), ("api_paths", "api_path")):
        if kind is None:
            rows = (report["indicators"]["ipv4"] +
                    report["indicators"]["ipv6"])
        else:
            rows = report["indicators"][key]
        _report.write_lines(
            os.path.join(sdir, f"{key}.txt"),
            [f"{r['value']}  <- {r['source']}"
             + (f" @{r['offset']}" if r.get("offset") else "  @offset:unknown")
             + (f"  [{r['confidence']}]" if r.get("confidence") else "")
             for r in rows],
            header="# value  <- source  offset  confidence\n")

    _report.write_hashes(outdir, report)
    written = _report.write_report(report, outdir)
    report["output"] = written

    # ---- console --------------------------------------------------------
    txt = _report.render_text(report)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(txt)
    log(f"\nwrote {outdir}/report.json and report.txt", args.quiet)
    if report["errors"]:
        log(f"completed with {len(report['errors'])} error(s); see report.json",
            args.quiet)
    return 0


def _extract_member(container: str, member: str, dest: str):
    """Extract one member from a zip container. Returns (abs, label) or None."""
    import zipfile
    try:
        os.makedirs(dest, exist_ok=True)
        base = os.path.basename(member) or "member"
        out = os.path.join(dest, base)
        with zipfile.ZipFile(container) as zf:
            with zf.open(member) as src, open(out, "wb") as dst:
                dst.write(src.read())
        return out, f"{os.path.basename(container)}!{member}"
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return None


def _target_type(target: str, sniffed: str) -> str:
    if os.path.isdir(target):
        return "directory"
    if sniffed == "APK (zip)":
        return "android-apk"
    if sniffed in ("Mach-O", "Mach-O universal (FAT)"):
        return "macho-binary"
    if sniffed == "PE":
        return "pe-binary"
    if sniffed == "ELF":
        return "elf-binary"
    if sniffed == "DEX":
        return "dex"
    if _formats.is_probably_archive(sniffed):
        return sniffed + "-archive"
    if "zip" in sniffed:
        return "zip-archive"
    return sniffed


def _looks_android(rec: dict) -> bool:
    members = (rec.get("unknown_analysis") and None)
    name = os.path.basename(rec["path"]).lower()
    if name.endswith((".apk", ".aab", ".apks", ".xapk")):
        return True
    summary = rec.get("unknown_analysis")
    return bool(name.endswith((".apk", ".aab", ".xapk", ".apks")))


def _is_binary(rec: dict) -> bool:
    if rec.get("format") in ("elf", "pe", "macho", "macho-fat", "dex"):
        return True
    if (rec.get("extension") or "").lower() in BINARY_EXTS:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())