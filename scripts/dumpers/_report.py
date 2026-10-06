"""
_report.py -- write the dump, and rank what to look at next.

Two rules shape this module.

**Nothing is invented.** A field that could not be determined is ``null`` with
a reason, never a plausible value.

**The output must be useful to the next step.** A dump that only says "found
123 files" has not done its job. :func:`next_steps` ranks candidates using
observed properties only, and each entry states the evidence behind its rank
so a reader can disagree with it.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

SCHEMA_VERSION = "1.0"


def new_report(target: str, tool_report=None) -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"),
        "generator": "universal-dump.py",
        "target": {
            "path": target,
            "type": "unknown",
            "architectures": [],
        },
        "tools": (tool_report.to_dict() if tool_report else
                  {"found": {}, "missing_groups": [],
                   "note": "tool discovery was not run"}),
        "files": {
            "count": 0,
            "total_bytes": 0,
            "catalogue": [],
            "summary": {},
        },
        "binaries": [],
        "android": None,
        "unity": {
            "detected": False,
            "il2cpp": False,
            "metadata": None,
            "version_hints": [],
            "dumper": {"attempted": False,
                       "error": "not attempted; nothing detected"},
        },
        "archives": [],
        "assets": {},
        "configs": [],
        "indicators": {
            "urls": [], "domains": [], "ipv4": [], "ipv6": [],
            "api_paths": [], "ports": [], "summary": {},
        },
        "notable": [],
        "next_steps": [],
        "reconstruction_candidates": [],
        "warnings": [],
        "errors": [],
        "coverage": {
            "files_catalogue": "complete",
            "files_scanned_for_strings": 0,
            "files_not_scanned": 0,
            "partial_scan_files": [],
            "notes": [],
        },
    }


def add_error(report: Dict, where: str, message: str) -> None:
    report["errors"].append({"stage": where, "message": message})


def add_warning(report: Dict, where: str, message: str) -> None:
    report["warnings"].append({"stage": where, "message": message})


# ---------------------------------------------------------------- next steps

_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def next_steps(report: Dict, max_items: int = 25) -> List[Dict]:
    """Rank investigation targets from observed evidence.

    Every entry names the observations that produced it. A candidate with no
    evidence behind it is not listed -- guessing a priority would be exactly
    the failure the skill exists to prevent.
    """
    steps: List[Dict] = []

    def add(target: str, reasons: List[str], priority: str,
            suggestion: str, kind: str = "file"):
        if not reasons:
            return
        steps.append({
            "target": target,
            "kind": kind,
            "priority": priority,
            "reason": "; ".join(reasons),
            "suggested_action": suggestion,
        })

    # -- binaries -------------------------------------------------------
    for b in report.get("binaries", []):
        if not b.get("analysed"):
            continue
        reasons: List[str] = []
        arch = b.get("architecture") or "unknown arch"
        reasons.append(f"{b.get('format')} {arch} {b.get('size')} bytes")
        if b.get("stripped"):
            reasons.append("symbols stripped")
        jni = b.get("jni_export_count") or 0
        if jni:
            reasons.append(f"{jni} JNI export(s)")
        hint = b.get("notable_hint") or {}
        if hint.get("reasons"):
            reasons.extend(hint["reasons"])
        prio = hint.get("priority") or ("medium" if b.get("stripped") else "low")
        suggestion = ("run scripts/elf-summary.py and scripts/strings-map.py "
                      "--xrefs on it")
        if b.get("format") == "PE":
            suggestion = "run objdump -x, then examine imports and the IAT"
        elif b.get("format") == "Mach-O":
            suggestion = ("check LC_ENCRYPTION_INFO (cryptid) before trusting "
                          "on-disk text, then nm")
        add(b["path"], reasons, prio, suggestion, kind="binary")

    # -- unity / il2cpp -------------------------------------------------
    unity = report.get("unity", {})
    if unity.get("detected"):
        reasons = list(unity.get("evidence", []))
        add("unity", reasons or ["Unity indicators observed"],
            "high" if unity.get("il2cpp") else "medium",
            "read references/unity guidance; locate the build's data directory",
            kind="container")
        meta = unity.get("metadata")
        if meta and meta.get("detected"):
            meta_reasons = [f"metadata file {os.path.basename(meta['path'])}",
                            f"status={meta.get('status')}"]
            if not meta.get("standard_magic"):
                meta_reasons.append("standard IL2CPP magic absent")
            add(meta["path"], meta_reasons, "high",
                "read references/android.md Unity section; if a dumper tool is "
                "listed as available, run it and record the outcome",
                kind="metadata")

    # -- android --------------------------------------------------------
    android = report.get("android")
    if android:
        reasons = []
        if android.get("kind") == "apk":
            reasons.append("APK container")
        if android.get("abis"):
            reasons.append("ABIs: " + ", ".join(android["abis"]))
        if android.get("dex_files"):
            reasons.append(f"{len(android['dex_files'])} DEX file(s)")
        nl = android.get("native_libraries") or []
        if nl:
            reasons.append(f"{len(nl)} native librar{'y' if len(nl)==1 else 'ies'}")
        add(android["path"], reasons, "high",
            "read references/android.md; triage each ABI's native libraries "
            "with universal-dump.py --depth binaries")

    # -- indicators -----------------------------------------------------
    ind = report.get("indicators", {}).get("summary", {})
    counts = ind.get("counts", {})
    urls = counts.get("url", 0)
    domains = counts.get("domain", 0)
    if urls or domains:
        reasons = [f"{urls} URL(s)", f"{domains} domain(s)"]
        add("indicators", reasons, "medium",
            "review strings/urls.txt; each entry carries its source file and "
            "offset so it can be traced back",
            kind="indicators")

    # -- unrecognised, high entropy -------------------------------------
    summary = report.get("files", {}).get("summary", {})
    unk = summary.get("unknown_format_files", [])
    if unk:
        big = [u for u in unk if (u.get("size") or 0) >= 65536][:5]
        reasons = [f"{len(unk)} file(s) of unidentified format"]
        if big:
            reasons.append("largest: " + ", ".join(
                f"{u['path']} ({u.get('size')}B)" for u in big))
        add("unidentified files", reasons,
            "high" if big else "low",
            "check magic at non-zero offsets and look for a length prefix; "
            "classify_blob() records why each one is unknown",
            kind="category")

    he = summary.get("high_entropy_files", [])
    if he:
        reasons = [f"{len(he)} file(s) with entropy >= 7.5 over >= 4 KiB"]
        reasons.append("largest: " + he[0]["path"])
        add("high-entropy files", reasons, "medium",
            "compare byte distribution against known compressors; confirm "
            "compression by attempting decompression before claiming it",
            kind="category")

    # -- archives -------------------------------------------------------
    for arc in report.get("archives", []):
        if arc.get("interesting"):
            interesting = arc["interesting"]
            reasons = [f"archive with {arc.get('member_count')} members",
                       f"contains {', '.join(sorted(interesting))}"]
            add(arc["path"], reasons, "high",
                "extract and re-run universal-dump.py on the extracted tree",
                kind="archive")
        elif not arc.get("readable_with_stdlib"):
            reasons = [f"{arc.get('kind')} archive not readable with the "
                       "standard library"]
            add(arc["path"], reasons, "medium",
                "install one of the listed tools, or extract manually, then "
                "re-run the dump",
                kind="archive")

    steps.sort(key=lambda s: (_PRIORITY_ORDER.get(s["priority"], 9),
                              s["target"]))
    return steps[:max_items]


def build_priorities(report: Dict) -> None:
    report["next_steps"] = next_steps(report)
    report["reconstruction_candidates"] = reconstruction_candidates(report)


def reconstruction_candidates(report: Dict, max_items: int = 20) -> List[Dict]:
    """Rank targets by how much a reconstruction of them would explain.

    The difference from :func:`next_steps` is the question being asked. That
    function asks "what should I look at first"; this one asks "what should I
    reconstruct first", which favours large binaries, central data files and
    anything another artefact depends on -- and disfavours what is merely
    interesting to read.

    A candidate is only listed when an observation supports it. A file with no
    observations is not a reconstruction candidate, however suspicious it
    looks, because ranking it would be a guess wearing a priority.
    """
    items: List[Dict] = []

    def add(target: str, kind: str, reasons: List[str], priority: str,
            action: str, size=None):
        if not reasons:
            return
        items.append({
            "target": target, "kind": kind, "priority": priority,
            "reasons": reasons, "reason": "; ".join(reasons),
            "suggested_action": action, "size": size,
        })

    # -- binaries: the executable bodies a reimplementation must replace --
    for b in report.get("binaries", []):
        if not b.get("analysed"):
            continue
        reasons: List[str] = []
        size = b.get("size")
        if b.get("entrypoint"):
            reasons.append("has an entry point: this is program logic, not "
                           "just a library")
        if b.get("elf_type") == "EXEC" or b.get("format") == "PE":
            pass
        counts = b.get("counts") or {}
        funcs = counts.get("functions") or 0
        if funcs:
            reasons.append(f"{funcs} function(s) to reconstruct")
        if b.get("stripped"):
            reasons.append("stripped: names must be recovered, so a "
                           "reimplementation has more to re-derive")
        if b.get("jni_export_count"):
            reasons.append(f"{b['jni_export_count']} JNI export(s) define a "
                           f"reconstruction boundary with the Java layer")
        if b.get("interpreter"):
            reasons.append("executable with a PT_INTERP: it can be run, so "
                           "differential testing is available")
        size_mb = (size or 0) / (1024 * 1024)
        if size_mb >= 1:
            reasons.append(f"{size_mb:.1f} MiB: a substantial share of the "
                           f"behaviour lives here")
        if reasons:
            prio = "high" if (b.get("entrypoint") and size_mb >= 1) else \
                ("medium" if reasons else "low")
            add(b["path"], "binary", reasons, prio,
                "record each understood function in the ledger "
                "(recon-ledger.py); a reimplementation follows the ledger",
                size=size)

    # -- android: the layer a native reimplementation must interoperate with
    android = report.get("android")
    if android and not android.get("error"):
        reasons = []
        dex = android.get("dex_files") or []
        if dex:
            reasons.append(f"{len(dex)} DEX file(s): the managed layer defines "
                           f"the entry points")
        nl = android.get("native_libraries") or []
        if nl:
            reasons.append(f"{len(nl)} native librar"
                           f"{'y' if len(nl) == 1 else 'ies'}: the boundary "
                           f"between the two layers")
        m = android.get("manifest") or {}
        if m.get("activities"):
            reasons.append(f"{len(m['activities'])} declared activities: "
                           f"the reconstruction's surface")
        if reasons:
            add(android["path"], "android", reasons, "high",
                "reconstruct the JNI boundary before either side: it is the "
                "contract both implementations must satisfy")

    # -- unity / il2cpp: naming is the bottleneck, and it is recoverable --
    unity = report.get("unity") or {}
    if unity.get("il2cpp"):
        reasons = list(unity.get("evidence") or [])
        meta = unity.get("metadata") or {}
        if meta.get("detected"):
            reasons.append(f"metadata present ({meta.get('size')} bytes): "
                           f"method and field names are recoverable from it")
        if meta.get("standard_magic"):
            reasons.append("standard metadata header: a dumper is likely to "
                           "work, which makes name recovery mechanical")
        if reasons:
            add("unity/il2cpp", "managed-runtime", reasons, "high",
                "run a dumper on the metadata and enter the recovered names "
                "into the ledger; do not reverse the stripped runtime by hand")

    # -- data files: reconstruction targets that are not code at all -------
    summary = report.get("files", {}).get("summary", {})
    structured = []
    for rec in report.get("files", {}).get("catalogue", []):
        fmt = rec.get("format")
        if fmt in ("zip", "gzip", "xz", "bzip2", "7z", "rar", "tar",
                   "cab", "lzma"):
            continue          # containers are listed separately
        size = rec.get("size") or 0
        if fmt in ("dex", "sqlite", "wasm", "unity-assetbundle", "elf", "pe",
                   "macho", "macho-fat"):
            continue          # already covered above
        if fmt in ("text", "json", "xml", "javascript", "html", "config"):
            # A configuration file is a reconstruction target when something
            # else depends on it, which the indicator scan cannot show. Listed
            # low, and only when it is large enough to carry structure.
            if size >= 64 * 1024:
                structured.append((rec.get("path"), fmt, size,
                                   "large text or configuration file: it may "
                                   "encode a format rather than be one"))
        elif fmt == "unknown" and size >= 32 * 1024:
            structured.append((rec.get("path"), fmt, size,
                               "unidentified and substantial: a format to "
                               "decode before it can be reimplemented"))
    for path, fmt, size, why in sorted(structured, key=lambda x: -(x[2] or 0)):
        prio = "high" if (fmt == "unknown" and size >= 256 * 1024) else "low"
        add(path, "data", [why], prio,
            "identify the format by content (magic, structure, entropy) "
            "before assuming what it holds")

    # -- archives: containers whose contents are the real targets ---------
    for arc in report.get("archives", []):
        interesting = arc.get("interesting") or {}
        if not interesting:
            continue
        members = sum(len(v) for v in interesting.values())
        reasons = [f"contains {members} member(s) across "
                   f"{len(interesting)} notable categories"]
        if "unity" in interesting:
            reasons.append("contains Unity or IL2CPP data")
        if "dex" in interesting:
            reasons.append("contains DEX files")
        add(arc["path"], "archive", reasons, "medium",
            "extract and re-run this dump on the extracted tree; the members "
            "are the actual reconstruction targets")

    # -- indicators: the interface a reimplementation must satisfy --------
    counts = (report.get("indicators", {}).get("summary", {}).get("counts")
              or {})
    if counts.get("url") or counts.get("domain"):
        reasons = [f"{counts.get('url', 0)} URL(s), "
                   f"{counts.get('domain', 0)} domain(s)"]
        if counts.get("api_path"):
            reasons.append(f"{counts['api_path']} API path(s)")
        add("network interface", "interface", reasons, "medium",
            "an independent implementation must satisfy this interface; "
            "verify it against the original rather than against the strings")

    order = {"high": 0, "medium": 1, "low": 2}
    items.sort(key=lambda i: (order.get(i["priority"], 9), i["target"]))
    return items[:max_items]


# ------------------------------------------------------------------- output

def write_report(report: Dict, outdir: str) -> Dict:
    """Write report.json and report.txt. Returns what was written."""
    os.makedirs(outdir, exist_ok=True)
    written: List[str] = []

    jpath = os.path.join(outdir, "report.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    written.append(jpath)

    tpath = os.path.join(outdir, "report.txt")
    with open(tpath, "w", encoding="utf-8") as fh:
        fh.write(render_text(report))
    written.append(tpath)
    return {"written": written}


def write_lines(path: str, lines: List[str], header: str = "") -> bool:
    """Write a text artefact. Returns False on failure instead of raising."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            if header:
                fh.write(header)
            for line in lines:
                fh.write(line + "\n")
        return True
    except OSError:
        return False


def write_hashes(outdir: str, report: Dict) -> Optional[str]:
    path = os.path.join(outdir, "hashes.txt")
    try:
        os.makedirs(outdir, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# sha256  size  path\n")
            t = report.get("target", {})
            for rec in report.get("files", {}).get("catalogue", []):
                if rec.get("sha256"):
                    fh.write(f"{rec['sha256']}  {rec.get('size')}  "
                             f"{rec['path']}\n")
        return path
    except OSError:
        return None


def _h(value) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value[:8]) or "none"
    return str(value)


def render_text(report: Dict) -> str:
    """Human-readable rendering. Same facts as report.json, no extras."""
    L: List[str] = []
    t = report.get("target", {})
    add = L.append

    add("=" * 74)
    add("UNIVERSAL DUMP")
    add("=" * 74)
    add(f"generated : {report.get('generated_utc')} (UTC)")
    add(f"schema    : {report.get('schema_version')}")
    add(f"target    : {t.get('path')}")
    add(f"type      : {_h(t.get('type'))}")
    add(f"architectures: {_h(t.get('architectures'))}")
    add("")

    add("-" * 74)
    add("TOOLS AVAILABLE (probed at run time; absence is not an error)")
    add("-" * 74)
    tools = report.get("tools", {})
    found = tools.get("found", {})
    if found:
        for group, exe in sorted(found.items()):
            ver = (tools.get("versions", {}) or {}).get(group)
            add(f"  {group:<16} {exe}" + (f"   ({ver})" if ver else ""))
    else:
        add("  none of the probed tools were found")
    missing = tools.get("missing_groups") or []
    if missing:
        add(f"  not found: {', '.join(missing)}")
    add("")

    files = report.get("files", {})
    summary = files.get("summary", {})
    add("-" * 74)
    add("FILES")
    add("-" * 74)
    add(f"  count        : {_h(files.get('count'))}")
    add(f"  total bytes  : {_h(files.get('total_bytes'))}")
    if summary.get("by_format"):
        add("  by format    : " + ", ".join(
            f"{k}={v}" for k, v in list(summary["by_format"].items())[:12]))
    if summary.get("by_category"):
        add("  by category  : " + ", ".join(
            f"{k}={v}" for k, v in list(summary["by_category"].items())[:12]))
    add(f"  unidentified : {_h(summary.get('unknown_format_count'))}")
    add(f"  high entropy : {_h(summary.get('high_entropy_count'))} "
        f"(entropy >= 7.5 and size >= 4 KiB)")
    if summary.get("extension_mismatches"):
        add("  extension/content mismatches:")
        for m in summary["extension_mismatches"][:10]:
            add(f"    {m['path']}: extension {m['extension']} but content "
                f"looks like {m['content_format']}")
    add("")

    if report.get("android"):
        add("-" * 74)
        add("ANDROID")
        add("-" * 74)
        _render_android(L, report["android"])
        add("")

    if report.get("binaries"):
        add("-" * 74)
        add("BINARIES")
        add("-" * 74)
        for b in report["binaries"]:
            if not b.get("analysed"):
                add(f"  {b.get('path')}: not analysed "
                    f"({b.get('error') or 'unknown reason'})")
                continue
            add(f"  {b['path']}")
            add(f"    {b.get('format')} {b.get('architecture')} "
                f"{b.get('bits')}-bit {b.get('endianness')}")
            add(f"    size {_h(b.get('size'))}  stripped={_h(b.get('stripped'))}"
                f"  pie={_h(b.get('position_independent'))}")
            if b.get("entrypoint"):
                add(f"    entry {b['entrypoint']}")
            if b.get("soname"):
                add(f"    soname {b['soname']}")
            if b.get("interpreter"):
                add(f"    interpreter {b['interpreter']}")
            if b.get("needed"):
                add(f"    needs: {', '.join(b['needed'][:10])}")
            c = b.get("counts", {})
            add(f"    symbols {c.get('symbols')} "
                f"(exports {c.get('exports')}, imports {c.get('imports')})")
            if b.get("jni_export_count"):
                add(f"    JNI exports: {b['jni_export_count']}")
            if b.get("has_tls") is not None:
                add(f"    TLS section: {_h(b.get('has_tls'))}")
            rel = b.get("relocations") or {}
            if rel.get("count") is not None:
                add(f"    relocations: {rel['count']}")
            elif rel.get("error"):
                add(f"    relocations: not read ({rel['error']})")
            hint = b.get("notable_hint") or {}
            if hint:
                add(f"    notable: {hint.get('priority')} -- "
                    f"{'; '.join(hint.get('reasons', []))}")
        add("")

    unity = report.get("unity", {})
    add("-" * 74)
    add("UNITY / IL2CPP")
    add("-" * 74)
    if not unity.get("detected"):
        add("  not detected (no Unity or IL2CPP indicators observed)")
    else:
        add(f"  detected: yes   il2cpp: {_h(unity.get('il2cpp'))}   "
            f"mono: {_h(unity.get('mono'))}")
        for e in unity.get("evidence", []):
            add(f"    - {e}")
        meta = unity.get("metadata")
        if meta:
            add(f"  metadata {os.path.basename(meta.get('path', '?'))}")
            add(f"    size {meta.get('size')}  standard_magic="
                f"{_h(meta.get('standard_magic'))}")
            add(f"    status {meta.get('status')}  confidence="
                f"{meta.get('confidence')}")
            for n in meta.get("notes", []):
                add(f"    note: {n}")
        d = unity.get("dumper", {})
        add(f"  dumper: attempted={_h(d.get('attempted'))} "
            f"tool={_h(d.get('tool'))} ok={_h(d.get('ok'))}")
        if d.get("error"):
            add(f"    error: {d['error']}")
        if d.get("argv"):
            add(f"    argv: {d['argv']}")
        if d.get("produced_files"):
            add(f"    produced {len(d['produced_files'])} file(s)")
        add("")

    ind = report.get("indicators", {})
    add("-" * 74)
    add("NETWORK INDICATORS")
    add("-" * 74)
    counts = ind.get("summary", {}).get("counts", {})
    if not counts:
        add("  none extracted")
    else:
        for kind in ("url", "domain", "ipv4", "ipv6", "api_path"):
            n = counts.get(kind, 0)
            if n:
                add(f"  {kind}: {n}")
        add("  full detail with source and offset in strings/*.txt and "
            "report.json")
    add("")

    if report.get("archives"):
        add("-" * 74)
        add("ARCHIVES")
        add("-" * 74)
        for arc in report["archives"][:30]:
            add(f"  {arc['path']}")
            add(f"    kind {arc.get('kind')}  readable={_h(arc.get('readable_with_stdlib'))}"
                f"  members={_h(arc.get('member_count'))}")
            if arc.get("interesting"):
                for k, v in sorted(arc["interesting"].items()):
                    add(f"    {k}: {len(v)} (e.g. {v[0]})")
        add("")

    add("-" * 74)
    add("NEXT STEPS (ranked from observed evidence only)")
    add("-" * 74)
    steps = report.get("next_steps", [])
    if not steps:
        add("  no prioritised targets: not enough observed evidence")
    for i, s in enumerate(steps, 1):
        add(f"  {i}. [{s['priority'].upper()}] {s['target']}  ({s['kind']})")
        add(f"      reason : {s['reason']}")
        add(f"      action : {s['suggested_action']}")
    add("")

    recon = report.get("reconstruction_candidates") or []
    if recon:
        add("-" * 74)
        add("RECONSTRUCTION CANDIDATES  (what to rebuild, not what to read)")
        add("-" * 74)
        for i, r in enumerate(recon, 1):
            add(f"  {i}. [{r['priority'].upper()}] {r['target']}  ({r['kind']})")
            for reason in r["reasons"]:
                add(f"      because : {reason}")
            add(f"      next    : {r['suggested_action']}")
        add("")
        add("  A candidate here means a reconstruction of it would explain a")
        add("  large share of the observed behaviour. It is a starting point,")
        add("  not a scope estimate.")
        add("")

    cov = report.get("coverage", {})
    add("-" * 74)
    add("COVERAGE AND LIMITS")
    add("-" * 74)
    add(f"  files string-scanned : {_h(cov.get('files_scanned_for_strings'))}")
    add(f"  files not scanned    : {_h(cov.get('files_not_scanned'))}")
    if cov.get("partial_scan_files"):
        add(f"  partially scanned    : {len(cov['partial_scan_files'])}")
    for n in cov.get("notes", []):
        add(f"  note: {n}")
    if report.get("warnings"):
        add(f"  warnings            : {len(report['warnings'])}")
        for w in report["warnings"][:15]:
            add(f"    [{w.get('stage')}] {w.get('message')}")
    if report.get("errors"):
        add(f"  errors              : {len(report['errors'])}")
        for e in report["errors"][:15]:
            add(f"    [{e.get('stage')}] {e.get('message')}")
    add("")
    add("=" * 74)
    add("This report contains observations and explicitly labelled inference.")
    add("A field reading 'unknown' means it could not be determined from the")
    add("evidence available; it is not a placeholder to be filled in later.")
    add("=" * 74)
    return "\n".join(L)


def _render_android(L: List[str], a: Dict) -> None:
    add = L.append
    add(f"  kind           : {_h(a.get('kind'))}")
    add(f"  members        : {_h(a.get('member_count'))}")
    add(f"  ABIs           : {_h(a.get('abis'))}")
    add(f"  DEX files      : {_h(a.get('dex_files'))}")
    if a.get("native_libraries"):
        add(f"  native libs    : {len(a['native_libraries'])}")
        for n in a["native_libraries"][:20]:
            add(f"    {n}")
    if a.get("signing"):
        add(f"  signing        : {', '.join(a['signing'][:5])}")
    m = a.get("manifest")
    if m:
        add("  manifest:")
        add(f"    decoded={_h(m.get('decoded'))}"
            + (f"  error={m['error']}" if m.get("error") else ""))
        for k in ("package", "version_name", "version_code", "min_sdk",
                  "target_sdk"):
            if m.get(k) is not None:
                add(f"    {k:<14}: {m[k]}")
        if m.get("debuggable") is not None:
            add(f"    debuggable    : {m['debuggable']}")
        if m.get("uses_cleartext_traffic") is not None:
            add(f"    cleartext     : {m['uses_cleartext_traffic']}")
        if m.get("network_security_config"):
            add(f"    netsec config : {m['network_security_config']}")
        if m.get("permissions"):
            add(f"    permissions   : {len(m['permissions'])}")
            for p in m["permissions"][:20]:
                add(f"      {p}")
        for bucket, items in (m.get("components") or {}).items():
            add(f"    {bucket:<14}: {len(items)}")
            for c in items[:10]:
                add(f"      {c.get('name')}  exported={_h(c.get('exported'))}")
        if m.get("deep_links"):
            add("    deep links:")
            for dl in m["deep_links"][:10]:
                add(f"      {dl['scheme']}://{dl['host']}{dl.get('path') or ''}")
    for w in (a.get("warnings") or [])[:10]:
        add(f"  warning: {w}")