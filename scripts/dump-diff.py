#!/usr/bin/env python3
"""dump-diff.py -- compare two universal-dump reports.

Answers "what changed between these two targets" at the level of files,
strings, indicators, binaries and Unity/Android state -- without pretending a
byte change is a behaviour change.

The report it reads is the one ``universal-dump.py`` produces, so a diff is
reproducible: compare two dumps, not two files at large.

The central distinction this tool preserves:

  binary difference   something in the artefact changed
  semantic difference behaviour changed

Only the first can be established by comparing artefacts. The second needs a
test against running software, which this tool cannot do and does not claim.

Examples
--------
  dump-diff.py v1/report.json v2/report.json
  dump-diff.py v1/report.json v2/report.json --section strings --limit 40
  dump-diff.py v1/report.json v2/report.json --json
"""
import argparse
import json
import os
import sys
from typing import Dict, List


def load(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def as_set(obj) -> set:
    if obj is None:
        return set()
    if isinstance(obj, list):
        return {str(x) for x in obj}
    if isinstance(obj, dict):
        return {str(k) for k in obj}
    return {str(obj)}


def diff_paths(a: Dict, b: Dict) -> Dict:
    """Files present in one dump but not the other, by path and by hash."""
    def index(rep):
        out = {}
        for rec in (rep.get("files", {}).get("catalogue", []) or []):
            out[rec.get("path")] = rec
        return out

    ia, ib = index(a), index(b)
    only_a = sorted(set(ia) - set(ib))
    only_b = sorted(set(ib) - set(ia))
    changed, same = [], 0
    for path in sorted(set(ia) & set(ib)):
        ra, rb = ia[path], ib[path]
        if ra.get("sha256") and rb.get("sha256"):
            if ra["sha256"] != rb["sha256"]:
                changed.append({
                    "path": path,
                    "sha256_before": ra["sha256"],
                    "sha256_after": rb["sha256"],
                    "size_before": ra.get("size"),
                    "size_after": rb.get("size"),
                    "format_before": ra.get("format"),
                    "format_after": rb.get("format"),
                    "size_delta": (rb.get("size") or 0) - (ra.get("size") or 0),
                })
            else:
                same += 1
        elif ra.get("size") != rb.get("size"):
            changed.append({"path": path, "note": "size differs; no hashes "
                                                   "were recorded"})
        else:
            same += 1
    return {"only_in_before": only_a, "only_in_after": only_b,
            "changed": changed, "unchanged": same}


def diff_indicators(a: Dict, b: Dict) -> Dict:
    ia, ib = a.get("indicators", {}) or {}, b.get("indicators", {}) or {}
    out = {}
    for key in ("urls", "domains", "ipv4", "ipv6", "api_paths", "ports"):
        # Indicators are dicts carrying value+source+offset. Compare on the
        # *value* so provenance does not make an identical endpoint look new.
        sa = {v for v in indicator_values(ia.get(key))}
        sb = {v for v in indicator_values(ib.get(key))}
        out[key] = {
            "added": sorted(sb - sa),
            "removed": sorted(sa - sb),
            "common_count": len(sa & sb),
        }
    return out


def indicator_values(items) -> List[str]:
    """Extract comparable values from an indicator list."""
    out = []
    for it in items or []:
        if isinstance(it, dict):
            v = it.get("value")
            if v is None and it.get("port") is not None:
                v = f"port:{it['port']}"
            if v is not None:
                out.append(str(v))
        elif it is not None:
            out.append(str(it))
    return out


def diff_binaries(a: Dict, b: Dict) -> Dict:
    def index(rep):
        return {b_.get("path"): b_ for b_ in (rep.get("binaries") or [])}

    ia, ib = index(a), index(b)
    out = {"only_in_before": sorted(set(ia) - set(ib)),
           "only_in_after": sorted(set(ib) - set(ia)),
           "changed": []}
    for path in sorted(set(ia) & set(ib)):
        ba, bb = ia[path], ib[path]
        fields = []
        for key in ("architecture", "bits", "entrypoint", "soname",
                    "stripped", "position_independent", "build_id",
                    "interpreter"):
            if ba.get(key) != bb.get(key):
                fields.append({"field": key, "before": ba.get(key),
                               "after": bb.get(key)})
        na, nb = as_set(ba.get("needed")), as_set(bb.get("needed"))
        if na != nb:
            fields.append({"field": "needed",
                           "added": sorted(nb - na),
                           "removed": sorted(na - nb)})
        ca = ba.get("counts", {}) or {}
        cb = bb.get("counts", {}) or {}
        for key in ("exports", "imports", "functions", "sections"):
            if ca.get(key) != cb.get(key):
                fields.append({"field": f"count.{key}",
                               "before": ca.get(key), "after": cb.get(key)})
        if fields:
            out["changed"].append({"path": path, "fields": fields})
    return out


def diff_android(a: Dict, b: Dict) -> Dict:
    ma = (a.get("android") or {}).get("manifest") or {}
    mb = (b.get("android") or {}).get("manifest") or {}
    fields = []
    for key in ("package", "version_name", "version_code", "min_sdk",
                "target_sdk", "debuggable", "uses_cleartext_traffic"):
        if ma.get(key) != mb.get(key):
            fields.append({"field": key, "before": ma.get(key),
                           "after": mb.get(key)})
    pa, pb = as_set(ma.get("permissions")), as_set(mb.get("permissions"))
    out = {"fields": fields,
           "permissions_added": sorted(pb - pa),
           "permissions_removed": sorted(pa - pb),
           "abis_before": (a.get("android") or {}).get("abis"),
           "abis_after": (b.get("android") or {}).get("abis")}
    return out


def diff_unity(a: Dict, b: Dict) -> Dict:
    ua, ub = a.get("unity", {}) or {}, b.get("unity", {}) or {}
    meta_a = ua.get("metadata") or {}
    meta_b = ub.get("metadata") or {}
    return {
        "detected_before": ua.get("detected"),
        "detected_after": ub.get("detected"),
        "il2cpp_before": ua.get("il2cpp"),
        "il2cpp_after": ub.get("il2cpp"),
        "metadata_status_before": meta_a.get("status"),
        "metadata_status_after": meta_b.get("status"),
        "metadata_magic_before": meta_a.get("standard_magic"),
        "metadata_magic_after": meta_b.get("standard_magic"),
        "metadata_size_before": meta_a.get("size"),
        "metadata_size_after": meta_b.get("size"),
        "evidence_before": ua.get("evidence"),
        "evidence_after": ub.get("evidence"),
    }


def build(a: Dict, b: Dict, args) -> Dict:
    paths = diff_paths(a, b)
    # When both dumps are of a single container file, that file appears as a
    # "changed" path purely because the two versions differ. Comparing a
    # version against itself is not informative, so it is set aside.
    container_before = os.path.basename(
        (a.get("target", {}) or {}).get("path") or "")
    container_after = os.path.basename(
        (b.get("target", {}) or {}).get("path") or "")
    if (a.get("files", {}).get("count") == 1
            and b.get("files", {}).get("count") == 1):
        paths["only_in_before"] = [p for p in paths["only_in_before"]
                                   if p != container_before]
        paths["only_in_after"] = [p for p in paths["only_in_after"]
                                  if p != container_after]
    inds = diff_indicators(a, b)
    bins = diff_binaries(a, b)
    andr = diff_android(a, b) if (a.get("android") or b.get("android")) else None
    unity = diff_unity(a, b)

    added_urls = inds["urls"]["added"]
    removed_urls = inds["urls"]["removed"]
    added_domains = inds["domains"]["added"]
    removed_domains = inds["domains"]["removed"]

    hypotheses: List[Dict] = []

    def hyp(text, basis, test):
        hypotheses.append({"hypothesis": text, "basis": basis,
                           "test_that_would_confirm": test,
                           "confidence": "low"})

    if paths["only_in_after"]:
        hyp(f"{len(paths['only_in_after'])} file(s) were added",
            "present in the second dump, absent from the first",
            "identify what they are and whether the app uses them at runtime")
    if paths["only_in_before"]:
        hyp(f"{len(paths['only_in_before'])} file(s) were removed",
            "present in the first dump, absent from the second",
            "check for a deliberate removal versus a packaging change")
    if added_domains:
        hyp(f"new domain(s) referenced: {', '.join(added_domains[:5])}",
            "extracted from strings in the second build",
            "confirm each is contacted at runtime and by which component")
    if removed_domains:
        hyp(f"domain(s) no longer referenced: {', '.join(removed_domains[:5])}",
            "absent from the second build's strings",
            "check whether the capability moved or was dropped")
    if andr and andr["permissions_added"]:
        hyp(f"permissions added: {', '.join(andr['permissions_added'][:8])}",
            "manifest comparison",
            "check what each newly requested permission is used for")
    if andr and andr["permissions_removed"]:
        hyp(f"permissions removed: {', '.join(andr['permissions_removed'][:8])}",
            "manifest comparison", "confirm the capability is genuinely gone")
    if unity.get("metadata_status_before") != unity.get("metadata_status_after"):
        hyp("IL2CPP metadata state differs between builds",
            f"status {unity.get('metadata_status_before')} -> "
            f"{unity.get('metadata_status_after')}",
            "compare metadata version fields and header layout")
    for bc in bins.get("changed", []):
        for f in bc["fields"]:
            if f["field"] == "needed":
                hyp(f"{bc['path']} dependency set changed "
                    f"(+{len(f.get('added', []))}/-{len(f.get('removed', []))})",
                    "DT_NEEDED comparison",
                    "identify what the new dependency is used for")

    n_changed = len(paths["changed"])
    return {
        "schema_version": "1.0",
        "before": {"path": a.get("target", {}).get("path"),
                   "generated": a.get("generated_utc"),
                   "type": a.get("target", {}).get("type")},
        "after": {"path": b.get("target", {}).get("path"),
                  "generated": b.get("generated_utc"),
                  "type": b.get("target", {}).get("type")},
        "warning": (
            "This is a comparison of artefacts. A byte, symbol or string "
            "difference is a binary difference. It is not evidence that "
            "behaviour changed; establishing that requires running both "
            "versions and comparing their responses."),
        "paths": paths,
        "indicators": inds,
        "binaries": bins,
        "android": andr,
        "unity": unity,
        "counts": {
            "files_added": len(paths["only_in_after"]),
            "files_removed": len(paths["only_in_before"]),
            "files_changed": n_changed,
            "files_unchanged": paths["unchanged"],
            "urls_added": len(added_urls),
            "urls_removed": len(removed_urls),
            "domains_added": len(added_domains),
            "domains_removed": len(removed_domains),
        },
        "hypotheses": hypotheses,
    }


def render(d: Dict, args) -> str:
    L: List[str] = []
    add = L.append
    add("=" * 74)
    add("DUMP DIFF  (artefact comparison, not behaviour comparison)")
    add("=" * 74)
    add(f"before : {d['before']['path']}   ({d['before']['generated']})")
    add(f"after  : {d['after']['path']}   ({d['after']['generated']})")
    add("")
    add(f"!! {d['warning']}")
    add("")
    c = d["counts"]
    add("-" * 74)
    add("SUMMARY")
    add("-" * 74)
    add(f"  files added     : {c['files_added']}")
    add(f"  files removed   : {c['files_removed']}")
    add(f"  files changed   : {c['files_changed']}")
    add(f"  files unchanged : {c['files_unchanged']}")
    add(f"  urls added/removed : {c['urls_added']}/{c['urls_removed']}")
    add(f"  domains added/removed : {c['domains_added']}/{c['domains_removed']}")
    add("")

    p = d["paths"]
    if p["only_in_before"] or p["only_in_after"]:
        add("-" * 74)
        add("FILES PRESENT IN ONE DUMP ONLY")
        add("-" * 74)
        for x in p["only_in_before"][:args.limit]:
            add(f"  - {x}   (in before only)")
        for x in p["only_in_after"][:args.limit]:
            add(f"  + {x}   (in after only)")
        add("")
    if p["changed"]:
        add("-" * 74)
        add("FILES WITH A DIFFERENT HASH")
        add("-" * 74)
        for ch in sorted(p["changed"], key=lambda r: -abs(r.get("size_delta", 0)))[:args.limit]:
            add(f"  ~ {ch['path']}")
            add(f"      size {ch.get('size_before')} -> {ch.get('size_after')}"
                f"  (delta {ch.get('size_delta')})")
            if ch.get("format_before") != ch.get("format_after"):
                add(f"      format {ch.get('format_before')} -> "
                    f"{ch.get('format_after')}  (content identification changed)")
        add("")

    inds = d["indicators"]
    if any(v["added"] or v["removed"] for v in inds.values()):
        add("-" * 74)
        add("NETWORK INDICATORS")
        add("-" * 74)
        for kind, v in inds.items():
            if not v["added"] and not v["removed"]:
                continue
            add(f"  {kind}:")
            for x in v["added"][:args.limit]:
                add(f"    + {x}")
            for x in v["removed"][:args.limit]:
                add(f"    - {x}")
        add("")

    b = d["binaries"]
    if b["only_in_before"] or b["only_in_after"] or b["changed"]:
        add("-" * 74)
        add("BINARIES")
        add("-" * 74)
        for x in b["only_in_before"]:
            add(f"  - {x}  (in before only)")
        for x in b["only_in_after"]:
            add(f"  + {x}  (in after only)")
        for ch in b["changed"]:
            add(f"  ~ {ch['path']}")
            for f in ch["fields"]:
                if "added" in f:
                    add(f"      {f['field']}: +{f['added']} -{f['removed']}")
                else:
                    add(f"      {f['field']}: {f['before']!r} -> "
                        f"{f['after']!r}")
        add("")

    if d.get("android"):
        a = d["android"]
        add("-" * 74)
        add("ANDROID MANIFEST")
        add("-" * 74)
        if a["fields"]:
            for f in a["fields"]:
                add(f"  {f['field']}: {f['before']!r} -> {f['after']!r}")
        if a["permissions_added"]:
            add(f"  permissions added   : {', '.join(a['permissions_added'])}")
        if a["permissions_removed"]:
            add(f"  permissions removed : {', '.join(a['permissions_removed'])}")
        if a["abis_before"] != a["abis_after"]:
            add(f"  ABIs: {a['abis_before']} -> {a['abis_after']}")
        add("")

    u = d["unity"]
    if u.get("detected_before") or u.get("detected_after"):
        add("-" * 74)
        add("UNITY / IL2CPP")
        add("-" * 74)
        add(f"  detected   : {u['detected_before']} -> {u['detected_after']}")
        add(f"  il2cpp     : {u['il2cpp_before']} -> {u['il2cpp_after']}")
        add(f"  metadata status : {u['metadata_status_before']} -> "
            f"{u['metadata_status_after']}")
        add(f"  metadata magic  : {u['metadata_magic_before']} -> "
            f"{u['metadata_magic_after']}")
        add("")

    add("-" * 74)
    add("HYPOTHESES  (each needs a test; none is a conclusion)")
    add("-" * 74)
    if not d["hypotheses"]:
        add("  none generated: not enough observed difference to be worth a "
            "claim")
    for i, h in enumerate(d["hypotheses"], 1):
        add(f"  {i}. {h['hypothesis']}")
        add(f"     basis : {h['basis']}")
        add(f"     test  : {h['test_that_would_confirm']}")
    add("")
    add("=" * 74)
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(
        description="Compare two universal-dump reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("before", help="report.json from the earlier dump")
    p.add_argument("after", help="report.json from the later dump")
    p.add_argument("--limit", type=int, default=25,
                   help="max entries per section (default 25)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    for f in (args.before, args.after):
        if not os.path.isfile(f):
            print(f"error: no such file: {f}", file=sys.stderr)
            return 2
    try:
        a, b = load(args.before), load(args.after)
    except json.JSONDecodeError as e:
        print(f"error: a report is not valid JSON: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for name, rep in (("before", a), ("after", b)):
        if "schema_version" not in rep:
            print(f"warning: {name} report has no schema_version; it may not "
                  f"be a universal-dump report", file=sys.stderr)

    d = build(a, b, args)
    print(json.dumps(d, indent=2, default=str) if args.json
          else render(d, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())