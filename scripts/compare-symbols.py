#!/usr/bin/env python3
"""compare-symbols.py -- diff the symbols, imports and exports of two binaries.

Works on ELF, PE/COFF and Mach-O using only the standard library. Reports what
was added, removed and changed between two builds of the same software.

A changed entry means the *symbol table* differs (name, size, type, binding or
address moved). It does not by itself mean behaviour changed -- see
references/binary-diff.md for how to turn symbol differences into testable
hypotheses.

Examples
--------
  compare-symbols.py v1/libfoo.so v2/libfoo.so
  compare-symbols.py old.exe new.dll --kind exports
  compare-symbols.py a.so b.so --kind imports --json
  compare-symbols.py a.so b.so --strip-names     # compare shapes, not names
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _binlib as B  # noqa: E402


def collect(info, kind):
    """Return ``{name: record}`` for the requested symbol class."""
    out = {}
    if kind in ("exports", "all"):
        for s in info.exports():
            out[s.name] = {"name": s.name, "value": s.value, "size": s.size,
                           "type": s.type, "bind": s.bind}
    elif kind in ("imports", "all"):
        for s in info.imports():
            out[s.name] = {"name": s.name, "value": 0, "size": 0,
                           "type": s.type, "bind": s.bind}
    else:  # all defined symbols
        for s in info.symbols:
            if not s.name or s.is_undefined:
                continue
            out[s.name] = {"name": s.name, "value": s.value, "size": s.size,
                           "type": s.type, "bind": s.bind}
    return out


def shape(name):
    """Reduce a symbol to a build-independent shape for fuzzy matching.

    Two builds rename a symbol but keep its role; comparing shapes finds that
    even when the names differ. Collisions are reported as ambiguous.
    """
    base = name.split("@@")[0]
    base = re.sub(r"\.\d+$", "", base)          # foo.123 -> foo
    return (base.count("_"), len(base), base[-6:])


def diff(a, b, args):
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    common = sorted(set(a) & set(b))
    changed = []
    for name in common:
        ra, rb = a[name], b[name]
        fields = []
        if ra["size"] != rb["size"]:
            fields.append(f"size {ra['size']}->{rb['size']}")
        if ra["type"] != rb["type"]:
            fields.append(f"type {ra['type']}->{rb['type']}")
        if ra["bind"] != rb["bind"]:
            fields.append(f"bind {ra['bind']}->{rb['bind']}")
        if args.follow_address and ra["value"] != rb["value"]:
            fields.append(f"addr 0x{ra['value']:x}->0x{rb['value']:x}")
        if fields:
            changed.append({"name": name, "changes": fields,
                            "before": ra, "after": rb})
    result = {
        "added": [{"name": n, "after": b[n]} for n in added],
        "removed": [{"name": n, "before": a[n]} for n in removed],
        "changed": changed,
        "unchanged": len(common) - len(changed),
    }
    if args.fuzzy and removed and added:
        result["possible_renames"] = fuzzy_match(
            [a[n] for n in removed], [b[n] for n in added])
    return result


def fuzzy_match(removed, added):
    """Pair removed/added symbols whose shapes agree.

    This is a *candidate* list to investigate, not a rename decision.
    """
    by_shape = {}
    for r in removed:
        by_shape.setdefault(shape(r["name"]), []).append(r)
    pairs = []
    for a in added:
        key = shape(a["name"])
        for r in by_shape.get(key, []):
            pairs.append({
                "before": r["name"], "after": a["name"],
                "basis": f"shape {key} and size {r['size']}->{a['size']}",
                "confidence": "low -- verify in a disassembler",
            })
    return pairs


def render(pa, pb, ka, kb, result, fmt_a, fmt_b, args):
    out = [
        "symbol diff",
        f"  A: {pa}  ({fmt_a})",
        f"  B: {pb}  ({fmt_b})",
        f"  kind: {args.kind}",
        "",
        f"  added   : {len(result['added'])}",
        f"  removed : {len(result['removed'])}",
        f"  changed : {len(result['changed'])}",
        f"  same    : {result['unchanged']}",
    ]
    if result["added"]:
        out += ["", "added:"]
        out += [f"  + {e['name']}" + size_note(e["after"]) for e in result["added"][:args.limit]]
    if result["removed"]:
        out += ["", "removed:"]
        out += [f"  - {e['name']}" + size_note(e["before"]) for e in result["removed"][:args.limit]]
    if result["changed"]:
        out += ["", "changed:"]
        out += [f"  ~ {e['name']}: {'; '.join(e['changes'])}"
                for e in result["changed"][:args.limit]]
    if result.get("possible_renames"):
        out += ["", "possible renames (candidates, not conclusions):"]
        out += [f"  ? {p['before']} -> {p['after']}  [{p['basis']}]"
                for p in result["possible_renames"][:args.limit]]
    out += ["", "note: symbol differences are not behavioural differences.",
            "      verify each candidate in the binary before claiming a change."]
    return "\n".join(out)


def size_note(rec):
    return f"   (size {rec['size']}, type {rec['type']})" if rec.get("size") else ""


def main():
    p = argparse.ArgumentParser(
        description="Compare symbols, imports and exports between two binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("old", help="baseline binary")
    p.add_argument("new", help="binary to compare against the baseline")
    p.add_argument("--kind", choices=["exports", "imports", "all"],
                   default="exports",
                   help="which symbol class to compare (default exports)")
    p.add_argument("--follow-address", action="store_true",
                   help="also flag symbols whose address moved")
    p.add_argument("--fuzzy", action="store_true",
                   help="list possible renames by symbol shape")
    p.add_argument("--limit", type=int, default=50,
                   help="max entries per section (default 50)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    for f in (args.old, args.new):
        if not os.path.isfile(f):
            print(f"error: no such file: {f}", file=sys.stderr)
            return 2

    infos = {}
    for label, path in (("old", args.old), ("new", args.new)):
        try:
            infos[label] = B.load(path)
        except B.ParseError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    a = collect(infos["old"], args.kind)
    b = collect(infos["new"], args.kind)
    result = diff(a, b, args)

    if (infos["old"].stripped and infos["new"].stripped
            and not a and not b):
        print("error: both binaries expose no comparable symbols "
              f"(kind={args.kind}).\n"
              "       They are probably stripped; use a byte/function-level "
              "diff instead -- see references/binary-diff.md.",
              file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({
            "old": {"file": args.old, "format": infos["old"].fmt,
                    "arch": infos["old"].arch, "stripped": infos["old"].stripped},
            "new": {"file": args.new, "format": infos["new"].fmt,
                    "arch": infos["new"].arch, "stripped": infos["new"].stripped},
            "kind": args.kind, "counts": {
                "old": len(a), "new": len(b)},
            "diff": result,
        }, indent=2))
    else:
        print(render(args.old, args.new, "a", "b", result,
                     infos["old"].fmt, infos["new"].fmt, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())