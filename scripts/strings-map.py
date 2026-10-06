#!/usr/bin/env python3
"""strings-map.py -- locate strings and the code/data that references them.

Extracts ASCII and UTF-16 strings, reports their static addresses, and finds
references to them. Address resolution uses the file's own section/segment
tables, so results are static (pre-ASLR) addresses.

Scope and limits are stated explicitly rather than guessed:
  * A "literal reference" is a pointer-sized value in a non-executable region
    that equals the string address. High confidence.
  * An "instruction reference" requires a disassembler. When objdump is
    available it is used; otherwise this script reports only literal
    references and says so.

Examples
--------
  strings-map.py ./app.so                       # most frequent strings
  strings-map.py ./app.so --search token        # strings matching a pattern
  strings-map.py ./app.so --xrefs 0x1234        # who references this address?
  strings-map.py ./app.so --section .rodata     # limit to one section
  strings-map.py ./app.so --json --min-len 8
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _binlib as B  # noqa: E402


def collect_strings(info, data, args):
    encodings = []
    if "ascii" in args.encoding:
        encodings.append("ascii")
    if "utf16" in args.encoding:
        encodings += ["utf16le", "utf16be"]
    rows = []
    for off, text, enc in B.extract_strings(data, args.min_len, encodings):
        vaddr = info.offset_to_vaddr(off)
        sec = info.section_for(vaddr) if vaddr is not None else None
        if args.section and (sec is None or args.section not in sec.name):
            continue
        if args.search and not re.search(args.search, text, re.I):
            continue
        rows.append({
            "offset": off,
            "address": vaddr,
            "text": text,
            "encoding": enc,
            "section": sec.name if sec else None,
        })
    return rows


def find_literal_xrefs(info, data, target, args):
    """Find pointer-sized values equal to ``target``.

    Only searches regions that are not executable: a bare pointer in .text is
    far more likely to be a coincidental immediate than a real reference.
    """
    bits = info.bits or 64
    width = bits // 8
    needle_le = target.to_bytes(width, "little", signed=False)
    needle_be = target.to_bytes(width, "big", signed=False)
    hits = []
    for sec in info.sections:
        if not sec.size:
            continue
        if args.in_code:
            pass  # explicit opt-in: search everything
        elif _is_executable(info, sec):
            continue
        start, end = sec.offset, sec.offset + sec.size
        if end > len(data):
            end = len(data)
        chunk = data[start:end]
        for needle, endian in ((needle_le, "little"), (needle_be, "big")):
            pos = chunk.find(needle)
            while pos != -1:
                addr = info.offset_to_vaddr(start + pos)
                hits.append({
                    "at": addr,
                    "offset": start + pos,
                    "section": sec.name,
                    "kind": "pointer",
                    "endian": endian,
                })
                pos = chunk.find(needle, pos + 1)
                if len(hits) >= args.max_xrefs:
                    return hits
    return hits


def _is_executable(info, sec):
    if info.fmt == "ELF":
        return bool(sec.flags & 0x4)          # SHF_EXECINSTR
    if info.fmt == "PE":
        return bool(sec.flags & 0x20000000)   # IMAGE_SCN_MEM_EXECUTE
    if info.fmt == "Mach-O":
        return "TEXT," in sec.name or "__text" in sec.name
    return False


def build_reference_index(info, args):
    """Disassemble once and index every address the code refers to.

    Returns ``({target_address: [xref, ...]}, note)``. Resolving this properly
    in pure Python would mean writing a disassembler per architecture, so this
    delegates to objdump and combines:

      * branch targets objdump already resolves (b, bl, b.cond, jmp);
      * AArch64 ``adrp`` + ``add``/``ldr`` pairs, which objdump prints as a
        page value plus a separate immediate;
      * x86-64 RIP-relative operands.

    Absence of a hit means "not found", never "does not exist".
    """
    tool = None
    for cand in ("objdump", "llvm-objdump"):
        if shutil.which(cand):
            tool = cand
            break
    if tool is None:
        return {}, ("objdump and llvm-objdump are both unavailable, so "
                    "instruction-level references cannot be resolved. "
                    "Only pointer references are reported above.")

    cmd = [tool, "-d", "--no-show-raw-insn", info.path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=args.timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {}, f"{tool} failed: {e}"
    if proc.returncode != 0:
        return {}, (f"{tool} exited {proc.returncode}: "
                    f"{proc.stderr.strip()[:200]}")

    index: dict = {}
    last_adrp: dict = {}      # register -> page base address

    def record(target, at, text):
        if len(index.get(target, [])) < 64:
            index.setdefault(target, []).append(
                {"at": at, "instruction": text, "kind": "instruction"})

    line_re = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
    imm_re = re.compile(r"#(-?(?:0x)?[0-9a-f]+|-?\d+)")
    # objdump prints adrp page values bare ("adrp x8, 20000") but may also use
    # 0x, so accept both and normalise through int(x, 16).
    addr_re = re.compile(r"\b(?:0x)?([0-9a-f]+)\b")

    for line in proc.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        at = int(m.group(1), 16)
        text = m.group(2).strip()
        parts = text.split(None, 1)
        mnem = parts[0].lower() if parts else ""
        ops = parts[1] if len(parts) > 1 else ""

        # Direct branch / call: objdump appends the resolved target.
        if mnem[:1] == "b" and mnem not in ("bic", "bfi", "bfxil"):
            tail = ops.split("<")[-1] if "<" in ops else ops
            for hx in re.findall(r"\b([0-9a-f]{4,})\b", tail):
                try:
                    record(int(hx, 16), at, text)
                except ValueError:
                    pass

        # AArch64: adrp sets a page base; a following add completes it.
        # An entry is invalidated only when an instruction *overwrites* the
        # base register with something unrelated. The completing
        # ``add Xd, Xn, #imm`` (Xd == Xn) is that overwrite by design, so it
        # is resolved first and must not be treated as an invalidation.
        regs = [r.strip() for r in ops.split(",")]

        if mnem == "adrp":
            if len(regs) >= 2:
                am = addr_re.search(regs[1])
                if am:
                    last_adrp[regs[0]] = int(am.group(1), 16)
            continue

        if mnem in ("add", "adr") and len(regs) >= 2:
            base = last_adrp.get(regs[1])
            if base is not None and regs[0] == regs[1]:
                # This is the canonical adrp+add pair.
                del last_adrp[regs[1]]
                folded = None
                im = imm_re.search(ops)
                if im:
                    folded = base + int(im.group(1), 16)
                if folded is None and len(regs) >= 3:
                    hx = re.match(r"\s*([0-9a-f]+)\b", regs[2])
                    if hx:
                        folded = int(hx.group(1), 16)
                if folded is not None:
                    record(folded, at, text)
            continue

        dests = set()
        if regs and regs[0] and not regs[0].startswith(("#", "[", "<")):
            dests.add(regs[0])
            # LDP/STP and SIMD forms write every register in the operand list.
            if mnem.startswith(("ldp", "stp")) or "{" in ops:
                dests.update(re.findall(r"\b([wx]\d+|q\d+|d\d+|s\d+)\b", ops))
        for reg in dests & last_adrp.keys():
            del last_adrp[reg]

        # x86-64: RIP-relative operands appear as "sym-0x4(%rip)".
        if "%rip" in ops:
            for hx in addr_re.findall(ops):
                record(int(hx, 16), at, text)

    return index, ("Instruction references come from objdump linear "
                   "disassembly; references hidden inside unreachable or "
                   "indirect code may be missed.")


def render_text(path, fmt, rows, totals, args):
    out = [f"file      : {path}",
           f"format    : {fmt}",
           f"strings   : {len(rows)} (min-len {args.min_len}, "
           f"encoding {','.join(args.encoding)})",
           f"xrefs     : literal {totals['literal']}  "
           f"instruction {totals['instruction'] if totals['instruction'] is not None else 'n/a'}",
           ""]
    by_section = Counter(r["section"] or "(unmapped)" for r in rows)
    out.append("strings per section:")
    for name, n in by_section.most_common():
        out.append(f"  {name:<24} {n}")
    out.append("")
    for r in rows[:args.limit]:
        addr = f"0x{r['address']:x}" if r["address"] is not None else "unmapped"
        sec = r["section"] or "-"
        line = f"{addr:>14}  {sec:<20} {r['encoding']:<8} {r['text']!r}"
        out.append(line)
        for x in r.get("xrefs", []):
            if x["kind"] == "pointer":
                out.append(f"{'':>14}  {'':<20} -> pointer in {x['section']}"
                           f" at 0x{x['at']:x}")
            else:
                out.append(f"{'':>14}  {'':<20} -> {x['instruction']}")
    if len(rows) > args.limit:
        out.append(f"... {len(rows) - args.limit} more (use --limit)")
    if totals.get("note"):
        out += ["", "note:", totals["note"]]
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(
        description="Extract strings and locate references to them.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("file", help="binary to inspect")
    p.add_argument("--search", "-s", metavar="REGEX",
                   help="only strings matching this regex (case-insensitive)")
    p.add_argument("--section", metavar="NAME",
                   help="only strings inside sections matching this substring")
    p.add_argument("--min-len", type=int, default=4, help="minimum length")
    p.add_argument("--encoding", nargs="+", default=["ascii", "utf16"],
                   choices=["ascii", "utf16"], help="encodings to scan")
    p.add_argument("--xrefs", action="store_true",
                   help="find references to each string address")
    p.add_argument("--in-code", action="store_true",
                   help="also scan executable sections for pointers (noisy)")
    p.add_argument("--no-instruction-xrefs", action="store_true",
                   help="skip objdump-based instruction reference resolution")
    p.add_argument("--max-xrefs", type=int, default=8,
                   help="max references per string (default 8)")
    p.add_argument("--limit", type=int, default=60,
                   help="max strings to print (default 60)")
    p.add_argument("--timeout", type=int, default=120,
                   help="disassembly timeout in seconds")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 2

    try:
        info = B.load(args.file)
        with open(args.file, "rb") as fh:
            data = fh.read()
    except B.ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    rows = collect_strings(info, data, args)
    totals = {"literal": 0, "instruction": None, "note": None}

    if args.xrefs:
        index = {}
        if not args.no_instruction_xrefs:
            index, note = build_reference_index(info, args)
            totals["note"] = note
        for r in rows:
            if r["address"] is None:
                continue
            lits = find_literal_xrefs(info, data, r["address"], args)
            totals["literal"] += len(lits)
            ins = index.get(r["address"], [])[:args.max_xrefs]
            if ins:
                totals["instruction"] = (totals["instruction"] or 0) + len(ins)
            r["xrefs"] = lits + ins

    if args.json:
        print(json.dumps({"file": args.file, "format": info.fmt,
                          "count": len(rows), "strings": rows,
                          "note": totals["note"]}, indent=2))
    else:
        print(render_text(args.file, info.fmt, rows, totals, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())