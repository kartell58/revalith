#!/usr/bin/env python3
"""find-xrefs.py -- locate references to an address, symbol or string.

Two reference classes are reported, and the distinction matters:

  pointer      A pointer-sized value in a non-executable region whose value
               equals the target. Found by direct byte search -- high
               confidence, but it may sit inside an unrelated table.
  instruction  A branch, call, or address-materialising instruction computed
               by objdump (AArch64 adrp+add, x86-64 RIP-relative, direct
               branches). Requires objdump or llvm-objdump.

If neither tool is available the script says so and still reports pointer
references. It never claims "no references exist" when a tool was missing.

Examples
--------
  find-xrefs.py ./app.so --symbol parse_header
  find-xrefs.py ./app.so --addr 0x2a4c0
  find-xrefs.py ./app.so --string "login_failed"
  find-xrefs.py ./app.so --string "login_failed" --containing-funcs
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _binlib as B  # noqa: E402


def resolve_target(info, data, args):
    """Turn the user's selector into one or more target addresses."""
    targets = {}
    if args.addr:
        for a in args.addr:
            targets[a] = f"address {a:#x}"
    for name in args.symbol or []:
        addr = B.resolve_symbol(info, name)
        if addr is None:
            alt = [s for s in info.symbols if name in s.name]
            if alt:
                for s in alt[:20]:
                    targets[s.value] = f"symbol {s.name}"
            else:
                print(f"warning: symbol {name!r} not found", file=sys.stderr)
        else:
            targets[addr] = f"symbol {name}"
    for text in args.string or []:
        rows = B.extract_strings(data, args.min_len, ("ascii", "utf16le"))
        hits = [off for off, t, _ in rows if t == text]
        if not hits:
            hits = [off for off, t, _ in rows if text in t]
        if not hits:
            print(f"warning: string {text!r} not found", file=sys.stderr)
            continue
        for off in hits:
            v = info.offset_to_vaddr(off)
            if v is not None:
                targets[v] = f"string {text!r}"
    return targets


def pointer_xrefs(info, data, target, args):
    bits = info.bits or 64
    width = bits // 8
    hits = []
    for sec in info.sections:
        if not sec.size or sec.type == "NOBITS":
            continue
        if not args.in_code and _executable(info, sec):
            continue
        start = sec.offset
        end = min(sec.offset + sec.size, len(data))
        if end <= start:
            continue
        chunk = data[start:end]
        for endian in ("little", "big"):
            needle = target.to_bytes(width, endian, signed=False)
            pos = chunk.find(needle)
            while pos != -1:
                hits.append({"at": info.offset_to_vaddr(start + pos),
                             "offset": start + pos, "section": sec.name,
                             "kind": "pointer", "endian": endian})
                pos = chunk.find(needle, pos + 1)
                if len(hits) >= args.max:
                    return hits
    return hits


def _executable(info, sec):
    if info.fmt == "ELF":
        return bool(sec.flags & 0x4)
    if info.fmt == "PE":
        return bool(sec.flags & 0x20000000)
    if info.fmt == "Mach-O":
        return "TEXT," in sec.name or "__text" in sec.name
    return False


def instruction_xrefs(info, targets, args):
    """One disassembly pass; reuse the same parser as strings-map."""
    tool = None
    for cand in ("objdump", "llvm-objdump"):
        if shutil.which(cand):
            tool = cand
            break
    if tool is None:
        return {}, ("no objdump/llvm-objdump on PATH: instruction-level "
                    "references were NOT searched. Only pointer references "
                    "are listed.")
    try:
        proc = subprocess.run([tool, "-d", "--no-show-raw-insn", info.path],
                              capture_output=True, text=True,
                              timeout=args.timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {}, f"{tool} failed: {e}"
    if proc.returncode != 0:
        return {}, f"{tool} exited {proc.returncode}: {proc.stderr.strip()[:160]}"

    wanted = set(targets)
    found = {t: [] for t in wanted}
    line_re = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
    imm_re = re.compile(r"#(-?(?:0x)?[0-9a-f]+|-?\d+)")
    addr_re = re.compile(r"\b(?:0x)?([0-9a-f]+)\b")
    last_adrp = {}

    for line in proc.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        at = int(m.group(1), 16)
        text = m.group(2).strip()
        parts = text.split(None, 1)
        mnem = parts[0].lower() if parts else ""
        ops = parts[1] if len(parts) > 1 else ""
        regs = [r.strip() for r in ops.split(",")]

        def record(t):
            if t in found and len(found[t]) < args.max:
                found[t].append({"at": at, "instruction": text,
                                 "kind": "instruction"})

        if mnem[:1] == "b" and mnem not in ("bic", "bfi", "bfxil"):
            tail = ops.split("<")[-1] if "<" in ops else ops
            for hx in re.findall(r"\b([0-9a-f]{4,})\b", tail):
                record(int(hx, 16))

        if mnem == "adrp":
            if len(regs) >= 2:
                am = addr_re.search(regs[1])
                if am:
                    last_adrp[regs[0]] = int(am.group(1), 16)
            continue

        if mnem in ("add", "adr") and len(regs) >= 2:
            base = last_adrp.get(regs[1])
            if base is not None and regs[0] == regs[1]:
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
                    record(folded)
            continue

        dests = set()
        if regs and regs[0] and not regs[0].startswith(("#", "[", "<")):
            dests.add(regs[0])
            if mnem.startswith(("ldp", "stp")) or "{" in ops:
                dests.update(re.findall(r"\b([wx]\d+|q\d+|d\d+|s\d+)\b", ops))
        for reg in dests & last_adrp.keys():
            del last_adrp[reg]

        if "%rip" in ops:
            for hx in addr_re.findall(ops):
                record(int(hx, 16))

    note = ("Instruction references come from objdump linear disassembly; "
            "references inside unreachable or indirect code may be missed.")
    return found, note


def containing_functions(info, xref_addrs):
    """Map each xref address to the function symbol that contains it."""
    funcs = sorted((s for s in info.symbols if s.is_func and s.size),
                   key=lambda s: s.value)
    if not funcs:
        return {}
    out = {}
    for a in xref_addrs:
        if a is None:
            continue
        cand = None
        for s in funcs:
            if s.value <= a < s.value + s.size:
                cand = s
                break
        out[a] = cand.name if cand else None
    return out


def main():
    p = argparse.ArgumentParser(
        description="Find references to an address, symbol or string.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("file", help="binary to inspect")
    g = p.add_argument_group("target selection (at least one required)")
    g.add_argument("--addr", type=lambda s: int(s, 0), action="append",
                   help="target address (repeatable, accepts 0x form)")
    g.add_argument("--symbol", action="append",
                   help="target symbol name (repeatable)")
    g.add_argument("--string", action="append",
                   help="target string content (repeatable)")
    g.add_argument("--min-len", type=int, default=4,
                   help="minimum string length when matching (default 4)")

    p.add_argument("--in-code", action="store_true",
                   help="also scan executable sections for pointers")
    p.add_argument("--no-instruction-xrefs", action="store_true",
                   help="skip objdump-based instruction references")
    p.add_argument("--containing-funcs", action="store_true",
                   help="report which function each xref sits in")
    p.add_argument("--max", type=int, default=50,
                   help="max references per target (default 50)")
    p.add_argument("--timeout", type=int, default=180,
                   help="disassembly timeout in seconds")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    if not (args.addr or args.symbol or args.string):
        p.error("specify at least one of --addr, --symbol or --string")
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

    targets = resolve_target(info, data, args)
    if not targets:
        print("error: no target address could be resolved", file=sys.stderr)
        return 1

    instr = {}
    note = "instruction search skipped by --no-instruction-xrefs"
    if not args.no_instruction_xrefs:
        instr, note = instruction_xrefs(info, targets, args)

    report = []
    for addr, label in sorted(targets.items()):
        sec = info.section_for(addr)
        ptrs = pointer_xrefs(info, data, addr, args)
        ins = instr.get(addr, [])
        all_x = ptrs + ins
        entry = {
            "target": addr, "label": label,
            "address_hex": f"0x{addr:x}",
            "section": sec.name if sec else None,
            "symbol_here": next(
                (s.name for s in info.symbols if s.value == addr and s.name),
                None),
            "pointer_xrefs": ptrs,
            "instruction_xrefs": ins,
            "total": len(all_x),
        }
        if args.containing_funcs:
            funcs = containing_functions(info, [x["at"] for x in all_x])
            entry["containing_functions"] = sorted({
                funcs[x["at"]] for x in all_x if funcs.get(x["at"])})
        report.append(entry)

    if args.json:
        print(json.dumps({"file": args.file, "format": info.fmt,
                          "note": note, "targets": report},
                         indent=2, default=str))
    else:
        print(render(args.file, info.fmt, report, note))
    return 0


def render(path, fmt, report, note):
    out = [f"file   : {path}", f"format : {fmt}", ""]
    for e in report:
        out.append(f"target {e['address_hex']}  ({e['label']})")
        if e["symbol_here"]:
            out.append(f"  symbol    : {e['symbol_here']}")
        if e["section"]:
            out.append(f"  section   : {e['section']}")
        out.append(f"  references: {e['total']}")
        for x in e["pointer_xrefs"]:
            out.append(f"    pointer     0x{x['at']:x} in {x['section']}")
        for x in e["instruction_xrefs"]:
            out.append(f"    instruction 0x{x['at']:x}  {x['instruction']}")
        if not e["total"]:
            out.append("    (none found -- see note below; this is not "
                       "proof that no reference exists)")
        if e.get("containing_functions"):
            out.append(f"  containing functions: "
                       f"{', '.join(e['containing_functions'])}")
        out.append("")
    out += ["note:", note]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())