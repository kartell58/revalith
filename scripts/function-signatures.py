#!/usr/bin/env python3
"""function-signatures.py -- infer a probable signature for a function.

IMPORTANT: everything this prints is INFERENCE, not proof. It reports which
argument registers a function reads before writing them, whether it returns a
value, whether it allocates a stack frame, and which callees it calls. Those
facts constrain the signature; they do not determine parameter types or names.

Evidence rules used here:
  * An argument register is "used" if it is read before any instruction
    writes it. On all four ABIs covered here the first N integer registers
    are the integer argument registers, so reading one implies an argument.
  * A function is treated as returning a value only if its return register is
    written with something other than the incoming value, or the caller is
    seen consuming it. The script cannot see callers, so it reports this as
    "weak" evidence.
  * Frame size, callee-saved register use and calls are reported as facts.

Examples
--------
  function-signatures.py ./app.so --symbol parse_header
  function-signatures.py ./app.so --addr 0x2a4c0 --json
  function-signatures.py ./app.so --list-args        # rank by arg count
  function-signatures.py ./app.so --addr 0x2a4c0 --abi aapcs64
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

# Integer argument / return registers per ABI.
ABIS = {
    "aapcs64": {"arch": ("AArch64",), "args": [f"x{i}" for i in range(8)],
                "ret": "x0", "wordsize": 4},
    "aapcs32": {"arch": ("ARM",), "args": [f"r{i}" for i in range(4)],
                "ret": "r0", "wordsize": 4},
    "sysv-x86_64": {"arch": ("x86-64",), "args": ["rdi", "rsi", "rdx", "rcx",
                                                  "r8", "r9"],
                    "ret": "rax", "wordsize": 8},
    "cdecl-x86": {"arch": ("x86",), "args": [], "ret": "eax", "wordsize": 4},
    "win64": {"arch": ("x86-64",), "args": ["rcx", "rdx", "r8", "r9"],
              "ret": "rax", "wordsize": 8},
}


def pick_abi(info, override):
    if override:
        return override, ABIS[override]
    arch = (info.arch or "").lower()
    if "aarch64" in arch or "arm64" in arch:
        return "aapcs64", ABIS["aapcs64"]
    if arch == "arm":
        return "aapcs32", ABIS["aapcs32"]
    if "x86-64" in arch or "x86_64" in arch:
        if info.fmt == "PE":
            return "win64", ABIS["win64"]
        return "sysv-x86_64", ABIS["sysv-x86_64"]
    if arch == "x86":
        return "cdecl-x86", ABIS["cdecl-x86"]
    return None, None


def disassemble(info, start, size, args):
    tool = None
    for cand in ("objdump", "llvm-objdump"):
        if shutil.which(cand):
            tool = cand
            break
    if tool is None:
        return None, ("objdump/llvm-objdump unavailable: no instruction-level "
                      "analysis was performed. Without a disassembler only "
                      "symbol metadata can be reported.")
    stop = start + size if size else 0
    cmd = [tool, "-d", "--no-show-raw-insn"]
    if info.fmt == "ELF":
        cmd += ["--start-address", f"0x{start:x}"]
        if stop:
            cmd += ["--stop-address", f"0x{stop:x}"]
    elif info.fmt == "PE":
        # objdump addresses PE files by RVA-relative virtual address.
        cmd += ["--start-address", f"0x{start:x}"]
        if stop:
            cmd += ["--stop-address", f"0x{stop:x}"]
    cmd.append(info.path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=args.timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"{tool} failed: {e}"
    if proc.returncode != 0:
        return None, f"{tool} exited {proc.returncode}: {proc.stderr.strip()[:160]}"
    return proc.stdout, None


REG = r"\b([wx]\d{1,2}|r\d{1,2}|e[abcd]x|[abcd]l|[abcd]h|sip|sp|pc|lr)\b"
LINE = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")


def parse_body(text, abi):
    """Split disassembly into (address, mnemonic, operands) tuples."""
    rows = []
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        parts = m.group(2).strip().split(None, 1)
        if not parts:
            continue
        rows.append((int(m.group(1), 16), parts[0].lower(),
                     parts[1] if len(parts) > 1 else ""))
    return rows


NON_WRITES = {
    # compare/test: operands are read, not written
    "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz", "str", "stur",
    "stp", "stxr", "ldxr", "ldar", "ccmp", "ccmn", "test", "sete", "setne",
    # branch / call: no register is defined
    "b", "bl", "br", "blr", "ret", "cb", "tb", "b.eq", "b.ne", "nop",
}


def is_write(mnem, ops, regs, abi):
    """Heuristic: does this instruction define (write) any register in ``regs``?

    This drives the return-value inference, so it must not count reads as
    writes: ``add x0, x0, #0x8c0`` reads x0 and must not be treated as
    producing a return value.
    """
    if mnem in NON_WRITES:
        return False
    # AArch64 three-operand add/sub write the *first* operand, but the
    # common address-materialising forms "add x0, x0, #imm" and
    # "adrp x0, page" merely carry a value already in the same register.
    # They must not be read as "produces a return value".
    if mnem in ("add", "sub", "adrp", "adr"):
        op_list = [o.strip() for o in ops.split(",")]
        if len(op_list) >= 2 and op_list[0] == op_list[1]:
            return False
        if mnem in ("adrp", "adr"):
            return True          # defines a fresh address, not a reuse
    dests = set()
    head = ops.split(",")[0].strip() if ops else ""
    if head and not head.startswith(("[", "#", "<")):
        dests.update(re.findall(REG, head))
    if "{" in ops:
        dests.update(re.findall(REG, ops))
    return bool(dests & regs)


def reads_register(mnem, ops, regs):
    """Does this instruction read any of ``regs``?"""
    if mnem.startswith(("str", "stp", "stur")) and "{" not in ops:
        return False                       # store form: operands are addresses
    return bool(set(re.findall(REG, ops)) & regs)


def analyse(rows, abi_name, abi, sym):
    args = abi["args"]
    ret = abi["ret"]
    evidence = {
        "instruction_count": len(rows),
        "argument_registers_read": [],
        "return_register_written": False,
        "return_evidence": "none",
        "stack_frame": [],
        "calls": [],
        "returns_seen": False,
    }
    written = set()
    calls = []
    frame_ops = []
    ret_writes = []
    arg_reads = []

    for at, mnem, ops in rows:
        ops_clean = re.sub(r"<[^>]*>", "", ops)      # drop symbol comments

        writes = set(re.findall(REG, ops_clean.split(",")[0])) \
            if ops_clean else set()

        # Argument registers read *before* the function writes them are the
        # strongest available signal of a parameter.
        for reg in args:
            if reg in written:
                continue
            if reg == ret:
                continue          # x0/eax/rax is the return register too
            if reads_register(mnem, ops_clean, {reg}):
                arg_reads.append(reg)

        if mnem in ("bl", "blx", "call"):
            calls.append((at, ops_clean))

        if mnem.startswith("ret"):
            evidence["returns_seen"] = True

        if mnem in ("sub", "add", "stp", "push", "stppre") \
                and re.search(r"\bsp\b", ops_clean):
            frame_ops.append(f"{mnem} {ops_clean.strip()}")

        if is_write(mnem, ops_clean, {ret}, abi):
            ret_writes.append((at, mnem, ops_clean))

        written |= writes
        # AArch64 32-bit writes (w0) also clobber the 64-bit register.
        written |= {r[1:] for r in writes if r.startswith("w") and r[1:].isdigit()}

    # Keep only a contiguous argument prefix: a use of x3 without x0/x1 is far
    # more likely to be an unrelated register than a 4-argument call.
    prefix = []
    for reg in args:
        if reg in arg_reads:
            prefix.append(reg)
        else:
            break
    if not prefix:
        prefix = sorted(set(arg_reads),
                        key=lambda r: args.index(r))[:1] if arg_reads else []

    evidence["argument_registers_read"] = prefix
    evidence["argument_registers_read_out_of_order"] = sorted(
        set(arg_reads) - set(prefix))
    evidence["stack_frame"] = frame_ops[:4]
    evidence["calls"] = [{"at": hex(a), "target": o.strip()}
                         for a, o in calls[:12]]
    evidence["return_register_written"] = bool(ret_writes)
    evidence["argument_setup_only"] = False
    if ret_writes:
        # A write to the return register that is consumed by the very next
        # instruction being a call is argument marshalling, not a return.
        call_at = {a for a, _ in calls}
        consumed = any(
            any(0 < c - a <= 8 for c in call_at) for a, _, _ in ret_writes)
        if consumed:
            evidence["return_register_written"] = False
            evidence["argument_setup_only"] = True
            evidence["return_evidence"] = (
                f"{ret} is written only to set up arguments for calls "
                f"(first at {hex(ret_writes[0][0])}); no return value is "
                "produced in this window")
        else:
            evidence["return_evidence"] = (
                "return register " + ret + " written at " +
                ", ".join(f"{hex(a)} ({m})" for a, m, _ in ret_writes[:3]))
    else:
        evidence["return_evidence"] = (
            f"{ret} never written in this window: likely void, or the value "
            "is produced by a tail call")

    n_args = len(prefix)
    sig = render_signature(sym, abi_name, abi, evidence)
    return {"symbol": sym, "abi": abi_name,
            "probable_signature": sig, "arg_count_estimate": n_args,
            "evidence": evidence}


def render_signature(sym, abi_name, abi, ev):
    """Build a conservative C-like signature from the evidence.

    Parameter types are deliberately left unknown: register usage proves that
    a value arrives in a register, not what it represents.
    """
    rets = abi["ret"] if ev["return_register_written"] else "void"
    params = [f"arg_{reg} /* type unknown */"
              for reg in ev["argument_registers_read"][:8]]
    return (f"{rets} {sym}("
            f"{', '.join(params) if params else '/* no arguments detected */'})")


def main():
    p = argparse.ArgumentParser(
        description="Infer a probable function signature (inference only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("file", help="binary to inspect")
    p.add_argument("--addr", type=lambda s: int(s, 0),
                   help="function start address")
    p.add_argument("--symbol", help="function symbol name")
    p.add_argument("--size", type=lambda s: int(s, 0), default=0,
                   help="bytes to analyse (default: from the symbol size)")
    p.add_argument("--abi", choices=sorted(ABIS),
                   help="force a calling convention instead of guessing")
    p.add_argument("--list-args", action="store_true",
                   help="rank exported functions by estimated argument count")
    p.add_argument("--limit", type=int, default=40,
                   help="max rows for --list-args (default 40)")
    p.add_argument("--timeout", type=int, default=120,
                   help="disassembly timeout in seconds")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 2
    if not (args.addr or args.symbol or args.list_args):
        p.error("specify --addr, --symbol or --list-args")

    try:
        info = B.load(args.file)
    except B.ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    abi_name, abi = pick_abi(info, args.abi)
    if abi is None:
        print(f"error: no calling convention known for architecture "
              f"{info.arch!r}; pass --abi explicitly.", file=sys.stderr)
        return 1

    if args.list_args:
        return list_args(info, abi_name, abi, args)

    sym = args.symbol or f"sub_{args.addr:x}"
    start = args.addr
    size = args.size
    if args.symbol:
        s = next((x for x in info.symbols if x.name == args.symbol), None)
        if s is None:
            print(f"error: symbol {args.symbol!r} not found", file=sys.stderr)
            return 1
        start, size = s.value, (size or s.size or 0)
        sym = args.symbol
    if start is None:
        print("error: could not determine the function address",
              file=sys.stderr)
        return 1
    if not size:
        size = args.size or 0x200   # default window when the size is unknown

    text, note = disassemble(info, start, size, args)
    if text is None:
        result = {"symbol": sym, "abi": abi_name,
                  "probable_signature": None,
                  "error": note}
        print(json.dumps(result, indent=2) if args.json
              else f"error: {note}", file=sys.stderr)
        return 1

    rows = parse_body(text, abi)
    if not rows:
        msg = (f"no instructions disassembled at 0x{start:x}; the address may "
               "be wrong, or outside the executable sections.")
        print(f"error: {msg}", file=sys.stderr)
        return 1

    result = analyse(rows, abi_name, abi, sym)
    result["address"] = f"0x{start:x}"
    result["size_analysed"] = len(rows) * 4 if abi["wordsize"] == 4 else len(rows)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result, note))
    return 0


def list_args(info, abi_name, abi, args):
    """Rank functions by estimated argument count.

    Useful for triage -- wide signatures are often the interesting ones. Each
    row is still inference and needs confirming before use.
    """
    funcs = [s for s in info.symbols if s.is_func and s.size and s.name]
    funcs = sorted(funcs, key=lambda s: s.value)[:args.limit]
    rows = []
    for s in funcs:
        body, n2 = disassemble(info, s.value, s.size, args)
        if body is None:
            continue
        rws = parse_body(body, abi)
        if not rws:
            continue
        ev = analyse(rws, abi_name, abi, s.name)
        rows.append((ev["arg_count_estimate"], s.name, s.value, ev["calls"]
                 if "calls" in ev else ev["evidence"]["calls"]))
    rows.sort(reverse=True)
    lines = [f"argument-count estimates ({abi_name}) -- INFERENCE, verify in a "
             f"disassembler", ""]
    lines.append(f"  {'args':>4}  {'address':>12}  name")
    for n, name, addr, _ in rows:
        lines.append(f"  {n:>4}  0x{addr:x}  {name}")
    lines += ["", "note: an argument count inferred from register use is a "
                  "lower bound;", "      a function may read arguments "
                  "it does not need, or be tail-called."]
    print("\n".join(lines))
    return 0


def render(result, note):
    ev = result["evidence"]
    out = [
        f"symbol : {result['symbol']}",
        f"address: {result['address']}",
        f"abi    : {result['abi']}",
        "",
        f"probable signature (INFERENCE): {result['probable_signature']}",
        "",
        "evidence:",
        f"  instructions analysed : {ev['instruction_count']}",
        f"  arg registers read    : "
        f"{ev['argument_registers_read'] or 'none detected'}",
        f"  estimated arg count   : {result['arg_count_estimate']}",
        f"  return register       : {ev['return_evidence']}",
        f"  stack frame ops       : "
        f"{ev['stack_frame'] if ev['stack_frame'] else 'none detected'}",
    ]
    if ev["calls"]:
        out.append("  calls:")
        out += [f"    {c['at']}  {c['target']}" for c in ev["calls"]]
    else:
        out.append("  calls                 : none detected")
    out += ["", "This is an inference from register usage, not proof of the",
            "real signature. Types and parameter names are unknown; confirm by",
            "tracing callers and callees before concluding."]
    if note:
        out += ["", f"note: {note}"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())