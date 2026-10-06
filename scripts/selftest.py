#!/usr/bin/env python3
"""Regression tests for _binlib parsers.

Run:  python3 scripts/selftest.py
Requires no external tools and no network. Binary fixtures are generated in a
temp dir, so every expected value below is known by construction.
"""
import os
import struct
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _binlib as B  # noqa: E402

FAILURES = []
COUNT = 0


def check(cond, msg):
    global COUNT
    COUNT += 1
    if not cond:
        FAILURES.append(msg)


def eq(got, want, msg):
    check(got == want, f"{msg}: got {got!r}, want {want!r}")


# --------------------------------------------------------------- PE fixture

def build_pe(path):
    """Build a PE32+ with a 2-entry export table and a 3-entry import table.

    .rdata is laid out by a bump allocator so the tables cannot overlap.
    """
    text_rva, text_raw = 0x1000, 0x200
    rdata_rva, rdata_raw = 0x2000, 0x400
    imagebase, opt_size = 0x140000000, 240
    r = bytearray(0x200)
    cur = [0]

    def alloc(size):
        """Reserve `size` bytes in .rdata, 8-byte aligned, return the offset."""
        off = (cur[0] + 7) & ~7
        cur[0] = off + size
        assert cur[0] <= len(r), "rdata overflow"
        return off

    def put(off, text):
        r[off:off + len(text)] = text.encode()

    EXP_DIR = alloc(0x28)
    EXP_FUNC = alloc(4 * 3)            # 2 functions + terminator
    EXP_NAME = alloc(4 * 3)            # 2 names + terminator
    EXP_ORD = alloc(2 * 3)             # 2 ordinals + terminator
    S_DLL1 = alloc(16)
    S_FN1A = alloc(16)
    S_FN1B = alloc(16)
    IMP_ILT = alloc(8 * 4)             # 3 thunks + NUL terminator
    IMP_IAT = alloc(8 * 4)
    IMP_DESC = alloc(20 * 2)           # one descriptor + NUL descriptor
    S_DLL2 = alloc(16)
    S_FN2A = alloc(24)
    S_FN2B = alloc(24)
    S_FN2C = alloc(24)

    sectab = bytearray()
    for name, vsize, vaddr, rsize, rptr, flags in [
        (b".text\0\0\0", 0x10, text_rva, 0x200, text_raw, 0x60000020),
        (b".rdata\0\0", 0x200, rdata_rva, 0x200, rdata_raw, 0x40000040),
    ]:
        sectab += name.ljust(8, b"\x00")
        sectab += struct.pack("<IIII", vsize, vaddr, rsize, rptr)
        sectab += struct.pack("<IIHHI", 0, 0, 0, 0, flags)

    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x5F5E1000, 0, 0, opt_size, 0x0022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<B", opt, 2, 14)
    struct.pack_into("<I", opt, 16, text_rva + 0x4)
    struct.pack_into("<I", opt, 20, text_rva)
    struct.pack_into("<Q", opt, 24, imagebase)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<H", opt, 68, 0x0162)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112, rdata_rva + EXP_DIR, 0x40)
    struct.pack_into("<II", opt, 120, rdata_rva + IMP_DESC, 0x28)

    struct.pack_into("<IIHHIIIIIII", r, EXP_DIR, 0, 0x5F5E1000, 0, 0,
                     rdata_rva + S_DLL1, 1, 2, 2,
                     rdata_rva + EXP_FUNC, rdata_rva + EXP_NAME,
                     rdata_rva + EXP_ORD)
    struct.pack_into("<I", r, EXP_FUNC + 0, text_rva + 0x00)
    struct.pack_into("<I", r, EXP_FUNC + 4, text_rva + 0x10)
    struct.pack_into("<I", r, EXP_NAME + 0, rdata_rva + S_FN1A)
    struct.pack_into("<I", r, EXP_NAME + 4, rdata_rva + S_FN1B)
    struct.pack_into("<H", r, EXP_ORD + 0, 0)
    struct.pack_into("<H", r, EXP_ORD + 2, 1)
    put(S_DLL1, "sample.dll"); put(S_FN1A, "alpha_fn"); put(S_FN1B, "beta_fn")

    # ILT and IAT both point at IMAGE_IMPORT_BY_NAME records: a 2-byte hint
    # followed by a NUL-terminated name.
    for i, soff in enumerate((S_FN2A, S_FN2B, S_FN2C)):
        thunk = rdata_rva + soff
        struct.pack_into("<Q", r, IMP_ILT + i * 8, thunk)
        struct.pack_into("<Q", r, IMP_IAT + i * 8, thunk)
    struct.pack_into("<IIIII", r, IMP_DESC, rdata_rva + IMP_ILT, 0, 0,
                     rdata_rva + S_DLL2, rdata_rva + IMP_IAT)
    put(S_DLL2, "kernel32.dll")
    for i, (soff, hint, nm) in enumerate(((S_FN2A, 0, "CreateFileA"),
                                          (S_FN2B, 1, "CloseHandle"),
                                          (S_FN2C, 2, "VirtualAlloc"))):
        struct.pack_into("<H", r, soff, hint)
        put(soff + 2, nm)

    data = bytearray(0x600)
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    data[0:64] = dos
    data[64:74] = b"stub\r\n$\x00\x00\x00\x00"
    p = 0x80
    data[p:p + 4] = b"PE\x00\x00"
    data[p + 4:p + 24] = coff
    data[p + 24:p + 24 + opt_size] = bytes(opt)
    data[p + 24 + opt_size:p + 24 + opt_size + len(sectab)] = sectab
    data[text_raw:text_raw + 4] = b"\x48\x31\xc0\xc3"
    data[rdata_raw:rdata_raw + len(r)] = r
    open(path, "wb").write(bytes(data))


# ---------------------------------------------------------- Mach-O fixture

def build_macho(path, bits=64):
    end = "<"
    cputype = 0x0100000C
    if bits == 64:
        hdr = struct.pack(end + "IiiIIIII", 0xFEEDFACF, cputype, 3, 2, 4, 0,
                          0x00200085, 0)
        seg_cmd_size, sec_struct_size = 72, 80
    else:
        hdr = struct.pack(end + "IiiIIII", 0xFEEDFACE, cputype, 3, 2, 4, 0,
                          0x00200085)
        seg_cmd_size, sec_struct_size = 56, 68

    seg = bytearray(struct.pack(end + "II", 0x19 if bits == 64 else 0x1, 0))
    seg += b"__TEXT".ljust(16, b"\x00")
    if bits == 64:
        seg += struct.pack(end + "QQQQ", 0x100000000, 0x4000, 0, 0x4000)
    else:
        seg += struct.pack(end + "IIII", 0x1000, 0x4000, 0, 0x4000)
    seg += struct.pack(end + "IIII", 7, 5, 1, 0)
    # cmdsize spans the load command plus its inline section records
    struct.pack_into(end + "I", seg, 4, seg_cmd_size + sec_struct_size)

    sec = b"__text".ljust(16, b"\x00") + b"__TEXT".ljust(16, b"\x00")
    if bits == 64:
        sec += struct.pack(end + "QQIIIIIIII", 0x100000F00, 0x100, 0, 0x1000,
                           0, 0, 0x80000400, 0, 0, 0)
    else:
        sec += struct.pack(end + "IIIIIIIII", 0x1000F00, 0x100, 0x1000,
                           0, 0, 0x80000400, 0, 0)

    load = struct.pack(end + "II", 0xC, 48) + \
        struct.pack(end + "IIII", 24, 0, 0x10000, 0) + \
        b"/usr/lib/libSystem.B.dylib\x00"

    symoff, stroff = 0x4000, 0x4200
    symtab_cmd = struct.pack(end + "II", 0x2, 24) + \
        struct.pack(end + "IIII", symoff, 2, stroff, 0)

    names = ["_helper", "_main"]
    strtab = bytearray(b"\x00")
    strx = []
    for nm in names:
        strx.append(len(strtab))
        strtab += nm.encode() + b"\x00"
    nlist = bytearray()
    fmt = end + ("IBBHQ" if bits == 64 else "IBBhI")
    for i, sx in enumerate(strx):
        nlist += struct.pack(fmt, sx, 0x0E, 1, 0x0E, 0x100000F00 + i * 0x10)

    out = bytearray(hdr) + seg + sec + symtab_cmd + load
    struct.pack_into(end + "I", out, 20, len(seg) + len(sec) + len(symtab_cmd) + len(load))
    out += b"\x00" * (symoff - len(out))
    out += nlist
    out += b"\x00" * (stroff - len(out))
    out += strtab
    open(path, "wb").write(bytes(out))


# ------------------------------------------------------------ ELF fixtures

def build_elf(path, bits=64, endian="<", machine=183, etype=3,
              needed=("libc.so",), soname=None):
    """Minimal ET_DYN ELF with .text/.rodata/.dynsym/.dynstr/.dynamic."""
    data = bytearray(0x2000)
    addr = 0x1000

    def w16(off, v):
        struct.pack_into(endian + "H", data, off, v)

    def w32(off, v):
        struct.pack_into(endian + "I", data, off, v)

    def w64(off, v):
        struct.pack_into(endian + "Q", data, off, v)

    ehsize = 64 if bits == 64 else 52
    phentsize = 56 if bits == 64 else 32
    shentsize = 64 if bits == 64 else 40

    # string tables are filled after offsets are known
    names = [".text", ".rodata", ".dynsym", ".dynstr", ".dynamic", ".shstrtab"]
    shstrtab_off = 0xF00
    # sh_name is an offset *into* .shstrtab; index 0 must be a NUL byte.
    data[shstrtab_off] = 0
    names_off, cur = [], 1
    for n in names:
        names_off.append(cur)
        data[shstrtab_off + cur:shstrtab_off + cur + len(n)] = n.encode()
        cur += len(n) + 1

    dynstr_off, dynstr = 0xE00, bytearray()
    needed_idx = []
    for n in list(needed) + ([soname] if soname else []):
        needed_idx.append(len(dynstr))
        dynstr += n.encode() + b"\x00"
    dynstr += b"\x00"

    dynsym_off = 0xD00
    sym_idx = []
    dynstr += b"defined_symbol\x00"
    defined_name_idx = len(dynstr) - len("defined_symbol") - 1
    for i, n in enumerate(needed):
        # STB_GLOBAL | STT_NOTYPE, SHN_UNDEF -> an import
        sym_idx.append((needed_idx[i], 0x10, 0))
    # STB_GLOBAL(1) << 4 | STT_FUNC(2) = 0x12, shndx = 1 (.text)
    sym_idx.append((defined_name_idx, 0x12, addr))

    esz = 24 if bits == 64 else 16
    for i, (strx, info, value) in enumerate(sym_idx):
        base = dynsym_off + i * esz
        shndx = 0 if value == 0 else 1
        if bits == 64:
            struct.pack_into(endian + "IBBHQQ", data, base, strx, info, 0,
                             shndx, value, 0x20)
        else:
            struct.pack_into(endian + "IIIBBH", data, base, strx, value,
                             0x20, info, 0, shndx)

    # .dynamic
    dyn_entries = [(1, needed_idx[0] if needed else 0)]
    for i in range(1, len(needed)):
        dyn_entries.append((1, needed_idx[i]))
    if soname:
        dyn_entries.append((14, needed_idx[-1]))
    dyn_entries.append((5, addr + 0xE00))     # DT_STRTAB (vaddr of .dynstr)
    dyn_entries.append((0, 0))
    dynamic_off = 0xC00
    for i, (tag, val) in enumerate(dyn_entries):
        if bits == 64:
            struct.pack_into(endian + "qQ", data, dynamic_off + i * 16, tag, val)
        else:
            struct.pack_into(endian + "iI", data, dynamic_off + i * 8, tag, val)

    # section headers  (sh_name must be relative to .shstrtab)
    shoff = 0x1800
    secs = [
        (0, 0, 0, 0, 0, 0, 0),                       # NULL
        (names_off[0], 1, 0x6, addr, 0x1000, 0x100, 0),
        (names_off[1], 1, 0x2, addr + 0x1000, 0x1100, 0x40, 0),
        (names_off[2], 11, 0x2, addr + 0xD00, dynsym_off, len(sym_idx) * esz, 0),
        (names_off[3], 3, 0x2, addr + 0xE00, dynstr_off, len(dynstr), 0),
        (names_off[4], 6, 0x3, addr + 0xC00, dynamic_off,
         len(dyn_entries) * (16 if bits == 64 else 8), 0),
        (names_off[5], 3, 0, 0, shstrtab_off, cur, 0),
    ]
    for i, s in enumerate(secs):
        base = shoff + i * shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link = s
        if bits == 64:
            struct.pack_into(endian + "IIQQQQIIQQ", data, base, sh_name,
                             sh_type, sh_flags, sh_addr, sh_off, sh_size,
                             sh_link, 0, 0, 0)
        else:
            struct.pack_into(endian + "IIIIIIIIII", data, base, sh_name,
                             sh_type, sh_flags, sh_addr, sh_off, sh_size,
                             sh_link, 0, 0, 0)

    # ELF header
    data[0:4] = b"\x7fELF"
    data[4] = 2 if bits == 64 else 1
    data[5] = 1 if endian == "<" else 2
    data[6] = 1
    if bits == 64:
        struct.pack_into(endian + "HHIQQQIHHHHHH", data, 16, etype, machine,
                         1, addr, 0, shoff, 0, ehsize, phentsize, 0,
                         shentsize, len(secs), 6)
    else:
        struct.pack_into(endian + "HHIIIIIHHHHHH", data, 16, etype, machine,
                         1, addr, 0, shoff, 0, ehsize, phentsize, 0,
                         shentsize, len(secs), 6)
    # PT_LOAD covering .text/.rodata so vaddr<->offset mapping works
    if bits == 64:
        struct.pack_into(endian + "IIQQQQQQ", data, 64, 1, 5, 0x1000, addr,
                         addr, 0x200, 0x200, 0x1000)
    else:
        struct.pack_into(endian + "IIIIIIII", data, 52, 1, 0x1000, addr, addr,
                         0x200, 0x200, 5, 0x1000)

    data[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    need = shoff + len(secs) * shentsize
    if len(data) < need:
        data += bytearray(need - len(data))
    open(path, "wb").write(bytes(data))


# ------------------------------------------------------------------- tests

def test_elf_64(tmp):
    p = os.path.join(tmp, "lib.so")
    build_elf(p, 64, "<", 183, 3, ("libc.so", "libm.so"), "libtest.so")
    i = B.load(p)
    eq(i.fmt, "ELF", "elf fmt")
    eq(i.bits, 64, "elf bits")
    eq(i.endian, "little", "elf endian")
    eq(i.arch, "AArch64", "elf arch")
    eq(i.entrypoint, 0x1000, "elf entry")
    eq(i.is_pie, True, "elf pie")
    eq(i.needed, ["libc.so", "libm.so"], "elf needed")
    eq(i.soname, "libtest.so", "elf soname")
    eq([s.name for s in i.sections], ["", ".text", ".rodata", ".dynsym",
                                      ".dynstr", ".dynamic", ".shstrtab"],
       "elf sections")
    eq(i.vaddr_to_offset(0x1000), 0x1000, "elf v2o")
    eq(i.offset_to_vaddr(0x1000), 0x1000, "elf o2v")
    eq(len(i.imports()), 2, "elf import count")
    eq(len(i.exports()), 1, "elf export count")
    check(i.exports()[0].is_func, "elf export is func")


def test_elf_32_be(tmp):
    p = os.path.join(tmp, "be32.elf")
    build_elf(p, 32, ">", 40, 2, ("libc.so",))
    i = B.load(p)
    eq(i.bits, 32, "be elf bits")
    eq(i.endian, "big", "be elf endian")
    eq(i.arch, "ARM", "be elf arch")
    eq(i.is_pie, False, "be elf not pie")
    eq(i.needed, ["libc.so"], "be elf needed")
    eq(i.entrypoint, 0x1000, "be elf entry")
    eq(len(i.exports()), 1, "be elf export count")


def test_pe(tmp):
    p = os.path.join(tmp, "s.exe")
    build_pe(p)
    i = B.load(p)
    eq(i.fmt, "PE", "pe fmt")
    eq(i.bits, 64, "pe bits")
    eq(i.arch, "x86-64", "pe arch")
    eq(i.imagebase, 0x140000000, "pe imagebase")
    eq(i.entrypoint, 0x140001004, "pe entry")
    eq([s.name for s in i.sections], [".text", ".rdata"], "pe sections")
    eq(i.needed, ["kernel32.dll"], "pe needed")
    eq([s.name for s in i.exports()],
       ["sample.dll!alpha_fn", "sample.dll!beta_fn"], "pe exports")
    imports = [s.name for s in i.imports()]
    eq(sorted(imports), ["kernel32.dll!CloseHandle",
                         "kernel32.dll!CreateFileA",
                         "kernel32.dll!VirtualAlloc"], "pe imports")
    # Each import must carry its own 8-byte-strided IAT slot, not the base.
    slots = sorted(s.value for s in i.imports())
    eq([b - a for a, b in zip(slots, slots[1:])], [8, 8],
       "pe import slots are 8 bytes apart")
    eq(i.vaddr_to_offset(slots[0]), 0x400 + (slots[0] - 0x140002000),
       "pe iat slot 0 maps back into .rdata")
    check(all(s.is_undefined for s in i.imports()), "pe imports are undefined")
    eq(i.vaddr_to_offset(0x140001000), 0x200, "pe v2o text")
    eq(i.vaddr_to_offset(0x140002000), 0x400, "pe v2o rdata")
    eq(i.offset_to_vaddr(0x400), 0x140002000, "pe o2v rdata")
    eq(i.section_for(0x140001004).name, ".text", "pe section_for")


def test_macho(tmp):
    p = os.path.join(tmp, "s.macho")
    build_macho(p, 64)
    i = B.load(p)
    eq(i.fmt, "Mach-O", "macho fmt")
    eq(i.bits, 64, "macho bits")
    eq(i.arch, "ARM64", "macho arch")
    eq(i.extra["filetype"], "executable", "macho filetype")
    eq(i.needed, ["/usr/lib/libSystem.B.dylib"], "macho needed")
    eq([s.name for s in i.exports()], ["helper", "main"], "macho exports")
    eq([s.name for s in i.sections], ["__TEXT,__text"], "macho sections")
    eq(i.sections[0].addr, 0x100000F00, "macho section addr")
    eq(i.sections[0].size, 0x100, "macho section size")


def test_sniff(tmp):
    eq(B.sniff(os.path.join(tmp, "s.exe")), "PE", "sniff PE")
    eq(B.sniff(os.path.join(tmp, "s.macho")), "Mach-O", "sniff Mach-O")
    eq(B.sniff(os.path.join(tmp, "lib.so")), "ELF", "sniff ELF")
    bad = os.path.join(tmp, "bad.bin")
    open(bad, "wb").write(b"\x00" * 64)
    eq(B.sniff(bad), "unknown", "sniff unknown")
    try:
        B.load(bad)
        check(False, "load(unknown) should raise")
    except B.ParseError:
        check(True, "load(unknown) raises ParseError")


def test_strings():
    blob = b"\x00\x00hello\x00\x00\x00world\x00" + b"\xff" * 8
    got = B.extract_strings(blob, 4, ("ascii",))
    eq([t[1] for t in got], ["hello", "world"], "ascii strings")
    eq([t[0] for t in got], [2, 10], "ascii string offsets")
    # utf16le: "hi" stored as 'h\0i\0'
    wide = b"\x00\x00" + "hi".encode("utf-16le") + b"\x00\x00"
    w = B.extract_strings(wide, 2, ("utf16le",))
    eq([t[1] for t in w], ["hi"], "utf16le string")
    eq([t[0] for t in w], [2], "utf16le offset")


def test_arm64_branch():
    # BL with imm26 = 0x10 (words) -> pc + 0x40
    eq(B.arm64_target(0x1000, 0x94000010), 0x1040, "arm64 BL target")
    # B (unconditional) imm26 = 0x20 -> pc + 0x80
    eq(B.arm64_target(0x1000, 0x14000020), 0x1080, "arm64 B target")
    # B.cond backwards: imm19 = -4 words -> pc - 0x10
    imm19 = (-4) & 0x7FFFF
    insn = 0x54000000 | (imm19 << 5) | 0x0
    eq(B.arm64_target(0x2000, insn), 0x2000 - 0x10, "arm64 B.cond target")
    # CBZ forwards: imm19 = 0x10 words -> pc + 0x40
    cbz = 0x34000000 | (0x10 << 5)
    eq(B.arm64_target(0x3000, cbz), 0x3040, "arm64 CBZ target")
    # not a branch
    eq(B.arm64_target(0x1000, 0xD503201F), None, "arm64 non-branch")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        for fn in (test_elf_64, test_elf_32_be, test_pe, test_macho,
                   test_sniff):
            try:
                fn(tmp)
            except Exception:
                FAILURES.append(f"{fn.__name__} raised:\n{traceback.format_exc()}")
        for fn in (test_strings, test_arm64_branch):
            try:
                fn()
            except Exception:
                FAILURES.append(f"{fn.__name__} raised:\n{traceback.format_exc()}")

    if FAILURES:
        print(f"FAILED: {len(FAILURES)} problem(s) out of {COUNT} checks")
        for f in FAILURES:
            print("  -", f)
        return 1
    print(f"OK: {COUNT} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())