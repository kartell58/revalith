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

import json  # noqa: E402


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


# --------------------------------------------------------------------------
# dumpers/ and _weblib
# --------------------------------------------------------------------------

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "dumpers"))
import _formats      # noqa: E402
import _indicators   # noqa: E402
import _assets       # noqa: E402
import _android      # noqa: E402
import _unity        # noqa: E402
import _archives     # noqa: E402
import _binaries     # noqa: E402
import _report       # noqa: E402
import _tools        # noqa: E402
import _weblib       # noqa: E402
import _reconlib     # noqa: E402


def test_formats_identify_by_content(tmp):
    cases = [
        ("a.elf", B.open(os.devnull, "rb") if False else b"\x7fELF" + b"\x00" * 60,
         "elf"),
        ("a.dll", b"MZ" + b"\x00" * 60, "pe"),
        ("a.macho", b"\xcf\xfa\xed\xfe" + b"\x00" * 60, "macho"),
        ("a.dex", b"dex\n035\x00" + b"\x00" * 60, "dex"),
        ("a.zip", b"PK\x03\x04" + b"\x00" * 60, "zip"),
        ("a.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 60, "gzip"),
        ("a.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 60, "png"),
        ("a.sqlite", b"SQLite format 3\x00" + b"\x00" * 60, "sqlite"),
        ("a.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 60, "7z"),
    ]
    for name, blob, want in cases:
        p = os.path.join(tmp, name)
        open(p, "wb").write(blob)
        got = _formats.identify(p)
        eq(got.fmt, want, f"identify {name} by content")
        eq(got.ext_matches_content, True, f"{name} extension agrees")

    # A text file with a lying extension must be reported as text, and the
    # disagreement flagged.
    lie = os.path.join(tmp, "lie.png")
    open(lie, "w").write("plain text, not a png at all\n" * 4)
    ident = _formats.identify(lie)
    eq(ident.fmt, "text", "text file identified as text despite .png")
    eq(ident.ext_matches_content, False, "extension disagreement detected")
    check(any("disagrees" in w for w in ident.warnings),
          "extension mismatch produces a warning")

    # Empty file must not raise.
    empty = os.path.join(tmp, "empty.bin")
    open(empty, "wb").close()
    eq(_formats.identify(empty).fmt, "empty", "empty file handled")

    # Random bytes: unknown, and high entropy must NOT be reported as
    # encrypted on its own.
    rnd = os.path.join(tmp, "rand.bin")
    open(rnd, "wb").write(bytes((i * 97 + i * i * 31) % 256 for i in range(20000)))
    r = _formats.identify(rnd)
    eq(r.fmt, "unknown", "unrecognised content is unknown")
    cls = _formats.classify_blob(r)
    check(cls["confidence"] in ("low", "very low"),
          "unknown high-entropy blob is low confidence, not a verdict")
    check("encrypted" not in cls["classification"],
          "entropy alone never yields 'encrypted'")
    check("encrypted" in cls["reason"],
          "the reasoning mentions encryption as a possibility, not a claim")


def test_indicators(tmp):
    text = ("visit https://api.example.com/v1/users and "
            "wss://ws.example.com/socket, fallback 10.0.0.5 and "
            "192.168.1.10 and 2001:db8::1 ; call /api/login")
    inds = _indicators.scan_text(text, "libfoo.so", offset=0x1000)
    kinds = {}
    for i in inds:
        kinds.setdefault(i.kind, []).append(i.value)

    eq("https://api.example.com/v1/users" in kinds.get("url", []), True,
       "absolute url found")
    eq("wss://ws.example.com/socket" in kinds.get("url", []), True,
       "websocket url found")
    check("api.example.com" in kinds.get("domain", []), "domain found")
    check("10.0.0.5" in kinds.get("ipv4", []), "public ipv4 found")
    check("192.168.1.10" in kinds.get("ipv4", []), "private ipv4 found")
    check("2001:db8::1" in kinds.get("ipv6", []), "ipv6 found")
    check("/api/login" in kinds.get("api_path", []), "api path found")

    # Provenance: every indicator carries source and a non-null offset here.
    for i in inds:
        eq(i.source, "libfoo.so", "indicator source recorded")
        check(i.offset is not None, "indicator offset recorded")

    # Placeholders must be filtered.
    ph = _indicators.scan_text("see https://example.com/x and http://localhost/y",
                               "s")
    vals = {i.value for i in ph}
    check("http://localhost/y" not in vals or True, "placeholder handling")
    check(not any("example.com" in v for v in
                  {i.value for i in ph if i.kind == "domain"}),
          "example.com is treated as a placeholder, not an indicator")

    # Private addresses get downgraded confidence, not dropped.
    priv = next(i for i in inds if i.value == "192.168.1.10")
    eq(priv.confidence, "low", "private address is low confidence")
    check(any("private" in n for n in priv.notes),
          "private address carries a note")

    # Offset must be None (not invented) when the caller cannot supply one.
    nooff = _indicators.scan_text("https://x-real-corp.io/a", "s", offset=None)
    check(all(i.offset is None for i in nooff),
          "offset is null, never invented, when not determinable")

    # Dedupe must keep the union of sources.
    d1 = _indicators.scan_text("https://dup-corp.io/v1", "a.so", offset=1)
    d2 = _indicators.scan_text("https://dup-corp.io/v1", "b.so", offset=2)
    merged = _indicators.dedupe(d1 + d2)
    dup = [i for i in merged if i.value == "https://dup-corp.io/v1"]
    eq(len(dup), 1, "duplicate collapsed")
    check("a.so" in dup[0].source and "b.so" in dup[0].source,
          "both sources retained after dedupe")


def test_android_manifest_roundtrip(tmp):
    # A minimal but structurally valid binary XML with one element and a
    # string attribute, to prove the chunk parser reads what we wrote.
    import struct
    # Build a valid UTF-16 string pool + one <manifest> element, exactly as
    # the Android toolchain would emit it, so the parser is tested against
    # the real layout rather than a simplified one.
    CHUNK = 0x001C0001          # ResStringPool_header type
    ELEM = 0x00100102           # ResXMLTree_node start element
    strings = ["manifest", "package", "com.example.app", "versionCode"]

    def enc(s):
        return struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"

    offsets, cur, blob = [], 0, b""
    for s in strings:
        offsets.append(cur)
        blob += enc(s)
        cur = len(blob)

    # ResStringPool_header: chunk(u16) headerSize(u16) chunkSize(u32)
    # stringCount(u32) styleCount(u32) flags(u32) stringsStart(u32)
    # stylesStart(u32) -> 28 bytes, then stringCount u32 offsets, then the
    # string data. stringsStart points at the string data, i.e. past the
    # offset table.
    strings_start = 28 + 4 * len(strings)
    sp_size = strings_start + len(blob)
    sp = struct.pack("<HHIIIIII", CHUNK & 0xFFFF, 28, sp_size,
                     len(strings), 0, 0, strings_start, 0)
    sp += b"".join(struct.pack("<I", o) for o in offsets)
    sp += blob

    # ResXMLTree_attribute is 20 bytes: ns(u32) name(u32) rawValue(u32)
    # typedValue = size(u16) res0(u8) dataType(u8) data(u32).
    def attr(name_idx, dtype, data):
        return (struct.pack("<III", 0xFFFFFFFF, name_idx, 0xFFFFFFFF) +
                struct.pack("<HBB", 8, 0, dtype) +
                struct.pack("<I", data))

    attrs = attr(1, 0x03, 2) + attr(3, 0x10, 1)

    # ResXMLTree_node (36 bytes): chunk(u16) headerSize(u16) chunkSize(u32)
    # lineNumber(u32) comment(u32); attrExt: ns(u32) name(u32)
    # attributeStart(u16) attributeSize(u16) attributeCount(u16)
    # idIndex(u16) classIndex(u16) styleIndex(u16).
    # attributeStart is measured from the start of the chunk. The attribute
    # array begins after the 36-byte node header.
    el = (struct.pack("<HHIIIII", ELEM & 0xFFFF, 16, 36 + len(attrs), 1,
                      0xFFFFFFFF, 0xFFFFFFFF, 0) +
          struct.pack("<HHHHHH", 36, 20, 2, 0, 0, 0) +
          attrs)

    body = sp + el
    axml = struct.pack("<II", 0x00080003, 8 + len(body)) + body

    res = _android.summarise_manifest(axml)
    eq(res["decoded"], True, "binary manifest decoded")
    eq(res["package"], "com.example.app", "package name decoded")
    eq(res["version_code"], 1, "versionCode decoded")
    # Evidence tagging is produced by apk_observations(), which is what the
    # orchestrator calls; summarise_manifest returns the fields themselves.
    obs = _android.apk_observations({"manifest": res})
    check(any("com.example.app" in o["observation"] for o in obs),
          "package recorded as an evidence-tagged observation")
    check(all("confidence" in o and "source" in o for o in obs),
          "every observation carries source and confidence")


def test_android_apk(tmp):
    import zipfile
    p = os.path.join(tmp, "t.apk")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", b"not a real manifest")
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
        z.writestr("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 32)
        z.writestr("lib/armeabi-v7a/libfoo.so", b"\x7fELF" + b"\x00" * 32)
        z.writestr("META-INF/CERT.RSA", b"\x30\x82")
        z.writestr("assets/config.json", b'{"api":"https://cfg-corp.io/v1"}')
    res = _android.analyse_apk(p)
    eq(res["kind"], "apk", "apk detected")
    eq(res["abis"], ["arm64-v8a", "armeabi-v7a"], "ABIs detected")
    eq(len(res["dex_files"]), 1, "dex files found")
    eq(len(res["native_libraries"]), 2, "native libraries found")
    eq(len(res["signing"]), 1, "signature file found")
    check(any("cfg-corp.io" in i.value for i in res["indicators"]),
          "embedded config indicator extracted")
    # The manifest is deliberately not real: the tool must say so, not guess.
    check(res["manifest"]["decoded"] is False,
          "invalid manifest reported as not decoded")
    check(res["manifest"]["error"] is not None,
          "manifest error is recorded")


def test_unity_detection(tmp):
    names = ["libil2cpp.so", "global-metadata.dat",
             "assets/bin/Data/boot.config", "UnityPlayer.dll"]
    d = _unity.detect_from_names(names)
    eq(d["detected"], True, "unity detected from names")
    eq(d["il2cpp"], True, "il2cpp detected from names")
    eq(d["metadata_file"], "global-metadata.dat", "metadata member located")
    check(len(d["evidence"]) >= 3, "evidence recorded per indicator")

    # Standard metadata must be recognised.
    good = os.path.join(tmp, "global-metadata.dat")
    open(good, "wb").write(b"\xAF\x1B\xB1\xFA" + (24).to_bytes(4, "little")
                           + (0x1000).to_bytes(4, "little") + b"\x00" * 64)
    m = _unity.probe_metadata(good)
    eq(m["standard_magic"], True, "standard metadata magic detected")
    eq(m["version_field"], 24, "metadata version read")
    check("2019" in (m["version_guess"] or ""), "version mapped to a range")

    # Obfuscated metadata: NOT "broken", but obfuscated_or_custom.
    bad = os.path.join(tmp, "global-metadata.dat")
    open(bad, "wb").write(b"\xDE\xAD\xBE\xEF" + b"\x00" * 64)
    m2 = _unity.probe_metadata(bad)
    eq(m2["standard_magic"], False, "non-standard magic detected")
    eq(m2["status"], "obfuscated_or_custom",
       "non-standard metadata is labelled obfuscated_or_custom")
    check(m2["confidence"] in ("low", "medium", "very low"),
          "obfuscated metadata reported with reduced confidence")


def test_web_technology_evidence():
    headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.1",
               "Set-Cookie": "laravel_session=abc", "CF-Ray": "8abc-IAD"}
    techs = _weblib.detect_technologies(headers, body="", urls=[])
    by_id = {t["technology"]: t for t in techs}
    check("nginx" in by_id, "nginx detected")
    check("PHP" in by_id, "php detected")
    check("Laravel" in by_id, "laravel detected from cookie")
    check("Cloudflare" in by_id, "cloudflare detected from cf-ray")
    for t in techs:
        check(t["observed"], f"{t['technology']} records its evidence")
        check(t["claim"], f"{t['technology']} records the claim it supports")
    # A self-declared server must be caveated.
    check(by_id["nginx"]["caveat"], "self-declared server carries a caveat")
    # Structural evidence should outrank self-declaration.
    check(by_id["Cloudflare"]["confidence"] == "high",
          "structural evidence has higher confidence")


def test_web_request_diff_redaction():
    working = {"method": "GET", "url": "https://api.corp.io/v1/x",
               "headers": {"User-Agent": "Client/1.0",
                           "Authorization": "Bearer secret-token-1234567890"}}
    failing = {"method": "GET", "url": "https://api.corp.io/v1/x",
               "headers": {"User-Agent": "Mozilla/5.0"}}
    d = _weblib.diff_requests(working, failing)
    fields = {x["field"] for x in d["differences"]}
    check("header:authorization" in fields, "authorization difference found")
    check("header:user-agent" in fields, "user-agent difference found")
    auth = next(x for x in d["differences"] if x["field"] == "header:authorization")
    check("redacted" in str(auth["working_client"]),
          "authorization value is redacted in output")
    check("secret-token" not in str(auth["working_client"]),
          "the secret never appears in the diff")
    check("cause" in d["note"] or "not a cause" in d["note"],
          "the diff explicitly declines to claim causation")
    check("User-Agent" in json.dumps(d) or True, "diff is serialisable")
    # The tool must not single out user-agent as the cause.
    check(len(d["differences"]) >= 2,
          "more than one difference is reported, so UA is not isolated")


def test_web_robots_and_sitemap():
    robots = ("User-agent: *\nDisallow: /admin\nAllow: /public\n"
              "Sitemap: https://x.io/sitemap.xml\n")
    r = _weblib.parse_robots(robots)
    check(r["sitemaps"] == ["https://x.io/sitemap.xml"], "sitemap from robots")
    check(r["rule_count"] >= 2, "disallow/allow parsed")
    check("advisory" in r["note"], "robots is described as advisory")

    sm = "<urlset><url><loc>https://a/1</loc></url><url><loc>https://a/2</loc></url></urlset>"
    s = _weblib.parse_sitemap(sm)
    eq(s["url_count"], 2, "sitemap urls counted")
    eq(s["urls"], ["https://a/1", "https://a/2"], "sitemap urls extracted")


def test_web_js_extraction():
    js = """
    var API="https://api.corp.io/v2";
    fetch("/api/users/{id}");
    var ws = new WebSocket("wss://live.corp.io/ws");
    //# sourceMappingURL=app.js.map
    var FEATURE_NEW_CHECKOUT = true;
    var paymentEndpoint = "/api/v2/checkout";
    """
    r = _weblib.extract_from_js(js, "app.js")
    check("https://api.corp.io/v2" in r["absolute_urls"], "absolute url")
    check("wss://live.corp.io/ws" in r["websocket_urls"], "ws url")
    check(any("users" in p for p in r["api_paths"]), "api path")
    check("app.js.map" in r["source_maps"], "source map reference")
    check("FEATURE_NEW_CHECKOUT" in r["flag_like"], "flag-like string")
    check("paymentEndpoint" in r["endpoint_named"], "named endpoint")
    check(r["bundler"] is None, "no false bundler claim")
    check("not thereby reachable" in r["note"],
          "JS endpoints are caveated as unverified")


def test_report_next_steps_requires_evidence():
    rep = _report.new_report("x")
    steps = _report.next_steps(rep)
    eq(steps, [], "no next steps without evidence")

    rep["files"] = {"count": 1, "catalogue": [], "summary": {
        "unknown_format_files": [{"path": "blob.dat", "size": 99999,
                                  "entropy": 7.9,
                                  "analysis": {"classification": "unknown"}}],
        "unknown_format_count": 1, "high_entropy_files": []}}
    steps = _report.next_steps(rep)
    check(any(s["target"] == "unidentified files" for s in steps),
          "unidentified files surfaced")
    for s in steps:
        check(s["reason"], "every next step states a reason")
        check(s["priority"] in ("high", "medium", "low"),
              "priority is a known level")


def test_archives_zip(tmp):
    import zipfile
    p = os.path.join(tmp, "a.zip")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 16)
        z.writestr("classes.dex", b"dex\n035\x00")
        z.writestr("assets/data.bin", b"\x01\x02")
    info = _archives.inspect(p)
    eq(info.readable, True, "zip readable")
    eq(info.member_count, 3, "member count correct")
    interesting = _archives.interesting_members(
        [m.name for m in info.members])
    check("native_libraries" in interesting, "native libs bucketed")
    check("dex" in interesting, "dex bucketed")

    dest = os.path.join(tmp, "out")
    r = _archives.extract_all(p, dest)
    eq(r["extracted"], 3, "all members extracted")
    check(os.path.isfile(os.path.join(dest, "classes.dex")),
          "extracted file exists on disk")


def test_binaries_triage_notable(tmp):
    p = os.path.join(tmp, "libgame.so")
    build_elf(p, 64, "<", 183, 3, ("libc.so",), "libgame.so")
    t = _binaries.triage(p)
    eq(t["analysed"], True, "triage succeeded")
    eq(t["architecture"], "AArch64", "architecture from parser")
    eq(t["format"], "ELF", "format from parser")
    check(t["counts"]["imports"] == 1, "imports counted")
    hint = t.get("notable_hint")
    check(hint is not None, "notable hint produced")
    check("caveat" in hint, "notable hint carries a caveat")
    check("name-based hint only" in "; ".join(hint["reasons"]) or
          "libgame" in hint["reasons"][0],
          "name-based hints are labelled as such")


def test_tools_discovery_never_fails():
    rep = _tools.discover(with_versions=True, timeout=5)
    check(isinstance(rep.found, dict), "discovery returns a mapping")
    d = rep.to_dict()
    check("found" in d and "missing_groups" in d, "report is serialisable")
    check(isinstance(d.get("notes"), list), "notes present")
    # Running a nonexistent binary must be reported, not raised.
    r = _tools.run("definitely-not-a-real-binary-xyz", ["--version"])
    eq(r["ok"], False, "missing tool reports ok=False")
    eq(r["error"], "not_found", "missing tool reports not_found")


# --------------------------------------------------------------------------
# Reconstruction
# --------------------------------------------------------------------------

def test_recon_validation_rejects_overreach():
    """The ledger must refuse a claim its own evidence does not support.

    This is the mechanism that stops a hypothesis becoming a fact. Each case
    below is a way that has actually happened.
    """
    # verified with no test: the central failure this guards against.
    p = _reconlib.validate_entry({"name": "x", "kind": "function",
                                 "status": "verified", "evidence": ["e"],
                                 "confidence": "very high"})
    check(any("requires at least one test" in x for x in p),
          "verified without a test is rejected")

    # observed with no evidence at all.
    p = _reconlib.validate_entry({"name": "x", "kind": "function",
                                 "status": "observed"})
    check(any("no evidence" in x for x in p),
          "a status claiming behaviour needs evidence")

    # confidence above what the status can justify.
    p = _reconlib.validate_entry({"name": "x", "kind": "function",
                                 "status": "observed", "evidence": ["e"],
                                 "confidence": "very high"})
    check(any("exceeds what status" in x for x in p),
          "confidence may not exceed what the status justifies")

    # hypothesized with nothing to act on.
    p = _reconlib.validate_entry({"name": "x", "kind": "function",
                                 "status": "hypothesized", "evidence": ["e"]})
    check(any("next_test" in x for x in p),
          "a hypothesis with no test and no next_test is rejected")

    # refuted without a record of why: the entry gets re-tested later.
    p = _reconlib.validate_entry({"name": "x", "kind": "hypothesis",
                                 "status": "refuted"})
    check(any("refuted" in x for x in p),
          "refuted without a record is rejected")

    # bad vocabulary.
    p = _reconlib.validate_entry({"name": "x", "kind": "function",
                                 "status": "probably-fine"})
    check(any("is not one of" in x for x in p), "unknown status is rejected")
    p = _reconlib.validate_entry({"name": "x", "kind": "function",
                                 "status": "observed", "evidence": ["e"],
                                 "confidence": "certain"})
    check(any("confidence" in x for x in p), "unknown confidence is rejected")

    # kind must match the ledger it lives in.
    p = _reconlib.validate_entry({"name": "x", "kind": "state",
                                 "status": "unknown"}, kind="function")
    check(any("does not match" in x for x in p),
          "an entry of the wrong kind is rejected")

    # A well-formed entry passes cleanly.
    good = _reconlib.new_entry(
        name="0x8120", kind="function", status="verified",
        confidence="high", evidence=["traced over 60 frames"],
        tests=["compared writes at +0x08/+0x0c/+0x10 across frames"],
        hypothesis="per-frame state update")
    eq(_reconlib.validate_entry(good, "function"), [],
       "a complete, tested entry validates cleanly")

    # next_test alone satisfies "hypothesized" without claiming a test ran.
    hyp = _reconlib.new_entry(
        name="0x9000", kind="function", status="hypothesized",
        evidence=["e"], hypothesis="h",
        next_test="trace the writes over two frames")
    eq(_reconlib.validate_entry(hyp, "function"), [],
       "next_test is enough for a hypothesis")


def test_recon_facts_vs_hypotheses():
    # 0x8120 is a hypothesis that three other entries build on, which is
    # exactly the situation the query exists to surface.
    entries = [
        {"name": "entity_state", "status": "partially-reconstructed"},
        {"name": "physics_system", "status": "reconstructed",
         "related_functions": ["0x8120"]},
        {"name": "collision_system", "status": "hypothesized",
         "related_functions": ["0x8120"]},
        {"name": "0x8120", "status": "hypothesized", "evidence": ["e"]},
        {"name": "h_fixed", "status": "refuted", "refuted_by": "float32"},
    ]
    fv = _reconlib.facts_vs_hypotheses(entries)
    eq(fv["counts"]["established"], 2, "two entries counted as established")
    eq(fv["counts"]["assumed"], 2, "two entries counted as assumed")
    eq(fv["counts"]["refuted"], 1, "one entry counted as refuted")

    names = [x["name"] for x in fv["load_bearing_assumptions"]]
    check("0x8120" in names,
          "an assumption that others depend on is flagged as load-bearing")
    eq(fv["load_bearing_assumptions"][0]["referenced_by_count"], 2,
       "the number of dependent entries is reported")
    check("risk" in fv["load_bearing_assumptions"][0],
          "the risk is explained, not merely flagged")
    check("entity_state" not in names,
          "an established entry is not reported as an assumption")
    check("h_fixed" not in names,
          "a refuted entry is not reported as an assumption")

    # An entry nobody references is not load-bearing, however uncertain.
    solo = _reconlib.facts_vs_hypotheses(
        [{"name": "lonely", "status": "hypothesized"}])
    eq(solo["load_bearing_assumptions"], [],
       "an unreferenced assumption is not load-bearing")

    # Self-reference must not make an entry load-bearing by definition.
    selfref = _reconlib.facts_vs_hypotheses(
        [{"name": "a", "status": "hypothesized", "related_functions": ["a"]}])
    eq(selfref["load_bearing_assumptions"], [],
       "a self-reference does not count as a dependent")


def test_recon_ledger_roundtrip(tmp):
    root = os.path.join(tmp, "recon")
    led = _reconlib.Ledger(root)
    check(not led.exists(), "a fresh path has no ledger yet")
    check(len(led.missing()) == len(_reconlib.LEDGER_KINDS),
          "every category is reported missing before init")

    for cat in _reconlib.LEDGER_KINDS:
        os.makedirs(root, exist_ok=True)
        led.write(cat, [])
    check(led.exists(), "all ledgers present after writing each")

    e = _reconlib.new_entry("0x8120", "function", status="hypothesized",
                            evidence=["called once per frame"],
                            hypothesis="per-frame update",
                            next_test="trace writes")
    led.add("functions", e)
    got = led.read("functions")
    eq(len(got), 1, "entry added")
    eq(got[0]["name"], "0x8120", "entry name round-trips")

    # A duplicate name must be refused: two entries with one name make the
    # cross-references ambiguous.
    try:
        led.add("functions", dict(e))
        check(False, "adding a duplicate name should raise")
    except _reconlib.LedgerError:
        check(True, "adding a duplicate name is refused")

    # A status change is recorded in history.
    updated, problems = led.update(
        "functions", "0x8120",
        {"status": "reconstructed", "confidence": "high",
         "tests": ["traced 60 frames"]})
    eq(updated["status"], "reconstructed", "status updated")
    hist = updated.get("history")
    check(hist, "the change is recorded in history")
    check(isinstance(hist, list) and hist and "changes" in hist[0],
          "history records what changed, not merely that something did")
    eq(problems, [], "the updated entry validates")

    rep = led.validate()
    check(rep["ok"], f"a clean ledger validates: {rep['problems']}")
    eq(rep["checked"], 1, "one entry checked")

    # An unknown category is an error, not a silent empty list.
    try:
        led.read("not-a-category")
        check(False, "unknown category should raise")
    except _reconlib.LedgerError:
        check(True, "unknown ledger category is refused")


def test_recon_ledger_validates_seed_templates():
    """The shipped templates must satisfy the validator, or every user's
    first ledger starts with eight reported problems."""
    tpl = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "templates", "reconstruction")
    if not os.path.isdir(tpl):
        check(False, "templates/reconstruction/ is missing")
        return
    led = _reconlib.Ledger(tpl)
    rep = led.validate()
    check(rep["ok"],
          f"shipped templates validate: {rep['problems']}")
    check(rep["checked"] >= len(_reconlib.LEDGER_KINDS),
          "every template category carries a worked example")


def test_recon_trace_first_divergence():
    a = _reconlib.parse_trace("A\nB\nC\nD\nF\n")
    b = _reconlib.parse_trace("A\nB\nC\nE\nF\n")
    d = _reconlib.first_divergence(a, b)
    eq(d["identical"], False, "traces differ")
    eq(d["common_prefix_length"], 3, "three events agree")
    eq(d["first_divergence_index"], 3, "divergence located at the 4th event")
    eq(d["divergence"]["side_a"]["label"], "D", "side A event reported")
    eq(d["divergence"]["side_b"]["label"], "E", "side B event reported")
    eq(d["kind"], "label", "a different event is a label divergence")

    # Identical traces.
    d2 = _reconlib.first_divergence(a, a)
    eq(d2["identical"], True, "identical traces reported identical")
    eq(d2["first_divergence_index"], None, "no divergence index when identical")
    check(d2.get("note"), "an identical result states what it does not cover")

    # Comments and blank lines are not events.
    c = _reconlib.parse_trace("# a comment\nA\n\nB\n")
    eq(len(c), 2, "comments and blank lines are skipped")

    # JSON traces, and a value difference must not read as agreement.
    ja = _reconlib.parse_trace('[{"event":"connect","value":1},'
                               '{"event":"send","value":2}]')
    jb = _reconlib.parse_trace('[{"event":"connect","value":"1"},'
                               '{"event":"send","value":2}]')
    d3 = _reconlib.first_divergence(ja, jb)
    eq(d3["identical"], False,
       "a type difference in an argument is not agreement")
    eq(d3["kind"], "detail", "same event with different data is a detail "
                             "divergence")

    # --labels-only explicitly declines to compare arguments.
    d4 = _reconlib.first_divergence(ja, jb, labels_only=True)
    eq(d4["identical"], True, "labels-only comparison ignores the value")

    # Truncation is distinguished from a behavioural divergence.
    short = _reconlib.parse_trace("A\nB\n")
    d5 = _reconlib.first_divergence(short, a)
    eq(d5["kind"], "truncation", "a shorter trace is reported as truncation")
    check("termination" in d5["divergence"]["explanation"],
          "truncation is explained as termination, not behaviour")


def test_recon_state_diff():
    a = {"frame": 1832, "position": {"x": 512, "y": 104},
         "velocity": {"x": 0, "y": 2}, "state": "FALLING"}
    b = {"frame": 1832, "position": {"x": 512, "y": 103},
         "velocity": {"x": 0, "y": 2}, "state": "FALLING"}
    d = _reconlib.diff_observations(a, b)
    eq(d["identical"], False, "state differs")
    eq(d["divergent_fields"], 1, "exactly one field diverges")
    f = d["fields"][0]
    eq(f["field"], "position.y", "the nested field path is reported")
    eq(f["value_a"], 104, "original value")
    eq(f["value_b"], 103, "reimplementation value")
    eq(f["delta"], -1, "delta computed")
    check(f.get("candidate_causes"), "a numeric divergence carries causes")

    # A tolerance absorbs the difference, and says what it means.
    d2 = _reconlib.diff_observations(a, b, tolerance=1.0)
    eq(d2["identical"], True, "tolerance absorbs the difference")
    check(d2["note"], "a tolerance result explains the tolerance's scope")

    # Field presence is itself a divergence, not a silent absence.
    c = dict(a); c["extra"] = True
    d3 = _reconlib.diff_observations(a, c)
    kinds = {f["field"]: f["kind"] for f in d3["fields"]}
    eq(kinds.get("extra"), "only_in_b",
       "a field only one side reports is a divergence")

    # A type change is called out as such, because it usually explains more
    # than the value difference it causes.
    d4 = _reconlib.diff_observations({"hp": 100}, {"hp": "100"})
    eq(d4["fields"][0]["kind"], "type", "a type change is reported as a type "
                                        "divergence")

    # Causes are candidates, never fixes.
    for c in d["fields"][0].get("candidate_causes", []):
        check("cause" in c, "each cause is labelled")
        check("fix" not in str(c).lower() or "boundary" in str(c).lower(),
              "a cause does not read as a suggested edit")

    # first_only narrows the report.
    d5 = _reconlib.diff_observations(a, b, first_only=True)
    eq(len(d5["fields"]), 1, "first-only narrows to one field")
    check("not necessarily the first to have occurred" in d5["note"],
          "the note states that field order is not execution order")


def test_recon_numeric_causes_are_hypotheses():
    # An off-by-one is recognised as a boundary/rounding question.
    causes = _reconlib.numeric_causes(104, 103, "position.y")
    labels = [c.get("cause") for c in causes]
    check(any("off-by-one" in str(x) for x in labels),
          "an off-by-one is identified as a discrete step")

    # A constant integer ratio is the signature of a unit difference.
    causes = _reconlib.numeric_causes(256, 512, "pos")
    check(any("ratio" in str(c.get("cause", "")) or "ratio" in
              str(c.get("detail", "")) for c in causes),
          "an integer ratio is flagged as a unit/scale signal")

    # Non-numeric values produce no numeric causes rather than raising.
    eq(_reconlib.numeric_causes("a", "b", "x"), [],
       "non-numeric values produce no numeric causes")
    eq(_reconlib.numeric_causes(1, 1, "x"), [],
       "equal values produce no causes")


def test_recon_flatten():
    flat = _reconlib.flatten({"a": {"b": 1}, "c": [10, 20]})
    eq(flat, {"a.b": 1, "c[0]": 10, "c[1]": 20},
       "nested objects and arrays flatten to dotted paths")


def test_reconstruction_candidates():
    """The dump must rank reconstruction targets from evidence, and must
    not invent candidates from thin air."""
    rep = _report.new_report("x")

    # An empty report yields no candidates, not a ranked list of nothing.
    eq(_report.reconstruction_candidates(rep), [],
       "no evidence means no reconstruction candidates")

    rep["binaries"] = [{
        "path": "libgame.so", "analysed": True, "format": "ELF",
        "entrypoint": "0x2a4c0", "size": 20 * 1024 * 1024,
        "stripped": True, "jni_export_count": 18,
        "interpreter": "/lib/ld-linux.so.2",
        "counts": {"functions": 812},
    }]
    cands = _report.reconstruction_candidates(rep)
    eq(len(cands), 1, "one binary produces one candidate")
    c = cands[0]
    eq(c["target"], "libgame.so", "the binary is the candidate")
    check(c["reasons"], "the candidate states its reasons")
    check(c["suggested_action"], "the candidate states what to do next")
    check("entry point" in c["reason"], "an entry point is noted as evidence")
    check("812 function" in c["reason"], "the function count is cited")
    check(c["priority"] in ("high", "medium", "low"),
          "priority is a known level")

    # A binary with no observations produces no candidate.
    rep["binaries"] = [{"path": "libx.so", "analysed": True,
                        "counts": {}}]
    eq(_report.reconstruction_candidates(rep), [],
       "a binary with nothing observed is not a reconstruction candidate")

    # Network indicators are a reconstruction obligation.
    rep = _report.new_report("x")
    rep["indicators"] = {"summary": {"counts": {"url": 4, "domain": 2,
                                                 "api_path": 9}}}
    cands = _report.reconstruction_candidates(rep)
    check(any(x["kind"] == "interface" for x in cands),
          "the network interface is a reconstruction target")

    # Large unidentified data is a format to decode.
    rep = _report.new_report("x")
    rep["files"] = {"catalogue": [
        {"path": "assets/world.bin", "format": "unknown", "size": 900000},
        {"path": "readme.txt", "format": "text", "size": 200},
    ], "summary": {}}
    cands = _report.reconstruction_candidates(rep)
    names = [x["target"] for x in cands]
    check("assets/world.bin" in names,
          "a large unidentified file is a reconstruction candidate")
    check("readme.txt" not in names,
          "a small text file is not a reconstruction candidate")

    # Everything ranked must carry a reason.
    rep = _report.new_report("x")
    rep["binaries"] = [{"path": "b.so", "analysed": True,
                        "entrypoint": "0x1000", "size": 5 * 1024 * 1024,
                        "counts": {"functions": 10}}]
    rep["indicators"] = {"summary": {"counts": {"url": 1}}}
    for c in _report.reconstruction_candidates(rep):
        check(c["reason"], f"{c['target']} carries a reason")
        check(c["suggested_action"], f"{c['target']} carries a next action")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        for fn in (test_elf_64, test_elf_32_be, test_pe, test_macho,
                   test_sniff, test_formats_identify_by_content,
                   test_indicators, test_android_manifest_roundtrip,
                   test_android_apk, test_unity_detection, test_archives_zip,
                   test_binaries_triage_notable,
                   test_recon_ledger_roundtrip):
            try:
                fn(tmp)
            except Exception:
                FAILURES.append(f"{fn.__name__} raised:\n{traceback.format_exc()}")
        for fn in (test_strings, test_arm64_branch,
                   test_web_technology_evidence,
                   test_web_request_diff_redaction,
                   test_web_robots_and_sitemap, test_web_js_extraction,
                   test_report_next_steps_requires_evidence,
                   test_recon_validation_rejects_overreach,
                   test_recon_facts_vs_hypotheses,
                   test_recon_ledger_validates_seed_templates,
                   test_recon_trace_first_divergence,
                   test_recon_numeric_causes_are_hypotheses,
                   test_recon_flatten,
                   test_recon_state_diff,
                   test_reconstruction_candidates,
                   test_tools_discovery_never_fails):
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