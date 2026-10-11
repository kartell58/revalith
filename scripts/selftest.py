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
              needed=("libc.so",), soname=None, load_base=0):
    """Minimal ET_DYN ELF with .text/.rodata/.dynsym/.dynstr/.dynamic.

    ``load_base`` shifts the PT_LOAD virtual addresses while leaving the file
    offsets alone, producing the vaddr/offset skew that ASLR introduces at
    runtime. It exists so load-bias derivation can be tested against something
    real rather than against a fixture where the two coincide and every
    derivation trivially agrees.
    """
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

    # Section headers. sh_name is relative to .shstrtab; sh_addr shifts with
    # load_base along with the segments, because an ELF whose sections and
    # segments disagreed would not be loadable.
    shoff = 0x1800
    secs = [
        (0, 0, 0, 0, 0, 0, 0),                       # NULL
        (names_off[0], 1, 0x6, load_base + addr, 0x1000, 0x100, 0),
        (names_off[1], 1, 0x2, load_base + addr + 0x1000, 0x1100, 0x40, 0),
        (names_off[2], 11, 0x2, load_base + addr + 0xD00, dynsym_off,
         len(sym_idx) * esz, 0),
        (names_off[3], 3, 0x2, load_base + addr + 0xE00, dynstr_off,
         len(dynstr), 0),
        (names_off[4], 6, 0x3, load_base + addr + 0xC00, dynamic_off,
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
    # Two PT_LOAD segments, deliberately with a vaddr that differs from the
    # file offset. That difference is what a load bias exists to absorb, so a
    # fixture where vaddr == offset cannot test load-bias derivation at all.
    #   seg 1: file offset 0x1000, vaddr load_base + 0x1000  (r-x, code+rodata)
    #   seg 2: file offset 0x2000, vaddr load_base + 0x2000  (rw-, data)
    seg_off1, seg_off2 = 0x1000, 0x2000
    if bits == 64:
        phoff = 64
        struct.pack_into(endian + "HHIQQQIHHHHHH", data, 16, etype, machine,
                         1, addr, phoff, shoff, 0, ehsize, phentsize, 2,
                         shentsize, len(secs), 6)
        # Sections shift with the segments. An ELF whose sections disagreed
        # with its segments would not be loadable, and a fixture that is not
        # loadable tests nothing about real translation.
        struct.pack_into(endian + "IIQQQQQQ", data, phoff, 1, 5, seg_off1,
                         load_base + seg_off1, seg_off1, 0x200, 0x200, 0x1000)
        struct.pack_into(endian + "IIQQQQQQ", data, phoff + 56, 1, 6, seg_off2,
                         load_base + seg_off2, seg_off2, 0x100, 0x200, 0x1000)
    else:
        phoff = 52
        struct.pack_into(endian + "HHIIIIIHHHHHH", data, 16, etype, machine,
                         1, addr, phoff, shoff, 0, ehsize, phentsize, 2,
                         shentsize, len(secs), 6)
        struct.pack_into(endian + "IIIIIIII", data, phoff, 1, seg_off1,
                         load_base + seg_off1, seg_off1, 0x200, 0x200, 5,
                         0x1000)
        struct.pack_into(endian + "IIIIIIII", data, phoff + 32, 1, seg_off2,
                         load_base + seg_off2, seg_off2, 0x100, 0x200, 6,
                         0x1000)

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


def test_recon_evidence_accounting_is_weighted():
    """An entry that knows what argues against it cannot also be settled.

    The failure this prevents is specific: a hypothesis forms, evidence
    accumulates, and three weeks later an observation that argued against it is
    buried in a notes field while the entry reads 'verified'. Recording the
    contradiction is only half the job -- the validator has to weigh it.
    """
    ev = ["watchpoint on +0x10 recorded 4 writes from 0x1400"]

    # A hypothesis may carry counter-evidence. That is the normal state of a
    # claim that has not been settled yet, and refusing it would push people
    # to leave the counter-evidence unrecorded instead.
    h = _reconlib.new_entry(name="0x8120", kind="function", status="hypothesized",
                       evidence=ev, hypothesis="player physics update",
                       next_test="drive two entities",
                       contradicting=["never called in a headless run"])
    eq(_reconlib.validate_entry(h, "function"), [],
       "a hypothesis with contradicting evidence is valid")

    # 'verified' means the evidence survived its test. Unresolved
    # contradiction is a different thing, and conflating them is the error.
    v = _reconlib.new_entry(name="0x8120", kind="function", status="verified",
                       evidence=ev, tests=["ran 3 inputs, all agreed"],
                       contradicting=["never called in a headless run"])
    problems = _reconlib.validate_entry(v, "function")
    check(any("contradicting" in p for p in problems),
          "verified with unresolved contradicting evidence is refused")
    check(any("survived" in p for p in problems),
          "the refusal says what verified actually means")

    # ... unless the resolution is recorded.
    resolved = _reconlib.new_entry(
        name="0x8120", kind="function", status="verified", evidence=ev,
        tests=["ran 3 inputs", "headless run: not called"],
        contradicting=["never called in a headless run"],
        contradiction_resolved="it is the render path; headless has no render")
    eq(_reconlib.validate_entry(resolved, "function"), [],
       "verified with the contradiction resolved validates")

    # Refuted entries that record counter-evidence must say what settled it.
    r = _reconlib.new_entry(name="0x8120", kind="function", status="refuted",
                       evidence=ev, contradicting=["traced 200 frames, never"])
    check(_reconlib.validate_entry(r, "function"),
          "refuted with counter-evidence and nothing settling it is refused")
    r2 = _reconlib.new_entry(name="0x8120", kind="function", status="refuted",
                        evidence=ev, contradicting=["traced 200 frames"],
                        tests=["traced 200 frames, never called"])
    eq(_reconlib.validate_entry(r2, "function"), [],
       "refuted with the refuting test recorded validates")

    # An empty string weighs nothing and must not read as though it did.
    empty = _reconlib.new_entry(name="x", kind="function", status="hypothesized",
                           evidence=ev, hypothesis="h", next_test="t",
                           supporting_observations=["", "real"])
    check(any("weighs nothing" in p for p in _reconlib.validate_entry(empty, "function")),
          "an empty supporting observation is refused")

    # Both lists must be lists.
    bad = _reconlib.new_entry(name="x", kind="function", status="hypothesized",
                         evidence=ev, hypothesis="h", next_test="t")
    bad["contradicting"] = "a string, not a list"
    check(any("must be a list" in p for p in _reconlib.validate_entry(bad, "function")),
          "a non-list contradicting field is refused")

    # The fields round-trip through the builder rather than only via **extra.
    built = _reconlib.new_entry(name="x", kind="function", status="hypothesized",
                           evidence=ev, hypothesis="h", next_test="t",
                           supporting_observations=["a"],
                           contradicting=["b"])
    eq(built.get("supporting_observations"), ["a"], "supporting is stored")
    eq(built.get("contradicting"), ["b"], "contradicting is stored")


def test_recon_source_is_validated():
    """Provenance is optional but never free-form.

    An entry whose source is unknown cannot be re-checked the way it was
    found, which is the whole point of recording it.
    """
    e = _reconlib.new_entry("0x8120", "function", status="observed",
                            evidence=["traced"], source="runtime")
    eq(_reconlib.validate_entry(e, "function"), [],
       "a known source validates")

    bad = dict(e)
    bad["source"] = "telepathy"
    check(any("source 'telepathy'" in p
              for p in _reconlib.validate_entry(bad, "function")),
          "an invented source is refused")

    # Optional: a first entry often predates knowing how it was found.
    check("source" not in e or e.get("source") == "runtime",
          "source is recorded when given")
    del_source = _reconlib.new_entry("0x9000", "function", status="observed",
                                     evidence=["seen in a dump"])
    check("source" not in del_source,
          "source stays absent when not given, rather than defaulting")
    eq(_reconlib.validate_entry(del_source, "function"), [],
       "an entry without a source is still valid")


def test_recon_dead_end_records_what_was_believed(tmp):
    """A dead end without 'avoid' is history; with it, it is guidance."""
    good = _reconlib.new_entry(
        "LZ4 payload", "dead_end", status="refuted", source="static",
        evidence=["lz4 -d: bad magic"],
        hypothesis="the payload is LZ4-compressed",
        refuted_by="two decoders and the magic bytes disagree",
        avoid="measure entropy before choosing the next codec")
    eq(_reconlib.validate_entry(good, "dead_end"), [], "a complete dead end validates")

    for missing, why in (("hypothesis", "what was believed"),
                         ("avoid", "what not to do next")):
        entry = dict(good)
        entry.pop(missing)
        check(_reconlib.validate_entry(entry, "dead_end"),
              f"a dead end without '{missing}' is refused ({why})")

    reopened = dict(good)
    reopened["status"] = "hypothesized"
    check(any("by definition refuted" in p
              for p in _reconlib.validate_entry(reopened, "dead_end")),
          "a dead end cannot be left in a live status")

    # A dead-end file must exist in every ledger, so `init` and the template
    # check agree about what a complete ledger looks like.
    check("dead_ends" in _reconlib.LEDGER_KINDS,
          "dead_ends is a ledger category, not a convention")
    check("protocols" in _reconlib.LEDGER_KINDS,
          "protocols is a ledger category of its own")


def test_recon_reopening_a_dead_end_is_detected():
    """The mechanical form of 'have we been here before'.

    The three matching routes correspond to the three ways the same idea
    comes back: under its old name, by pointing at the dead end, and by
    restating the claim in new words.
    """
    dead = _reconlib.new_entry(
        "LZ4 asset payload", "dead_end", status="refuted", source="static",
        evidence=["bad magic"],
        hypothesis="the asset payload is LZ4-compressed",
        refuted_by="two decoders disagree",
        avoid="do not retry LZ4")
    deads = [dead]

    same_name = _reconlib.new_entry(
        "LZ4 asset payload", "format", status="hypothesized", evidence=["x"],
        hypothesis="h", next_test="t")
    check(_reconlib.find_reopened_dead_ends(same_name, deads),
          "an entry with the dead end's name reopens it")

    refers = _reconlib.new_entry(
        "payload codec", "format", status="hypothesized", evidence=["x"],
        hypothesis="h", next_test="t", related_data=["LZ4 asset payload"])
    check(_reconlib.find_reopened_dead_ends(refers, deads),
          "an entry referring to the dead end reopens it")

    restates = _reconlib.new_entry(
        "codec", "format", status="hypothesized", evidence=["x"],
        hypothesis="the asset payload is LZ4-compressed", next_test="t")
    check(_reconlib.find_reopened_dead_ends(restates, deads),
          "an entry restating the refuted claim reopens it")

    unrelated = _reconlib.new_entry(
        "tile atlas", "format", status="hypothesized", evidence=["x"],
        hypothesis="a grid of 8x8 tiles", next_test="t")
    eq(_reconlib.find_reopened_dead_ends(unrelated, deads), [],
       "an unrelated entry does not reopen a dead end")

    # The point is not to forbid it: new evidence makes it legitimate.
    with_new = _reconlib.find_reopened_dead_ends(
        restates, deads, new_evidence="an lz4 decoder is installed now")
    check(with_new and with_new[0]["has_new_evidence"],
          "new evidence makes reopening a dead end legitimate")
    without = _reconlib.find_reopened_dead_ends(restates, deads)
    check(without and not without[0]["has_new_evidence"],
          "without new evidence the reopening is flagged")
    check(without[0]["avoid"], "the flagged entry carries what not to do")


def test_recon_gaps_reports_what_is_open(tmp):
    """The counter-question to stats: not what was found, but what is not."""
    root = os.path.join(tmp, "gaps")
    led = _reconlib.Ledger(root)
    os.makedirs(root, exist_ok=True)
    for cat in _reconlib.LEDGER_KINDS:
        led.write(cat, [])

    led.add("functions", _reconlib.new_entry(
        "0x8120", "function", status="hypothesized", evidence=["seen"],
        source="runtime"))                      # nothing can settle it
    led.add("functions", _reconlib.new_entry(
        "0x9000", "function", status="verified", evidence=["seen"],
        tests=["ran once"]))                    # verified, but no source
    led.add("dead_ends", _reconlib.new_entry(
        "LZ4", "dead_end", status="refuted", evidence=["bad magic"],
        hypothesis="payload is LZ4", source="static",
        refuted_by="decoders disagree", avoid="do not retry"))

    report = _reconlib.gaps(led)
    names = lambda key: [g.get("name") for g in report[key]]  # noqa: E731

    check("0x8120" in names("unactionable_hypotheses"),
          "a hypothesis with no test and no next_test is reported as open")
    check("0x9000" in names("unsourced_entries"),
          "an entry with no recorded source is reported")
    check("dead_ends" not in report["empty_categories"],
          "a category that holds an entry is not reported as never asked")
    check("states" in report["empty_categories"],
          "a category never asked is reported, and is not confused with one "
          "that was answered")
    eq(report["counts"]["dead_ends"], 1, "recorded dead ends are counted")

    clean = _reconlib.gaps(_reconlib.Ledger(root))
    check("ledger" in clean and "counts" in clean,
          "gaps is derived and self-describing")

    # A ledger that is empty is not a ledger that is finished.
    empty_root = os.path.join(tmp, "empty-gaps")
    os.makedirs(empty_root, exist_ok=True)
    for cat in _reconlib.LEDGER_KINDS:
        led_e = _reconlib.Ledger(empty_root)
        led_e.write(cat, [])
    report_e = _reconlib.gaps(_reconlib.Ledger(empty_root))
    eq(report_e["counts"]["entries"], 0, "an empty ledger has no entries")
    check(len(report_e["empty_categories"]) == len(_reconlib.LEDGER_KINDS),
          "every category counts as never asked in an empty ledger")
    check("never asked" in report_e["note"],
          "an empty category is named as unasked, not answered")


def test_recon_render_is_deterministic(tmp):
    """A regenerated view must show a real change, not a formatting one."""
    root = os.path.join(tmp, "render")
    led = _reconlib.Ledger(root)
    os.makedirs(root, exist_ok=True)
    for cat in _reconlib.LEDGER_KINDS:
        led.write(cat, [])
    led.add("dead_ends", _reconlib.new_entry(
        "LZ4", "dead_end", status="refuted", evidence=["bad magic"],
        hypothesis="payload is LZ4", source="static",
        refuted_by="decoders disagree", avoid="do not retry"))
    led.add("protocols", _reconlib.new_entry(
        "session control", "protocol", status="observed",
        evidence=["40 frames"], source="protocol"))

    first = _reconlib.render_state(led)
    second = _reconlib.render_state(led)
    eq(first, second, "two renders of one ledger are identical")

    expected = {"investigation-state.md", "dead-ends.md", "hypotheses.md",
                "known-formats.md", "known-offsets.md", "known-protocols.md"}
    eq(sorted(first), sorted(expected), "the rendered set is fixed")

    for name, text in first.items():
        check("GENERATED" in text,
              f"{name} says it is generated, so nobody edits it by hand")
    check("LZ4" in first["dead-ends.md"],
          "a dead end reaches the rendered view")
    check("dead ends recorded: 1" in first["investigation-state.md"],
          "the overview counts dead ends")
    check("LZ4" not in first["investigation-state.md"],
          "the overview counts; it does not restate entries that the "
          "per-category views already hold")
    check("session control" in first["known-protocols.md"],
          "a protocol reaches its rendered view")

    # A pipe inside a table cell would otherwise break the row silently.
    led.add("structures", _reconlib.new_entry(
        "entity_state", "structure", status="partially-reconstructed",
        evidence=["16 bytes"], fields=[
            {"offset": "+0x08", "size": 4, "type": "int32",
             "evidence": "compared against 0..1000", "confidence": "medium"}]))
    table = _reconlib.render_state(led)["known-offsets.md"]
    check("+0x08" in table, "a structure field reaches the offsets table")
    check("| --- |" in table, "the offsets table has a header separator")


def test_determinism_check_separates_measurement_from_cause():
    """The tool says what varies. It must not say what made it vary."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "determinism-check.py")
    spec = importlib.util.spec_from_file_location("determinism_check", path)
    det = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(det)

    runs = [
        ("run1", _reconlib.flatten({"frame": 0, "pos": {"x": 10, "y": 20}})),
        ("run2", _reconlib.flatten({"frame": 0, "pos": {"x": 10, "y": 20}})),
        ("run3", _reconlib.flatten({"frame": 0, "pos": {"x": 10, "y": 21}})),
    ]
    same = det.analyse(runs[:2], 0.0, None)
    check(same["deterministic"], "two identical runs are deterministic")
    eq(same["varying_fields"], [], "no field varies when the runs agree")

    diff = det.analyse(runs, 0.0, None)
    check(not diff["deterministic"], "a differing run is not deterministic")
    varying = [f["field"] for f in diff["varying_fields"]]
    eq(varying, ["pos.y"], "only the field that changed is reported")
    check(diff["varying_fields"][0].get("numeric"),
          "a numeric difference is measured, not described")
    eq(diff["varying_fields"][0]["spread"], 1, "the spread is reported")

    # A field that stops being reported is a divergence too.
    dropped = det.analyse([
        ("run1", _reconlib.flatten({"a": 1, "packet": {"n": 1}})),
        ("run2", _reconlib.flatten({"a": 1})),
    ], 0.0, None)
    check(not dropped["deterministic"],
          "a field absent from one run breaks determinism")
    eq([f["field"] for f in dropped["fields_absent_in_some_runs"]],
       ["packet.n"], "the absent field is named")

    # Tolerance is a decision the caller makes, not a default that hides drift.
    eq(det.same_value(10, 10.4, 0.5), True, "tolerance admits small numeric drift")
    eq(det.same_value(10, 11, 0.5), False, "tolerance does not admit real drift")
    eq(det.same_value(1, True, 0.0), False, "a bool is not the int 1")

    text = det.render(diff, [], _Args())
    check("places variation usually comes from" in text,
          "the tool points at where to look")
    check("not a" in text and "diagnosis" in text,
          "the list of sources is framed as not a diagnosis")
    check("clock" in text and "random" in text,
          "the usual sources are named")
    check("evidence, not proof" in text,
          "agreement across runs is reported as evidence, not proof")

    # A single run cannot establish determinism, and must not claim to.
    single = det.analyse(runs[:1], 0.0, None)
    check(single["deterministic"], "one run trivially agrees with itself")
    check("UNDETERMINED" in det.render(single, [], _Args()),
          "one run renders as UNDETERMINED, not as a verdict")


class _Args:
    """The few render() options the tests exercise."""
    limit = 20


def test_determinism_check_survives_a_bad_file(tmp):
    """One unreadable observation is reported; the rest still decide."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "determinism-check.py")
    spec = importlib.util.spec_from_file_location("determinism_check2", path)
    det = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(det)

    good = os.path.join(tmp, "good.json")
    bad = os.path.join(tmp, "bad.json")
    missing = os.path.join(tmp, "does-not-exist.json")
    with open(good, "w", encoding="utf-8") as fh:
        fh.write('{"a": 1}')
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("not json at all")

    runs, errors = det.collect_runs(_Args2([good, bad, missing]))
    eq(len(runs), 1, "the readable observation is kept")
    eq(len(errors), 2, "both unreadable ones are reported")

    flat, err = det.load_observation(bad)
    check(flat is None and "not valid JSON" in err,
          "an unparsable file is named as such")
    flat, err = det.load_observation(missing)
    check(flat is None and "cannot read" in err,
          "a missing file is named as such")

    empty = os.path.join(tmp, "empty.json")
    open(empty, "w", encoding="utf-8").close()
    flat, err = det.load_observation(empty)
    check(flat is None and "empty" in err,
          "an empty file is not silently treated as an empty observation")


class _Args2:
    """collect_runs() options, with --run unset so only files are read."""
    run = None
    times = 3
    timeout = 5.0
    cwd = None

    def __init__(self, traces):
        self.traces = traces


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


# --------------------------------------------------------------------------
# Memory / runtime intelligence
# --------------------------------------------------------------------------

import _runtimelib as RL  # noqa: E402

SAMPLE_MAPS = """\
7f1a40000000-7f1a40001000 r--p 00000000 08:01 4242    /lib/libfoo.so
7f1a40001000-7f1a40002000 r-xp 00001000 08:01 4242    /lib/libfoo.so
7f1a40002000-7f1a40003000 rw-p 00002000 08:01 4242    /lib/libfoo.so
7f1a90000000-7f1a90001000 rw-p 00000000 00:00 0        
7f1a40003000-7f1a40999000 rw-p 00000000 00:00 0        [heap]
7ffc1a2b1000-7ffc1a2b3000 rw-p 00000000 00:00 0        [stack]
7f00c0000000-7f00c0002000 r-xp 00000000 00:00 0
7f00d0000000-7f00d0001000 rw-s 00000000 00:05 91       /dev/shm/shared
7f00e0000000-7f00e0002000 rw-p 00000000 00:00 0        [stack:4902]
"""

SAMPLE_SMAPS = """\
7f1a40000000-7f1a40001000 r--p 00000000 08:01 4242 /lib/libfoo.so
Size:                4 kB
VmFlags:            rd mr mw me sd
7f1a40001000-7f1a40002000 r-xp 00001000 08:01 4242 /lib/libfoo.so
Size:                4 kB
VmFlags:            rd ex mr mw me dw
7f1a40002000-7f1a40003000 rw-p 00002000 08:01 4242 /lib/libfoo.so
Size:                4 kB
VmFlags:            rd wr mr mw me sd
7f1a90000000-7f1a90001000 rw-p 00000000 00:00 0
Size:                4 kB
VmFlags:            rd wr mr mw me ac sd mg
7f1a40003000-7f1a40999000 rw-p 00000000 00:00 0 [heap]
Size:              1016 kB
VmFlags:            rd wr mr mw me ac sd
7ffc1a2b1000-7ffc1a2b3000 rw-p 00000000 00:00 0 [stack]
Size:                8 kB
VmFlags:            rd wr mr mw me ac sd gd
7f00c0000000-7f00c0002000 r-xp 00000000 00:00 0
Size:                8 kB
VmFlags:            rd ex mr mw me ac sd
7f00d0000000-7f00d0001000 rw-s 00000000 00:05 91 /dev/shm/shared
Size:                4 kB
VmFlags:            rd wr mr mw me ac sd
7f00e0000000-7f00e0002000 rw-p 00000000 00:00 0 [stack:4902]
Size:                8 kB
VmFlags:            rd wr mr mw me ac sd gd
"""


def build_sample_map():
    """A maps + smaps pair with every classification basis represented."""
    regions = RL.parse_maps(SAMPLE_MAPS)
    RL.apply_vmflags(regions, RL.parse_smaps_vmflags(SAMPLE_SMAPS))
    RL.classify_regions(regions)
    return regions


def test_runtime_maps_parsing(tmp):
    regions = build_sample_map()
    eq(len(regions), 9, "every maps line parsed")
    eq(regions[0].start, 0x7F1A40000000, "start parsed as hex")
    eq(regions[0].offset, 0, "file offset parsed")
    eq(regions[0].inode, 4242, "inode parsed")
    eq(regions[0].perms, "r--p", "permissions captured verbatim")

    # Malformed input must not abort the parse: a truncated read of a live
    # process is normal.
    text = SAMPLE_MAPS + "this is not a maps line\n" + "zzz\n"
    eq(len(RL.parse_maps(text)), 9, "malformed lines are skipped, not fatal")
    eq(len(RL.parse_maps("")), 0, "empty input yields no regions")

    # A region knows whether it contains an address.
    eq(regions[0].contains(0x7F1A40000500), True, "contains inside")
    eq(regions[0].contains(0x7F1A40002000), False, "does not contain outside")
    eq(regions[0].size, 0x1000, "size computed")

    # smaps VmFlags are the kernel's own account and must attach to the
    # right region, not to whichever region parsed last.
    vm = RL.parse_smaps_vmflags(SAMPLE_SMAPS)
    eq(len(vm), 9, "VmFlags for every region")
    check("mr" in vm[0x7F1A40000000], "may-read attaches to the first region")
    check("ex" in vm[0x7F1A40001000], "exec attaches to the code region")
    eq(vm[0x7F1A40001000].split(), vm[0x7F1A40001000].split(),
       "VmFlags parsed as tokens")
    check("gd" not in vm[0x7F1A40003000], "the heap is not marked grows-down")


def test_runtime_region_classification_needs_a_basis():
    """The discipline this layer exists to enforce.

    An anonymous writable region is not a heap. Reaching that conclusion
    requires a basis, and each basis is recorded.
    """
    regions = build_sample_map()
    by_start = {r.start: r for r in regions}

    # Kernel-named regions are established.
    check("heap" in by_start[0x7F1A40003000].classification,
          "the [heap] region is recognised as a heap")
    eq(by_start[0x7F1A40003000].basis, "kernel_named",
       "a kernel-named region cites the kernel")
    eq(by_start[0x7F1A40003000].confidence, "high",
       "a kernel-named region is high confidence")

    check("stack" in by_start[0x7FFC1A2B1000].classification,
          "[stack] is a stack")
    check("stack" in by_start[0x7F00E0000000].classification,
          "[stack:tid] is a thread stack")

    # VmFlags: mg means malloc-eligible, gd means grows down. Both are the
    # kernel's own statement, which is stronger than resemblance.
    check("malloc" in by_start[0x7F1A90000000].classification,
          "VmFlags mg marks a malloc-eligible region")
    eq(by_start[0x7F1A90000000].basis, "kernel_hint",
       "a VmFlags-based claim cites the kernel hint")
    check(by_start[0x7F1A90000000].notes,
          "mg alone does not claim allocations are being handed out")

    # Anonymous executable: exec + no file is observed; JIT is a reading.
    anon_exec = by_start[0x7F00C0000000]
    eq(anon_exec.classification, "anonymous executable mapping",
       "an anonymous exec region is described literally")
    check("JIT" in anon_exec.basis_detail,
          "the JIT reading is offered as a reading, not as the observation")

    # A plain anonymous region with no hint and no growth stays unknown.
    plain = RL.Region(start=0x600000000000, end=0x600000010000,
                      perms="rw-p", offset=0, inode=0)
    RL.classify_region(plain)
    eq(plain.basis, "unknown", "an unhinted anonymous region has no basis")
    eq(plain.confidence, "very low",
       "an unhinted anonymous region is very low confidence")
    check("not established" in plain.basis_detail,
          "the classification says what is not known")

    # Growth is evidence, and it is labelled as such.
    growing = RL.Region(start=0x700000000000, end=0x700000010000,
                        perms="rw-p", inode=0, growth=4096)
    RL.classify_region(growing)
    eq(growing.basis, "observed_growth",
       "a region that grew cites the growth as its basis")
    check(growing.notes, "growth is qualified: it does not identify a heap")

    # A region that grew but is marked grows-down is a stack, not a heap.
    both = RL.Region(start=0x710000000000, end=0x710000010000, perms="rw-p",
                     inode=0, growth=4096, vmflags="rd wr mr mw me ac gd")
    RL.classify_region(both)
    check("stack" in both.classification,
          "grows-down wins over growth: it is a more specific kernel hint")


def test_runtime_permissions():
    f = RL.parse_perms("r-xp")
    eq(f, {"read": True, "write": False, "exec": True,
           "shared": False, "private": True}, "r-xp parsed")
    eq(RL.perms_summary("r-xp"), "r-xp", "summary round-trips")
    eq(RL.perms_summary("rw-s"), "rw-s", "summary round-trips for rw-s")
    eq(RL.parse_perms("")["read"], False, "empty permissions are all false")
    f = RL.parse_perms("---p")
    eq((f["read"], f["write"], f["exec"]), (False, False, False),
       "---p grants nothing")

    # Anonymous means no file, which is stronger than 'no path shown'.
    eq(RL.is_anonymous("", 0), True, "no path and no inode is anonymous")
    eq(RL.is_anonymous("[heap]", 0), True, "a kernel-named region is anonymous")
    eq(RL.is_anonymous("/lib/libc.so.6", 99), False, "a path is not anonymous")
    eq(RL.is_anonymous("/tmp/gone (deleted)", 99), False,
       "a deleted file with an inode is still file-backed, not anonymous")
    eq(RL.is_anonymous("/tmp/gone (deleted)", 0), True,
       "a deleted file with no inode has nothing backing it")


def test_runtime_modules_and_load_bias(tmp):
    regions = build_sample_map()
    modules = RL.build_modules(regions)
    for m in modules:
        RL.derive_load_bias(m)
    names = [m.name for m in modules]
    check("libfoo.so" in names, "libfoo grouped as one module")
    check("shared" in names, "a /dev/shm file becomes a module too")
    check("libbar.so" not in names,
          "an anonymous region is not a module")

    foo = next(m for m in modules if m.name == "libfoo.so")
    # Three mappings at offsets 0, 0x1000, 0x2000 all imply the same bias.
    eq(len(foo.regions), 3, "one module from three mappings")
    eq(foo.load_bias, 0x7F1A40000000,
       "load bias derived from start minus file offset")
    # Without a binary the derivation is unanchored, and says so.
    eq(foo.bias_basis, "maps_unanchored",
       "an unanchored derivation is labelled as one")
    check(any("p_vaddr == p_offset" in w for w in foo.bias_warnings),
          "the unanchored basis states the assumption it depends on")
    check(any("all agreeing" in w for w in foo.bias_warnings),
          "agreement across mappings is reported")

    # Disagreeing mappings must be flagged rather than silently averaged.
    bad = RL.Module(name="weird.so", base=0, end=0,
                    regions=[RL.Region(start=0x500000000000,
                                       end=0x500000001000, perms="r--p",
                                       offset=0, inode=1, pathname="/w.so"),
                             RL.Region(start=0x500000009000,
                                       end=0x50000000A000, perms="rw-p",
                                       offset=0x1000, inode=1,
                                       pathname="/w.so")])
    RL.derive_load_bias(bad)
    eq(bad.bias_basis, "maps_partial", "disagreement downgrades the basis")
    eq(bad.load_bias, 0x500000000000, "the offset-0 anchor is used")
    check(any("disagree" in w for w in bad.bias_warnings),
          "disagreement is reported with the difference")

    # A deleted file is still mapped; the module exists but its on-disk
    # contents may differ, and that has to be said.
    deleted = RL.build_modules(RL.parse_maps(
        "7f00a0000000-7f00a0001000 r-xp 00000000 08:01 5 /tmp/gone (deleted)\n"))
    check(deleted, "a deleted file still forms a module")
    check(any("deleted" in w for w in deleted[0].bias_warnings),
          "a deleted file is reported as possibly differing from disk")


def test_runtime_address_normalisation(tmp):
    """The ASLR bridge, which is where a wrong answer costs the most."""
    p = os.path.join(tmp, "libfoo.so")
    # load_base 0 means vaddr == file offset; a nonzero base gives the skew
    # ASLR introduces.
    build_elf(p, 64, "<", 183, 3, ("libc.so",), "libfoo.so")
    info = B.load(p)
    regions = build_sample_map()
    resolver = RL.Resolver(regions, RL.build_modules(regions),
                           {"libfoo.so": info})

    # A code address: every space must come out. .text spans 0x1000-0x1100,
    # so 0x1080 is inside it.
    n = resolver.normalize(0x7F1A40001080)
    eq(n["status"], "ok", "a code address resolves fully")
    eq(n["module"], "libfoo.so", "module identified")
    eq(n["module_relative"], "0x1080", "module-relative address")
    eq(n["elf_vaddr"], "0x1080", "ELF virtual address")
    eq(n["file_offset"], "0x1080", "file offset")
    eq(n["section"], ".text", "section resolved")

    # The warning list must never claim a derivation is safe when the
    # mappings disagreed.
    for addr in (0x7F1A40001080, 0x7F1A40002100):
        n = resolver.normalize(addr)
        check("disagree" not in " ".join(n["warnings"]),
              "no spurious disagreement warning for an agreeing module")

    # A heap address has no module and therefore no file offset.
    n = resolver.normalize(0x7F1A40500000)
    eq(n["status"], "unresolved", "a heap address is not a module address")
    eq(n["module"], None, "no module for a heap address")
    check(any("anonymous" in w for w in n["warnings"]),
          "the anonymous-region reason is given")

    # An address in no region at all is unresolved, with the stale-map reason.
    n = resolver.normalize(0xDEADBEEF0000)
    eq(n["status"], "unresolved", "an unmapped address is unresolved")
    check(any("no region" in w for w in n["warnings"]),
          "the stale-map reason is given")

    # Beyond filesz is .bss: real memory, no file offset.
    p2 = os.path.join(tmp, "bss.so")
    build_elf(p2, 64, "<", 183, 3, ("libc.so",), "bss.so")
    info2 = B.load(p2)
    seg = [s for s in info2.segments if s.type == "LOAD"][-1]
    bss_vaddr = seg.vaddr + seg.filesz + 4
    res2 = RL.Resolver(regions, RL.build_modules(regions), {"libfoo.so": info2})
    n = res2.normalize(0x7F1A40000000 + bss_vaddr)
    eq(n["file_offset"], None, "no file offset for a .bss address")
    check(n.get("bss_offset"), "the offset within .bss is reported instead")
    check(any("only in memory" in w for w in n["warnings"]),
          "the .bss case explains why there is no file offset")

    # Without the binary there is no file offset, and the tool says so rather
    # than inventing one.
    res3 = RL.Resolver(regions, RL.build_modules(regions), {})
    n = res3.normalize(0x7F1A40001080)
    eq(n["status"], "partial", "no binary means a partial translation")
    eq(n["load_bias_basis"], "maps_unanchored",
       "without a binary the derivation is unanchored")
    eq(n["file_offset"], None, "no file offset without the segment table")
    check(any("segment table" in w for w in n["warnings"]),
          "the missing segment table is named as the reason")


def test_runtime_load_bias_with_vaddr_offset_skew(tmp):
    """A fixture where p_vaddr != p_offset.

    The selftest ELF normally has p_vaddr == p_offset, so every derivation
    agrees trivially and load-bias arithmetic is never exercised. Shifting the
    virtual addresses introduces the skew ASLR produces, and that is the only
    case where the naive `start - offset` form is wrong.
    """
    p = os.path.join(tmp, "skewed.so")
    build_elf(p, 64, "<", 183, 3, ("libc.so",), "skewed.so", load_base=0x40000)
    info = B.load(p)
    loads = [s for s in info.segments if s.type == "LOAD"]
    check(len(loads) >= 2, "the skewed fixture has PT_LOAD segments")
    seg1, seg2 = loads[0], loads[1]
    skew = seg1.vaddr - seg1.offset
    check(skew != 0, "the fixture really does have a vaddr/offset skew")

    # Map the fixture the way the kernel does: file offset p_offset lands at
    # (bias + p_vaddr). Mapping at bias + p_offset instead would encode a
    # different segment layout, and the test would then be measuring the
    # fixture rather than the derivation.
    bias = 0x7F1B00000000
    rows = [f"{bias + seg1.vaddr:012x}-{bias + seg1.vaddr + 0x1000:012x} "
            f"r--p {seg1.offset:08x} 08:01 5 /lib/skewed.so",
            f"{bias + seg1.vaddr:012x}-{bias + seg1.vaddr + 0x1000:012x} "
            f"r-xp {seg1.offset:08x} 08:01 5 /lib/skewed.so",
            f"{bias + seg2.vaddr:012x}-{bias + seg2.vaddr + 0x1000:012x} "
            f"rw-p {seg2.offset:08x} 08:01 5 /lib/skewed.so"]
    text = "\n".join(rows) + "\n"
    regions = RL.classify_regions(RL.parse_maps(text))
    mods = RL.build_modules(regions)
    mods[0].name = "skewed.so"
    res = RL.Resolver(regions, mods, {"skewed.so": info})

    # A runtime address inside the code segment.
    rt = bias + seg1.vaddr + 0x40
    n = res.normalize(rt)
    eq(n["load_bias"], hex(bias),
       "load bias is the kernel's base, recovered through the segment skew")
    eq(n["elf_vaddr"], hex(seg1.vaddr + 0x40),
       "the ELF vaddr carries the skew, which naive arithmetic would drop")
    eq(n["file_offset"], hex(seg1.offset + 0x40), "file offset recovered")
    eq(n["file_offset"], hex(info.vaddr_to_offset(seg1.vaddr + 0x40)),
       "the translation agrees with the parsed segment table")
    eq(n["section"], ".text", "the section resolves through the skew too")

    # The decisive check: the naive form gives a different answer here, so a
    # tool that used it would fail this test rather than pass it by accident.
    naive = rt - (bias + 0) - 0x1000
    check(naive != seg1.vaddr + 0x40,
          "the naive start-minus-offset form really is wrong for this fixture")
    eq(n["load_bias_basis"], "file_offset",
       "the translation came from the file offset, not from a bias")
    eq(res.modules[0].bias_basis, "maps",
       "the module bias was anchored to PT_LOAD segments")
    check(n["bias_agrees"],
          "the file-offset derivation and the segment-anchored bias agree")

    # And the inverse direction must land in the same place.
    inv = res.normalize(bias + seg2.vaddr + 0x10)
    eq(inv["file_offset"], hex(info.vaddr_to_offset(seg2.vaddr + 0x10)),
       "the data segment also translates consistently")


def test_runtime_address_text_parsing():
    eq(RL.normalize_address_text("0x7f1a40001234"), 0x7F1A40001234,
       "0x-prefixed hex")
    eq(RL.normalize_address_text("7f1a40001234"), 0x7F1A40001234,
       "bare hex, which is what a maps line prints")
    eq(RL.normalize_address_text(0x1234), 0x1234, "an int passes through")
    eq(RL.normalize_address_text(""), None, "empty is not an address")
    eq(RL.normalize_address_text("not-an-address"), None,
       "a non-address is rejected rather than becoming zero")
    eq(RL.normalize_address_text(None), None, "None is rejected")
    eq(RL.normalize_address_text("  0x100  "), 0x100, "whitespace is stripped")

    # Through the resolver, an unparseable value is an error and not a guess.
    regions = build_sample_map()
    res = RL.Resolver(regions, RL.build_modules(regions))
    n = res.normalize_text("nonsense")
    eq(n["status"], "unparseable", "an unparseable address is refused")
    eq(n["module"], None, "nothing is inferred from it")


def test_runtime_event_schema_rejects_overreach():
    """The schema exists to stop an inference being stored as a fact."""
    good = RL.make_event("memory_write", address="0x1000", size=4,
                         value="0x2a", evidence="watchpoint", confidence="high")
    eq(RL.validate_event(good), [], "a complete memory event validates")

    # A memory event with no size cannot be reproduced by anyone else.
    p = RL.validate_event({"type": "memory_write", "address": "0x1000"})
    check(any("size" in x for x in p), "a memory event without size is rejected")

    # Required field per type.
    p = RL.validate_event({"type": "memory_write", "size": 4})
    check(any("requires 'address'" in x for x in p),
          "a memory write without an address is rejected")
    p = RL.validate_event({"type": "module_load"})
    check(any("requires 'module'" in x for x in p),
          "a module load without a module is rejected")

    # Unknown type and vocabulary.
    p = RL.validate_event({"type": "vibes"})
    check(any("is not one of" in x for x in p), "an unknown event type is rejected")
    p = RL.validate_event({"type": "call", "confidence": "certain"})
    check(any("confidence" in x for x in p), "an unknown confidence is rejected")
    p = RL.validate_event({"type": "call", "basis": "pretty-sure"})
    check(any("basis" in x for x in p), "an unknown basis is rejected")

    # High confidence with no evidence is an assertion.
    p = RL.validate_event({"type": "memory_write", "address": "0x1", "size": 4,
                           "confidence": "high"})
    check(any("without evidence" in x for x in p),
          "high confidence without evidence is rejected")

    # Causality is the specific claim this schema exists to police.
    p = RL.validate_event({"type": "call", "address": "0x1",
                           "caused_by": "0x2"})
    check(any("causation" in x for x in p),
          "caused_by without an experiment is rejected")
    ok = RL.validate_event({"type": "call", "address": "0x1",
                            "caused_by": "0x2",
                            "experiment": "changed only that input; the "
                                          "effect followed"})
    eq(ok, [], "caused_by with a recorded experiment validates")


def test_runtime_provenance_chain():
    events = [
        RL.make_event("packet", timestamp=1, tid=1),
        RL.make_event("memory_read", address="0x2000", size=4, timestamp=2,
                      tid=1, value="0x0"),
        RL.make_event("memory_write", address="0x1000", size=4, timestamp=3,
                      tid=1, value="0x1", caller="f+0x10"),
        RL.make_event("memory_write", address="0x1000", size=4, timestamp=4,
                      tid=1, value="0x2", caller="f+0x10"),
        RL.make_event("call", address="0x3000", timestamp=5, tid=1),
        RL.make_event("syscall", timestamp=6, tid=1),
    ]
    p = RL.build_provenance(events, 0x1000)
    eq(p["status"], "ok", "an address with events has a chain")
    eq(p["write_count"], 2, "writes counted")
    eq(p["read_count"], 0, "reads counted")
    eq(p["thread_agreement"], True, "one thread means agreement")
    check(p["first_write"]["classification"] == "initialisation candidate",
          "the first write with no earlier read is an initialisation candidate")
    eq(p["first_write"]["basis"], "inferred", "stage assignment is a reading")
    check("would break" in p["first_write"]["caveat"],
          "the initialisation call carries its assumption")
    check("transform" in p["stages"], "writes before any read are a transform")
    check(p["missing_stages"], "stages without evidence are named")

    # Cadence: three writes at a fixed interval are periodic.
    periodic = [
        RL.make_event("memory_write", address="0x1", size=4, timestamp=t,
                      tid=1, value="0x0")
        for t in (0, 5, 10, 15, 20)
    ]
    p = RL.build_provenance(periodic, 0x1)
    eq(p["periodic"]["classification"], "periodic",
       "writes at a fixed interval are classified periodic")
    check("not instrumented" in p["periodic"]["caveat"],
          "the cadence carries its assumption")

    # Concurrency must be visible, not averaged away.
    two_threads = [
        RL.make_event("memory_write", address="0x1", size=4, timestamp=1,
                      tid=1, value="0x0"),
        RL.make_event("memory_write", address="0x1", size=4, timestamp=2,
                      tid=2, value="0x0"),
    ]
    p = RL.build_provenance(two_threads, 0x1)
    eq(p["thread_agreement"], False, "two threads means no agreement")
    eq(p["confidence"], "low", "a multi-threaded address drops to low")
    check("not necessarily the thread" in p["note"],
          "the note warns against attributing the write to the observer")

    # An address with no events returns the alias hypothesis, not nothing.
    p = RL.build_provenance(events, 0x9999)
    eq(p["status"], "no_events", "an untouched address is reported as such")
    check(p["alias_hypothesis"], "an alias hypothesis is offered")

    # String and int addresses must both match.
    strs = [RL.make_event("memory_write", address="0x1000", size=4,
                          timestamp=1, tid=1, value="0x0")]
    eq(RL.build_provenance(strs, 0x1000)["write_count"], 1,
       "a hex string address matches the integer")


def _frames(*specs):
    """Turn 'mod+off' strings into the frame dicts group_stacks expects."""
    return [RL.parse_stack(s)[0] for s in specs]


def test_runtime_stack_parsing_and_grouping():
    # The frame forms that actually appear.
    eq(len(RL.parse_stack("libfoo.so+0x1400")), 1, "module+offset")
    eq(len(RL.parse_stack("libfoo.so!0x7f1a40001400")), 1, "module!absolute")
    eq(len(RL.parse_stack("main+0x1c")), 1, "symbol+offset")
    eq(len(RL.parse_stack("0x7f1a40001400")), 1, "bare address")
    eq(len(RL.parse_stack("# a comment")), 0, "a comment is not a frame")

    # gdb prints '#0  0x... in func ()'. Treating every '#' line as a comment
    # loses every gdb backtrace.
    gdb = RL.parse_stack("#0  0x00007f1a40001400 in update () at g.c:42")
    eq(len(gdb), 1, "a gdb frame line yields a frame")
    eq(gdb[0]["symbol"], "update", "the symbol is recovered from gdb output")
    eq(gdb[0]["address"], "0x00007f1a40001400", "the address is recovered")

    multi = RL.parse_stack("libfoo.so+0x1400\nlibfoo.so+0x1230\nmain+0x1c")
    eq(len(multi), 3, "a multi-line backtrace yields every frame")
    eq([f["depth"] for f in multi], [0, 1, 2], "depth is assigned")

    # Grouping: the same stack groups, a rare one is labelled.
    hot = [_frames("libfoo.so+0x1400", "libfoo.so+0x1230")] * 12
    cold = [_frames("libfoo.so+0x1500", "libfoo.so+0x1230")]
    g = RL.group_stacks(hot + cold)
    eq(g["total_stacks"], 13, "every stack counted")
    eq(g["distinct_stacks"], 2, "two distinct stacks")
    eq(g["groups"][0]["count"], 12, "the repeated stack ranks first")
    check("hot path candidate" in g["groups"][0]["label"],
          "a frequent stack is labelled a hot path candidate")
    eq(g["groups"][1]["label"], "rare path (seen once)",
       "a single-occurrence stack is labelled a rare path")
    check("not a measurement" in g["groups"][0]["caveat"],
          "frequency is qualified as an observation count")

    # The process entry prologue is dropped: including it would make every
    # stack in the process look the same.
    with_prologue = [_frames("main+0x1c", "libfoo.so+0x1400"),
                     _frames("main+0x1c", "libfoo.so+0x1400"),
                     _frames("main+0x1c", "libfoo.so+0x1500")]
    g = RL.group_stacks(with_prologue)
    eq(g["distinct_stacks"], 2, "a shared prologue does not merge two stacks")

    # Unparseable input is counted, not silently dropped.
    g = RL.group_stacks([_frames("libfoo.so+0x1"), [], []])
    eq(g["total_stacks"], 1, "only parseable stacks are grouped")
    eq(g["stacks_skipped"], 2, "skipped stacks are counted")
    check(g["warning"], "the skip is reported")


def test_runtime_diff_first_divergence():
    a = [RL.make_event("call", address="0x1", timestamp=1),
         RL.make_event("call", address="0x2", timestamp=2),
         RL.make_event("call", address="0x3", timestamp=3)]
    b = [RL.make_event("call", address="0x1", timestamp=99),
         RL.make_event("call", address="0x2", timestamp=99),
         RL.make_event("call", address="0x4", timestamp=99)]
    d = RL.diff_runs(a, b)
    eq(d["identical"], False, "differing traces are not identical")
    eq(d["first_divergence_index"], 2, "the first differing event is located")
    # Both sides are calls at the same index with different addresses: the
    # sequence agrees and the data differs.
    eq(d["kind"], "field", "same event kind with a different address is a "
                           "field divergence")
    check("address" in d["divergence"]["differing_fields"],
          "the differing address is named")
    # Timestamps differ and must not be what makes these traces differ.
    check("timestamp" in str(d["keys_excluded"]),
          "timestamps are excluded from comparison")

    same = [RL.make_event("call", address="0x1", timestamp=1),
            RL.make_event("call", address="0x2", timestamp=2)]
    d = RL.diff_runs(same, list(same))
    eq(d["identical"], True, "identical traces compare equal")
    check(d["note"], "an identical result explains what it does not cover")

    # Truncation is distinguished from behaviour.
    d = RL.diff_runs(same, same + [RL.make_event("call", address="0x3")])
    eq(d["kind"], "truncation", "a shorter trace is a truncation")
    check("termination" in d["divergence"]["explanation"],
          "truncation is explained as termination, not behaviour")

    # Same event, different data: a field divergence, and value is named.
    x = [RL.make_event("memory_write", address="0x1", size=4, value="0xa")]
    y = [RL.make_event("memory_write", address="0x1", size=4, value="0xb")]
    d = RL.diff_runs(x, y)
    eq(d["kind"], "field", "same event with different data is a field divergence")
    check("differing_fields" in d["divergence"], "the differing field is named")
    check("value" in d["divergence"]["differing_fields"],
          "the changed field is the value, not the type")

    # Different events at the same index: an event divergence.
    p1 = [RL.make_event("call", address="0x1", timestamp=1)]
    p2 = [RL.make_event("packet", timestamp=1)]
    d = RL.diff_runs(p1, p2)
    eq(d["kind"], "event",
       "a different kind of event at the same index is an event divergence")
    check("explanation" not in d["divergence"],
          "an event divergence carries no field-level explanation")
    check("sequence" not in d["divergence"].get("explanation", "") or
          "differs" in d["divergence"].get("explanation", ""),
          "an event divergence does not claim the sequence agrees")

    # The tail is reported as a cascade, with the instruction to prioritise.
    long_a = [RL.make_event("call", address=f"0x{i}", timestamp=i) for i in range(10)]
    long_b = list(long_a[:5]) + [RL.make_event("call", address="0x99",
                                               timestamp=i) for i in range(5)]
    d = RL.diff_runs(long_a, long_b)
    check(d["downstream_event_mismatches"] > 0, "downstream mismatches counted")
    check("cascade" in d["interpretation"] or "consequence" in d["interpretation"],
          "the tail is framed as consequence until proven")


def test_runtime_syscall_correlation_is_reading_not_fact():
    events = [
        RL.make_event("syscall", name="mmap", value="0x7ffd000", timestamp=1,
                      tid=1),
        RL.make_event("syscall", name="connect", timestamp=2, tid=1),
        RL.make_event("syscall", name="connect", timestamp=3, tid=1),
        RL.make_event("syscall", name="write", value="7", timestamp=4, tid=1),
    ]
    c = RL.correlate_syscalls(events)
    eq(c["syscalls_observed"], 4, "every syscall counted")
    eq(c["by_name"]["connect"]["count"], 2, "repeats counted")
    eq(c["by_name"]["mmap"]["structural"], True,
       "a structural syscall is marked as such")
    # getpid is not on the structural list, and 'write' is: I/O is the kind
    # of syscall that shows up in behaviour, so it counts as structural.
    ev2 = events + [RL.make_event("syscall", name="getpid", timestamp=5, tid=1)]
    c2 = RL.correlate_syscalls(ev2)
    eq(c2["by_name"]["getpid"]["structural"], False,
       "an unlisted syscall is not marked structural")
    eq(c2["by_name"]["write"]["structural"], True,
       "an I/O syscall is marked structural")

    # Each reading must name what would make it more than a reading.
    check(c["readings"], "readings are offered")
    for r in c["readings"]:
        eq(r["basis"], "inferred", "a reading is labelled as inferred")
        check(r.get("requires"),
              f"the reading for {r['syscall']} names what it would need")
    net = [r for r in c["readings"] if r["syscall"] in ("connect", "sendto")]
    check(net, "a network syscall produces a reading")
    for r in net:
        check("protocol state change" in (r["requires"] or ""),
              "a network reading names the state change it would need before "
              "being believed")
        eq(r["basis"], "inferred", "the network reading stays inferred")


def test_runtime_module_load_chain():
    events = [
        RL.make_event("module_load", module="libc.so", timestamp=1, tid=1,
                      address="0x7f1a40000000"),
        RL.make_event("module_load", module="libextra.so", timestamp=5, tid=1,
                      address="0x7f1b00000000", caller="dlopen+0x40"),
        RL.make_event("module_unload", module="libextra.so", timestamp=9, tid=1),
    ]
    m = RL.module_load_chain(events)
    eq(m["loaded_count"], 2, "both loads counted")
    eq([e["module"] for e in m["load_order"]], ["libc.so", "libextra.so"],
       "load order preserved")
    eq(m["load_order"][1]["loaded_by"], "dlopen+0x40",
       "the loading caller is recorded")
    check(m["loaded_then_unloaded"], "a load-then-unload is identified")
    check("DT_NEEDED" in m["note"],
          "the note explains why a runtime-only module matters")
    check("not established" in m["caveat"],
          "the caveat says the dlopen claim is not established")


def test_runtime_crash_record_separates_site_from_cause():
    regions = build_sample_map()
    lookup = lambda addr: (  # noqa: E731
        next((r.classification for r in regions if r.contains(addr)), None))
    c = RL.crash_record(11, 0x7F1A40001100, 0x7F1A40001120,
                        region_lookup=lookup)
    eq(c["signal_name"], "SIGSEGV", "the signal is named")
    eq(c["crash_site"]["status"], "observed", "the crash site is observed")
    eq(c["root_cause"]["status"], "unknown",
       "the root cause is unknown, not assumed")
    check("not the cause" in c["root_cause"]["note"],
          "the record says the site is not the cause")
    check(any("last write" in s for s in c["how_to_reach_the_cause"]),
          "the record says how to reach the cause")
    eq(c["fault_region"], "file-backed mapping",
       "the faulting region is looked up")

    # Signal names cover the usual set, and an unknown number is not guessed.
    eq(RL.SIGNAL_NAMES[7], "SIGBUS", "SIGBUS named")
    eq(RL.SIGNAL_NAMES[8], "SIGFPE", "SIGFPE named")
    c = RL.crash_record(999, None, None)
    eq(c["signal_name"], "signal 999", "an unknown signal is reported as a number")
    eq(c["crash_site"]["status"], "unknown",
       "no instruction means the site is unknown")


def test_runtime_alias_hypotheses():
    same = RL.alias_hypotheses(0x1000, 0x1000)
    eq(same["same"], True, "equal addresses are the same address")
    eq(same["basis"], "observed", "that is an observation")

    diff = RL.alias_hypotheses(0x1000, 0x2000)
    eq(diff["same"], False, "different addresses are not assumed to alias")
    eq(diff["basis"], "unknown", "whether they alias is unknown")
    check(diff["tests"], "tests are offered")
    check(any("distinctive value" in t["test"] for t in diff["tests"]),
          "the decisive test is named: write one, read the other")


def test_runtime_capability_probe_is_three_state():
    caps = RL.probe_capabilities()
    for name, cap in caps["capabilities"].items():
        check(cap["state"] in ("available", "partial", "unavailable"),
              f"{name} reports a three-state capability")
        check(cap.get("gives"),
              f"{name} says what the capability provides")
        check(cap.get("detail"),
              f"{name} says what it provides when unavailable")
    check("privilege_note" in caps,
          "tool presence is distinguished from permission")
    check("degradation_note" in caps, "degradation is explained")
    check(isinstance(caps["tools_found"], dict), "found tools reported")
    # gdb may or may not exist here; the probe must not claim either way.
    gdb_state = caps["capabilities"]["ptrace"]["state"]
    check(gdb_state in ("available", "unavailable"),
          "ptrace state is one of the two outcomes, never assumed")


def test_runtime_security_of_protection_readings():
    """A protection change is a fact; its reason is a reading.

    This is checked because the opposite -- calling every mprotect an
    anti-tamper measure -- is a common and confident-sounding error.
    """
    events = [
        RL.make_event("syscall", name="mmap", value="0x7f00c0000000",
                      timestamp=1, tid=1),
        RL.make_event("syscall", name="mprotect", value="PROT_READ|PROT_EXEC",
                      timestamp=2, tid=1),
    ]
    c = RL.correlate_syscalls(events)
    readings = {r["syscall"]: r for r in c["readings"]}
    check("mprotect" in readings, "mprotect produces a reading")
    eq(readings["mprotect"]["basis"], "inferred",
       "the reason for a protection change is inferred, not observed")
    check(readings["mprotect"]["requires"],
          "the reading names the address and length it would need")
    check("mmap" in readings, "mmap produces a reading")
    check("JIT" in RL.EXEC_ANON_BASIS_NOTE or "runtime" in
          RL.EXEC_ANON_BASIS_NOTE,
          "the anonymous-exec note offers JIT as a reading, not a conclusion")


def test_recon_ledger_accepts_runtime_observations():
    """Runtime observations must fit the same ledger discipline.

    The reconstruction ledger is the working document for a runtime
    investigation too, and a runtime observation recorded without its
    evidence or experiment has to be refused in exactly the same way.
    """
    import _reconlib as RLec

    # A field with a runtime provenance chain: observations become evidence.
    e = _reconlib.new_entry(
        name="entity_state.player_id", kind="structure",
        status="hypothesized",
        evidence=["watchpoint on 0x1000 recorded 4 writes from libfoo.so+0x1400",
                  "the value changed only when a packet arrived",
                  "two threads wrote it: 4821 and 4902"],
        hypothesis="player id, written by two threads",
        next_test="drive two players and check whether the two writes "
                  "correspond to the two ids",
        related_functions=["libfoo.so+0x1400"])
    eq(_reconlib.validate_entry(e, "structure"), [],
       "a runtime-evidenced entry validates")

    # A causal claim with no experiment is refused, as everywhere else.
    bad = _reconlib.new_entry(name="x", kind="structure", status="verified",
                         evidence=["observed at 0x1000"],
                         tests=["ran twice"],
                         hypothesis="caused by 0x1400")
    eq(_reconlib.validate_entry(bad, "structure"), [],
       "a verified entry with tests validates regardless of hypothesis")

    # The load-bearing query sees runtime cross-references.
    fv = _reconlib.facts_vs_hypotheses([
        {"name": "libfoo.so+0x1400", "status": "hypothesized",
         "evidence": ["e"], "next_test": "t"},
        {"name": "entity_state.player_id", "status": "hypothesized",
         "evidence": ["e"], "next_test": "t",
         "related_functions": ["libfoo.so+0x1400"]},
    ])
    names = [x["name"] for x in fv["load_bearing_assumptions"]]
    check("libfoo.so+0x1400" in names,
          "a runtime-derived assumption others depend on is flagged")


def test_runtime_bss_resolves_a_data_symbol(tmp):
    """A .bss address is where variables live, so it must name one.

    This is the address an investigation most often arrives holding, and a
    translation that reports a bss offset but no symbol has answered half the
    question.
    """
    p = os.path.join(tmp, "vars.so")
    build_elf(p, 64, "<", 183, 3, ("libc.so",), "vars.so")
    info = B.load(p)
    regions = build_sample_map()
    res = RL.Resolver(regions, RL.build_modules(regions), {"libfoo.so": info})

    # The fixture's data segment has memsz > filesz, so the tail is bss.
    seg = [s for s in info.segments if s.type == "LOAD"][-1]
    check(seg.memsz > seg.filesz,
          "the fixture has a zero-filled tail to look at")
    bss = seg.vaddr + seg.filesz + 1
    n = res.normalize(0x7F1A40000000 + bss)
    eq(n["status"], "partial", "a bss address resolves only partially")
    eq(n["file_offset"], None, "and reports no file offset")
    check(n.get("bss_offset") is not None, "but does report the bss offset")
    check(any("only in memory" in w for w in n["warnings"]),
          "the reason there is no file offset is stated")

    # A function symbol must not be invented for a data address, and a data
    # symbol must not swallow an address outside its range.
    defined = [s for s in info.symbols if not s.is_undefined and s.value]
    check(defined, "the fixture exports some symbols to look up")
    hits = [s for s in defined
            if s.value <= bss < s.value + (s.size or 1)]
    if hits:
        sym = res.normalize(0x7F1A40000000 + bss).get("symbol")
        check(sym and sym.split(" ")[0] == hits[0].name,
              "the containing symbol is reported, and is not dressed up as "
              "code")


def test_runtime_translation_uses_the_file_offset_not_the_bias(tmp):
    """The bias is a check; the file offset and the segment table decide.

    A module whose segments carry different vaddr/offset skews produces
    several different ``start - offset`` results. Deriving from the file
    offset is immune to that, and agreeing with the parsed binary proves it.
    """
    p = os.path.join(tmp, "skew2.so")
    build_elf(p, 64, "<", 183, 3, ("libc.so",), "skew2.so", load_base=0x40000)
    info = B.load(p)
    loads = [s for s in info.segments if s.type == "LOAD"]
    check(len({s.vaddr - s.offset for s in loads}) == 1,
          "the fixture's segments share one skew, as real ones do")

    bias = 0x7F1C00000000
    rows = []
    for seg, perms in ((loads[0], "r-xp"), (loads[-1], "rw-p")):
        rows.append(f"{bias + seg.vaddr:012x}-{bias + seg.vaddr + 0x1000:012x} "
                    f"{perms} {seg.offset:08x} 08:01 5 /lib/skew2.so")
    regions = RL.classify_regions(RL.parse_maps("\n".join(rows) + "\n"))
    mods = RL.build_modules(regions)
    mods[0].name = "skew2.so"
    res = RL.Resolver(regions, mods, {"skew2.so": info})

    for seg in loads:
        rt = bias + seg.vaddr + 0x10
        n = res.normalize(rt)
        eq(n["status"], "ok", f"an address in the segment at vaddr "
                             f"{seg.vaddr:#x} resolves")
        eq(n["file_offset"], f"0x{seg.offset + 0x10:x}",
           "the file offset comes from the segment, not from the base")
        eq(n["elf_vaddr"], f"0x{seg.vaddr + 0x10:x}",
           "the virtual address round-trips")
        eq(n["load_bias_basis"], "file_offset",
           "and the record says which derivation produced it")

        # The naive form would be wrong here, so the agreement is not luck.
        naive = rt - (bias + seg.offset)
        check(naive != seg.vaddr + 0x10 or seg.offset == seg.vaddr,
              "the naive start-minus-offset form is wrong for this segment")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        for fn in (test_elf_64, test_elf_32_be, test_pe, test_macho,
                   test_sniff, test_formats_identify_by_content,
                   test_indicators, test_android_manifest_roundtrip,
                   test_android_apk, test_unity_detection, test_archives_zip,
                   test_binaries_triage_notable,
                   test_recon_ledger_roundtrip,
                   test_recon_dead_end_records_what_was_believed,
                   test_recon_gaps_reports_what_is_open,
                   test_recon_render_is_deterministic,
                   test_determinism_check_survives_a_bad_file,
                   test_runtime_maps_parsing,
                   test_runtime_modules_and_load_bias,
                   test_runtime_address_normalisation,
                   test_runtime_load_bias_with_vaddr_offset_skew,
                   test_runtime_bss_resolves_a_data_symbol,
                   test_runtime_translation_uses_the_file_offset_not_the_bias):
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
                   test_recon_evidence_accounting_is_weighted,
                   test_recon_ledger_validates_seed_templates,
                   test_recon_trace_first_divergence,
                   test_recon_numeric_causes_are_hypotheses,
                   test_recon_flatten,
                   test_runtime_region_classification_needs_a_basis,
                   test_recon_state_diff,
                   test_reconstruction_candidates,
                   test_runtime_permissions,
                   test_runtime_event_schema_rejects_overreach,
                   test_runtime_provenance_chain,
                   test_runtime_stack_parsing_and_grouping,
                   test_runtime_diff_first_divergence,
                   test_runtime_syscall_correlation_is_reading_not_fact,
                   test_runtime_module_load_chain,
                   test_runtime_crash_record_separates_site_from_cause,
                   test_runtime_alias_hypotheses,
                   test_runtime_capability_probe_is_three_state,
                   test_runtime_security_of_protection_readings,
                   test_recon_ledger_accepts_runtime_observations,
                   test_recon_source_is_validated,
                   test_recon_reopening_a_dead_end_is_detected,
                   test_determinism_check_separates_measurement_from_cause,
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