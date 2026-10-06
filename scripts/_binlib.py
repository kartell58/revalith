"""
_binlib.py -- minimal, dependency-free binary format readers.

Shared by the helper scripts in this skill. Standard library only.

Supported containers: ELF, PE/COFF, Mach-O (thin + FAT), plus sniffing for
zip-based containers (APK/JAR) and DEX.

Design rules that the rest of the skill depends on:
  * Never invent data. Anything not derivable from the file is reported as
    ``None``/``unknown`` with a reason string.
  * Every address reported is a *static* (file/image) address. Runtime
    addresses require a load base and are out of scope here.
  * Parsers are defensive: malformed input raises :class:`ParseError` with a
    human-readable message instead of an opaque struct/IndexError traceback.
"""

from __future__ import annotations

import struct
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class ParseError(Exception):
    """Raised when a file cannot be parsed as the requested/guessed format."""


# --------------------------------------------------------------------------
# Machine / architecture tables
# --------------------------------------------------------------------------

ELF_MACHINES = {
    0: "none", 2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    22: "S390", 40: "ARM", 42: "SuperH", 43: "SPARCv9", 50: "IA-64",
    62: "x86-64", 83: "AVR", 92: "OpenRISC", 94: "Tensilica Xtensa",
    105: "MSP430", 106: "Blackfin", 140: "TMS320C6000", 183: "AArch64",
    188: "Tilera TILE64", 189: "Tilera TILEPro", 190: "Tilera TILE-Gx",
    191: "Z80", 224: "AMDGPU", 243: "RISC-V", 247: "eBPF", 252: "C-SKY",
    258: "LoongArch",
}

ELF_TYPES = {
    0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE",
}

PE_MACHINES = {
    0x0000: "unknown", 0x014C: "x86", 0x0166: "MIPS R4000", 0x0169: "PowerPC",
    0x01A2: "Hitachi SH3", 0x01C0: "ARM", 0x01C2: "ARM Thumb-2",
    0x01C4: "ARM Thumb-2 (ARMNT)", 0x0200: "IA-64", 0x0266: "MIPS16",
    0x5032: "RISC-V 32", 0x5064: "RISC-V 64", 0x5128: "LoongArch32",
    0x8664: "x86-64", 0xAA64: "ARM64", 0x0200: "Itanium",
    0x0EBC: "EFI byte code",
}

MACHO_CPUS = {
    6: "PowerPC", 7: "x86", 7 | 0x01000000: "x86-64",
    8: "MIPS", 8 | 0x01000000: "MIPS64", 9: "HPPA", 10: "MC680x0",
    11: "MC88000", 12: "ARM", 12 | 0x01000000: "ARM64",
    12 | 0x02000000: "ARM64_32", 13: "MC98000", 14: "HPPA64",
    15: "MC88000", 18: "PowerPC64", 0x01000012: "ppc970",
}

MACHO_FILETYPES = {
    1: "object", 2: "executable", 3: "fixed VM lib", 4: "core",
    5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib stub",
    10: "dsym", 11: "kext", 12: "file-set",
}

MACHO_LOAD_CMD_NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD",
    0xb: "LC_DYSYMTAB", 0xc: "LC_LOAD_DYLIB", 0xd: "LC_ID_DYLIB",
    0xe: "LC_LOAD_DYLINKER", 0x15: "LC_SUB_FRAMEWORK",
    0x19: "LC_SEGMENT_64", 0x1b: "LC_UUID", 0x1d: "LC_CODE_SIGNATURE",
    0x21: "LC_ENCRYPTION_INFO", 0x22: "LC_DYLD_INFO", 0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x28: "LC_MAIN", 0x29: "LC_DATA_IN_CODE", 0x2A: "LC_SOURCE_VERSION",
    0x2B: "LC_DYLIB_CODE_SIGN_DRS", 0x2C: "LC_ENCRYPTION_INFO_64",
    0x2E: "LC_LINKER_OPTION", 0x2F: "LC_LINKER_OPTIMIZATION_HINT",
    0x32: "LC_BUILD_VERSION", 0x33: "LC_DYLD_EXPORTS_TRIE",
    0x34: "LC_DYLD_CHAINED_FIXUPS", 0x80000022: "LC_DYLD_INFO_ONLY",
    0x80000028: "LC_MAIN", 0x80000033: "LC_DYLD_CHAINED_FIXUPS",
}

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Section:
    name: str
    addr: int = 0
    offset: int = 0
    size: int = 0
    type: str = ""
    flags: int = 0
    entropy: Optional[float] = None

    def to_dict(self) -> Dict:
        return {
            "name": self.name, "addr": self.addr, "offset": self.offset,
            "size": self.size, "type": self.type, "flags": self.flags,
            "entropy": self.entropy,
        }


@dataclass
class Segment:
    type: str
    offset: int = 0
    vaddr: int = 0
    filesz: int = 0
    memsz: int = 0
    flags: int = 0
    align: int = 0

    def to_dict(self) -> Dict:
        return {
            "type": self.type, "offset": self.offset, "vaddr": self.vaddr,
            "filesz": self.filesz, "memsz": self.memsz, "flags": self.flags,
            "align": self.align,
        }


@dataclass
class Symbol:
    name: str
    value: int = 0
    size: int = 0
    type: str = ""
    bind: str = ""
    shndx: int = 0
    table: str = ""  # "dynsym" | "symtab"

    @property
    def is_undefined(self) -> bool:
        return self.shndx == 0

    @property
    def is_func(self) -> bool:
        return self.type.upper() in ("STT_FUNC", "FUNC", "FUNCTION")

    def to_dict(self) -> Dict:
        return {
            "name": self.name, "value": self.value, "size": self.size,
            "type": self.type, "bind": self.bind, "shndx": self.shndx,
            "table": self.table, "undefined": self.is_undefined,
        }


@dataclass
class BinaryInfo:
    """Uniform view over ELF / PE / Mach-O."""
    path: str
    fmt: str
    arch: Optional[str] = None
    bits: Optional[int] = None
    endian: Optional[str] = None
    entrypoint: Optional[int] = None
    imagebase: Optional[int] = None
    sections: List[Section] = field(default_factory=list)
    segments: List[Segment] = field(default_factory=list)
    needed: List[str] = field(default_factory=list)
    soname: Optional[str] = None
    symbols: List[Symbol] = field(default_factory=list)
    stripped: Optional[bool] = None
    is_pie: Optional[bool] = None
    build_id: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    extra: Dict = field(default_factory=dict)

    # -- address translation -------------------------------------------
    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for seg in self.segments:
            if seg.filesz and seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                return seg.offset + (vaddr - seg.vaddr)
        for sec in self.sections:
            if sec.size and sec.addr <= vaddr < sec.addr + sec.size:
                return sec.offset + (vaddr - sec.addr)
        return None

    def offset_to_vaddr(self, off: int) -> Optional[int]:
        for seg in self.segments:
            if seg.filesz and seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset)
        for sec in self.sections:
            if sec.size and sec.offset <= off < sec.offset + sec.size:
                return sec.addr + (off - sec.offset)
        return None

    def section_for(self, vaddr: int) -> Optional[Section]:
        for sec in self.sections:
            if sec.size and sec.addr <= vaddr < sec.addr + sec.size:
                return sec
        return None

    @property
    def executable_sections(self) -> List[Section]:
        return [s for s in self.sections
                if s.size and (s.flags & 0x4 or s.flags & 0x80000000
                               or s.type in ("SHT_PROGBITS", "PROGBITS",
                                             "TEXT", "code"))]

    def dyn_symbols(self) -> List[Symbol]:
        return [s for s in self.symbols if s.table == "dynsym"]

    def static_symbols(self) -> List[Symbol]:
        return [s for s in self.symbols if s.table == "symtab"]

    def imports(self) -> List[Symbol]:
        return [s for s in self.dyn_symbols() if s.is_undefined and s.name]

    def exports(self) -> List[Symbol]:
        out = []
        for s in self.dyn_symbols():
            if s.name and not s.is_undefined and (s.is_func or s.size):
                out.append(s)
        return out

    def functions(self) -> List[Symbol]:
        return [s for s in self.symbols if s.is_func and s.name]


# --------------------------------------------------------------------------
# Sniffing
# --------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"
PE_LE_MAGIC = b"PE\x00\x00"
MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe": ("little", 32),   # MH_MAGIC   (bytes reversed)
    b"\xcf\xfa\xed\xfe": ("little", 64),   # MH_MAGIC_64
    b"\xfe\xed\xfa\xce": ("big", 32),
    b"\xfe\xed\xfa\xcf": ("big", 64),
}
MACHO_FAT_MAGICS = {b"\xca\xfe\xba\xbe": 32, b"\xca\xfe\xba\xbf": 64}
DEX_MAGIC = b"dex\n"


def sniff(path: str) -> str:
    """Return a coarse format name. Never raises for a readable file."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc

    if head.startswith(ELF_MAGIC):
        return "ELF"
    if head.startswith(b"MZ"):
        return "PE" if _pe_sig_ok(path) else "PE/DOS"
    if head[:4] in MACHO_FAT_MAGICS:
        return "Mach-O universal (FAT)"
    if head[:4] in MACHO_MAGICS:
        return "Mach-O"
    if head.startswith(DEX_MAGIC):
        return "DEX"
    if head.startswith(CA_MAGIC := b"\xca\xfe\xd0\x0d"):
        return "Java class"
    if head.startswith(b"\x50\x4b\x03\x04"):
        return _sniff_zip(path)
    if head.startswith(b"\x7f\x45\x4c\x46"):
        return "ELF"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE2 (legacy MS Office / MSI)"
    if head.startswith(b"\x25\x21"):
        return "script/text"
    return "unknown"


def _pe_sig_ok(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0x3C)
            off = struct.unpack("<I", fh.read(4))[0]
            fh.seek(off)
            return fh.read(4) == PE_LE_MAGIC
    except (OSError, struct.error):
        return False


def _sniff_zip(path: str) -> str:
    names: List[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (OSError, zipfile.BadZipFile):
        return "zip"
    if "AndroidManifest.xml" in names:
        return "APK (zip)"
    if any(n.endswith(".dex") for n in names):
        return "zip with DEX"
    if any(n.endswith(".so") for n in names):
        return "zip with native libs"
    if any(n.endswith(".class") for n in names):
        return "JAR (zip)"
    return "zip"


def load(path: str, fmt: Optional[str] = None) -> BinaryInfo:
    """Load ``path`` and return a :class:`BinaryInfo`.

    ``fmt`` overrides auto-detection (one of ELF/PE/Mach-O).
    """
    if fmt is None:
        fmt = sniff(path)
    if fmt == "ELF":
        return parse_elf(path)
    if fmt in ("PE", "PE/DOS"):
        return parse_pe(path)
    if fmt in ("Mach-O", "Mach-O universal (FAT)"):
        return parse_macho(path)
    raise ParseError(
        f"{path}: format {fmt!r} is not parsed by the bundled helpers. "
        "Use an external tool: `file`, `objdump -x`, `llvm-readobj`, or "
        "unzip and inspect the contained DEX/ELF members."
    )


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------

PT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
            5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME",
            0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO",
            0x6474E553: "GNU_PROPERTY", 0x70000001: "EXIDX"}

SHT_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
             5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
             10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
             0x6FFFFFF5: "GNU_ATTRIBUTES", 0x6FFFFFF6: "GNU_HASH",
             0x6FFFFFF8: "GNU_verdef", 0x6FFFFFFD: "GNU_verdym",
             0x6FFFFFFE: "GNU_versym", 0x6FFFFFFF: "GNU_verneed"}

STT_TYPES = {0: "STT_NOTYPE", 1: "STT_OBJECT", 2: "STT_FUNC", 3: "STT_SECTION",
             4: "STT_FILE", 5: "STT_COMMON", 6: "STT_TLS", 10: "STT_GNU_IFUNC"}
STB_TYPES = {0: "STB_LOCAL", 1: "STB_GLOBAL", 2: "STB_WEAK", 10: "STB_GNU_UNIQUE"}

DT_TAGS = {
    0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT", 4: "DT_HASH",
    5: "DT_STRTAB", 6: "DT_SYMTAB", 7: "DT_RELA", 8: "DT_RELASZ", 9: "DT_RELAENT",
    10: "DT_STRSZ", 11: "DT_SYMENT", 12: "DT_INIT", 13: "DT_FINI",
    14: "DT_SONAME", 15: "DT_RPATH", 16: "DT_SYMBOLIC", 17: "DT_REL",
    18: "DT_RELSZ", 19: "DT_RELENT", 20: "DT_PLTREL", 21: "DT_DEBUG",
    22: "DT_TEXTREL", 23: "DT_JMPREL", 24: "DT_BIND_NOW", 25: "DT_INIT_ARRAY",
    26: "DT_FINI_ARRAY", 27: "DT_INIT_ARRAYSZ", 28: "DT_FINI_ARRAYSZ",
    29: "DT_RUNPATH", 30: "DT_FLAGS", 32: "DT_PREINIT_ARRAY",
    0x6FFFFEF5: "DT_GNU_HASH", 0x6FFFFFF0: "DT_VERSYM", 0x6FFFFFF9: "DT_RELACOUNT",
    0x6FFFFFFA: "DT_RELCOUNT", 0x6FFFFFFB: "DT_FLAGS_1",
}


def _cstr(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", "replace")


def _entropy(data: bytes) -> Optional[float]:
    if not data:
        return None
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def parse_elf(path: str) -> BinaryInfo:
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(ELF_MAGIC):
        raise ParseError(f"{path}: not an ELF file")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ParseError(f"{path}: invalid EI_CLASS/EI_DATA ({ei_class}/{ei_data})")

    is64 = ei_class == 2
    end = "<" if ei_data == 1 else ">"
    info = BinaryInfo(
        path=path, fmt="ELF",
        bits=64 if is64 else 32,
        endian="little" if ei_data == 1 else "big",
    )

    if is64:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, e_flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, e_flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack_from(end + "HHIIIIIHHHHHH", data, 16)

    info.arch = ELF_MACHINES.get(e_machine, f"unknown({e_machine})")
    info.entrypoint = e_entry
    info.is_pie = (e_type == 3)
    info.extra["elf_type"] = ELF_TYPES.get(e_type, f"0x{e_type:x}")
    info.extra["machine_id"] = e_machine
    info.extra["flags"] = f"0x{e_flags:x}"
    info.extra["abi"] = {
        0: "System V", 3: "Linux", 6: "Solaris", 9: "FreeBSD", 12: "OpenBSD",
        64: "ARM EABI", 97: "ARM EABI (embedded)", 255: "Standalone",
    }.get(data[7], f"OSABI {data[7]}")

    # Extended numbering (sh_size/sh_link of section 0 carry real counts).
    shstrtab_off = 0
    if e_shoff and e_shnum == 0 and e_shoff + 64 <= len(data):
        if is64:
            e_shnum = struct.unpack_from(end + "Q", data, e_shoff + 32)[0]
        else:
            e_shnum = struct.unpack_from(end + "I", data, e_shoff + 20)[0]
    if e_shoff and e_shstrndx == 0xFFFF and e_shoff + 64 <= len(data):
        if is64:
            e_shstrndx = struct.unpack_from(end + "I", data, e_shoff + 40)[0]
        else:
            e_shstrndx = struct.unpack_from(end + "I", data, e_shoff + 24)[0]

    # --- program headers -> segments ---
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data) or e_phentsize == 0:
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from(end + "IIQQQQQQ", data, off)
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack_from(end + "IIIIIIII", data, off)
        info.segments.append(Segment(
            type=PT_TYPES.get(p_type, f"0x{p_type:x}"), offset=p_offset,
            vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz, flags=p_flags,
            align=p_align))

    # --- section headers ---
    raw_sections: List[Tuple[int, int, int, int, int, int, int, int]] = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data) or e_shentsize == 0:
            break
        if is64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, _sh_info, _sh_align, sh_entsize = \
                struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, _sh_info, _sh_align, sh_entsize = \
                struct.unpack_from(end + "IIIIIIIIII", data, off)
        raw_sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                             sh_size, sh_link, sh_entsize))

    if raw_sections and e_shstrndx < len(raw_sections):
        shstrtab_off = raw_sections[e_shstrndx][4]

    for (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
         sh_entsize) in raw_sections:
        nm = _cstr(data, shstrtab_off + sh_name) if shstrtab_off else ""
        sec = Section(name=nm, addr=sh_addr, offset=sh_offset, size=sh_size,
                      type=SHT_TYPES.get(sh_type, f"0x{sh_type:x}"),
                      flags=sh_flags)
        if sh_size and sh_type != 8 and sh_offset + sh_size <= len(data):
            chunk = data[sh_offset:sh_offset + min(sh_size, 1 << 20)]
            sec.entropy = _entropy(chunk)
        info.sections.append(sec)

    # --- dynamic section ---
    _elf_dynamic(data, info, is64, end, shstrtab_off)

    # --- symbol tables ---
    for sec in info.sections:
        if sec.type == "DYNSYM":
            _elf_symtab(data, info, sec, "dynsym", is64, end)
        elif sec.type == "SYMTAB":
            _elf_symtab(data, info, sec, "symtab", is64, end)

    info.stripped = not info.static_symbols() and bool(info.dyn_symbols())
    if info.stripped is None or not info.symbols:
        info.stripped = True
    info.build_id = _elf_build_id(data, info)
    if "android_ident" in info.extra:
        info.notes.append(
            f"Android NDK {info.extra['android_ident']['ndk_version']} "
            f"(API {info.extra['android_ident']['api_level']})")
    return info


def _elf_dynamic(data: bytes, info: BinaryInfo, is64: bool, end: str,
                 shstrtab_off: int) -> None:
    """Read DT_NEEDED / DT_SONAME from .dynamic (or PT_DYNAMIC)."""
    dyn_sec = next((s for s in info.sections if s.type == "DYNAMIC"), None)
    if dyn_sec is not None:
        base, size = dyn_sec.offset, dyn_sec.size
    else:
        seg = next((s for s in info.segments if s.type == "DYNAMIC"), None)
        if seg is None:
            return
        base, size = seg.offset, seg.filesz
    if not size:
        return

    step = 16 if is64 else 8
    fmt = end + ("qQ" if is64 else "iI")
    needed_idx: List[int] = []
    strtab_va = None
    for off in range(base, min(base + size, len(data) - step + 1), step):
        try:
            tag, val = struct.unpack_from(fmt, data, off)
        except struct.error:
            break
        if tag == 0:
            break
        if tag == 1:
            needed_idx.append(val)
        elif tag == 14:
            info.soname = info.extra.setdefault("soname_idx", val)
        elif tag == 5:
            strtab_va = val
        elif tag == 29:
            info.extra["runpath_idx"] = val
        elif tag == 15:
            info.extra["rpath_idx"] = val

    # Resolve string table: prefer a section with matching vaddr (more robust
    # for ET_REL objects with no PT_LOAD), else translate via segments.
    str_off = None
    if strtab_va is not None:
        for sec in info.sections:
            if sec.type == "STRTAB" and sec.addr == strtab_va:
                str_off = sec.offset
                break
    if str_off is None and strtab_va is not None:
        str_off = info.vaddr_to_offset(strtab_va)
    if str_off is None:
        str_off = shstrtab_off or 0

    for idx in needed_idx:
        s = _cstr(data, str_off + idx)
        if s:
            info.needed.append(s)

    if "soname_idx" in info.extra:
        info.soname = _cstr(data, str_off + info.extra["soname_idx"]) or None
    if "runpath_idx" in info.extra:
        info.extra["runpath"] = _cstr(data, str_off + info.extra["runpath_idx"])
    if "rpath_idx" in info.extra:
        info.extra["rpath"] = _cstr(data, str_off + info.extra["rpath_idx"])


def _elf_symtab(data: bytes, info: BinaryInfo, sec: Section, table: str,
                is64: bool, end: str) -> None:
    # Locate the matching STRTAB via sh_link is unavailable (not captured);
    # fall back to .dynstr/.strtab by name.
    name = ".dynstr" if table == "dynsym" else ".strtab"
    strtab = next((s for s in info.sections if s.name == name), None)
    if strtab is None:
        cands = [s for s in info.sections if s.type == "STRTAB"]
        strtab = cands[0] if cands else None
    if strtab is None:
        return
    ent = 24 if is64 else 16
    fmt = end + ("IBBHQQ" if is64 else "IIIBBH")
    for off in range(sec.offset, min(sec.offset + sec.size, len(data) - ent + 1), ent):
        try:
            st_name, st_info, _other, st_shndx, st_value, st_size = \
                struct.unpack_from(fmt, data, off)
        except struct.error:
            break
        info.symbols.append(Symbol(
            name=_cstr(data, strtab.offset + st_name), value=st_value,
            size=st_size, type=STT_TYPES.get(st_info & 0xF, str(st_info & 0xF)),
            bind=STB_TYPES.get(st_info >> 4, str(st_info >> 4)),
            shndx=st_shndx, table=table))
    # Static symbols conventionally come first; keep order stable regardless.


def _elf_build_id(data: bytes, info: BinaryInfo) -> Optional[str]:
    """Extract GNU build-id and Android NDK notes from SHT_NOTE sections.

    Note layout: namesz(u32) descsz(u32) type(u32) name[padded] desc[padded].
    """
    end = endian_of(info)
    for sec in info.sections:
        if sec.type != "NOTE" or not sec.size:
            continue
        if sec.offset + sec.size > len(data):
            continue
        pos = sec.offset
        limit = sec.offset + sec.size
        while pos + 12 <= limit:
            namesz, descsz, ntype = struct.unpack_from(end + "III", data, pos)
            name_off = pos + 12
            desc_off = name_off + ((namesz + 3) & ~3)
            desc_end = desc_off + descsz
            if descsz < 0 or desc_end > limit or descsz > 1 << 20:
                break
            name = _cstr(data, name_off) if namesz else ""
            if name == "GNU" and ntype == 3:  # NT_GNU_BUILD_ID
                return data[desc_off:desc_end].hex()
            if name == "Android" and ntype == 1:  # NT_ANDROID_IDENT
                ident = data[desc_off:desc_end]
                if len(ident) >= 64:
                    api = struct.unpack_from(end + "I", ident, 0)[0]
                    ndk = data[8:64].split(b"\x00")[0].decode("utf-8", "replace")
                    info.extra["android_ident"] = {
                        "api_level": api,
                        "ndk_version": ndk,
                        "ndk_build_number": ident[8 + 56:8 + 64].decode(
                            "utf-8", "replace").strip("\x00"),
                    }
            pos = desc_off + ((descsz + 3) & ~3)
    return None


def endian_of(info: BinaryInfo) -> str:
    return "<" if (info.endian or "little") == "little" else ">"


# --------------------------------------------------------------------------
# PE / COFF
# --------------------------------------------------------------------------

SCN_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMBOLS", 3: "STRTAB", 4: "RELO",
             5: "DEBUG", 6: "CONTENTS", 7: "IMPORT", 8: "EXPORT",
             0x02000000: "CODE", 0x04000000: "INITIALIZED_DATA",
             0x08000000: "UNINITIALIZED_DATA", 0x10000000: "LNK_INFO",
             0x20000000: "LNK_REMOVE", 0x40000000: "LNK_COMDAT",
             0x80000000: "LNK_NRELOC_OVFL"}

PE_CHARS = {
    0x0001: "RELOCS_STRIPPED", 0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED", 0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE", 0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED", 0x1000: "SYSTEM", 0x2000: "DLL",
}


def parse_pe(path: str) -> BinaryInfo:
    with open(path, "rb") as fh:
        data = fh.read()
    if not data.startswith(b"MZ"):
        raise ParseError(f"{path}: no MZ header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != PE_LE_MAGIC:
        raise ParseError(f"{path}: no PE signature at 0x{e_lfanew:x}")

    coff = e_lfanew + 4
    (machine, nsec, timestamp, _symtab, nsyms, opt_size, chars) = \
        struct.unpack_from("<HHIIIHH", data, coff)

    info = BinaryInfo(path=path, fmt="PE", arch=PE_MACHINES.get(machine, f"0x{machine:x}"))
    info.extra["characteristics"] = [n for b, n in PE_CHARS.items() if chars & b]
    info.extra["timestamp"] = timestamp
    info.is_pie = bool(chars & 0x0001) is False and "RELOCS_STRIPPED" not in info.extra["characteristics"]

    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        info.bits = 32
        (_, _lnk, _szcode, _szidata, entry_rva, base_code, base_data,
         imagebase) = struct.unpack_from("<HBBIIIIIII", data, opt)
        ndd_off = opt + 92
    elif magic == 0x20B:
        info.bits = 64
        imagebase = struct.unpack_from("<Q", data, opt + 24)[0]
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        base_code = struct.unpack_from("<I", data, opt + 20)[0]
        base_data = struct.unpack_from("<I", data, opt + 24 - 4)[0]
        ndd_off = opt + 108
    else:
        raise ParseError(f"{path}: unknown optional header magic 0x{magic:x}")
    info.endian = "little"
    info.imagebase = imagebase
    info.entrypoint = imagebase + entry_rva
    info.extra["entry_rva"] = entry_rva
    info.extra["is_dll"] = bool(chars & 0x2000)

    try:
        ndd = struct.unpack_from("<I", data, ndd_off)[0]
    except struct.error:
        ndd = 0
    # NumberOfRvaAndSizes sits at ndd_off; the directory array starts at
    # ndd_off + 4, so entry i is at ndd_off + 4 + 8*i.
    data_dirs = []
    for i in range(min(ndd, 16)):
        try:
            rva, sz = struct.unpack_from("<II", data, ndd_off + 4 + 8 * i)
        except struct.error:
            break
        data_dirs.append((rva, sz))
    info.extra["data_directories"] = data_dirs

    sec_off = opt + opt_size
    sections: List[Section] = []
    for i in range(nsec):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        raw_name = data[base:base + 8].rstrip(b"\x00").decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        flags = struct.unpack_from("<I", data, base + 36)[0]
        sec = Section(name=raw_name, addr=imagebase + vaddr, offset=rawptr,
                      size=rawsize or vsize, type=SCN_TYPES.get(flags & 0xF0000000,
                      hex(flags)), flags=flags)
        sec.extra_vaddr = vaddr  # type: ignore[attr-defined]
        sec.extra_vsize = vsize   # type: ignore[attr-defined]
        sec.entropy = _entropy(data[rawptr:rawptr + min(rawsize, 1 << 20)]) if rawsize else None
        sections.append(sec)
        info.segments.append(Segment(type="SECTION", offset=rawptr,
                                     vaddr=imagebase + vaddr, filesz=rawsize,
                                     memsz=vsize, flags=flags))
    info.sections = sections

    def rva_to_off(rva: int) -> Optional[int]:
        for s in sections:
            sv = getattr(s, "extra_vaddr", 0)
            sz = max(getattr(s, "extra_vsize", 0), getattr(s, "extra_rawsize", s.size))
            if sv <= rva < sv + max(sz, 1):
                return s.offset + (rva - sv)
        return None

    info.vaddr_to_offset = lambda v: rva_to_off(v - imagebase)  # type: ignore[assignment]
    info.offset_to_vaddr = lambda o: next(  # type: ignore[assignment]
        (imagebase + getattr(s, "extra_vaddr", 0)
         for s in sections
         if s.offset <= o < s.offset + s.size), None)
    info.section_for = lambda v: next(  # type: ignore[assignment]
        (s for s in sections
         if imagebase + getattr(s, "extra_vaddr", 0)
         <= v < imagebase + getattr(s, "extra_vaddr", 0) + s.size), None)

    # imports (directory 1)
    if len(data_dirs) > 1 and data_dirs[1][0]:
        for dll, funcs in _pe_imports(data, data_dirs[1], rva_to_off,
                                     info.bits == 64):
            if dll:
                info.needed.append(dll)
            for fname, iat_rva in funcs:
                # value = the IAT slot the loader will fill in, which is the
                # address a call-through-IAT actually reads.
                info.symbols.append(Symbol(
                    name=f"{dll}!{fname}" if fname else f"{dll}!<ordinal>",
                    value=imagebase + iat_rva, type="FUNC", bind="GLOBAL",
                    shndx=0, table="dynsym"))

    # exports (directory 0)
    if data_dirs and data_dirs[0][0]:
        for fname, rva in _pe_exports(data, data_dirs[0], rva_to_off):
            sec_idx = next((i + 1 for i, s in enumerate(sections)
                            if rva_to_off(rva) is not None
                            and s.offset <= rva_to_off(rva) < s.offset + s.size), 1)
            info.symbols.append(Symbol(name=fname, value=imagebase + rva,
                                       type="FUNC", bind="GLOBAL",
                                       shndx=sec_idx, table="dynsym"))

    if any(s.name == ".text" or (s.flags & 0x20000000) for s in sections):
        info.stripped = "LOCAL_SYMS_STRIPPED" in info.extra["characteristics"]
    return info


def _pe_imports(data: bytes, dd: Tuple[int, int], rva_to_off,
                is64: bool = True) -> List[Tuple[str, List]]:
    """Return ``[(dll_name, [(func_name, iat_rva), ...]), ...]``.

    ``iat_rva`` is the RVA of that function's slot in the *import address
    table*, which is the slot the loader patches at runtime. ``is64`` comes
    from the optional header magic and selects the 8- or 4-byte thunk width.
    """
    out: List[Tuple[str, List]] = []
    off = rva_to_off(dd[0])
    if off is None:
        return out
    step = 8 if is64 else 4
    ordinal_flag = (1 << 63) if is64 else (1 << 31)
    unpack = "<Q" if is64 else "<I"

    i = off
    while i + 20 <= len(data):
        ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", data, i)
        if not any((ilt, name_rva, iat)):
            break
        noff = rva_to_off(name_rva)
        dll = _cstr(data, noff) if noff is not None else f"RVA_{name_rva:x}"
        # Prefer the ILT (OriginalFirstThunk): the IAT is overwritten by the
        # loader at runtime and may already hold resolved addresses.
        thunk_rva = ilt or iat
        funcs: List[Tuple[str, int]] = []
        toff = rva_to_off(thunk_rva)
        if toff is not None:
            slot_rva = iat if iat else thunk_rva
            j = toff
            k = 0
            while j + step <= len(data):
                val = struct.unpack_from(unpack, data, j)[0]
                if val == 0:
                    break
                this_slot = slot_rva + k * step
                k += 1
                if val & ordinal_flag:
                    funcs.append((f"#{val & 0xFFFF}", this_slot))
                else:
                    hint_off = rva_to_off(val & 0x7FFFFFFF)
                    if hint_off is not None and hint_off + 2 < len(data):
                        funcs.append((_cstr(data, hint_off + 2), this_slot))
                j += step
        out.append((dll, funcs))
        i += 20
    return out


def _pe_exports(data: bytes, dd: Tuple[int, int], rva_to_off) -> List[Tuple[str, int]]:
    off = rva_to_off(dd[0])
    if off is None or off + 40 > len(data):
        return []
    (_ch, _ts, _mjr, _mnr, name_rva, ordinal_base, nfuncs, nnames,
     funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", data, off)
    dll = _cstr(data, rva_to_off(name_rva) or 0)
    names: List[Tuple[str, int]] = []
    noff = rva_to_off(names_rva)
    foff = rva_to_off(funcs_rva)
    if noff is None or foff is None:
        return names
    for i in range(nnames):
        try:
            nrv = struct.unpack_from("<I", data, noff + i * 4)[0]
            ordv = struct.unpack_from("<H", data, rva_to_off(ords_rva) + i * 2)[0]
        except (struct.error, TypeError):
            break
        fname = _cstr(data, rva_to_off(nrv) or 0)
        try:
            frva = struct.unpack_from("<I", data, foff + ordv * 4)[0]
        except struct.error:
            break
        if frva and fname:
            names.append((f"{dll}!{fname}" if dll else fname, frva))
    return names


# --------------------------------------------------------------------------
# Mach-O
# --------------------------------------------------------------------------


def parse_macho(path: str) -> BinaryInfo:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] in MACHO_FAT_MAGICS:
        raise ParseError(
            f"{path}: Mach-O universal (FAT) binary -- contains several "
            "slices. Extract one slice first, e.g. "
            "`lipo -thin <arch> -output out.bin input`.")
    if data[:4] not in MACHO_MAGICS:
        raise ParseError(f"{path}: not a Mach-O file")

    endian, bits = MACHO_MAGICS[data[:4]]
    end = "<" if endian == "little" else ">"
    info = BinaryInfo(path=path, fmt="Mach-O", bits=bits, endian=endian)
    if bits == 64:
        (magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags,
         _res) = struct.unpack_from(end + "IiiIIIII", data, 0)
    else:
        (magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags) = \
            struct.unpack_from(end + "IiiIIII", data, 0)

    cpu = cputype & 0xFFFFFFFF
    info.arch = MACHO_CPUS.get(cpu, MACHO_CPUS.get(cputype, f"cpu 0x{cpu:x}"))
    info.extra["filetype"] = MACHO_FILETYPES.get(filetype, f"{filetype}")
    info.extra["flags"] = f"0x{flags:x}"
    info.is_pie = filetype in (2, 6)  # MH_EXECUTE / MH_DYLIB are PIE

    off = 32 if bits == 64 else 28
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", data, off)
        name = MACHO_LOAD_CMD_NAMES.get(cmd, f"LC_0x{cmd:x}")
        if cmdsize == 0:
            break
        if cmd in (0x1, 0x19) and off + 56 <= len(data):  # LC_SEGMENT(_64)
            segname = data[off + 8:off + 24].rstrip(b"\x00").decode("utf-8", "replace")
            if cmd == 0x19:
                # segment_command_64: nsects at offset 64, sections follow at 72
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    end + "QQQQ", data, off + 24)
                nsects = struct.unpack_from(end + "I", data, off + 64)[0] \
                    if off + 68 <= len(data) else 0
                sec_off = off + 72
                sec_sz = 80
            else:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    end + "IIII", data, off + 24)
                nsects = struct.unpack_from(end + "I", data, off + 48)[0]
                sec_off = off + 56
                sec_sz = 68
            info.segments.append(Segment(type=segname, offset=fileoff, vaddr=vmaddr,
                                         filesz=filesize, memsz=vmsize))
            for i in range(nsects):
                sb = sec_off + i * sec_sz
                if sb + sec_sz > len(data):
                    break
                sname = data[sb:sb + 16].rstrip(b"\x00").decode("utf-8", "replace")
                if cmd == 0x19:
                    # section_64: addr@32 size@40 offset@48 align@52
                    # reloff@56 nreloc@60 flags@64
                    saddr, ssize, soff = struct.unpack_from(end + "QQI", data, sb + 32)
                    sflags = struct.unpack_from(end + "I", data, sb + 64)[0]
                else:
                    saddr, ssize, soff = struct.unpack_from(end + "III", data, sb + 32)
                    sflags = struct.unpack_from(end + "I", data, sb + 56)[0]
                info.sections.append(Section(
                    name=f"{segname},{sname}", addr=saddr, offset=soff,
                    size=ssize, type="SHT_PROGBITS", flags=sflags,
                    entropy=_entropy(data[soff:soff + min(ssize, 1 << 20)])
                    if ssize and soff + ssize <= len(data) else None))
        elif cmd in (0xC, 0xD, 0x8000001C, 0x18, 0x1F, 0x20) and off + 24 <= len(data):
            name_off = struct.unpack_from(end + "I", data, off + 8)[0]
            info.needed.append(_cstr(data, off + name_off))
        elif cmd == 0x2 and off + 24 <= len(data):  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from(end + "IIII", data, off + 8)
            step = 16 if bits == 64 else 12
            nlist_fmt = end + ("IBBHQ" if bits == 64 else "IBBhI")
            for i in range(nsyms):
                p = symoff + i * step
                if p + step > len(data):
                    break
                _n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                    nlist_fmt, data, p)
                if n_type & 0xE0:  # N_STAB debugging entry
                    continue
                # Symbol kind lives in n_desc & N_TYPE, not in n_type
                # (n_type is N_SECT / N_UNDF / N_ABS ...).
                nkind = n_desc & 0x0E
                fname = _cstr(data, stroff + _n_strx).lstrip("_")
                if not fname:
                    continue
                info.symbols.append(Symbol(
                    name=fname, value=n_value,
                    type={0: "STT_NOTYPE", 0x2: "STT_OBJECT",
                          0xE: "STT_FUNC", 0xC: "STT_GNU_IFUNC"}
                    .get(nkind, f"0x{nkind:x}"),
                    bind="GLOBAL",
                    shndx=n_sect + 1 if n_type == 0x0E else 0,
                    table="dynsym"))
            info.extra["symtab_strings"] = strsize
        elif cmd == 0x1B and off + 24 <= len(data):  # LC_UUID
            u = data[off + 8:off + 24]
            info.extra["uuid"] = u.hex()
        elif cmd in (0x22, 0x80000022) and off + 48 <= len(data):  # LC_DYLD_INFO
            _tags = struct.unpack_from(end + "10I", data, off + 8)
            info.extra["dyld_info"] = {
                "rebase_off": _tags[0], "rebase_size": _tags[1],
                "bind_off": _tags[2], "bind_size": _tags[3],
                "weak_bind_off": _tags[4], "lazy_bind_off": _tags[6],
            }
        off += cmdsize
    info.stripped = not info.symbols
    return info


# --------------------------------------------------------------------------
# Strings
# --------------------------------------------------------------------------

PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\n\r\x0b\x0c"


def extract_strings(data: bytes, min_len: int = 4,
                    encodings: Sequence[str] = ("ascii", "utf16le"),
                    base: int = 0) -> List[Tuple[int, str, str]]:
    """Return ``(offset + base, text, encoding)`` tuples.

    ``ascii`` collects runs of printable bytes; ``utf16le``/``utf16be`` collect
    ASCII-range code units stored as 16-bit values, which is what Windows and
    many engines use for wide strings. Offsets are byte offsets into ``data``.
    """
    out: List[Tuple[int, str, str]] = []
    printable = bytes(PRINTABLE)

    for enc in encodings:
        if enc == "ascii":
            run = bytearray()
            start = 0
            for i, b in enumerate(data):
                if b in printable:
                    if not run:
                        start = i
                    run.append(b)
                else:
                    if len(run) >= min_len:
                        out.append((base + start, run.decode("ascii"), "ascii"))
                    run = bytearray()
            if len(run) >= min_len:
                out.append((base + start, run.decode("ascii"), "ascii"))
        elif enc in ("utf16le", "utf16be"):
            start = 0
            run_chars: List[str] = []
            i = 0
            limit = len(data) - 1
            while i <= limit:
                lo, hi = (data[i], data[i + 1]) if enc == "utf16le" \
                    else (data[i + 1], data[i])
                if hi == 0 and 0x20 <= lo < 0x7F:
                    if not run_chars:
                        start = i
                    run_chars.append(chr(lo))
                else:
                    if len(run_chars) >= min_len:
                        out.append((base + start, "".join(run_chars), enc))
                    run_chars = []
                i += 2
            if len(run_chars) >= min_len:
                out.append((base + start, "".join(run_chars), enc))

    out.sort(key=lambda t: (t[0], t[2]))
    return out


# --------------------------------------------------------------------------
# Tiny disassembly helpers (enough for reference-finding heuristics)
# --------------------------------------------------------------------------

def arm64_target(pc: int, insn: int) -> Optional[int]:
    """Return the branch target encoded in an AArch64 branch instruction.

    Covers B/BL (imm26, word-scaled) and B.cond/CBZ/CBNZ/TBZ/TBNZ
    (imm19, scaled by 4/2). Returns None for non-branches.
    """
    if (insn >> 26) & 0x3F in (0b000101, 0b100101):  # B / BL
        imm = insn & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return pc + (imm << 2)
    # Exact bit-field tests (see ARM Architecture Reference Manual):
    #   B.cond : 0101010  imm19  0 cond        bits 31..25, bit 4 == 0
    #   CBZ    : sf       011010  op imm19 Rt   bits 30..25
    #   TBZ    : b5       011011  op imm14 b40  bits 30..25
    if (insn >> 25) & 0x7F == 0b0101010 and not (insn >> 4) & 1:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        return pc + (imm19 << 2)
    if (insn >> 25) & 0x3F == 0b011010:            # CBZ / CBNZ
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        return pc + (imm19 << 2)
    if (insn >> 25) & 0x3F == 0b011011:            # TBZ / TBNZ
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & 0x2000:
            imm14 -= 0x4000
        return pc + (imm14 << 2)
    return None


# --------------------------------------------------------------------------
# Misc helpers
# --------------------------------------------------------------------------


def hash_file(path: str, algo: str = "sha256") -> str:
    import hashlib
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_symbol(info: BinaryInfo, name: str) -> Optional[int]:
    """Return the static address of ``name``, or None if it is not defined."""
    for s in info.symbols:
        if s.name == name and not s.is_undefined:
            return s.value
    return None


def eprint(*a) -> None:
    print(*a, file=sys.stderr)