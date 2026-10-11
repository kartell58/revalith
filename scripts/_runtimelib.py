"""
_runtimelib.py -- shared library for memory and runtime intelligence.

The hard part of runtime analysis is not reading /proc or calling a debugger.
It is that a runtime observation and a static observation live in different
address spaces, and joining them wrongly produces a confident, wrong answer.
This module exists to make that join explicit and to refuse it when it cannot
be made safely.

Three rules run through everything here.

**Address translation is not arithmetic.** ``runtime - module_base`` is not a
file offset. A module maps at several file offsets, ASLR moves it, and the
segment table decides the rest. :func:`normalize_address` walks PT_LOAD and
returns ``unresolved`` with a reason when it cannot, rather than a plausible
number.

**Classification needs a basis.** An anonymous read-write region is not a
heap. It becomes one only with a basis -- a kernel hint, a name, or an
observed growth pattern -- and the basis travels with the claim.

**Correlation is not causation.** Two events near each other in time are not
one causing the other: another thread, a callback, a signal or a shared write
can be responsible. Causality requires a controlled experiment, and this module
never emits it on inference alone.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

CONFIDENCES = ["very low", "low", "medium", "high", "very high"]
CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}

# How a claim was reached. A claim without one of these is not reportable.
BASES = [
    "observed",     # directly read from the kernel, a file, or a trace
    "inferred",     # a reading consistent with observations
    "hypothesized", # a proposal, not yet tested
    "unknown",      # not determinable from what is available
]

EVENT_TYPES = [
    "memory_write", "memory_read", "call", "return", "syscall",
    "thread_create", "thread_exit", "module_load", "module_unload",
    "alloc", "free", "signal", "exception", "packet", "file_op", "ui_event",
]

MEMORY_EVENTS = ("memory_write", "memory_read", "alloc", "free")

# Which basis a region classification may claim, best first.
REGION_BASES = [
    "kernel_named",     # the kernel labelled it: [heap], [stack], [vdso]
    "kernel_hint",      # VmFlags in smaps says so: mg, gd, lo, df
    "file_backed",      # a path and a non-zero inode
    "observed_growth",  # it grew between two samples
    "inferred",         # consistent with a class, nothing more
    "unknown",
]

# Anonymous executable memory is observed; calling it JIT is a reading.
EXEC_ANON_BASIS_NOTE = (
    "an anonymous executable mapping. Observed: exec + no file. Inferred: "
    "code generated at runtime (JIT, unpacker, patcher). Nothing observed "
    "here distinguishes those.")

# Permission transitions worth correlating. A protection change is a fact; a
# reason for it is a hypothesis.
PROTECTION_EVENTS = ("mprotect", "pkey_mprotect", "mmap", "munmap", "mremap")

# Syscalls that carry the most structural weight on Linux.
STRUCTURAL_SYSCALLS = {
    "mmap", "mmap2", "munmap", "mremap", "mprotect", "brk", "sbrk",
    "clone", "clone3", "fork", "vfork", "execve", "execveat",
    "futex", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
    "ioctl", "openat", "read", "write", "connect", "sendto", "recvfrom",
    "socket", "bind", "listen", "accept", "accept4", "kill", "tgkill",
    "rt_sigaction", "rt_sigprocmask", "exit", "exit_group",
}

SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
    6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
    11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM",
    15: "SIGTERM", 16: "SIGSTKFLT", 17: "SIGCHLD", 18: "SIGCONT",
    19: "SIGSTOP", 20: "SIGTSTP", 21: "SIGTTIN", 22: "SIGTTOU",
    23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ", 26: "SIGVTALRM",
    27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR",
    31: "SIGSYS",
}


# --------------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------------

def parse_perms(perms: str) -> Dict[str, bool]:
    """Expand ``r-xp`` into readable/writable/executable/shared/private."""
    p = perms or ""
    return {
        "read": len(p) > 0 and p[0] == "r",
        "write": len(p) > 1 and p[1] == "w",
        "exec": len(p) > 2 and p[2] == "x",
        "shared": len(p) > 3 and p[3] == "s",
        "private": len(p) > 3 and p[3] == "p",
    }


def perms_summary(perms: str) -> str:
    """``rwxsp`` form, for compact reporting."""
    f = parse_perms(perms)
    return ("r" if f["read"] else "-") + ("w" if f["write"] else "-") + \
        ("x" if f["exec"] else "-") + ("s" if f["shared"] else
                                      ("p" if f["private"] else "-"))


def is_anonymous(path: str, inode: int) -> bool:
    """Anonymous means no file backs it, which is a stronger claim than
    'no path shown' -- an inotify or deleted file also shows no path."""
    return (not path or path.startswith("[") or path.endswith("(deleted)")) \
        and not inode


# --------------------------------------------------------------------------
# Regions
# --------------------------------------------------------------------------

@dataclass
class Region:
    start: int
    end: int
    perms: str
    offset: int = 0
    dev: str = ""
    inode: int = 0
    pathname: str = ""
    vmflags: Optional[str] = None      # only when smaps is available
    growth: Optional[int] = None       # bytes of growth between two samples
    classification: str = "unknown"
    basis: str = "unknown"
    basis_detail: str = ""
    confidence: str = "very low"
    notes: List[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def anonymous(self) -> bool:
        return is_anonymous(self.pathname, self.inode)

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def to_dict(self) -> Dict:
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "size": self.size,
            "perms": self.perms,
            "permissions": perms_summary(self.perms),
            "file_offset": f"0x{self.offset:x}",
            "pathname": self.pathname or None,
            "inode": self.inode or None,
            "anonymous": self.anonymous,
            "vmflags": self.vmflags,
            "growth_bytes": self.growth,
            "classification": self.classification,
            "basis": self.basis,
            "basis_detail": self.basis_detail or None,
            "confidence": self.confidence,
            "notes": self.notes or None,
        }


MAPS_LINE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+"
    r"([rwxps-]{4})\s+"
    r"([0-9a-fA-F]+)\s+"
    r"(\S+)\s+"
    r"(\d+)\s*"
    r"(.*)$")


def parse_maps(text: str) -> List[Region]:
    """Parse ``/proc/<pid>/maps`` content.

    Malformed lines are skipped and counted rather than raising: a truncated
    read of a live process's maps is normal, and aborting loses everything
    that did parse.
    """
    out: List[Region] = []
    for line in (text or "").splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = MAPS_LINE.match(line)
        if not m:
            continue
        start, end, perms, off, dev, inode, path = m.groups()
        try:
            out.append(Region(
                start=int(start, 16), end=int(end, 16), perms=perms,
                offset=int(off, 16), dev=dev, inode=int(inode),
                pathname=path.strip()))
        except ValueError:
            continue
    return out


VMFLAGS_LINE = re.compile(r"^VmFlags:\s*(.*)$")


def parse_smaps_vmflags(text: str) -> Dict[int, str]:
    """Extract VmFlags per region from ``smaps``.

    VmFlags is the kernel's own account of what a region is for: ``mg`` means
    the region may be used for malloc, ``gd`` that it grows down. That is
    evidence, and it is the difference between calling a region a heap and
    guessing that a writable anonymous region is one.
    """
    out: Dict[int, str] = {}
    for line in (text or "").splitlines():
        m = MAPS_LINE.match(line.rstrip())
        if m:
            try:
                cur = int(m.group(1), 16)
            except ValueError:
                cur = None
            continue
        mf = VMFLAGS_LINE.match(line.strip())
        if mf and cur is not None:
            out[cur] = mf.group(1).strip()
    return out


def apply_vmflags(regions: List[Region], vmflags: Dict[int, str]) -> List[Region]:
    for r in regions:
        if r.start in vmflags:
            r.vmflags = vmflags[r.start]
    return regions


# --------------------------------------------------------------------------
# Region classification
# --------------------------------------------------------------------------

def classify_region(r: Region) -> None:
    """Assign classification, basis and confidence to a region.

    The order matters and encodes the discipline: a kernel name or hint
    outranks a file backing, which outranks an observed growth, which outranks
    a resemblance. Nothing reaches ``heap`` on resemblance alone.
    """
    name = r.pathname
    flags = r.vmflags or ""

    # 1. The kernel named it. Strongest available basis.
    if name == "[heap]":
        r.classification = "heap (main arena)"
        r.basis = "kernel_named"
        r.basis_detail = "the kernel labelled this region [heap]"
        r.confidence = "high"
        return
    if name.startswith("[stack"):
        r.classification = "stack"
        r.basis = "kernel_named"
        r.basis_detail = f"the kernel labelled this region {name}"
        r.confidence = "high"
        return
    if name in ("[vdso]", "[vvar]", "[vsyscall]"):
        r.classification = f"kernel special region ({name})"
        r.basis = "kernel_named"
        r.basis_detail = "named by the kernel"
        r.confidence = "high"
        return
    if name.startswith("/dev/ashmem") or name.startswith("/dev/dri"):
        r.classification = "graphics/ashmem mapping"
        r.basis = "kernel_named"
        r.basis_detail = f"device-backed path {name}"
        r.confidence = "high"
        return

    # 2. A kernel hint from smaps.
    if flags:
        hints = set(flags.split())
        if "mg" in hints:
            r.classification = "malloc-eligible region"
            r.basis = "kernel_hint"
            r.basis_detail = ("VmFlags contains mg: the kernel records that "
                              "this region may be used for malloc")
            r.confidence = "high"
            if r.anonymous:
                r.notes.append("mg does not prove the region is currently "
                               "handing out allocations, only that it may")
            return
        if "gd" in hints:
            r.classification = "stack"
            r.basis = "kernel_hint"
            r.basis_detail = ("VmFlags contains gd: the kernel records this "
                              "region grows down")
            r.confidence = "high"
            return
        if "lo" in hints:
            r.classification = "locked allocation"
            r.basis = "kernel_hint"
            r.basis_detail = ("VmFlags contains lo: the kernel records this "
                              "region as locked (mlock)")
            r.confidence = "medium"
            return

    # 3. File backed.
    if not r.anonymous:
        r.classification = "file-backed mapping"
        r.basis = "file_backed"
        r.basis_detail = f"inode {r.inode}, offset 0x{r.offset:x}" \
            if r.inode else "a path is present"
        r.confidence = "high"
        return

    # 4. Observed growth between samples.
    if r.growth:
        if r.growth > 0 and parse_perms(r.perms)["write"]:
            r.classification = "growing anonymous region (heap-like)"
            r.basis = "observed_growth"
            r.basis_detail = (f"grew by {r.growth} bytes between samples; "
                              f"growth is characteristic of a heap or a "
                              f"stack, and this region is not marked gd")
            r.confidence = "medium"
            r.notes.append("growth does not distinguish a heap from any other "
                           "growing writable arena")
            return

    # 5. Anonymous executable.
    if r.anonymous and parse_perms(r.perms)["exec"]:
        r.classification = "anonymous executable mapping"
        r.basis = "observed"
        r.basis_detail = EXEC_ANON_BASIS_NOTE
        r.confidence = "medium"
        r.notes.append("not distinguished from a JIT region, an unpacked "
                       "code region or a runtime patch until something "
                       "writes or executes code there")
        return

    # 6. Everything else anonymous stays unknown.
    if r.anonymous:
        r.classification = "anonymous mapping"
        r.basis = "unknown"
        r.basis_detail = ("no path, no inode, and no kernel hint. It is not "
                          "established whether this is heap, a stack, a "
                          "thread-local block, an arena or something else")
        r.confidence = "very low"
        return

    r.classification = "mapping"
    r.basis = "observed"
    r.basis_detail = "read from the kernel"
    r.confidence = "high"


def classify_regions(regions: List[Region]) -> List[Region]:
    for r in regions:
        classify_region(r)
    return regions


# --------------------------------------------------------------------------
# Modules
# --------------------------------------------------------------------------

@dataclass
class Module:
    name: str
    base: int = 0
    end: int = 0
    paths: List[str] = field(default_factory=list)
    regions: List[Region] = field(default_factory=list)
    load_bias: Optional[int] = None
    bias_basis: str = "unknown"
    bias_warnings: List[str] = field(default_factory=list)
    # Filled by correlate_static when a binary on disk is available.
    binary_info: Any = None
    segments: List[Dict] = field(default_factory=list)
    # file offset -> (p_vaddr - p_offset), per PT_LOAD. Filled by Resolver so
    # load-bias derivation can anchor mappings whose vaddr and offset differ.
    segment_offsets: Dict[int, int] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.end - self.base

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end

    def relative(self, addr: int) -> int:
        return addr - self.base

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "base": f"0x{self.base:x}",
            "end": f"0x{self.end:x}",
            "size": self.size,
            "paths": sorted(set(self.paths)),
            "load_bias": f"0x{self.load_bias:x}"
            if self.load_bias is not None else None,
            "load_bias_basis": self.bias_basis,
            "load_bias_warnings": self.bias_warnings or None,
            "region_count": len(self.regions),
            "executable": any(parse_perms(r.perms)["exec"] for r in
                              self.regions),
        }


def build_modules(regions: List[Region]) -> List[Module]:
    """Group file-backed regions into modules.

    A module is identified by its file, not by adjacency: a library maps at
    several non-contiguous file offsets and those are one module. Grouping by
    address range alone would split every library into several.
    """
    groups: Dict[Tuple[str, int], List[Region]] = defaultdict(list)
    for r in regions:
        if r.anonymous:
            continue
        path = r.pathname or ""
        # ' (deleted)' suffixes mean the file was unlinked while mapped; the
        # module still exists, so keep it and record the fact.
        groups[(path, r.inode)].append(r)

    modules: List[Module] = []
    for (path, inode), regs in groups.items():
        regs.sort(key=lambda x: x.start)
        name = os.path.basename(path.split(" (deleted)")[0]) or path
        m = Module(name=name, base=regs[0].start, end=regs[-1].end,
                   paths=[path], regions=regs)
        if path.endswith("(deleted)"):
            m.bias_warnings.append(
                "the file was deleted while mapped; the on-disk contents may "
                "not match the mapping")
        modules.append(m)

    modules.sort(key=lambda m: m.base)
    return modules


def _align_down(value: int, page_size: int) -> int:
    return value - (value % page_size) if page_size else value


def load_segments(info) -> List:
    """The PT_LOAD segments of a parsed ELF, or nothing."""
    if info is None or getattr(info, "fmt", None) != "ELF":
        return []
    return [s for s in info.segments if s.type == "LOAD"]


def segment_for_file_offset(info, file_off: int):
    """The PT_LOAD whose file bytes include ``file_off``.

    A file-backed segment wins over a memsz-only match: when a mapping
    overlaps the file-backed part and the zero-fill part of one segment, the
    bytes at that offset are in the file.
    """
    memsz_only = None
    for seg in load_segments(info):
        size = seg.filesz or seg.memsz
        if not size or not (seg.offset <= file_off < seg.offset + size):
            continue
        if seg.filesz and file_off < seg.offset + seg.filesz:
            return seg
        if memsz_only is None:
            memsz_only = seg
    return memsz_only


def segment_for_mapping(info, file_off: int, page_size: int):
    """Which PT_LOAD a mapping at this file offset belongs to.

    Maps record page-granular file offsets while PT_LOAD offsets need not be
    page-aligned, so equality fails on most real binaries. Matching on the
    page range the segment's bytes occupy is what actually works, and it is
    why several mappings of one library can all report file offset 0.
    """
    lo = _align_down(file_off, page_size)
    best = None
    for seg in load_segments(info):
        size = max(seg.memsz, seg.filesz) or 1
        start = _align_down(seg.offset, page_size)
        end = _align_down(seg.offset + size - 1, page_size)
        if start <= lo <= end:
            if best is None or seg.offset < best.offset:
                best = seg
    return best


def derive_load_bias(m: Module, page_size: int = 4096) -> Dict:
    """Compute a module's load bias and, more importantly, its basis.

    For a mapping that starts at ``S`` and holds file bytes from offset ``O``,
    and the PT_LOAD segment that owns those bytes, the kernel placed that
    segment at ``S + (O - seg.offset)``. So the bias is
    ``S - seg.vaddr + seg.offset - O``.

    The common shortcut -- ``start - file_offset`` -- drops the segment term
    and is correct only when the first PT_LOAD has ``p_vaddr == p_offset``.
    That holds for many PIE binaries, which is why the shortcut survives, and
    it fails for every binary whose segments carry different vaddr/offset
    skews. A library with three segments at skews 0, 0x4000 and 0x8000 yields
    three different "biases" from the shortcut, and the code goes on to
    translate data-section addresses as if they were code.

    That is why the bias is a cross-check here, not the primary path.
    :meth:`Resolver.normalize` derives each address from the file offset and
    the segment table, and uses the bias only to confirm the two agree.

    Basis values: ``maps`` (anchored, agreeing), ``maps_partial`` (anchored,
    disagreeing), ``maps_unanchored`` (no binary, so the shortcut was used),
    ``unmatched`` (binary available, no mapping matched a segment) and
    ``unknown`` (no file-backed region at all).
    """
    info = m.binary_info
    segments = load_segments(info)
    candidates: List[Tuple[int, int, str]] = []
    unmatched: List[Tuple[int, int, str]] = []

    for r in m.regions:
        if segments:
            seg = segment_for_mapping(info, r.offset, page_size)
            if seg is None:
                unmatched.append((r.start, r.offset, r.pathname))
                continue
            candidates.append((r.start - seg.vaddr + seg.offset - r.offset,
                               r.offset, r.pathname))
        else:
            candidates.append((r.start - r.offset, r.offset, r.pathname))

    if not candidates:
        m.load_bias = None
        if unmatched:
            m.bias_basis = "unmatched"
            m.bias_warnings.append(
                "no mapping's file offset falls in any PT_LOAD segment of this "
                "module. The map and the binary disagree about the layout -- a "
                "remapping layer, a patched or replaced file, or a map from a "
                "different build. Translation is refused rather than guessed")
            return {"load_bias": None, "basis": "unmatched", "candidates": [],
                    "unmatched": [{"start": f"0x{s:x}", "offset": f"0x{o:x}",
                                   "path": p} for s, o, p in unmatched]}
        m.bias_basis = "unknown"
        m.bias_warnings.append("no file-backed region: this is an anonymous "
                               "mapping and has no load bias")
        return {"load_bias": None, "basis": "unknown", "candidates": []}

    biases = {c[0] for c in candidates}
    anchor = min(candidates, key=lambda c: c[1])

    if len(biases) == 1:
        m.load_bias = anchor[0]
        if segments:
            m.bias_basis = "maps"
            m.bias_warnings.append(
                f"derived from {len(candidates)} mapping(s) matched to PT_LOAD "
                f"segments; every match agrees on 0x{anchor[0]:x}")
        else:
            m.bias_basis = "maps_unanchored"
            m.bias_warnings.append(
                f"derived as start minus file offset from {len(candidates)} "
                f"mapping(s), all agreeing on 0x{anchor[0]:x}. That form is "
                f"correct only when the first PT_LOAD has p_vaddr == p_offset; "
                f"supply the module's binary to anchor it to the segment table")
    else:
        m.load_bias = anchor[0]
        m.bias_basis = "maps_partial"
        odd = sorted(b - anchor[0] for b in biases if b != anchor[0])
        detail = "matched to PT_LOAD segments" if segments else \
                 "as start minus file offset"
        m.bias_warnings.append(
            f"mappings disagree on the load bias by "
            f"{', '.join(hex(d) for d in odd)} when derived {detail}; the "
            f"anchor is 0x{anchor[0]:x}. Addresses are translated from the "
            f"file offset and the segment table, and this bias is used only to "
            f"check them, so a disagreement here is reported rather than "
            f"propagated")

    if unmatched:
        m.bias_warnings.append(
            f"{len(unmatched)} mapping(s) fell outside every PT_LOAD segment "
            f"and were excluded from the bias")
    return {"load_bias": m.load_bias, "basis": m.bias_basis,
            "candidates": [{"bias": f"0x{b:x}", "offset": f"0x{o:x}",
                            "path": p} for b, o, p in candidates]}


# --------------------------------------------------------------------------
# Address normalization
# --------------------------------------------------------------------------
def _fmt_addr(addr: int) -> str:
    """Format an address without a doubled prefix.

    Callers hand these tools addresses in several shapes: '0x7f1a...' from a
    backtrace, a bare hex '7f1a...' from some tracer output, or a plain
    integer. Echoing whatever the caller typed costs the reader nothing, but
    rendering it as '0x0x...' makes the output harder to paste back into a
    command.
    """
    return f"0x{addr:x}"


def normalize_address_text(value) -> Optional[int]:
    """Parse an address in any of the shapes tracers emit.

    A decimal-looking string is ambiguous between decimal and hex, and
    picking the wrong one is silent: the result is a real address, in the
    wrong module, and everything downstream agrees with the mistake. So the
    rule is explicit -- 0x-prefixed is hex, bare hex digits are hex (which is
    what a maps line and most tracers print), anything else is decimal.
    """
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        pass
    if all(c in "0123456789abcdefABCDEF" for c in text):
        try:
            return int(text, 16)
        except ValueError:
            pass
    try:
        return int(text, 10)
    except ValueError:
        return None



class Resolver:
    """Joins runtime addresses to static ones, or explains why it cannot.

    A resolver is built from a memory map, the modules in it, and optionally
    the parsed binary for each module. It never guesses: every translation
    carries a status and, when it fails, the reason.
    """

    def __init__(self, regions: List[Region],
                 modules: Optional[List[Module]] = None,
                 binaries: Optional[Dict[str, Any]] = None,
                 page_size: int = 4096):
        self.regions = regions
        self.modules = modules if modules is not None else build_modules(regions)
        self.binaries = binaries or {}
        self.page_size = page_size
        for m in self.modules:
            if m.name in self.binaries:
                m.binary_info = self.binaries[m.name]
            derive_load_bias(m, page_size)

    # -- lookups ---------------------------------------------------------
    def region_for(self, addr: int) -> Optional[Region]:
        for r in self.regions:
            if r.contains(addr):
                return r
        return None

    def module_for(self, addr: int) -> Optional[Module]:
        for m in self.modules:
            if m.contains(addr):
                return m
        return None

    def normalize_text(self, value) -> Dict:
        """Normalise an address given as text, in any common shape.

        Tracers, backtraces and debugger output all print addresses
        differently. Parsing them explicitly matters: reading a decimal value
        as hex produces a real address in the wrong module, and every later
        step then agrees with the mistake.
        """
        addr = normalize_address_text(value)
        if addr is None:
            return {
                "runtime_address": str(value),
                "status": "unparseable",
                "basis": "unknown",
                "warnings": [f"could not read {value!r} as an address; accepted "
                             f"forms are 0x-prefixed hex, bare hex, and decimal"],
            }
        out = self.normalize(addr)
        out["runtime_address"] = str(value)
        out["runtime_address_canonical"] = _fmt_addr(addr)
        return out

    def normalize(self, addr: int) -> Dict:
        """Translate one runtime address through every space we can.

        The result always has a ``status``. ``ok`` means every space was
        determined. Anything else says which step failed, because a partial
        translation presented as a whole one is how an investigation ends up
        reading the wrong bytes.
        """
        out: Dict[str, Any] = {
            "runtime_address": _fmt_addr(addr),
            "status": "unresolved",
            "module": None, "module_relative": None, "elf_vaddr": None,
            "file_offset": None, "section": None, "symbol": None,
            "region": None, "warnings": [],
        }
        region = self.region_for(addr)
        if region is None:
            out["warnings"].append(
                "the address is in no region of the sampled memory map; the "
                "map may be stale, or the region was created afterwards")
            out["basis"] = "observed"
            return out

        out["region"] = {
            "start": f"0x{region.start:x}", "perms": region.perms,
            "classification": region.classification, "basis": region.basis,
            "pathname": region.pathname or None,
        }
        out["basis"] = "observed"

        m = self.module_for(addr)
        if m is None:
            out["warnings"].append(
                "no file-backed module contains this address; it is in an "
                "anonymous or special region, so there is no file offset and "
                "no module-relative address to report")
            if region.classification == "anonymous executable mapping":
                out["warnings"].append(EXEC_ANON_BASIS_NOTE)
            return out

        out["module"] = m.name
        out["module_relative"] = f"0x{m.relative(addr):x}"

        info = m.binary_info
        if info is None:
            # Without the binary there is no segment table, so no virtual
            # address can be derived from the file offset. A load bias may
            # still exist, and it is reported as the unanchored derivation it
            # is rather than as a file offset.
            if m.load_bias is None:
                out["warnings"].append(
                    "no parsed binary for this module and no derivable load "
                    "bias, so no virtual address can be recovered")
                out["warnings"].extend(m.bias_warnings)
                return out
            out["elf_vaddr"] = f"0x{addr - m.load_bias:x}"
            out["load_bias"] = f"0x{m.load_bias:x}"
            out["load_bias_basis"] = m.bias_basis
            out["warnings"].append(
                f"no parsed binary for {m.name}; the module-relative address "
                f"is established and a load bias was derived, but the file "
                f"offset needs the segment table and is not reported")
            out["warnings"].extend(m.bias_warnings)
            out["status"] = "partial"
            out["confidence"] = "high"
            return out

        if info.fmt != "ELF":
            # PE and Mach-O use different translation rules; reporting an ELF
            # offset for them would be wrong.
            if info.fmt == "PE":
                out["rva"] = f"0x{addr - (info.imagebase or 0):x}"
                out["warnings"].append(
                    "PE: the RVA above uses the image base from the parsed "
                    "headers; verify it against the process's actual preferred "
                    "base before trusting it")
            elif info.fmt == "Mach-O":
                out["slide"] = f"0x{addr - (info.imagebase or m.base):x}"
                out["warnings"].append(
                    "Mach-O: translated through the image base as a slide; a "
                    "universal binary must be sliced first")
            out["status"] = "partial"
            out["confidence"] = "medium"
            return out

        # ELF. The primary path derives the virtual address from the file
        # offset and the segment table, which needs no bias and so cannot be
        # wrong because of one. The bias, when there is one, is only a check.
        seg = None
        vaddr = None
        file_off = None
        derived_bias = None
        via_offset = False

        if not region.anonymous:
            file_off = region.offset + (addr - region.start)
            seg = segment_for_file_offset(info, file_off)
            if seg is not None:
                vaddr = seg.vaddr + (file_off - seg.offset)
                derived_bias = addr - vaddr
                via_offset = True

        if vaddr is None:
            # No usable file offset. Two causes, told apart because they mean
            # different things: a region with no file behind it at all, or a
            # file offset no segment's file bytes cover -- which is exactly
            # what the zero-filled tail of a segment looks like.
            if m.load_bias is None:
                out["warnings"].append(
                    "no load bias could be derived and no file offset was "
                    "available, so the segment that owns this address cannot "
                    "be identified")
                out["warnings"].extend(m.bias_warnings)
                return out
            if region.anonymous:
                reason = ("the containing region carries no file, so the "
                          "virtual address came from the load bias rather "
                          "than from the file offset")
            else:
                reason = (f"file offset {_fmt_addr(file_off)} falls past every "
                          f"segment's file size, so these bytes exist only in "
                          f"memory and the virtual address came from the load "
                          f"bias instead")
            vaddr = addr - m.load_bias
            derived_bias = addr - vaddr
            seg = self._segment_for(info, vaddr)
            out["basis"] = "inferred"
            out["warnings"].append(
                f"{reason}. That is how the zero-filled tail of a segment is "
                f"normally laid out, and it is a weaker derivation than the "
                f"file-offset path, so it is reported as one")

        out["elf_vaddr"] = f"0x{vaddr:x}"
        out["load_bias"] = f"0x{derived_bias:x}"
        out["load_bias_basis"] = "file_offset" if via_offset else "bias_only"
        if m.load_bias is not None:
            out["module_load_bias"] = f"0x{m.load_bias:x}"
            out["module_load_bias_basis"] = m.bias_basis
            out["bias_agrees"] = (derived_bias == m.load_bias)
            if derived_bias != m.load_bias:
                out["warnings"].append(
                    f"this address implies a load bias of 0x{derived_bias:x} "
                    f"while the module's own mappings imply 0x{m.load_bias:x}. "
                    f"The translation above came from the file offset and the "
                    f"segment table, so it stands on its own, but the map and "
                    f"the binary disagree about this module")
        out["warnings"].extend(m.bias_warnings)

        if seg is None:
            where = _fmt_addr(file_off) if file_off is not None else "this address"
            out["warnings"].append(
                f"{where} falls in no PT_LOAD segment of {m.name}; the bytes "
                f"there are not described by this binary")
            out["status"] = "partial"
            out["confidence"] = "medium"
            return out

        out["segment"] = {"type": seg.type, "offset": f"0x{seg.offset:x}",
                          "filesz": seg.filesz, "memsz": seg.memsz}

        if seg.filesz and vaddr >= seg.vaddr + seg.filesz:
            # .bss and friends: real memory, no bytes in the file.
            out["status"] = "partial"
            out["confidence"] = "high"
            out["bss_offset"] = f"0x{vaddr - seg.vaddr:x}"
            # The symbol lookup belongs here as much as in the file-backed
            # case: this is where variables live, and it is exactly the
            # address whose name the investigation came looking for.
            sym = self._symbol_for(info, vaddr)
            if sym:
                out["symbol"] = sym
            sec = info.section_for(vaddr)
            if sec is not None:
                out["section"] = sec.name
                out["section_offset"] = f"0x{vaddr - sec.addr:x}"
            out["warnings"].append(
                "this address is beyond the segment's file size, so it is in "
                "a zero-filled or runtime-filled region (.bss or similar). "
                "There is no file offset: the bytes exist only in memory")
            return out

        if not via_offset:
            out["status"] = "partial"
            out["confidence"] = "medium"
            out["warnings"].append(
                "no file offset could be derived, because the containing "
                "region carries no file")
            return out

        out["file_offset"] = f"0x{file_off:x}"
        sec = info.section_for(vaddr)
        if sec is not None:
            out["section"] = sec.name
            out["section_offset"] = f"0x{vaddr - sec.addr:x}"
        sym = self._symbol_for(info, vaddr)
        if sym:
            out["symbol"] = sym
        out["status"] = "ok"
        out["confidence"] = "high"
        return out

    @staticmethod
    def _segment_for(info, vaddr: int):
        """The PT_LOAD segment containing vaddr, preferring file-backed range."""
        candidates = []
        for seg in info.segments:
            if seg.type not in ("LOAD", "PT_LOAD", "1"):
                continue
            size = seg.memsz or seg.filesz
            if size and seg.vaddr <= vaddr < seg.vaddr + size:
                candidates.append(seg)
        if not candidates:
            return None
        # When segments overlap in address space (common when a segment's
        # memsz is rounded up), prefer the one whose file range covers it.
        for seg in candidates:
            if seg.filesz and seg.vaddr <= vaddr < seg.vaddr + seg.filesz:
                return seg
        return candidates[0]

    @staticmethod
    def _symbol_for(info, vaddr: int) -> Optional[str]:
        """The symbol whose range contains ``vaddr``.

        Two things keep this from being a guess.

        A size check: without it an address in the padding between two
        functions is attributed to the one below it, which is a guess with a
        symbol's authority.

        Functions first, then data. A runtime address in ``.bss`` names a
        variable, not a function, and reporting nothing for it loses the most
        useful symbol on the record.

        Symbols without a recorded size cover one byte only. That is
        conservative in the right direction: an address past the first byte is
        reported as unnamed rather than attributed to a symbol whose extent is
        unknown.
        """
        func = None
        data = None
        for s in info.symbols:
            if s.is_undefined or not s.value:
                continue
            if not (s.value <= vaddr < s.value + (s.size or 1)):
                continue
            if s.is_func:
                if func is None or s.value > func.value:
                    func = s
            elif data is None or s.value > data.value:
                data = s
        hit = func or data
        if hit is None:
            return None
        return hit.name if hit.is_func else f"{hit.name} (data)"


# --------------------------------------------------------------------------
# Event schema
# --------------------------------------------------------------------------

EVENT_REQUIRED = {
    "memory_write": ("address",),
    "memory_read": ("address",),
    "alloc": ("address",),
    "free": ("address",),
    "call": ("address",),
    "return": (),
    "syscall": (),
    "thread_create": (),
    "thread_exit": (),
    "module_load": ("module",),
    "module_unload": ("module",),
    "signal": (),
    "exception": (),
    "packet": (),
    "file_op": (),
    "ui_event": (),
}


def make_event(type_: str, **fields) -> Dict:
    """Build a canonical event. Absent fields stay absent, never default."""
    ev: Dict[str, Any] = {"type": type_}
    for k in ("timestamp", "pid", "tid", "thread", "module", "address",
              "offset", "size", "value", "instruction", "caller", "symbol",
              "stack", "evidence", "confidence", "basis", "note", "name"):
        if fields.get(k) not in (None, [], {}):
            ev[k] = fields[k]
    return ev


def validate_event(ev: Dict) -> List[str]:
    """Check one event against the schema and the evidence discipline."""
    problems: List[str] = []
    if not isinstance(ev, dict):
        return ["event is not an object"]

    etype = ev.get("type")
    if not etype:
        problems.append("missing 'type'")
    elif etype not in EVENT_TYPES:
        problems.append(f"type '{etype}' is not one of: "
                        f"{', '.join(EVENT_TYPES)}")
    else:
        for field in EVENT_REQUIRED.get(etype, ()):
            if ev.get(field) in (None, ""):
                problems.append(f"a '{etype}' event requires '{field}'")

    if ev.get("confidence") is not None and \
            ev["confidence"] not in CONFIDENCES:
        problems.append(f"confidence '{ev['confidence']}' is not one of: "
                        f"{', '.join(CONFIDENCES)}")

    if ev.get("basis") is not None and ev["basis"] not in BASES:
        problems.append(f"basis '{ev['basis']}' is not one of: "
                        f"{', '.join(BASES)}")

    # A memory event without a size cannot be read or verified by anyone else.
    if etype in ("memory_write", "memory_read") and ev.get("size") is None:
        problems.append("a memory event must record 'size'; without it the "
                        "observation cannot be reproduced")

    if ev.get("confidence") in ("high", "very high") and not ev.get("evidence"):
        problems.append("high confidence without evidence is an assertion; "
                        "record what was seen")

    # Causality is the specific claim this schema exists to keep honest.
    for causal in ("caused_by", "cause", "root_cause"):
        if causal in ev and not ev.get("experiment"):
            problems.append(
                f"'{causal}' asserts causation from observation alone. Nearness "
                f"in time is not cause: another thread, a callback, a signal "
                f"or a shared write can be responsible. Record the experiment "
                f"that isolates it, or state it as a hypothesis")

    return problems


def validate_events(events: Sequence[Dict], max_report: int = 50) -> Dict:
    report = {"count": len(events), "valid": 0, "problems": [],
              "by_type": {}, "by_thread": {}, "by_module": {}}
    for i, ev in enumerate(events):
        etype = (ev or {}).get("type", "?") if isinstance(ev, dict) else "?"
        report["by_type"][etype] = report["by_type"].get(etype, 0) + 1
        if isinstance(ev, dict):
            t = ev.get("tid") or ev.get("thread")
            if t:
                report["by_thread"][str(t)] = \
                    report["by_thread"].get(str(t), 0) + 1
            if ev.get("module"):
                report["by_module"][ev["module"]] = \
                    report["by_module"].get(ev["module"], 0) + 1
        problems = validate_event(ev)
        if problems:
            for p in problems[:3]:
                report["problems"].append({"index": i, "problem": p})
        else:
            report["valid"] += 1
    report["ok"] = not report["problems"]
    report["problem_count"] = len(report["problems"])
    return report


# --------------------------------------------------------------------------
# Stacks
# --------------------------------------------------------------------------

# Frame formats seen in practice:
#   libfoo.so+0x1400          module-relative, from a backtrace
#   libfoo.so!0x7f1a40001400  module plus absolute address
#   main+0x1c                 symbol plus offset
#   0x7f1a40001400            bare address
#   #0  0x... in func () at f.c:12   gdb output, stripped by parse_stack
FRAME_RE = re.compile(
    r"^(?:(?P<mod>[\w.\-+@]+)[!+])?"          # module, then '!' or '+'
    r"(?:(?P<sym>\w+)@)?"                     # optional symbol@offset
    r"(?P<addr>0x[0-9a-fA-F]+|\+?0x[0-9a-fA-F]+)"
    r"(?:\s*\(.*\))?$")


def parse_stack(text: str) -> List[Dict]:
    """Parse frames of the forms ``libfoo.so!0x1230``, ``main+0x1c``, ``0x7f..``.

    The address is kept as written, because resolving it needs the module map
    and a symbol is only a label until one does.
    """
    frames: List[Dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        # A line beginning with '#' is either a comment or a gdb frame index
        # ('#0', '#12'), so the index is stripped and the rest is parsed as a
        # frame. Treating every '#' line as a comment loses every gdb
        # backtrace, which is the most common source.
        if line.startswith("#") and not re.match(r"^#\d+\s", line):
            continue
        line = re.sub(r"^#\d+\s+", "", line)
        m = FRAME_RE.match(line)
        if not m:
            addr_m = re.search(r"(0x[0-9a-fA-F]+)", line)
            sym_m = re.search(r"\bin\s+(\w+)", line)
            if addr_m:
                frames.append({
                    "module": None, "symbol": sym_m.group(1) if sym_m else None,
                    "address": addr_m.group(1), "depth": len(frames),
                    "raw": line,
                })
            continue
        frames.append({
            "module": m.group("mod"),
            "symbol": m.group("sym"),
            "address": m.group("addr"),
            "depth": len(frames),
        })
    return frames


def normalise_frame(frame: Dict, resolver: Optional[Resolver] = None) -> Dict:
    """Resolve one frame as far as the evidence allows.

    With no symbols and no resolver, ``module+0xoffset`` is the honest form.
    Inventing a name from proximity to a string is not.
    """
    out = dict(frame)
    addr_str = frame.get("address") or ""
    try:
        addr = int(addr_str, 16)
    except ValueError:
        addr = None
    out["normalized"] = None
    if addr is None:
        return out

    if resolver is not None:
        n = resolver.normalize(addr)
        if n.get("module"):
            out["normalized"] = (f"{n['module']}+{n['module_relative']}"
                                 + (f" {n['symbol']}" if n.get("symbol") else ""))
            out["resolution_status"] = n["status"]
            out["file_offset"] = n.get("file_offset")
            out["section"] = n.get("section")
            return out

    if frame.get("module"):
        # module!+0x1230 is a module-relative address from a backtrace.
        rel = addr_str.split("!")[-1] if "!" in addr_str else addr_str
        out["normalized"] = f"{frame['module']}+{rel}"
        return out
    if frame.get("symbol"):
        out["normalized"] = f"{frame['symbol']}@{addr_str}"
        return out
    out["normalized"] = addr_str
    out["resolution_status"] = "unresolved"
    return out


def normalise_stack(frames: Sequence[Dict],
                    resolver: Optional[Resolver] = None) -> List[Dict]:
    return [normalise_frame(f, resolver) for f in frames]


FRAME_SKIP = {
    "libc.so.6!libc_start_main", "libc.so.6!__libc_start_call_main",
    "ld-linux-x86-64.so.2!_start", "ld-linux-aarch64.so.1!_start",
}


def stack_key(frames: Sequence[Dict], skip_known_runtime_prologue: bool = True
              ) -> str:
    """A key for grouping similar stacks.

    The innermost frames are the informative ones, and the process entry
    prologue is identical for every call, so it is dropped: including it
    would make every stack in the process look the same.
    """
    keys = []
    for f in frames:
        norm = f.get("normalized") or f.get("address") or "?"
        if skip_known_runtime_prologue and norm in FRAME_SKIP:
            continue
        keys.append(norm)
    return ";".join(keys) if keys else "<empty>"


def group_stacks(stacks: Sequence[Sequence[Dict]], limit: int = 50,
                 resolver: Optional[Resolver] = None) -> Dict:
    """Group call stacks and rank by frequency.

    A single occurrence is not evidence of importance and a high count is not
    proof of a hot path: both are reported with their counts so the reader can
    judge, and a group of one is labelled a rare path rather than a hot one.
    """
    groups: Dict[str, Dict] = {}
    total = 0
    skipped = 0
    for raw in stacks:
        frames = normalise_stack(raw, resolver) if raw else []
        if not frames:
            # An unparseable line is counted, not silently dropped: a reader
            # who sees 500 stacks read must be able to ask where the other 30
            # went.
            skipped += 1
            continue
        key = stack_key(frames)
        g = groups.get(key)
        if g is None:
            g = {"key": key, "count": 0, "frames": frames, "modules": set()}
            groups[key] = g
        g["count"] += 1
        total += 1
        for f in frames:
            if f.get("module"):
                g["modules"].add(f["module"])

    out = []
    for g in groups.values():
        out.append({
            "key": g["key"],
            "count": g["count"],
            "frequency": round(g["count"] / total, 6) if total else 0.0,
            "depth": len(g["frames"]),
            "modules": sorted(g["modules"]) or None,
            "leaf": g["frames"][0]["normalized"] if g["frames"] else None,
            "frames": [f.get("normalized") for f in g["frames"]],
            "label": ("hot path candidate" if g["count"] >= 10 else
                      ("repeated" if g["count"] > 1 else "rare path (seen once)")),
            "caveat": "frequency is a count of observations, not a measurement "
                      "of execution time; a debugger or a hook changes what "
                      "runs and how often",
        })
    out.sort(key=lambda x: (-x["count"], x["key"]))
    return {
        "total_stacks": total,
        "stacks_skipped": skipped,
        "distinct_stacks": len(groups),
        "groups": out[:limit],
        "note": "a group of one is a rare path worth a look, and a high count "
                "is not by itself a performance problem: both are counts of "
                "what was observed under instrumentation",
        "warning": (f"{skipped} input(s) produced no parseable frames and were "
                    f"skipped" if skipped else None),
    }


# --------------------------------------------------------------------------
# Runtime diff
# --------------------------------------------------------------------------

def diff_runs(a: Sequence[Dict], b: Sequence[Dict],
              keys: Optional[Sequence[str]] = None,
              first_only: bool = False) -> Dict:
    """Compare two event streams and locate the first divergence.

    Timestamps are excluded by default: two runs of the same input will not
    align on wall-clock time, and including it would report a divergence at
    the first event every time.
    """
    # 'value' and 'caller' are in the default set on purpose. A run that
    # performs the same calls with different values has not behaved the same,
    # and a diff that reported those traces as identical would be worse than
    # no diff: it would look like a clean result.
    cmp_keys = list(keys or ("type", "module", "address", "size", "tid",
                             "caller", "value"))
    n = min(len(a), len(b))

    def key_of(ev: Dict) -> tuple:
        return tuple(str(ev.get(k)) if ev.get(k) is not None else None
                     for k in cmp_keys)

    first = None
    kind = "none"
    for i in range(n):
        ka, kb = key_of(a[i]), key_of(b[i])
        if ka == kb:
            continue
        first = i
        # 'event' when the two sides are doing different things, 'field'
        # when they are doing the same thing with different data. The
        # distinction matters because it says whether to look for a missing
        # call or for a changed value.
        same_kind = (a[i].get("type") == b[i].get("type")
                     and a[i].get("module") == b[i].get("module"))
        kind = "field" if same_kind else "event"
        break

    identical = first is None and len(a) == len(b)
    out: Dict[str, Any] = {
        "identical": identical,
        "kind": kind,
        "compared_keys": cmp_keys,
        "keys_excluded": ["timestamp"] if not keys else None,
        "length_a": len(a), "length_b": len(b),
        "first_divergence_index": first,
        "note": "timestamps are excluded from comparison; two runs of the "
                "same input do not align on wall-clock time, so including it "
                "would report a divergence at every event",
    }
    if identical:
        out["divergence"] = None
        return out
    if first is None:
        out["kind"] = "truncation"
        out["divergence"] = {
            "index": n,
            "explanation": f"one run recorded {len(a)} events and the other "
                           f"{len(b)}; the shorter stopped first, which is a "
                           f"difference in termination rather than behaviour",
        }
        return out

    out["divergence"] = {
        "index": first,
        "side_a": {k: a[first].get(k) for k in cmp_keys if a[first].get(k)
                   is not None},
        "side_b": {k: b[first].get(k) for k in cmp_keys if b[first].get(k)
                   is not None},
    }
    if kind == "field":
        differing = [k for k in cmp_keys
                     if a[first].get(k) != b[first].get(k)]
        out["divergence"]["differing_fields"] = differing
        out["divergence"]["explanation"] = (
            "both runs performed the same kind of event with different "
            "details. The sequence agrees; the data does not")

    if first_only:
        return out

    # Beyond the first divergence, count how much else differs so the reader
    # can tell one difference from a cascade. This compares the same keys the
    # first-divergence scan used; counting only event *types* would report
    # zero mismatches for two runs that took entirely different paths, which
    # is the exact case the count exists to reveal.
    tail = []
    for i in range(first, max(len(a), len(b))):
        ea = a[i] if i < len(a) else None
        eb = b[i] if i < len(b) else None
        ka = key_of(ea) if ea else None
        kb = key_of(eb) if eb else None
        if ka != kb:
            tail.append({
                "index": i,
                "side_a": (ea or {}).get("type") if ea else None,
                "side_b": (eb or {}).get("type") if eb else None,
                "same_kind": bool(ea and eb and
                                  ea.get("type") == eb.get("type")),
            })
    out["downstream_event_mismatches"] = len(tail)
    out["downstream_first_five"] = tail[:5]
    out["interpretation"] = (
        f"{len(tail)} further event mismatches follow the first. That is the "
        f"expected shape when one early difference cascades, so the first "
        f"divergence is the one to investigate; treat the tail as "
        f"consequence until proven otherwise")
    return out


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------

PROVENANCE_STAGES = ["source", "transform", "storage", "read", "decision",
                     "output"]


def build_provenance(events: Sequence[Dict], address: int,
                     resolver: Optional[Resolver] = None) -> Dict:
    """Reconstruct the chain around one memory location.

    Answering 'where does this value come from' means ordering the events that
    touch an address and reporting which stage each one represents. Stage
    assignment is a reading, and it is labelled as one: a write is not
    automatically the source, because the value may have been computed
    somewhere that did not touch this address at all.
    """
    events = list(events)
    touching = [e for e in events
                if e.get("address") and _same_address(e.get("address"), address)]

    if not touching:
        # An alias may hold the same value; say so rather than reporting
        # nothing at all.
        return {
            "address": f"0x{address:x}",
            "events": 0,
            "status": "no_events",
            "stages": {},
            "note": "no recorded event touched this address. Either the "
                    "address is wrong, or the value arrived through a path "
                    "that was not instrumented -- check for an alias holding "
                    "the same storage",
            "alias_hypothesis": (
                "another address may hold the same storage. Runtime address - "
                "module base is not an identity: confirm by writing through "
                "one address and reading through the other"),
        }

    ordered = sorted(
        touching,
        key=lambda e: (e.get("timestamp") if e.get("timestamp") is not None
                       else 0, e.get("type")))

    stages: Dict[str, List[Dict]] = defaultdict(list)
    for ev in ordered:
        stage = classify_event_stage(ev, ordered, ev)
        stages[stage].append({
            "index": events.index(ev),
            "type": ev.get("type"),
            "timestamp": ev.get("timestamp"),
            "tid": ev.get("tid"),
            "caller": ev.get("caller"),
            "value": ev.get("value"),
            "basis": "inferred",
            "caveat": "stage assignment is a reading of the event kind and "
                      "position in the sequence, not an observation",
        })

    writers = [e for e in touching if e.get("type") == "memory_write"]
    readers = [e for e in touching if e.get("type") == "memory_read"]
    threads = sorted({str(e.get("tid") or e.get("thread"))
                      for e in touching if e.get("tid") or e.get("thread")})

    out: Dict[str, Any] = {
        "address": f"0x{address:x}",
        "events": len(touching),
        "status": "ok" if touching else "no_events",
        "write_count": len(writers),
        "read_count": len(readers),
        "threads": threads or None,
        "stages": {k: v for k, v in stages.items()},
        "missing_stages": [s for s in PROVENANCE_STAGES if s not in stages],
        "thread_agreement": (len(threads) <= 1 if threads else None),
        "note": None,
    }

    if len(threads) > 1:
        out["note"] = (
            f"events on this address come from {len(threads)} different "
            f"threads. The thread that wrote is not necessarily the thread "
            f"you observed from, and attributing a write to the observing "
            f"thread is wrong under concurrency")
        out["confidence"] = "low"
    else:
        out["confidence"] = "medium"

    # A write with no prior read at that address is an initialisation
    # candidate, not an update.
    if writers:
        first_write_idx = ordered.index(writers[0])
        prior_reads = [e for e in ordered[:first_write_idx]
                       if e.get("type") == "memory_read"]
        out["first_write"] = {
            "index": touching.index(writers[0]),
            "timestamp": writers[0].get("timestamp"),
            "value": writers[0].get("value"),
            "classification": ("initialisation candidate"
                               if not prior_reads else "update"),
            "basis": "inferred",
            "caveat": "classified by whether an earlier read was recorded; a "
                      "path that was not instrumented would break this"
        }
        out["periodic"] = _is_periodic(writers)

    if resolver is not None:
        n = resolver.normalize(address)
        out["normalised"] = {k: n.get(k) for k in
                             ("status", "module", "module_relative",
                              "elf_vaddr", "file_offset", "section", "symbol",
                              "warnings")}
    return out


def _same_address(value, target: int) -> bool:
    """Compare an event's address to a target, tolerating string forms."""
    if value is None:
        return False
    if isinstance(value, int):
        return value == target
    try:
        return int(str(value), 16) == target
    except (TypeError, ValueError):
        return False


def _is_periodic(writers: List[Dict]) -> Optional[Dict]:
    """Report whether writes recur at a regular interval."""
    ts = [w.get("timestamp") for w in writers
          if isinstance(w.get("timestamp"), (int, float))]
    if len(ts) < 3:
        return None
    deltas = [round(ts[i + 1] - ts[i], 6) for i in range(len(ts) - 1)]
    counts: Dict[float, int] = defaultdict(int)
    for d in deltas:
        counts[d] += 1
    common, n = max(counts.items(), key=lambda kv: kv[1])
    return {
        "intervals": len(deltas),
        "most_common_interval": common,
        "share_of_that_interval": round(n / len(deltas), 4),
        "classification": "periodic" if n / len(deltas) >= 0.8
        else "irregular",
        "basis": "inferred",
        "caveat": "derived from the timestamps of the recorded writes only; "
                  "a path not instrumented would break the pattern",
    }


def classify_event_stage(ev: Dict, ordered: Sequence[Dict], self_ev: Dict) -> str:
    """Assign a provenance stage to one event. A reading, always labelled."""
    etype = ev.get("type")
    if etype == "syscall":
        return "output"
    if etype in ("packet", "ui_event"):
        return "source"
    if etype == "memory_write":
        earlier_reads = any(e.get("type") == "memory_read" for e in ordered)
        return "storage" if earlier_reads else "transform"
    if etype == "memory_read":
        return "read"
    if etype == "call":
        return "decision"
    if etype in ("alloc", "free"):
        return "storage"
    return "unknown"


# --------------------------------------------------------------------------
# Aliasing
# --------------------------------------------------------------------------

def alias_hypotheses(addr_a: int, addr_b: int) -> Dict:
    """Compare two addresses and state what would settle whether they alias."""
    if addr_a == addr_b:
        return {"same": True, "basis": "observed",
                "explanation": "the addresses are equal"}
    distance = abs(addr_a - addr_b)
    return {
        "same": False,
        "distance": distance,
        "basis": "unknown",
        "explanation": "different addresses hold different storage unless "
                       "proven otherwise; a similar value in both is not "
                       "evidence that they alias",
        "tests": [
            {"test": "write a distinctive value through one address and read "
                     "the other",
             "settles": "whether the storage is shared"},
            {"test": "check whether both addresses are covered by the same "
                     "region in the memory map, or by two regions that are "
                     "the same mapping at different load addresses",
             "settles": "whether a mapping explains the relationship"},
            {"test": "compare the region identities (inode and file offset); "
                     "a shared mapping has one inode",
             "settles": "whether the regions are the same object"},
        ],
    }


# --------------------------------------------------------------------------
# Crash analysis
# --------------------------------------------------------------------------

def crash_record(signal: int, fault_address: Optional[int],
                 instruction: Optional[int], region_lookup=None) -> Dict:
    """Build a crash record with the site kept distinct from the cause.

    Where the process died is observed. What made the state invalid is not,
    and conflating the two is how a crash is 'fixed' by adding a bounds check
    at the wrong line.
    """
    name = SIGNAL_NAMES.get(signal, f"signal {signal}")
    out: Dict[str, Any] = {
        "signal": signal,
        "signal_name": name,
        "fault_address": f"0x{fault_address:x}" if fault_address else None,
        "instruction_address": f"0x{instruction:x}" if instruction else None,
        "crash_site": {
            "instruction": f"0x{instruction:x}" if instruction else None,
            "status": "observed" if instruction else "unknown",
            "meaning": "where execution was when the fault was raised",
        },
        "root_cause": {
            "status": "unknown",
            "note": "the fault address and the instruction address locate the "
                    "crash site, not the cause. The cause is the write or the "
                    "assumption that made the state invalid earlier",
        },
        "how_to_reach_the_cause": [
            "look for the last write to the faulting region before the fault, "
            "across every thread, not just the crashing one",
            "check whether the faulting address was ever initialised; an "
            "uninitialised read and an overrun are different bugs",
            "check whether the fault address is a small offset from a known "
            "allocation, which suggests an overrun rather than a wild pointer",
            "replay the triggering input with a watchpoint on the region: the "
            "first write after a known-good value is the candidate",
        ],
    }
    if region_lookup is not None and fault_address is not None:
        out["fault_region"] = region_lookup(fault_address)
    return out


# --------------------------------------------------------------------------
# Capability probing
# --------------------------------------------------------------------------

RUNTIME_TOOL_GROUPS: Dict[str, List[str]] = {
    "debugger": ["gdb", "lldb"],
    "instrumentation": ["frida", "frida-ps", "frida-trace", "frida-ls-devices"],
    "syscall_tracer": ["strace", "ltrace", "sysdig", "bpftrace"],
    "profiler": ["perf"],
    "memcheck": ["valgrind", "callgrind_annotate", "dhat"],
    "emulator": ["qemu-aarch64", "qemu-arm", "qemu-x86_64", "qemu-system-arm"],
    "process_tools": ["ps", "top", "pmap", "vmmap", "lsof", "ss", "netstat"],
    "disassembler_rt": ["objdump", "llvm-objdump", "rizin", "rz-bin", "radare2"],
    "android_runtime": ["adb", "dumpsys", "run-as"],
}


def probe_capabilities() -> Dict:
    """Report what runtime capability exists here.

    Three states, never two: a tool that is absent produces ``unavailable``
    and the method notes which alternative is used instead. ``partial`` is for
    the case where something exists but not everything the technique needs --
    an unprivileged process can be inspected with /proc but not ptrace'd.
    """
    import shutil

    found: Dict[str, str] = {}
    missing: List[str] = []
    for group, names in RUNTIME_TOOL_GROUPS.items():
        hit = None
        for n in names:
            p = shutil.which(n)
            if p:
                hit = p
                break
        if hit:
            found[group] = hit
        else:
            missing.append(group)

    proc_ok = os.path.isdir("/proc/self")
    maps_ok = proc_ok and os.path.isfile("/proc/self/maps")
    smaps_ok = maps_ok and os.access("/proc/self/smaps", os.R_OK)

    capabilities: Dict[str, Dict] = {
        "proc_maps": {
            "state": "available" if maps_ok else "unavailable",
            "detail": "/proc/<pid>/maps is readable"
            if maps_ok else "/proc/<pid>/maps is not readable; on this host "
                           "process memory maps cannot be read directly",
            "gives": "regions, permissions, file offsets, inodes, paths",
        },
        "proc_smaps": {
            "state": "available" if smaps_ok else "unavailable",
            "detail": "VmFlags give the kernel's own account of what a region "
                      "is for" if smaps_ok else
                      "/proc/<pid>/smaps not readable; region classification "
                      "will have no kernel hints and stays weaker",
            "gives": "RSS, VmFlags (mg = malloc-eligible, gd = grows down)",
        },
        "process_vm": {
            "state": "available" if maps_ok else "unavailable",
            "detail": "addresses can be resolved to modules and offsets; the "
                      "bytes themselves need ptrace or /proc/<pid>/mem",
            "gives": "module attribution and address translation",
        },
        "ptrace": {
            "state": "available" if found.get("debugger") else "unavailable",
            "detail": ("a debugger is installed, but attaching additionally "
                       "requires permission: check /proc/sys/kernel/"
                       "yama/ptrace_scope and the target's ownership"
                       if found.get("debugger") else
                       "no debugger installed; breakpoints, watchpoints and "
                       "register inspection are unavailable"),
            "gives": "breakpoints, watchpoints, registers, single-stepping",
        },
        "instrumentation": {
            "state": "available" if found.get("instrumentation") else
                     "unavailable",
            "detail": ("Frida is installed; it also needs a matching "
                       "frida-server and permission on the target"
                       if found.get("instrumentation") else
                       "Frida not installed; in-process hooking is "
                       "unavailable, and dynamic evidence comes from a "
                       "debugger or an external tracer instead"),
            "gives": "in-process hooks, argument and return interception",
        },
        "syscall_trace": {
            "state": "available" if found.get("syscall_tracer") else
                     "unavailable",
            "detail": ("syscall tracing available" if found.get("syscall_tracer")
                       else "no syscall tracer; the syscall layer is inferred "
                            "from /proc counters and from effects in the "
                            "memory map, which is weaker evidence"),
            "gives": "syscalls with arguments, return values and thread",
        },
    }

    return {
        "capabilities": capabilities,
        "tools_found": dict(sorted(found.items())),
        "groups_missing": sorted(missing),
        "degradation_note": (
            "every method below states what it needs and what it falls back "
            "to. Absence of a tool reduces what can be observed; it never "
            "changes what is evidence"),
        "privilege_note": (
            "tool presence is not permission. A debugger that cannot attach "
            "is no better than no debugger, and /proc/sys/kernel/yama/"
            "ptrace_scope decides that before you try"),
    }


# --------------------------------------------------------------------------
# /proc reading, with honest failure
# --------------------------------------------------------------------------

def read_proc_file(pid: int | str, name: str) -> Tuple[Optional[str], Optional[str]]:
    """Read /proc/<pid>/<name>. Returns (content, error).

    A missing file, a permission denial and a process that exited mid-read are
    all ordinary outcomes, so each returns a reason instead of raising.
    """
    path = f"/proc/{pid}/{name}"
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(), None
    except PermissionError:
        return None, (f"permission denied reading {path}; the process belongs "
                      f"to another user, or ptrace_scope forbids it")
    except FileNotFoundError:
        return None, (f"{path} does not exist; the process may have exited, or "
                      f"this host has no /proc")
    except OSError as e:
        return None, f"cannot read {path}: {e}"


def load_resolver(pid: int | str, binaries: Optional[Dict[str, Any]] = None,
                  use_smaps: bool = True,
                  page_size: int = 4096) -> Tuple[Optional[Resolver], Dict]:
    """Build a Resolver from a live process. Returns (resolver, provenance)."""
    notes: Dict[str, Any] = {"pid": str(pid), "sources": [], "warnings": []}

    text, err = read_proc_file(pid, "maps")
    if err:
        notes["error"] = err
        return None, notes
    regions = parse_maps(text)
    if not regions:
        notes["error"] = ("/proc/<pid>/maps parsed to zero regions; the read "
                          "may have been truncated")
        return None, notes
    notes["sources"].append(f"maps: {len(regions)} regions")

    if use_smaps:
        stext, serr = read_proc_file(pid, "smaps")
        if stext and not serr:
            flags = parse_smaps_vmflags(stext)
            apply_vmflags(regions, flags)
            notes["sources"].append(f"smaps: VmFlags for {len(flags)} regions")
        else:
            notes["warnings"].append(
                f"smaps unavailable ({serr or 'empty'}); region classification "
                f"loses the kernel's own hints and every heap claim becomes "
                f"an inference")

    classify_regions(regions)
    modules = build_modules(regions)
    notes["sources"].append(f"modules: {len(modules)}")

    return Resolver(regions, modules, binaries, page_size), notes


# --------------------------------------------------------------------------
# Syscall correlation
# --------------------------------------------------------------------------

def correlate_syscalls(events: Sequence[Dict]) -> Dict:
    """Group syscall events and offer readings of what they imply.

    A syscall alone means little. ``connect`` followed by an authentication
    state change is a reading, and the state field is what makes it a reading
    rather than a fact.
    """
    syscalls = [e for e in events if e.get("type") == "syscall"]
    by_name: Dict[str, Dict] = {}
    for ev in syscalls:
        name = ev.get("name") or ev.get("symbol") or "unknown"
        rec = by_name.setdefault(name, {
            "name": name, "count": 0, "threads": set(),
            "return_values": set(), "structural": name in STRUCTURAL_SYSCALLS,
        })
        rec["count"] += 1
        if ev.get("tid") or ev.get("thread"):
            rec["threads"].add(str(ev.get("tid") or ev.get("thread")))
        if ev.get("value") is not None:
            rec["return_values"].add(str(ev.get("value")))

    readings: List[Dict] = []

    def reading(when: str, claim: str, basis: str = "inferred",
                needs: str = "") -> None:
        readings.append({"syscall": when, "reading": claim, "basis": basis,
                         "requires": needs or None})

    for ev in syscalls:
        name = ev.get("name") or ev.get("symbol")
        if name in ("mmap", "mmap2", "brk", "sbrk"):
            reading(name, "a new or grown mapping, which becomes an anonymous "
                          "region visible in the map",
                    needs="the returned address, to tie the syscall to a region")
        elif name == "mprotect":
            reading(name, "a protection change on an existing mapping",
                    needs="the address and length, to say which region changed")
        elif name in ("clone", "clone3", "fork", "vfork"):
            reading(name, "a new thread or process",
                    needs="the return value, to distinguish a thread (a tid) "
                          "from a child (a pid)")
        elif name == "execve":
            reading(name, "the process image was replaced",
                    basis="observed")
        elif name in ("connect", "sendto"):
            reading(name, "outbound network activity",
                    needs="a subsequent read or packet event, before this is "
                          "tied to a protocol state change")
        elif name == "futex":
            reading(name, "a wait or wake on a futex, which is the usual "
                          "implementation of a mutex or condition variable",
                    needs="the futex address, to tell a lock wait from a "
                          "condition wait from a requeue")

    return {
        "syscalls_observed": len(syscalls),
        "distinct": len(by_name),
        "by_name": {k: {
            "count": v["count"],
            "threads": sorted(v["threads"]) or None,
            "return_values": sorted(v["return_values"])[:10] or None,
            "structural": v["structural"],
        } for k, v in sorted(by_name.items())},
        "readings": readings,
        "note": "each reading names what would make it more than a reading. "
                "A syscall in isolation carries no meaning about the code "
                "that made it",
    }


# --------------------------------------------------------------------------
# Module load events
# --------------------------------------------------------------------------

def module_load_chain(events: Sequence[Dict]) -> Dict:
    """Order module loads and flag the ones that are not statically present.

    A library loaded with ``dlopen`` and absent from ``DT_NEEDED`` is a real
    finding: it is code the static analysis of the executable cannot reach.
    """
    loads = [e for e in events if e.get("type") == "module_load"]
    unloads = [e for e in events if e.get("type") == "module_unload"]

    order = []
    for ev in sorted(loads, key=lambda e: (e.get("timestamp")
                                           if e.get("timestamp") is not None
                                           else 0)):
        name = ev.get("module") or ev.get("name") or "unknown"
        order.append({
            "order": len(order) + 1,
            "module": name,
            "timestamp": ev.get("timestamp"),
            "loaded_by": ev.get("caller"),
            "base": ev.get("address"),
            "size": ev.get("size"),
        })

    unloaded = {e.get("module") or e.get("name") for e in unloads}
    return {
        "load_order": order,
        "loaded_count": len(order),
        "unloaded": sorted(x for x in unloaded if x) or None,
        "loaded_then_unloaded": sorted(
            {m["module"] for m in order if m["module"] in unloaded}) or None,
        "note": "a module absent from the executable's DT_NEEDED but present "
                "here was loaded at runtime. Static analysis of the executable "
                "alone cannot reach it, so it needs its own analysis",
        "caveat": "whether a module was dlopen'd or merely appears later "
                  "because the snapshot is partial is not established here; "
                  "confirm with a load event carrying a caller",
    }