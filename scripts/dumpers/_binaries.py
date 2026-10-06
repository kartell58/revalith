"""
_binaries.py -- ELF / PE / Mach-O triage built on ``_binlib``.

Adds the depth the orchestrator needs without duplicating the parser:
relocations, TLS, JNI exports, interpreter, and the "notable library" hint
that prioritises which binary deserves deep analysis.

Every field is either observed or ``None``. Nothing is filled in from the
file's name: ``libil2cpp.so`` is not IL2CPP until its contents say so.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, List, Optional

import _binlib as B

# SHT_TLS
SHT_TLS = 7

# Native libraries an analyst usually wants to look at first, and why.
# The second element is the reason string; it describes the name, not a claim
# about contents. Presence in the container is observed; purpose is not.
NOTABLE_NAMES = {
    "libil2cpp.so": "Unity IL2CPP runtime candidate (name-based hint only)",
    "libunity.so": "Unity player library candidate (name-based hint only)",
    "libmain.so": "common entry/library name for packaged apps",
    "libnative.so": "conventional native-logic library name",
    "libgame.so": "conventional game-logic library name",
    "libmonobdwgc.so": "Mono runtime",
    "libmonosgen-2.0.so": "Mono runtime (sgen GC)",
    "libflutter.so": "Flutter engine library candidate",
    "libreactnativejni.so": "React Native JNI library candidate",
    "libhermes.so": "Hermes JS engine candidate",
    "libjni.so": "JNI helper",
    "libc++_shared.so": "LLVM libc++ runtime",
    "libcrypto.so": "OpenSSL crypto",
    "libssl.so": "OpenSSL TLS",
}

JNI_EXPORT_PREFIX = "Java_"


def triage(path: str, want_relocs: bool = True,
          want_strings: bool = False) -> Dict:
    """Summarise one binary. Never raises; failures are recorded."""
    out: Dict = {
        "path": path,
        "basename": os.path.basename(path),
        "analysed": False,
        "format": None,
        "error": None,
        "warnings": [],
    }
    try:
        size = os.path.getsize(path)
    except OSError as e:
        out["error"] = f"stat failed: {e}"
        return out

    sniffed = B.sniff(path)
    out["sniffed"] = sniffed
    out["size"] = size
    if sniffed in ("APK (zip)", "JAR (zip)", "zip with DEX",
                   "zip with native libs", "zip"):
        out["error"] = "container, not a single binary; analyse its members"
        return out

    try:
        info = B.load(path)
    except B.ParseError as e:
        out["error"] = str(e)
        return out
    except (OSError, struct.error, IndexError, ValueError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    out["analysed"] = True
    out["format"] = info.fmt
    out["architecture"] = info.arch or "unknown"
    out["bits"] = info.bits
    out["endianness"] = info.endian
    out["elf_type"] = info.extra.get("elf_type")
    out["abi"] = info.extra.get("abi")
    out["entrypoint"] = f"0x{info.entrypoint:x}" if info.entrypoint else None
    out["image_base"] = f"0x{info.imagebase:x}" if info.imagebase else None
    out["stripped"] = info.stripped
    out["position_independent"] = info.is_pie
    out["build_id"] = info.build_id
    out["soname"] = info.soname
    out["needed"] = info.needed
    out["rpath"] = info.extra.get("rpath")
    out["runpath"] = info.extra.get("runpath")
    out["notes"] = info.notes
    out["counts"] = {
        "sections": len(info.sections),
        "segments": len(info.segments),
        "symbols": len(info.symbols),
        "dynamic_symbols": len(info.dyn_symbols()),
        "static_symbols": len(info.static_symbols()),
        "exports": len(info.exports()),
        "imports": len(info.imports()),
        "functions": len(info.functions()),
    }

    # -- interpreter (ELF) / section table -------------------------------
    out["interpreter"] = None
    if info.fmt == "ELF":
        interp = next((s for s in info.segments if s.type == "INTERP"), None)
        if interp is not None:
            try:
                with open(path, "rb") as fh:
                    fh.seek(interp.offset)
                    blob = fh.read(interp.filesz or 64)
                out["interpreter"] = blob.split(b"\x00")[0].decode("utf-8", "replace")
            except OSError as e:
                out["warnings"].append(f"interpreter read failed: {e}")
        out["has_tls"] = any(s.type == "TLS" for s in info.sections)
        out["gnu_properties"] = _gnu_properties(info)
        out["sections"] = [
            {"name": s.name, "addr": f"0x{s.addr:x}", "offset": f"0x{s.offset:x}",
             "size": s.size, "flags": f"0x{s.flags:x}", "entropy": s.entropy,
             "type": s.type}
            for s in info.sections]
        out["segments"] = [
            {"type": s.type, "vaddr": f"0x{s.vaddr:x}",
             "offset": f"0x{s.offset:x}", "filesz": s.filesz,
             "memsz": s.memsz, "flags": s.flags}
            for s in info.segments]

    # -- exports / imports worth surfacing ------------------------------
    exports = info.exports()
    out["exported_names_sample"] = sorted({s.name for s in exports})[:40]
    jni = sorted({s.name for s in info.symbols
                  if s.name.startswith(JNI_EXPORT_PREFIX) and not s.is_undefined})
    out["jni_exports"] = jni[:40]
    out["jni_export_count"] = len(jni)
    if jni:
        out["jni_export_note"] = (
            f"{len(jni)} JNI-style export(s); names follow the Java_ convention "
            "but the corresponding Java class was not resolved here")

    out["imported_names_sample"] = sorted({s.name for s in info.imports()})[:40]
    if info.fmt == "ELF":
        out["dependency_observation"] = _dependency_observation(info)

    if want_relocs:
        out["relocations"] = _relocations(path, info)
        if out["relocations"].get("error"):
            out["warnings"].append(out["relocations"]["error"])

    if want_strings:
        res = B.extract_strings(open(path, "rb").read(), 6, ("ascii",))
        out["string_count"] = len(res)
        out["strings_sample"] = [t for _, t, _ in res[:60]]

    out["notable_hint"] = _notable_hint(path, info)
    return out


def _gnu_properties(info: B.BinaryInfo) -> Optional[Dict]:
    """Read DT_GNU_PROPERTY_* style notes conservatively.

    Returns None when absent. We do not decode every property kind; an
    undecoded property is reported as unknown rather than guessed.
    """
    for sec in info.sections:
        if sec.type != "NOTE" or not sec.size:
            continue
        try:
            with open(info.path, "rb") as fh:
                fh.seek(sec.offset)
                blob = fh.read(min(sec.size, 4096))
        except OSError:
            continue
        if b"GNU" in blob and b"property" in blob.lower():
            return {"observed": "GNU_PROPERTY note present",
                    "decoded": False,
                    "note": "property types not decoded by the bundled parser; "
                            "use readelf -n for values"}
    return None


def _dependency_observation(info: B.BinaryInfo) -> List[Dict]:
    """Libraries that hint at what the binary touches.

    This reports the *name* and an expected kind. Whether the capability is
    actually used is unverified.
    """
    hints = []
    for lib in info.needed:
        low = lib.lower()
        kind = None
        if "ssl" in low or "crypto" in low:
            kind = "TLS/cryptography library present"
        elif low.startswith("libc.so") or low.startswith("libc."):
            kind = "C library"
        elif low.startswith("libc++") or low.startswith("libstdc++"):
            kind = "C++ runtime"
        elif "android" in low or "log" == low.split(".")[0].replace("lib", ""):
            kind = "Android runtime/logging"
        elif "dl" in low:
            kind = "dynamic loading"
        elif "z.so" in low or "zlib" in low:
            kind = "compression"
        hints.append({"library": lib, "observation": kind or "unclassified"})
    return hints


def _relocations(path: str, info: B.BinaryInfo) -> Dict:
    """Summarise relocations, which reveal indirect-reference structure."""
    out = {"available": False, "count": None, "types": {}, "sections": [],
           "error": None, "method": None}
    if info.fmt != "ELF":
        out["error"] = "relocation parsing implemented for ELF only; " \
                       "use llvm-readobj --relocations for other formats"
        return out
    rela = [s for s in info.sections if s.type in ("RELA", "REL")]
    if not rela:
        out["error"] = "no .rela/.rel section found"
        return out
    out["available"] = True
    out["method"] = "section presence; per-entry decoding not implemented"
    total = 0
    for sec in rela:
        ent = 24 if info.bits == 64 else 8
        if ent and sec.size:
            count = sec.size // ent
            total += count
            out["sections"].append({"name": sec.name, "type": sec.type,
                                    "entries": count})
    out["count"] = total
    out["interpretation"] = (
        f"{total} relocations. A run of R_*_RELATIVE relocations in one region "
        "is consistent with a table of pointers (a vtable or function-pointer "
        "table); confirm by reading the entries." if total else
        "no relocations: the file may be fully resolved or statically linked")
    return out


def _notable_hint(path: str, info: B.BinaryInfo) -> Optional[Dict]:
    """Suggest priority based on observable properties.

    Combines filename conventions with structural observations, and states
    both. It never asserts what the library does.
    """
    base = os.path.basename(path)
    low = base.lower()
    reasons: List[str] = []
    name_hint = NOTABLE_NAMES.get(low)
    if name_hint:
        reasons.append(f"filename '{base}': {name_hint}")

    if info.fmt == "ELF":
        if info.arch and "AArch64" in info.arch:
            reasons.append("AArch64 ELF")
        if info.stripped:
            reasons.append("symbols stripped")
        jni = sum(1 for s in info.symbols
                  if s.name.startswith(JNI_EXPORT_PREFIX) and not s.is_undefined)
        if jni:
            reasons.append(f"{jni} JNI export(s)")
        if any(s.type == "TLS" for s in info.sections):
            reasons.append("TLS section present")
        try:
            size = os.path.getsize(path)
            if size > 8 * 1024 * 1024:
                reasons.append(f"large ({size} bytes)")
        except OSError:
            pass

    if not reasons:
        return None
    return {
        "reasons": reasons,
        "priority": "high" if (name_hint or len(reasons) >= 3) else "medium",
        "caveat": "filename hints are conventions, not evidence of function",
    }