"""
_unity.py -- Unity and IL2CPP detection, metadata probing, tool delegation.

This module does **not** implement an IL2CPP dumper. Dumping IL2CPP metadata
is a solved, specialised problem; reimplementing it badly would be worse than
pointing at the tools that do it.

The orchestrator's job is narrower and worth doing well:

1. Detect Unity and IL2CPP from observed indicators.
2. Probe ``global-metadata.dat`` and record what the probe found.
3. Locate an appropriate external tool, and record its version and arguments.
4. Run it, capture what it produced.
5. Record tool, version, argv, success/failure, errors and output files.

If the metadata does not parse, the recorded status is
``obfuscated_or_custom`` with a confidence level -- never a claim that
"IL2CPP is broken", which would be an assertion about a file we did not
understand.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, List, Optional

# Standard IL2CPP global-metadata header magic.
STANDARD_MAGIC = b"\xAF\x1B\xB1\xFA"

# Header versions seen in the wild. Values are the low 32 bits of the
# version field for known releases; absence means "not recognised".
KNOWN_VERSIONS = {
    21: "Unity 2017.1 - 2018.x (metadata v21)",
    24: "Unity 2019.1 - 2019.4 (metadata v24)",
    27: "Unity 2020.2 - 2021.1 (metadata v27)",
    28: "Unity 2021.2 (metadata v28)",
    29: "Unity 2022.x / 2023.x (metadata v29)",
    31: "Unity 6000 (metadata v31)",
}

# Candidate dumper tools, in preference order. Each entry records what it is,
# so the reader knows what ran.
DUMPER_CANDIDATES = [
    ("Il2CppDumper", "Il2CppDumper (Windows .NET / Wine)",
     ["Il2CppDumper.exe", "./Il2CppDumper.exe"]),
    ("Il2CppInspector", "Il2CppInspector (.NET, needs a global-metadata aware build)",
     ["Il2CppInspector"]),
    ("Cpp2IL", "Cpp2IL (cross-platform .NET)",
     ["Cpp2IL", "cpp2il"]),
    ("il2cpp-dumper-ng", "il2cpp dumper (python)", ["il2cpp_dumper"]),
    ("il2cpp_header", "unreal/il2cpp header generator", ["il2cpp_header.py"]),
]

VERSION_HINT_FILES = [
    "assets/bin/Data/globalgamemanagers",
    "assets/bin/Data/data.unity3d",
    "globalgamemanagers",
    "unity default resources",
    "assets/bin/Data/boot.config",
]


def detect_from_names(names: List[str]) -> Dict:
    """Detect Unity / IL2CPP from archive member names.

    Name-based evidence is weaker than content-based evidence, so each hit is
    tagged with its basis.
    """
    res = {
        "detected": False,
        "unity": False,
        "il2cpp": False,
        "metadata_file": None,
        "mono": False,
        "evidence": [],
        "basis": "archive member names only; content not yet verified",
    }
    lowered = {n.lower(): n for n in names}

    for low, orig in lowered.items():
        base = os.path.basename(low)
        if base == "global-metadata.dat":
            res["metadata_file"] = orig
            res["il2cpp"] = True
            res["detected"] = True
            res["evidence"].append(
                f"member {orig}: the conventional IL2CPP metadata filename")
        if base.startswith("libil2cpp") or base == "il2cpp.dll":
            res["il2cpp"] = True
            res["detected"] = True
            res["evidence"].append(f"member {orig}: IL2CPP runtime library name")
        if base.startswith("libunity") or base.startswith("unityplayer"):
            res["unity"] = True
            res["detected"] = True
            res["evidence"].append(f"member {orig}: Unity runtime library name")
        if "managed" in low.split("/")[-2:] or low.endswith("/managed.dll"):
            res["mono"] = True
            res["detected"] = True
            res["evidence"].append(
                f"member {orig}: a Mono-style managed assembly is present, "
                "which indicates the Mono scripting backend")
        if "assets/bin/data" in low:
            res["unity"] = True
            res["detected"] = True
            res["evidence"].append(
                f"member {orig}: Unity's conventional data directory layout")
    return res


def probe_metadata(path: str) -> Dict:
    """Probe ``global-metadata.dat`` and report only what was observed."""
    res = {
        "path": path,
        "size": None,
        "detected": True,
        "format": "unknown",
        "standard_magic": False,
        "status": "unknown",
        "confidence": "very low",
        "version_field": None,
        "version_guess": None,
        "offset_table": None,
        "notes": [],
    }
    try:
        res["size"] = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError as e:
        res["status"] = "unreadable"
        res["notes"].append(f"read failed: {e}")
        res["error"] = str(e)
        return res

    if len(head) < 8:
        res["notes"].append(f"only {len(head)} bytes readable")
        res["status"] = "truncated_or_empty"
        return res

    if head[:4] == STANDARD_MAGIC:
        res["standard_magic"] = True
        res["format"] = "il2cpp-global-metadata (standard header)"
        if len(head) >= 8:
            ver = struct.unpack_from("<i", head, 4)[0]
            res["version_field"] = ver
            res["version_guess"] = KNOWN_VERSIONS.get(
                ver, f"unrecognised metadata version field {ver}")
        res["status"] = "standard_header_present"
        res["confidence"] = "high"
    else:
        res["standard_magic"] = False
        res["format"] = "unknown"
        res["observed_magic"] = head[:8].hex()
        res["status"] = "obfuscated_or_custom"
        res["confidence"] = "medium"
        res["notes"].append(
            f"the standard IL2CPP magic {STANDARD_MAGIC.hex()} was not found at "
            f"offset 0 (found {head[:8].hex()} instead)")

    # Read the data-offset table header if it looks plausible; do not guess
    # past a length check.
    try:
        with open(path, "rb") as fh:
            fh.seek(0)
            blob = fh.read(min(res["size"] or 0, 4096))
        if len(blob) >= 0x20:
            off_table = struct.unpack_from("<i", blob, 8)[0]
            res["offset_table"] = off_table
            if 0 < off_table < (res["size"] or 0):
                res["notes"].append(
                    f"header field at 0x08 = 0x{off_table:x}, within the file")
            else:
                res["notes"].append(
                    f"header field at 0x08 = {off_table}, outside the file: "
                    "consistent with a non-standard layout")
    except (OSError, struct.error) as e:
        res["notes"].append(f"header probe failed: {e}")

    return res


def find_tools(tool_report) -> List[Dict]:
    """Find a usable dumper among the candidates, recording what was searched."""
    found: List[Dict] = []
    for name, desc, candidates in DUMPER_CANDIDATES:
        hit = None
        for cand in candidates:
            path = cand if os.path.isabs(cand) else None
            if path is None:
                for base in (cand, os.path.join(".", cand)):
                    if os.path.isfile(base) and os.access(base, os.X_OK):
                        path = os.path.abspath(base)
                        break
            if path:
                hit = path
                break
        found.append({"tool": name, "description": desc,
                      "available": bool(hit), "path": hit})
    return found


def delegate(metadata_path: str, binary_path: Optional[str], outdir: str,
             tool_report=None, timeout: int = 600,
             max_tool: Optional[str] = None) -> Dict:
    """Run an external dumper if one is available.

    Records the tool, version, argv, outcome, errors and produced files --
    so a later reader can tell a failed dump from a skipped one.
    """
    import _tools

    os.makedirs(outdir, exist_ok=True)
    result = {
        "attempted": False,
        "tool": None, "version": None, "argv": None,
        "ok": False, "returncode": None, "error": None,
        "stderr_tail": None, "produced_files": [], "notes": [],
        "candidates": [],
    }

    try:
        with open(metadata_path, "rb") as fh:
            head = fh.read(4)
    except OSError as e:
        result["error"] = f"metadata unreadable: {e}"
        return result

    result["candidates"] = find_tools(tool_report)

    if head != STANDARD_MAGIC:
        result["notes"].append(
            "the standard IL2CPP metadata magic is absent. A dumper is very "
            "unlikely to parse this file, so none was run. Treat the metadata "
            "as obfuscated or in a custom format until proven otherwise.")
        result["error"] = "non-standard metadata header; delegation skipped"
        return result

    if not binary_path:
        result["notes"].append(
            "no IL2CPP binary path supplied; a dumper needs both the metadata "
            "and the binary")
        result["error"] = "binary path missing"
        return result

    chosen = None
    if max_tool:
        chosen = next((c for c in result["candidates"]
                       if c["tool"] == max_tool), None)
        if chosen and not chosen["available"]:
            result["error"] = f"requested tool {max_tool} not found"
            return result
    else:
        chosen = next((c for c in result["candidates"] if c["available"]), None)

    if chosen is None:
        result["notes"].append(
            "no external IL2CPP dumper is installed. Detection and metadata "
            "probing still apply; symbol recovery requires installing one. "
            "Candidates searched: "
            + ", ".join(c["tool"] for c in result["candidates"]))
        result["error"] = "no external dumper available"
        return result

    result["attempted"] = True
    result["tool"] = chosen["tool"]
    exe = chosen["path"]
    result["version"] = _tools.tool_version(exe, ["--version"]) \
        if chosen["tool"] not in ("Il2CppDumper",) else "not queryable"

    args = [binary_path, metadata_path, outdir]
    run = _tools.run(exe, args, timeout=timeout)
    result["argv"] = " ".join(run["argv"])
    result["ok"] = run["ok"]
    result["returncode"] = run["returncode"]
    result["error"] = run["error"]
    if run["stderr"]:
        result["stderr_tail"] = run["stderr"].strip()[-600:]

    for root, _dirs, files in os.walk(outdir):
        for f in files:
            full = os.path.join(root, f)
            try:
                result["produced_files"].append({
                    "path": os.path.relpath(full, outdir),
                    "size": os.path.getsize(full)})
            except OSError:
                result["produced_files"].append({"path": full, "size": None})
    if not result["produced_files"] and run["ok"]:
        result["notes"].append(
            "the tool exited successfully but wrote no files; the arguments "
            "may not match this version's CLI")
    return result


def version_hints(names: List[str], search_root: Optional[str] = None) -> List[Dict]:
    """Look for Unity version strings in the conventional files.

    Returns evidence-tagged hints; an unreadable file yields a note rather
    than a guess.
    """
    hints: List[Dict] = []
    if not search_root:
        return hints
    lowered = {os.path.basename(n.lower()): n for n in names}
    for base in VERSION_HINT_FILES:
        if base.lower() not in lowered:
            continue
        member = lowered[base.lower()]
        full = os.path.join(search_root, member) if not os.path.isabs(member) \
            else member
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "rb") as fh:
                blob = fh.read(65536)
        except OSError as e:
            hints.append({"file": member, "error": str(e)})
            continue
        text = blob.decode("utf-8", "replace")
        found = []
        for marker in ("20",):
            idx = 0
            while True:
                idx = text.find(marker + ".", idx)
                if idx < 0 or idx > 4096:
                    break
                chunk = text[idx:idx + 12]
                tail = chunk.split("\x00")[0]
                if len(tail) >= 5 and tail.replace(".", "").isdigit():
                    found.append(tail)
                idx += 1
        for v in dict.fromkeys(found):
            hints.append({"file": member, "observed_version_string": v,
                          "confidence": "low",
                          "note": "string in a Unity data file; the exact "
                                  "version should be confirmed"})
    return hints