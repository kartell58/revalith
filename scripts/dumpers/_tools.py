"""
_tools.py -- tool discovery and safe external command execution.

The skill's core rule applied to code: never assume a tool is installed.
Every consumer records what was searched for, what was found, and what was
skipped, so a reader can tell the difference between "no dependency" and
"dependency unavailable".
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

# Tools worth probing, grouped by what they provide. Order within a group is
# a preference order: the first available tool is used.
TOOL_GROUPS: Dict[str, List[str]] = {
    "file": ["file"],
    "strings": ["strings", "llvm-strings", "gstrings"],
    "readelf": ["readelf", "llvm-readelf", "greadelf"],
    "objdump": ["objdump", "llvm-objdump"],
    "readobj": ["llvm-readobj"],
    "nm": ["nm", "llvm-nm"],
    "strip": ["strip", "llvm-strip"],
    "objcopy": ["objcopy", "llvm-objcopy"],
    "size": ["size", "llvm-size"],
    "archive": ["unzip", "bsdtar", "7z", "7za"],
    "tar": ["tar"],
    "re_suite": ["radare2", "r2", "rizin", "rz-bin"],
    "decompiler": ["ghidra", "analyzeHeadless", "binaryninja", "binja"],
    "debugger": ["gdb", "lldb"],
    "instrumentation": ["frida", "frida-ps", "frida-trace"],
    "android": ["aapt", "aapt2", "apktool", "jadx", "apkanalyzer", "dexdump",
                "bundletool"],
    "embedded": ["binwalk"],
    "protobuf": ["protoc", "protoc-gen-jsonschema"],
    "python_pkgs": [],
}

# Commands that must never be run automatically, whatever a config says.
BLOCKED_PREFIXES = ("rm ", "mkfs", "dd if=", ":()", "shutdown", "reboot")


@dataclass
class ToolReport:
    """Result of probing the environment. Serialisable."""
    found: Dict[str, str] = field(default_factory=dict)   # group -> executable
    versions: Dict[str, str] = field(default_factory=dict)  # group -> version
    missing: List[str] = field(default_factory=list)      # groups with none found
    search_path_size: int = 0

    def has(self, group: str) -> bool:
        return group in self.found

    def path(self, group: str) -> Optional[str]:
        return self.found.get(group)

    def first_available(self, group: str) -> Optional[str]:
        return self.found.get(group)

    def to_dict(self) -> Dict:
        return {
            "found": dict(sorted(self.found.items())),
            "versions": dict(sorted(self.versions.items())),
            "missing_groups": sorted(self.missing),
            "search_path_entries": self.search_path_size,
            "notes": [
                "tools are probed with shutil.which at run time",
                "absence is recorded, never treated as a fatal error",
            ],
        }


_VERSION_ARGS = {
    "file": ["--version"],
    "strings": ["--version"],
    "readelf": ["--version"],
    "objdump": ["--version"],
    "readobj": ["--version"],
    "nm": ["--version"],
    "strip": ["--version"],
    "objcopy": ["--version"],
    "size": ["--version"],
    "archive": None,        # unzip/7z: --version is unreliable, differs per tool
    "tar": ["--version"],
    "re_suite": ["-v"],
    "debugger": ["--version"],
    "instrumentation": ["--version"],
    "android": ["--version"],
    "embedded": None,      # binwalk has no reliable --version
    "protobuf": ["--version"],
}


def discover(groups: Optional[Sequence[str]] = None,
             with_versions: bool = True,
             timeout: int = 10) -> ToolReport:
    """Probe PATH for the known tool groups.

    Returns a report of what is available. Never raises for a missing tool.
    """
    wanted = list(groups) if groups else list(TOOL_GROUPS)
    report = ToolReport()
    report.search_path_size = len(os.environ.get("PATH", "").split(os.pathsep))

    for group in wanted:
        candidates = TOOL_GROUPS.get(group)
        if candidates is None:
            candidates = [group]          # allow probing an arbitrary name
        hit = None
        for cand in candidates:
            p = shutil.which(cand)
            if p:
                hit = p
                break
        if hit:
            report.found[group] = hit
            if with_versions and _VERSION_ARGS.get(group):
                report.versions[group] = tool_version(hit,
                                                     _VERSION_ARGS[group],
                                                     timeout)
        else:
            report.missing.append(group)
    return report


def tool_version(exe: str, args: Sequence[str], timeout: int = 10) -> str:
    """Best-effort version string. Returns "unknown" rather than failing.

    ``args`` may be None for tools whose ``--version`` is unreliable; in that
    case the executable name alone is reported, which is honest about what
    was actually learned.
    """
    if not args:
        return "not queried (no reliable version flag)"
    try:
        proc = subprocess.run([exe, *args], capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if proc.returncode not in (0, 1):
        return "unknown"
    text = (proc.stdout or "") + (proc.stderr or "")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Reject lines that are clearly argument-parsing complaints rather
        # than a version string: unzip complains about -n/-o when asked for
        # "--version" and then goes on to print usage on stderr.
        if re.search(r"caution|unrecognized|invalid option|usage:", line,
                     re.IGNORECASE):
            continue
        m = re.search(r"\d+\.\d+(\.\d+)?", line)
        if m:
            return line[:120]
        if len(line) < 120:
            return line
    return "unknown"


def run(exe: str, args: Sequence[str], timeout: int = 60,
        cwd: Optional[str] = None) -> Dict:
    """Run a command and return a structured, serialisable result.

    Never raises. The caller gets ``ok``, ``returncode``, ``stdout``,
    ``stderr`` and ``argv`` so the invocation can be recorded as evidence.
    """
    argv = [exe, *args]
    joined = " ".join(argv)
    if joined.strip().startswith(BLOCKED_PREFIXES):
        return {"ok": False, "argv": argv, "returncode": None,
                "stdout": "", "stderr": "refused: command not allowed",
                "error": "blocked_by_policy"}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, cwd=cwd)
    except FileNotFoundError as e:
        return {"ok": False, "argv": argv, "returncode": None, "stdout": "",
                "stderr": str(e), "error": "not_found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "argv": argv, "returncode": None, "stdout": "",
                "stderr": "", "error": f"timeout after {timeout}s"}
    except OSError as e:
        return {"ok": False, "argv": argv, "returncode": None, "stdout": "",
                "stderr": str(e), "error": "os_error"}
    return {
        "ok": proc.returncode == 0,
        "argv": argv,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "error": None if proc.returncode == 0 else "nonzero_exit",
    }