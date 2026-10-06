"""
_archives.py -- inspect and extract archives without external tools.

Uses only ``zipfile`` and ``tarfile``. When an archive format is present but
the standard library cannot read it (7z, RAR, some cab/lzma cases), the
archive is reported with a member count of ``null`` and a note naming the
tools that could read it -- never a fabricated listing.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_MEMBERS = 20000


@dataclass
class ArchiveEntry:
    name: str
    size: int = 0
    compressed_size: int = 0
    is_dir: bool = False
    crc: Optional[int] = None
    comment: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "is_dir": self.is_dir,
            "crc32": f"{self.crc:08x}" if self.crc is not None else None,
            "comment": self.comment or None,
        }


@dataclass
class ArchiveInfo:
    path: str
    kind: str
    readable: bool
    members: List[ArchiveEntry] = field(default_factory=list)
    member_count: Optional[int] = None
    truncated: bool = False
    comment: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "readable_with_stdlib": self.readable,
            "member_count": self.member_count,
            "truncated": self.truncated,
            "comment": self.comment or None,
            "notes": self.notes or None,
            "members": [m.to_dict() for m in self.members],
        }


# Tool that can read each format we cannot read natively.
EXTERNAL_FOR = {
    "7z": "7z / 7za / bsdtar",
    "rar": "7z / unrar / bsdtar",
    "cab": "cabextract / 7z",
    "lzma": "xz / 7z",
    "gzip": "gzip / zcat",
    "apk": "unzip / apktool / jadx",
}


def inspect(path: str, fmt: Optional[str] = None) -> ArchiveInfo:
    """List an archive's members. Never raises."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return ArchiveInfo(path=path, kind=fmt or "unknown", readable=False,
                           notes=[f"stat failed: {e}"])

    if zipfile.is_zipfile(path):
        return _inspect_zip(path)
    if tarfile.is_tarfile(path):
        return _inspect_tar(path)

    kind = fmt or "unknown"
    info = ArchiveInfo(path=path, kind=kind, readable=False, member_count=None)
    info.notes.append(
        "container detected but not readable with the Python standard "
        "library; no member list was produced")
    if kind in EXTERNAL_FOR:
        info.notes.append(f"could be listed with: {EXTERNAL_FOR[kind]}")
    if size == 0:
        info.notes.append("file is empty")
    return info


def _inspect_zip(path: str) -> ArchiveInfo:
    info = ArchiveInfo(path=path, kind="zip", readable=True)
    try:
        with zipfile.ZipFile(path) as zf:
            info.comment = zf.comment.decode("utf-8", "replace") if zf.comment else ""
            n = len(zf.infolist())
            info.member_count = n
            for zi in zf.infolist()[:MAX_MEMBERS]:
                info.members.append(ArchiveEntry(
                    name=zi.filename, size=zi.file_size,
                    compressed_size=zi.compress_size,
                    is_dir=zi.is_dir(), crc=zi.CRC,
                    comment=(zi.comment.decode("utf-8", "replace")
                             if zi.comment else "")))
            if n > MAX_MEMBERS:
                info.truncated = True
                info.notes.append(
                    f"{n} members found; listing truncated at {MAX_MEMBERS}")
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as e:
        info.readable = False
        info.notes.append(f"zip open failed: {e}")
    return info


def _inspect_tar(path: str) -> ArchiveInfo:
    info = ArchiveInfo(path=path, kind="tar", readable=True)
    try:
        with tarfile.open(path) as tf:
            members = []
            n = 0
            for ti in tf:
                n += 1
                if len(members) >= MAX_MEMBERS:
                    info.truncated = True
                    continue
                members.append(ArchiveEntry(
                    name=ti.name, size=ti.size, is_dir=ti.isdir(),
                    comment=f"type={'dir' if ti.isdir() else ti.type.decode('utf-8','replace') if isinstance(ti.type, bytes) else ti.type}"))
            info.members = members
            info.member_count = n
    except (tarfile.TarError, OSError) as e:
        info.readable = False
        info.notes.append(f"tar open failed: {e}")
    return info


def extract_all(path: str, dest: str, fmt: Optional[str] = None,
                max_total_bytes: int = 512 * 1024 * 1024,
                max_members: int = 5000) -> Dict:
    """Extract an archive, with limits.

    Refuses paths that escape the destination (zip-slip). Records what was
    written and what was skipped, and why.
    """
    result = {"extracted": 0, "skipped": 0, "skipped_reasons": {},
              "bytes": 0, "dest": dest, "error": None,
              "tool_used": None, "notes": []}

    def skip(reason: str):
        result["skipped"] += 1
        result["skipped_reasons"][reason] = \
            result["skipped_reasons"].get(reason, 0) + 1

    try:
        os.makedirs(dest, exist_ok=True)
    except OSError as e:
        result["error"] = f"cannot create destination: {e}"
        return result

    dest_real = os.path.realpath(dest)

    def safe_join(base: str, name: str) -> Optional[str]:
        """Join and confirm the result stays inside ``base``."""
        target = os.path.realpath(os.path.join(base, name))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            return None
        return target

    if zipfile.is_zipfile(path):
        result["tool_used"] = "python zipfile"
        try:
            with zipfile.ZipFile(path) as zf:
                for zi in zf.infolist():
                    if result["extracted"] >= max_members:
                        skip("member limit reached")
                        break
                    if zi.is_dir():
                        continue
                    target = safe_join(dest, zi.filename)
                    if target is None:
                        skip("path escapes destination")
                        continue
                    if result["bytes"] + zi.file_size > max_total_bytes:
                        skip("total size limit reached")
                        continue
                    try:
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        # Stream to disk and enforce a real ceiling: a zip can
                        # declare a small size and decompress to far more, so
                        # the limit is applied to bytes actually written.
                        written = 0
                        overrun = False
                        with zf.open(zi) as src, open(target, "wb") as out:
                            while True:
                                chunk = src.read(1 << 20)
                                if not chunk:
                                    break
                                written += len(chunk)
                                if (written > max_total_bytes or
                                        result["bytes"] + written >
                                        max_total_bytes):
                                    overrun = True
                                    break
                                out.write(chunk)
                        if overrun:
                            skip("decompressed size limit reached")
                            try:
                                os.unlink(target)
                            except OSError:
                                pass
                        else:
                            result["bytes"] += written
                            result["extracted"] += 1
                    except (OSError, RuntimeError, zipfile.BadZipFile,
                            NotImplementedError) as e:
                        skip(f"extract error: {type(e).__name__}")
        except (zipfile.BadZipFile, OSError) as e:
            result["error"] = f"zip open failed: {e}"
        return result

    if tarfile.is_tarfile(path):
        result["tool_used"] = "python tarfile"
        try:
            with tarfile.open(path) as tf:
                for ti in tf:
                    if result["extracted"] >= max_members:
                        skip("member limit reached")
                        break
                    if ti.isdir():
                        continue
                    # Refuse links and devices: they can escape the sandbox or
                    # touch the host filesystem.
                    if ti.issym() or ti.islnk():
                        skip("link member refused")
                        continue
                    if not (ti.isfile() or ti.isreg()):
                        skip("non-regular member refused")
                        continue
                    target = safe_join(dest, ti.name)
                    if target is None:
                        skip("path escapes destination")
                        continue
                    if result["bytes"] + ti.size > max_total_bytes:
                        skip("total size limit reached")
                        continue
                    try:
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        src = tf.extractfile(ti)
                        if src is None:
                            skip("unreadable member")
                            continue
                        with src, open(target, "wb") as out:
                            out.write(src.read())
                        result["bytes"] += ti.size
                        result["extracted"] += 1
                    except OSError as e:
                        skip(f"extract error: {type(e).__name__}")
        except (tarfile.TarError, OSError) as e:
            result["error"] = f"tar open failed: {e}"
        return result

    result["error"] = f"archive format {fmt or 'unknown'} is not readable with the Python standard library"
    if fmt in EXTERNAL_FOR:
        result["notes"].append(f"could be extracted with: {EXTERNAL_FOR[fmt]}")
    return result


def iter_member_paths(archive_path: str, max_members: int = 20000) -> List[str]:
    """Convenience: just the member names of a zip or tar."""
    names: List[str] = []
    if zipfile.is_zipfile(archive_path):
        try:
            with zipfile.ZipFile(archive_path) as zf:
                for zi in zf.infolist()[:max_members]:
                    names.append(zi.filename)
        except (zipfile.BadZipFile, OSError):
            return names
    elif tarfile.is_tarfile(archive_path):
        try:
            with tarfile.open(archive_path) as tf:
                for ti in tf:
                    if len(names) >= max_members:
                        break
                    names.append(ti.name)
        except (tarfile.TarError, OSError):
            return names
    return names


def interesting_members(names: List[str]) -> Dict[str, List[str]]:
    """Bucket archive members by what an analyst would want to look at first."""
    buckets: Dict[str, List[str]] = {
        "native_libraries": [], "manifests": [], "dex": [], "certificates": [],
        "unity": [], "configs": [], "assets": [], "scripts": [],
    }
    for n in names:
        low = n.lower()
        if low.endswith((".so", ".dll", ".dylib", ".exe")):
            buckets["native_libraries"].append(n)
        if os.path.basename(low) in ("androidmanifest.xml", "manifest.json"):
            buckets["manifests"].append(n)
        if low.endswith(".dex"):
            buckets["dex"].append(n)
        if "/meta-inf/" in low or low.startswith("meta-inf/"):
            buckets["certificates"].append(n)
        if "il2cpp" in low or low.endswith("global-metadata.dat") \
                or "/unity" in low:
            buckets["unity"].append(n)
        if low.endswith((".json", ".xml", ".ini", ".cfg", ".conf", ".yml",
                         ".yaml", ".properties", ".plist")):
            buckets["configs"].append(n)
        if "/assets/" in low or low.startswith("assets/"):
            buckets["assets"].append(n)
        if low.endswith((".js", ".mjs", ".html", ".css", ".php")):
            buckets["scripts"].append(n)
    return {k: v for k, v in buckets.items() if v}