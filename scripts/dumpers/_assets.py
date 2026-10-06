"""
_assets.py -- catalogue assets and data files, hashing what matters.

Purpose is prioritisation, not identification. An analyst needs to know which
files are large, unusual, encrypted-looking or configuration-bearing, and
which are already-known formats. For anything unrecognised the honest
answer is ``unknown`` with the evidence recorded.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, List, Optional

import _formats
from _formats import classify_blob, identify

HASH_CHUNK = 1 << 20
MAX_HASH_BYTES = 256 * 1024 * 1024


def hashes(path: str, full: bool = True) -> Dict:
    """Hash a file. Reports which algorithms were computed."""
    out: Dict = {"path": path, "size": None, "md5": None, "sha1": None,
                 "sha256": None, "error": None, "truncated": False}
    try:
        size = os.path.getsize(path)
        out["size"] = size
    except OSError as e:
        out["error"] = f"stat failed: {e}"
        return out
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        read = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                if full:
                    md5.update(chunk)
                    sha1.update(chunk)
                sha256.update(chunk)
                if read >= MAX_HASH_BYTES:
                    out["truncated"] = True
                    break
        if full and not out["truncated"]:
            out["md5"] = md5.hexdigest()
            out["sha1"] = sha1.hexdigest()
        out["sha256"] = sha256.hexdigest()
        if out["truncated"]:
            out["error"] = (f"file larger than {MAX_HASH_BYTES} bytes; "
                            "sha256 covers the first "
                            f"{MAX_HASH_BYTES} bytes only")
    except OSError as e:
        out["error"] = f"read failed: {e}"
    return out


def catalogue_file(path: str, root: Optional[str] = None,
                   do_hash: bool = True) -> Dict:
    """Identify one file and produce the catalogue record."""
    ident = identify(path)
    rel = os.path.relpath(path, root) if root else path
    rec: Dict = {
        "path": rel,
        "size": ident.size,
        "format": ident.fmt,
        "format_detail": ident.fmt_detail or None,
        "extension": ident.ext or None,
        "extension_agrees_with_content": ident.ext_matches_content,
        "entropy": ident.entropy,
        "is_text": ident.is_text,
        "category": _formats.category_of(ident.fmt, ident.ext),
        "warnings": ident.warnings or None,
    }
    if do_hash and ident.size is not None:
        h = hashes(path, full=ident.size <= MAX_HASH_BYTES)
        rec["sha256"] = h["sha256"]
        if h.get("md5"):
            rec["md5"] = h["md5"]
        if h.get("error"):
            rec["hash_note"] = h["error"]
    if ident.fmt == "unknown":
        rec["unknown_analysis"] = classify_blob(ident)
    return rec


def catalogue_tree(root: str, max_files: int = 20000,
                   skip_dirs: Optional[List[str]] = None) -> List[Dict]:
    """Catalogue every file under ``root``."""
    skip = set(skip_dirs or [".git", "__pycache__", "node_modules"])
    out: List[Dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if len(out) >= max_files:
                return out
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            try:
                out.append(catalogue_file(full, root=root))
            except OSError as e:
                out.append({"path": os.path.relpath(full, root),
                            "size": None, "format": "unknown",
                            "error": f"{type(e).__name__}: {e}"})
    return out


def summarise(catalogue: List[Dict]) -> Dict:
    """Aggregate counts by category and format, and flag what stands out."""
    by_category: Dict[str, int] = {}
    by_format: Dict[str, int] = {}
    total_bytes = 0
    unknown: List[Dict] = []
    mismatched: List[Dict] = []
    high_entropy: List[Dict] = []

    for rec in catalogue:
        if rec.get("error"):
            continue
        cat = rec.get("category", "other")
        fmt = rec.get("format", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        by_format[fmt] = by_format.get(fmt, 0) + 1
        total_bytes += rec.get("size") or 0
        if fmt == "unknown":
            unknown.append({"path": rec["path"],
                            "size": rec.get("size"),
                            "entropy": rec.get("entropy"),
                            "analysis": rec.get("unknown_analysis")})
        if rec.get("extension_agrees_with_content") is False:
            mismatched.append({"path": rec["path"],
                               "extension": rec.get("extension"),
                               "content_format": fmt})
        ent = rec.get("entropy")
        if ent is not None and ent >= 7.5 and \
                (rec.get("size") or 0) >= 4096:
            high_entropy.append({"path": rec["path"], "size": rec.get("size"),
                                 "entropy": ent, "format": fmt,
                                 "note": "high entropy; consistent with "
                                         "compressed or encrypted data but "
                                         "not proof of either"})

    return {
        "file_count": len(catalogue),
        "total_bytes": total_bytes,
        "by_category": dict(sorted(by_category.items(),
                                   key=lambda kv: -kv[1])),
        "by_format": dict(sorted(by_format.items(),
                                 key=lambda kv: -kv[1])),
        "unknown_format_files": unknown[:200],
        "unknown_format_count": len(unknown),
        "extension_mismatches": mismatched[:50],
        "high_entropy_files": sorted(high_entropy,
                                     key=lambda r: -(r["entropy"] or 0))[:50],
        "high_entropy_count": len(high_entropy),
    }