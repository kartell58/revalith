"""
_formats.py -- identify files by content, and characterise what we cannot.

Identification is by magic bytes first, extension second, and the two are
reported separately so a mismatch is visible. An unrecognised file is
described (``unknown``) with the evidence that made it unrecognised, never
guessed into a category.

Also provides the entropy analysis used for prioritisation. Entropy alone is
never treated as proof of encryption: :func:`classify_blob` requires compound
conditions before it suggests compression or encryption.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# (offset, magic, format, note)
MAGICS: List[Tuple[int, bytes, str, str]] = [
    (0, b"\x7fELF", "elf", "Executable and Linkable Format"),
    (0, b"MZ", "pe", "DOS/PE executable (signature verified separately)"),
    (0, b"\x7fELF", "elf", ""),
    (0, b"\xfe\xed\xfa\xce", "macho", "Mach-O 32-bit BE"),
    (0, b"\xfe\xed\xfa\xcf", "macho", "Mach-O 64-bit BE"),
    (0, b"\xce\xfa\xed\xfe", "macho", "Mach-O 32-bit LE"),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O 64-bit LE"),
    (0, b"\xca\xfe\xba\xbe", "macho-fat", "Mach-O universal (FAT)"),
    (0, b"\xca\xfe\xba\xbf", "macho-fat", "Mach-O universal 64-bit"),
    (0, b"dex\n", "dex", "Dalvik Executable"),
    (0, b"cdex", "cdex", "CompactDex"),
    (0, b"PK\x03\x04", "zip", "ZIP / APK / JAR / AAB / DOCX"),
    (0, b"PK\x05\x06", "zip", "ZIP (empty archive)"),
    (0, b"PK\x07\x08", "zip", "ZIP (spanned)"),
    (0, b"\x1f\x8b", "gzip", "gzip"),
    (0, b"\xfd7zXZ\x00", "xz", "XZ"),
    (0, b"BZh", "bzip2", "bzip2"),
    (0, b"\x5d\x00\x00", "lzma", "LZMA alone"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (0, b"Rar!\x1a\x07", "rar", "RAR archive"),
    (0, b"\x00\x61\x73\x6d", "wasm", "WebAssembly"),
    (0, b"SQLite format 3\x00", "sqlite", "SQLite database"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2", "OLE2 compound file"),
    (0, b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (0, b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (0, b"GIF87a", "gif", "GIF image"),
    (0, b"GIF89a", "gif", "GIF image"),
    (0, b"RIFF", "riff", "RIFF container (WAV/AVI/WEBP)"),
    (0, b"OggS", "ogg", "Ogg container"),
    (0, b"fLaC", "flac", "FLAC audio"),
    (0, b"ID3", "mp3", "MP3 audio"),
    (0, b"\x1a\x45\xdf\xa3", "matroska", "Matroska/WebM"),
    (0, b"FLV\x01", "flv", "FLV video"),
    (0, b"\x00\x00\x01\xba", "mpeg-ps", "MPEG program stream"),
    (0, b"\x00\x00\x01\xb3", "mpeg-video", "MPEG video"),
    (0, b"ftyp", "mp4", "ISO base media (MP4/MOV/HEIF)"),
    (4, b"ftyp", "mp4", "ISO base media (MP4/MOV/HEIF)"),
    (0, b"wOFF", "woff", "WOFF font"),
    (0, b"wOF2", "woff2", "WOFF2 font"),
    (0, b"\x00\x01\x00\x00\x00", "ttf", "TrueType font"),
    (0, b"OTTO", "otf", "OpenType font"),
    (0, b"<!DOCTYPE", "html", "HTML text"),
    (0, b"<?xml", "xml", "XML text"),
    (0, b"{\\rtf", "rtf", "RTF"),
    (0, b"ustar", "tar", "POSIX tar (at offset 257)"),
    (257, b"ustar", "tar", "POSIX tar"),
    (0, b"MSCF", "cab", "Microsoft Cabinet"),
    (0, b"\xed\xab\xee\xdb", "rpm", "RPM package"),
    (0, b"!<arch>", "ar", "Unix archive (static libraries)"),
    (0, b"dex\n035\x00", "dex", "Dalvik Executable (035)"),
]

# Unity / IL2CPP signatures. Names are what the evidence supports.
UNITY_MAGICS = [
    (0, b"UnityFS", "unity-assetbundle", "Unity AssetBundle"),
    (0, b"UnityWeb", "unity-assetbundle", "Unity web asset"),
    (0, b"UnityRaw", "unity-assetbundle", "Unity raw asset"),
    (0, b"UnityArchive", "unity-assetbundle", "Unity archive"),
]

IL2CPP_METADATA_MAGIC = b"\xAF\x1B\xB1\xFA"   # standard global-metadata header

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tga", ".ktx",
              ".dds", ".astc", ".svg", ".psd"}
AUDIO_EXTS = {".wav", ".ogg", ".mp3", ".flac", ".aac", ".m4a", ".opus", ".wma"}
VIDEO_EXTS = {".mp4", ".webm", ".mov", ".avi", ".mkv", ".flv"}
TEXT_EXTS = {".txt", ".json", ".xml", ".html", ".htm", ".css", ".js", ".mjs",
             ".csv", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".properties",
             ".md", ".sh", ".py", ".lua", ".glsl", ".shader", ".hlsl"}
CONFIG_EXTS = {".json", ".xml", ".ini", ".cfg", ".conf", ".yml", ".yaml",
               ".properties", ".plist", ".env"}
DOC_EXTS = {".txt", ".md", ".pdf", ".json", ".xml", ".csv"}


@dataclass
class Ident:
    """Identification result for one file."""
    path: str
    size: int = 0
    fmt: str = "unknown"
    fmt_detail: str = ""
    magic_offset: Optional[int] = None
    ext: str = ""
    ext_matches_content: Optional[bool] = None   # None = unknown
    entropy: Optional[float] = None
    is_text: bool = False
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "size": self.size,
            "format": self.fmt,
            "format_detail": self.fmt_detail or None,
            "magic_offset": self.magic_offset,
            "extension": self.ext or None,
            "extension_agrees_with_content": self.ext_matches_content,
            "entropy": self.entropy,
            "is_text": self.is_text,
            "warnings": self.warnings or None,
        }


def entropy(data: bytes) -> Optional[float]:
    """Shannon entropy in bits per byte (0.0 - 8.0).

    None is returned for empty input because entropy of nothing is not a
    measurement, it is a placeholder.
    """
    if not data:
        return None
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return round(h, 4)


def looks_textual(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head:
        return False
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(head) > 0.85


def identify(path: str, head: Optional[bytes] = None,
             size: Optional[int] = None) -> Ident:
    """Identify one file by content.

    ``head`` may be supplied to avoid a second read when the caller already
    has the first bytes. Never raises for a missing or unreadable file; it
    returns an Ident with ``fmt='unknown'`` and a warning.
    """
    ident = Ident(path=path, ext=os.path.splitext(path)[1].lower())
    try:
        st = os.stat(path)
        ident.size = st.st_size if size is None else size
    except OSError as e:
        ident.warnings.append(f"stat failed: {e}")
        return ident

    try:
        with open(path, "rb") as fh:
            data = head if head is not None else fh.read(512)
    except OSError as e:
        ident.warnings.append(f"read failed: {e}")
        return ident

    if not data:
        ident.fmt = "empty"
        ident.warnings.append("file is empty; nothing to identify")
        return ident

    ident.is_text = looks_textual(data)
    # Entropy is only informative for a reasonably sized sample; for small
    # files the sample is the whole file and the number is near-meaningless.
    ident.entropy = entropy(data)

    for off, magic, fmt, note in MAGICS:
        if len(data) >= off + len(magic) and data[off:off + len(magic)] == magic:
            ident.fmt = fmt
            ident.fmt_detail = note
            ident.magic_offset = off
            break
    else:
        for off, magic, fmt, note in UNITY_MAGICS:
            if data[off:off + len(magic)] == magic:
                ident.fmt = fmt
                ident.fmt_detail = note
                ident.magic_offset = off
                break

    if ident.fmt == "unknown" and ident.is_text:
        # Text is identified by character distribution, not by magic. Report it
        # as a text format, and refine by sniffing the first non-blank line.
        ident.fmt = "text"
        ident.fmt_detail = _text_subtype(data)
        if ident.ext in (".json",):
            ident.fmt = "json"
        elif ident.ext in (".xml",):
            ident.fmt = "xml"
        elif ident.ext in (".js", ".mjs"):
            ident.fmt = "javascript"

    ident.ext_matches_content = _ext_agrees(ident)
    if ident.ext_matches_content is False:
        ident.warnings.append(
            f"extension '{ident.ext}' disagrees with detected content "
            f"'{ident.fmt}'")
    return ident


def _text_subtype(data: bytes) -> str:
    head = data.lstrip()[:200].lower()
    if head.startswith(b"{") or head.startswith(b"["):
        return "JSON-like text"
    if head.startswith(b"<?xml") or head.startswith(b"<svg"):
        return "XML-like text"
    if head.startswith(b"#!") or head.startswith(b"#include"):
        return "source/script text"
    if head.startswith(b"//") or head.startswith(b"/*"):
        return "source text"
    return "text"


def _ext_agrees(ident: Ident) -> Optional[bool]:
    """Does the extension corroborate the content identification?

    Returns None when the extension carries no expectation (unknown).
    """
    ext = ident.ext
    fmt = ident.fmt
    if not ext:
        return None
    expected = {
        ".elf": {"elf"}, ".so": {"elf"}, ".dylib": {"elf", "macho"},
        ".exe": {"pe"}, ".dll": {"pe"}, ".sys": {"pe"},
        ".dex": {"dex"}, ".apk": {"zip"}, ".aab": {"zip"}, ".jar": {"zip"},
        ".zip": {"zip"}, ".gz": {"gzip"}, ".xz": {"xz"}, ".bz2": {"bzip2"},
        ".7z": {"7z"}, ".rar": {"rar"}, ".tar": {"tar"}, ".db": {"sqlite"},
        ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"},
        ".gif": {"gif"}, ".wasm": {"wasm"}, ".pdf": {"pdf"},
        ".macho": {"macho"}, ".sqlite": {"sqlite"},
        ".html": {"html"}, ".js": {"javascript"}, ".json": {"json"},
        ".xml": {"xml"},
    }.get(ext)
    if expected is None:
        # No expectation recorded: cannot contradict, cannot confirm.
        return None
    if fmt in expected:
        return True
    if fmt == "unknown":
        return None
    return False


def classify_blob(ident: Ident) -> Dict:
    """Characterise a blob we could not identify.

    This is the honest alternative to guessing. It reports entropy and the
    specific conditions that would be needed before "compressed" or
    "encrypted" could be claimed, and it never asserts either on its own.
    """
    size = ident.size or 0
    ent = ident.entropy
    notes: List[str] = []
    confidence = "low"

    if ident.fmt != "unknown":
        return {"classification": "identified", "reason": f"content is {ident.fmt}",
                "confidence": "high"}

    if ent is None:
        return {"classification": "unknown", "reason": "no entropy: file empty or unreadable",
                "confidence": "very low"}

    high_entropy = ent >= 7.0
    if high_entropy:
        notes.append(f"high entropy ({ent} bits/byte)")
    if size >= 1024:
        notes.append(f"size {size} bytes")
    if not ident.is_text:
        notes.append("not textual")
    notes.append("no recognised magic bytes")

    if high_entropy and size >= 1024 and not ident.is_text:
        classification = "unknown-high-entropy"
        reason = (
            "high entropy, no known magic, no textual structure. This is "
            "consistent with compressed, encrypted or custom-encoded data, "
            "but entropy alone does not distinguish those.")
        confidence = "low"
    elif high_entropy:
        classification = "unknown-high-entropy-small"
        reason = (f"entropy {ent} on a {size}-byte sample; too small a sample "
                  "to draw a conclusion")
        confidence = "very low"
    else:
        classification = "unknown-low-entropy"
        reason = (f"entropy {ent} and no known magic. Low entropy with no "
                  "signature suggests a custom or little-endian-format "
                  "container rather than encryption.")
        confidence = "low"

    return {
        "classification": classification,
        "entropy": ent,
        "size": size,
        "observed": notes,
        "reason": reason,
        "confidence": confidence,
        "next_test": (
            "compare byte-frequency distribution against known compressors; "
            "check whether the first bytes repeat at a fixed stride"
            if high_entropy else
            "check for a length prefix, magic at a non-zero offset, or a "
            "pointer table"),
    }


def category_of(fmt: str, ext: str = "") -> str:
    """Coarse category for routing to deeper analysers."""
    ext = ext or ""
    if fmt in ("elf", "pe", "macho", "macho-fat") or ext in (".so", ".dll",
                                                             ".dylib", ".exe"):
        return "binary"
    if fmt in ("zip", "tar", "gzip", "xz", "bzip2", "7z", "rar", "ar", "cab",
               "lzma"):
        return "archive"
    if fmt in ("apk", "aab", "dex", "cdex"):
        return "android"
    if fmt == "sqlite":
        return "database"
    if fmt in IMAGE_EXTS or ext in IMAGE_EXTS:
        return "image"
    if fmt in ("riff", "ogg", "flac", "mp3") or ext in AUDIO_EXTS:
        return "audio"
    if fmt in ("matroska", "flv", "mpeg-ps", "mpeg-video", "mp4") or ext in VIDEO_EXTS:
        return "video"
    if fmt in ("png", "jpeg", "gif"):
        return "image"
    if fmt in ("json", "xml", "javascript", "html", "text"):
        return "text"
    if fmt in CONFIG_EXTS:
        return "config"
    if fmt in ("unity-assetbundle",):
        return "assetbundle"
    if fmt == "wasm":
        return "webassembly"
    if fmt in TEXT_EXTS:
        return "text"
    return "other"


def is_probably_archive(fmt: str) -> bool:
    return fmt in ("zip", "tar", "gzip", "xz", "bzip2", "7z", "rar", "ar",
                   "cab", "lzma")


def is_binary_container(fmt: str) -> bool:
    return fmt in ("elf", "pe", "macho", "macho-fat")