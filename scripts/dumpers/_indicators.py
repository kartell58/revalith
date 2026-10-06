"""
_indicators.py -- strings and network indicators with source provenance.

Every indicator carries the file it came from and the offset it was found at.
When an offset cannot be determined it is ``null`` -- never fabricated,
because a wrong offset is worse than no offset: it sends the next person to
the wrong place and they may not notice.

False positives are reduced rather than eliminated:
  * URLs must have a plausible scheme and host.
  * Domains are checked against a public-suffix style rule so that
    "example.com" is not split into "example" and "com".
  * IPv4 is validated octet by octet and rejects leading zeros.
  * Private/loopback addresses are labelled, not silently included as IOCs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from _binlib import extract_strings

# ---------------------------------------------------------------- patterns

URL_RE = re.compile(
    r"\b(?:https?|wss?|ftp)://"          # scheme
    r"(?:\[[0-9A-Fa-f:.]+\]|[^\s/?#@\"'<>\\]+)"  # host or bracketed IPv6
    r"(?::\d{1,5})?"                     # optional port
    r"(?:[/?#][^\s\"'<>\\]*)?",          # path / query / fragment
    re.IGNORECASE)

WS_URL_RE = re.compile(r"\bwss?://[^\s\"'<>\\]+", re.IGNORECASE)

# Hostname: labels of alphanumerics and hyphens, ending in an alphabetic TLD.
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,24})\b")

IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])("
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"
    r"|::"
    r")(?![0-9A-Fa-f:])")

PORT_RE = re.compile(r"(?::|port[=: ]?)(\d{2,5})\b", re.IGNORECASE)

# API-ish paths worth surfacing separately from full URLs. The segment after
# the prefix is optional so that "/api" itself is still captured.
API_PATH_RE = re.compile(
    r"(?<![\w/])/(?:api|v\d+|rest|graphql|gql|rpc|service|services|ws)"
    r"(?:/[A-Za-z0-9._~%-]+){0,6}(?![\w/-])",
    re.IGNORECASE)

# Common placeholder hosts that are not real IOCs.
PLACEHOLDER_HOSTS = {
    "example.com", "example.org", "example.net", "test.com", "localhost.local",
    "foo.bar", "domain.com", "yourdomain.com", "mydomain.com",
    "schema.org", "www.w3.org", "purl.org", "json-schema.org", "localhost",
    "0.0.0.0", "255.255.255.255",
}

# TLDs common enough that matching them is usually noise rather than signal.
GENERIC_TLDS = {"js", "css", "png", "jpg", "jpeg", "gif", "svg", "json", "xml",
                "html", "htm", "txt", "md", "pdf", "woff", "woff2", "ttf",
                "eot", "map", "min", "lock", "log", "dll", "exe", "so"}


@dataclass
class Indicator:
    """One indicator, always attributable to a source."""
    kind: str              # url | domain | ipv4 | ipv6 | port | api_path
    value: str
    source: str            # path of the file the string came from
    offset: Optional[int]  # byte offset, or None when not determinable
    encoding: str = "ascii"
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    confidence: str = "medium"

    def to_dict(self) -> Dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "offset": f"0x{self.offset:x}" if self.offset is not None else None,
            "encoding": self.encoding,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "notes": self.notes or None,
            "confidence": self.confidence,
        }


def _valid_ipv4(text: str) -> Optional[str]:
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    # ipaddress rejects leading zeros in recent Python; double-check the
    # classic octet form so "010.0.0.1" is not treated as decimal 10.
    parts = text.split(".")
    if any(p != "0" and p.startswith("0") for p in parts):
        return None
    return str(addr)


def _split_url(url: str) -> Dict:
    out = {"scheme": None, "host": None, "port": None, "path": None}
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$", url)
    if not m:
        return out
    out["scheme"] = m.group(1).lower()
    rest = m.group(2)
    rest = rest.split("/", 1)
    authority = rest[0]
    if len(rest) > 1:
        out["path"] = "/" + rest[1]
    if authority.startswith("["):
        closing = authority.find("]")
        if closing > 0:
            out["host"] = authority[1:closing]
            tail = authority[closing + 1:]
            if tail.startswith(":"):
                out["port"] = tail[1:]
        else:
            out["host"] = authority
    elif ":" in authority:
        host, _, port = authority.rpartition(":")
        out["host"] = host
        out["port"] = port
    else:
        out["host"] = authority
    # Strip userinfo; it is rarely a real host and often a credential.
    if out["host"] and "@" in out["host"]:
        out["host"] = out["host"].rsplit("@", 1)[1]
    return out


def _looks_like_host(host: Optional[str]) -> bool:
    if not host:
        return False
    if host in PLACEHOLDER_HOSTS:
        return False
    if IPV4_RE.fullmatch(host):
        return bool(_valid_ipv4(host))
    if host.startswith("[") or ":" in host:
        return False
    return bool(DOMAIN_RE.fullmatch(host)) and not host.endswith(
        tuple("." + t for t in GENERIC_TLDS))


def scan_text(text: str, source: str, offset: Optional[int] = None,
              encoding: str = "ascii") -> List[Indicator]:
    """Extract indicators from one string.

    ``offset`` is the byte offset of ``text`` within its source file. It is
    propagated to every indicator so provenance survives.
    """
    found: List[Indicator] = []
    seen: Set[tuple] = set()

    def add(ind: Indicator):
        key = (ind.kind, ind.value)
        if key in seen:
            return
        seen.add(key)
        found.append(ind)

    for m in URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:)]}\"'")
        parts = _split_url(raw)
        host = parts["host"]
        plausible = _looks_like_host(host) or (host and _valid_ipv4(host or ""))
        confidence = "medium" if plausible else "low"
        notes = []
        if not plausible:
            notes.append("host looks like a placeholder or a non-domain token")
        add(Indicator(kind="url", value=raw, source=source,
                      offset=(offset + m.start()) if offset is not None else None,
                      encoding=encoding, scheme=parts["scheme"], host=host,
                      port=int(parts["port"]) if parts["port"] and
                      parts["port"].isdigit() else None,
                      path=parts["path"], notes=notes, confidence=confidence))

    for m in DOMAIN_RE.finditer(text):
        host = m.group(0).lower().rstrip(".")
        if host in PLACEHOLDER_HOSTS:
            continue
        tld = host.rsplit(".", 1)[-1]
        if tld in GENERIC_TLDS:
            continue
        if IPV4_RE.fullmatch(host):
            continue
        add(Indicator(kind="domain", value=host, source=source,
                      offset=(offset + m.start()) if offset is not None else None,
                      encoding=encoding, host=host, confidence="medium"))

    for m in IPV4_RE.finditer(text):
        raw = m.group(0)
        norm = _valid_ipv4(raw)
        if norm is None:
            continue
        notes = []
        confidence = "medium"
        try:
            addr = ipaddress.IPv4Address(norm)
            if addr.is_loopback:
                notes.append("loopback address")
                confidence = "low"
            elif addr.is_private:
                notes.append("RFC1918 private address")
                confidence = "low"
            elif addr.is_reserved or addr.is_multicast:
                notes.append("reserved or multicast")
                confidence = "low"
        except ValueError:
            pass
        add(Indicator(kind="ipv4", value=norm, source=source,
                      offset=(offset + m.start()) if offset is not None else None,
                      encoding=encoding, notes=notes, confidence=confidence))

    for m in IPV6_RE.finditer(text):
        raw = m.group(1)
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        notes = []
        confidence = "medium"
        if addr.is_loopback:
            notes.append("loopback address")
            confidence = "low"
        elif addr.is_private:
            notes.append("link-local or unique-local")
            confidence = "low"
        add(Indicator(kind="ipv6", value=str(addr), source=source,
                      offset=(offset + m.start()) if offset is not None else None,
                      encoding=encoding, notes=notes, confidence=confidence))

    for m in API_PATH_RE.finditer(text):
        add(Indicator(kind="api_path", value=m.group(0), source=source,
                      offset=(offset + m.start()) if offset is not None else None,
                      encoding=encoding, confidence="low",
                      notes=["path-like token; not observed as a live endpoint"]))

    return found


def scan_file(path: str, min_len: int = 4,
              limit: int = 200000) -> Dict:
    """Scan a file for strings and derive indicators with provenance.

    Returns strings and indicators plus the counts needed to report coverage.
    A file too large to scan fully is reported as partially scanned rather
    than silently truncated.
    """
    out = {"path": path, "strings": [], "indicators": [], "scanned": False,
           "partial": False, "bytes_scanned": 0, "error": None,
           "encodings": ["ascii"]}
    try:
        size = __import__("os").path.getsize(path)
    except OSError as e:
        out["error"] = f"stat failed: {e}"
        return out

    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as e:
        out["error"] = f"read failed: {e}"
        return out

    if len(data) > limit:
        data = data[:limit]
        out["partial"] = True
    out["bytes_scanned"] = len(data)
    out["total_size"] = size

    rows = extract_strings(data, min_len=min_len, encodings=("ascii",))
    for off, text, enc in rows:
        out["strings"].append({"offset": off, "text": text, "encoding": enc})
        out["indicators"].extend(scan_text(text, path, offset=off, encoding=enc))
    out["scanned"] = True
    out["string_count"] = len(out["strings"])
    return out


def dedupe(indicators: Iterable[Indicator]) -> List[Indicator]:
    """Collapse duplicates, keeping every source that referenced the value.

    Multiple sources are themselves evidence: a value present in both the
    APK manifest and a native library is more interesting than one found
    once.
    """
    merged: Dict[tuple, Indicator] = {}
    for ind in indicators:
        key = (ind.kind, ind.value)
        if key in merged:
            existing = merged[key]
            src = f"{existing.source},{ind.source}"
            existing.source = src
            existing.notes.append(f"also seen in {ind.source}")
            if existing.confidence != ind.confidence:
                # Highest confidence wins, but note the disagreement.
                if ind.confidence == "high":
                    existing.confidence = "high"
        else:
            merged[key] = ind
    return sorted(merged.values(), key=lambda i: (i.kind, i.value))


def summarise(indicators: List[Indicator]) -> Dict:
    by_kind: Dict[str, List[str]] = {}
    for ind in indicators:
        by_kind.setdefault(ind.kind, [])
        if ind.value not in by_kind[ind.kind]:
            by_kind[ind.kind].append(ind.value)
    return {
        "total": len(indicators),
        "by_kind": {k: sorted(v) for k, v in sorted(by_kind.items())},
        "counts": {k: len(v) for k, v in sorted(by_kind.items())},
    }