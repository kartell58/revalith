"""
_weblib.py -- parsing helpers for web reconnaissance.

Everything here is passive or explicitly opt-in. The module never contacts a
host on import; network calls live in ``web-enum.py`` and are guarded by
``--active`` and an explicit host allowlist.

The distinction the skill cares about most:

* **Passive** -- reading what is already published: DNS records, certificate
  transparency entries, ``robots.txt``, ``sitemap.xml``, the site's own
  JavaScript. Nothing is sent to the target beyond ordinary requests for
  documents it publishes.
* **Active** -- sending crafted requests to elicit behaviour: directory
  probing, option fuzzing, header variations. This is interaction, and it is
  logged separately so a reader can tell what was asked.

Technology detection returns *evidence*, never a bare conclusion. A server
header is a self-declaration; it is reported as an observation with its
confidence, not as proof of what is running behind it.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Technology fingerprints. Each entry states what the match means and how
# much weight it carries. A "self_declaration" fingerprint is only as good as
# the target's honesty, which is why it is labelled as such.
# ---------------------------------------------------------------------------

TECH_FINGERPRINTS: List[Dict] = [
    # Server / infrastructure, from headers the server chose to send.
    {"id": "nginx", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)nginx"}],
     "confidence": "medium",
     "caveat": "Server header is set by the operator and can be spoofed or "
               "replaced by a CDN."},
    {"id": "Apache", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)apache"}],
     "confidence": "medium", "caveat": "Header can be spoofed."},
    {"id": "IIS", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)microsoft-iis"},
                  {"header": "x-powered-by", "pattern": r"(?i)asp\.net"}],
     "confidence": "medium", "caveat": "Header can be spoofed."},
    {"id": "Caddy", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)caddy"}],
     "confidence": "medium", "caveat": "Header can be spoofed."},
    {"id": "OpenResty", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)openresty"}],
     "confidence": "medium", "caveat": "Header can be spoofed."},
    {"id": "LiteSpeed", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)litespeed"}],
     "confidence": "medium", "caveat": "Header can be spoofed."},
    {"id": "Envoy", "class": "proxy", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)envoy"}],
     "confidence": "medium", "caveat": "Header can be spoofed."},

    # CDN / edge: some are strongly implied by headers the CDN itself adds.
    {"id": "Cloudflare", "class": "cdn", "kind": "structural",
     "evidence": [{"header": "cf-ray", "pattern": r"."},
                  {"header": "cf-cache-status", "pattern": r"."},
                  {"header": "server", "pattern": r"(?i)cloudflare"}],
     "confidence": "high",
     "caveat": "cf-ray is a Cloudflare-specific header; a spoofed copy is "
               "possible but unusual."},
    {"id": "Akamai", "class": "cdn", "kind": "structural",
     "evidence": [{"header": "x-akamai-transformed", "pattern": r"."},
                  {"header": "akamai-grn", "pattern": r"."}],
     "confidence": "medium"},
    {"id": "Fastly", "class": "cdn", "kind": "structural",
     "evidence": [{"header": "x-served-by", "pattern": r"(?i)fastly"},
                  {"header": "fastly-debug-digest", "pattern": r"."}],
     "confidence": "medium"},
    {"id": "Varnish", "class": "cache", "kind": "structural",
     "evidence": [{"header": "x-varnish", "pattern": r"."},
                  {"header": "age", "pattern": r"^\d+$"},
                  {"header": "via", "pattern": r"(?i)varnish"}],
     "confidence": "low",
     "caveat": "age is also set by other caches; weak evidence alone."},

    # Application frameworks, mostly self-declaration.
    {"id": "PHP", "class": "language", "kind": "self_declaration",
     "evidence": [{"header": "x-powered-by", "pattern": r"(?i)php"}],
     "confidence": "medium", "caveat": "Header often removed by configuration."},
    {"id": "ASP.NET", "class": "framework", "kind": "self_declaration",
     "evidence": [{"header": "x-powered-by", "pattern": r"(?i)asp\.net"},
                  {"header": "x-aspnet-version", "pattern": r"."},
                  {"header": "set-cookie", "pattern": r"(?i)asp\.net_sessionid"},
                  {"header": "set-cookie", "pattern": r"(?i)aspsessionid"}],
     "confidence": "medium"},
    {"id": "Django", "class": "framework", "kind": "self_declaration",
     "evidence": [{"header": "set-cookie", "pattern": r"(?i)csrftoken"},
                  {"header": "x-frame-options", "pattern": r"(?i)deny"}],
     "confidence": "low",
     "caveat": "csrftoken is a Django default but names overlap; low weight."},
    {"id": "Laravel", "class": "framework", "kind": "self_declaration",
     "evidence": [{"header": "set-cookie", "pattern": r"(?i)laravel_session"},
                  {"header": "x-powered-by", "pattern": r"(?i)laravel"}],
     "confidence": "medium"},
    {"id": "Express", "class": "framework", "kind": "self_declaration",
     "evidence": [{"header": "x-powered-by", "pattern": r"(?i)express"}],
     "confidence": "medium", "caveat": "Header often disabled by default."},
    {"id": "Node.js", "class": "runtime", "kind": "self_declaration",
     "evidence": [{"header": "x-powered-by", "pattern": r"(?i)(node|express)"}],
     "confidence": "medium", "caveat": "Header often disabled by default."},
    {"id": "Spring", "class": "framework", "kind": "self_declaration",
     "evidence": [{"header": "x-application-context", "pattern": r"."},
                  {"header": "set-cookie", "pattern": r"(?i)jsessionid"}],
     "confidence": "medium"},
    {"id": "Ruby on Rails", "class": "framework", "kind": "self_declaration",
     "evidence": [{"header": "x-powered-by", "pattern": r"(?i)(phusion|rails)"},
                  {"header": "set-cookie", "pattern": r"(?i)_session_id"}],
     "confidence": "medium"},
    {"id": "Gunicorn", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)gunicorn"}],
     "confidence": "medium"},
    {"id": "Tomcat", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)tomcat"}],
     "confidence": "medium"},
    {"id": "Jetty", "class": "server", "kind": "self_declaration",
     "evidence": [{"header": "server", "pattern": r"(?i)jetty"}],
     "confidence": "medium"},
]

# Body markers for technologies that leave fingerprints in HTML/JS.
BODY_FINGERPRINTS: List[Dict] = [
    {"id": "WordPress", "class": "cms",
     "evidence": [{"pattern": r"(?i)<meta[^>]+name=[\"']generator[\"'][^>]+"
                            r"content=[\"']WordPress", "where": "body"},
                  {"pattern": r"(?i)/wp-content/", "where": "body"},
                  {"pattern": r"(?i)/wp-includes/", "where": "body"}],
     "confidence": "high",
     "caveat": "wp-content paths are distinctive when present."},
    {"id": "Drupal", "class": "cms",
     "evidence": [{"pattern": r"(?i)<meta[^>]+generator[^>]+Drupal", "where": "body"},
                  {"pattern": r"(?i)/sites/(?:default|all)/themes/", "where": "body"}],
     "confidence": "high"},
    {"id": "Joomla", "class": "cms",
     "evidence": [{"pattern": r"(?i)<meta[^>]+generator[^>]+Joomla", "where": "body"}],
     "confidence": "high"},
    {"id": "React", "class": "frontend",
     "evidence": [{"pattern": r"(?i)data-reactroot", "where": "body"},
                  {"pattern": r"(?i)__REACT_DEVTOOLS", "where": "body"}],
     "confidence": "low",
     "caveat": "React leaves few reliable markers without devtools; treat as "
               "weak."},
    {"id": "Angular", "class": "frontend",
     "evidence": [{"pattern": r"<app-root[\s>]", "where": "body"},
                  {"pattern": r"(?i)ng-version", "where": "body"}],
     "confidence": "medium"},
    {"id": "Vue.js", "class": "frontend",
     "evidence": [{"pattern": r"(?i)data-v-[0-9a-f]{8}", "where": "body"},
                  {"pattern": r"(?i)__vue__", "where": "body"}],
     "confidence": "low", "caveat": "data-v attributes are also used by other "
                                    "tooling; weak evidence."},
    {"id": "GraphQL", "class": "api",
     "evidence": [{"pattern": r"(?i)/graphql", "where": "url"},
                  {"pattern": r"(?i)graphql", "where": "js"}],
     "confidence": "low",
     "caveat": "The string graphql appears in client libraries for many "
               "backends; a /graphql path is suggestive, not proof."},
]

COMPILED = []
for _fp in TECH_FINGERPRINTS:
    _c = dict(_fp)
    _c["_regex"] = [(e["header"], re.compile(e["pattern"]))
                    for e in _fp["evidence"]]
    COMPILED.append(_c)

BODY_COMPILED = []
for _fp in BODY_FINGERPRINTS:
    _c = dict(_fp)
    _c["_regex"] = [(e["where"], re.compile(e["pattern"]))
                    for e in _fp["evidence"]]
    BODY_COMPILED.append(_c)

# Default security-header audit. Absence is a finding; presence is not a
# guarantee, and neither is asserted to be.
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "clickjacking protection"),
    ("x-content-type-options", "MIME sniffing protection"),
    ("referrer-policy", "referrer control"),
    ("permissions-policy", "feature policy"),
]


def detect_technologies(headers: Dict[str, str],
                        body: Optional[str] = None,
                        urls: Optional[List[str]] = None) -> List[Dict]:
    """Return technology observations with the evidence that produced them.

    Each result names the exact header or pattern that matched, so a reader
    can check the claim rather than trust it.
    """
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    out: List[Dict] = []

    for fp in COMPILED:
        matched: List[Dict] = []
        for hname, rx in fp["_regex"]:
            val = lowered.get(hname)
            if val is not None and rx.search(val):
                matched.append({"kind": "header", "header": hname,
                                "value": val[:200]})
        if matched:
            out.append({
                "technology": fp["id"], "class": fp["class"],
                "evidence_kind": fp["kind"],
                "confidence": fp["confidence"],
                "observed": matched,
                "caveat": fp.get("caveat"),
                "claim": f"{fp['id']} is likely present. This is "
                         f"{'a structural indicator' if fp['kind'] == 'structural' else 'a self-declared header'}, "
                         f"not proof of the origin server.",
            })

    if body:
        for fp in BODY_COMPILED:
            matched = []
            for where, rx in fp["_regex"]:
                if where == "body" and rx.search(body):
                    matched.append({"kind": "body", "pattern": rx.pattern[:80]})
            if not matched and urls:
                for u in urls:
                    if fp["id"] == "GraphQL" and re.search(r"(?i)/graphql", u):
                        matched.append({"kind": "url", "url": u[:200]})
            if matched:
                out.append({
                    "technology": fp["id"], "class": fp["class"],
                    "evidence_kind": "body_or_url",
                    "confidence": fp["confidence"],
                    "observed": matched,
                    "caveat": fp.get("caveat"),
                    "claim": f"{fp['id']} indicators were found in the "
                             f"response; confirm before relying on it.",
                })
    return out


def audit_security_headers(headers: Dict[str, str]) -> Dict:
    """Report which security headers are present or absent. No verdicts."""
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    present, missing = [], []
    for hname, purpose in SECURITY_HEADERS:
        if hname in lowered:
            present.append({"header": hname, "value": lowered[hname][:300],
                            "purpose": purpose})
        else:
            missing.append({"header": hname, "purpose": purpose})
    return {
        "present": present,
        "missing": missing,
        "note": "A missing header is an observation about this response, not a "
                "verified vulnerability; a CDN or gateway may add headers on "
                "other paths.",
    }


# ---------------------------------------------------------------------------
# Certificate transparency / TLS
# ---------------------------------------------------------------------------

def parse_san_entries(cert: Dict) -> List[str]:
    """Normalise SAN entries from a certificate dict (ssl module shape)."""
    out: List[str] = []
    for kind in ("subjectAltName",):
        entries = cert.get(kind) or ()
        for entry in entries:
            if isinstance(entry, tuple) and len(entry) == 2:
                out.append(f"{entry[0]}:{entry[1]}")
            elif isinstance(entry, str):
                out.append(entry)
    return out


def classify_san(entries: List[str]) -> Dict:
    """Summarise SANs by kind. Wildcards and IP SANs are called out."""
    wildcards, dns, ips, emails, others = [], [], [], [], []
    for e in entries:
        val = e.split(":", 1)[1] if ":" in e and not e.lower().startswith("ip") \
            else e
        low = val.lower()
        if low.startswith("*."):
            wildcards.append(val)
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
            ips.append(val)
        elif "@" in val:
            emails.append(val)
        elif re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", low):
            dns.append(val)
        else:
            others.append(val)
    return {
        "wildcards": sorted(wildcards),
        "dns": sorted(dns),
        "ip": sorted(ips),
        "email": sorted(emails),
        "other": sorted(others),
        "note": "SANs are what the certificate asserts. They are not proof "
                "that the host is the origin, and a name listed here may not "
                "be resolvable or reachable.",
    }


def normalise_cn(host: str) -> str:
    """A host for comparison purposes: lowercase, no trailing dot, no port."""
    h = (host or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(normalise_cn(host))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# robots.txt / sitemap
# ---------------------------------------------------------------------------

ROBOT_RE = re.compile(r"^\s*(allow|disallow|crawl-delay|sitemap)\s*:\s*(.*)$",
                      re.IGNORECASE)
UA_RE = re.compile(r"^\s*user-agent\s*:\s*(.*)$", re.IGNORECASE)


def parse_robots(text: str, user_agent: str = "*") -> Dict:
    """Parse robots.txt.

    Returns the directives, plus the rules applicable to ``user_agent``.
    A group is the set of directives following one or more consecutive
    ``User-agent`` lines, up to the first rule line.
    """
    ua_lines, groups, sitemaps = [], [], []
    current_group: List[Dict] = []

    def flush():
        """Close the current group: one entry per user-agent, shared rules."""
        if current_group:
            for entry in current_group:
                groups.append(entry)
            current_group.clear()

    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = UA_RE.match(line)
        if m:
            agent = m.group(1).strip()
            ua_lines.append(agent)
            # A User-agent line that follows only other User-agent lines
            # joins the same group; any other line starts a new one.
            if current_group and current_group[-1]["rules"]:
                flush()
            current_group.append({"agents": [agent], "rules": []})
            continue
        m = ROBOT_RE.match(line)
        if not m:
            continue
        field, value = m.group(1).lower(), m.group(2).strip()
        if field == "sitemap":
            sitemaps.append(value)
            continue
        if not current_group:
            current_group.append({"agents": ["*"], "rules": []})
        if field in ("allow", "disallow") and value == "":
            continue          # "Disallow:" alone means allow-all
        current_group[-1]["rules"].append({"field": field, "path": value})
    flush()

    ua = (user_agent or "").lower()
    applicable = []
    for g in groups:
        for a in g["agents"]:
            if a == "*" or (ua and ua in a.lower()):
                applicable.extend(g["rules"])
                break

    return {
        "user_agents": ua_lines,
        "groups": len(groups),
        "rules": applicable,
        "rule_count": len(applicable),
        "sitemaps": sorted(set(sitemaps)),
        "note": "robots.txt is advisory. It describes what the site asks "
                "crawlers to do; it is not an access control and says nothing "
                "about what is actually reachable.",
    }


SITEMAP_LOC = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
SITEMAP_INDEX = re.compile(r"<sitemapindex", re.IGNORECASE)


def parse_sitemap(text: str, limit: int = 5000) -> Dict:
    """Extract URLs from a sitemap or sitemap index."""
    locs = [m.group(1) for m in SITEMAP_LOC.finditer(text or "")]
    return {
        "url_count": len(locs),
        "is_index": bool(SITEMAP_INDEX.search(text or "")),
        "urls": locs[:limit],
        "truncated": len(locs) > limit,
        "note": "Sitemap entries are URLs the site publishes for indexing. "
                "Inclusion does not imply the URL is functional now.",
    }


# ---------------------------------------------------------------------------
# Endpoint extraction from JavaScript
# ---------------------------------------------------------------------------

JS_STRING = re.compile(r"""["'`]((?:[^"'`\\]|\\.){3,300})["'`]""")
JS_ABS_URL = re.compile(r"""https?://[^\s"'`<>\\)\]]+""", re.IGNORECASE)
JS_WS_URL = re.compile(r"""wss?://[^\s"'`<>\\)\]]+""", re.IGNORECASE)
JS_PATH = re.compile(r"""["'`]((?:/|\./)(?:api|v\d|graphql|rest|rpc|ws|auth|"""
                     r"""user|admin|oauth|token|config|upload|download|"""
                     r"""search|login|signup|payment)"""
                     r"""[A-Za-z0-9._~/{}$-]{0,80})["'`]""",
                     re.IGNORECASE)
# Feature-flag style identifiers: SCREAMING_CASE names, whether quoted or a
# bare variable name. SCREAMING_CASE is a naming convention, not proof.
JS_FLAG_WORDS = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")
# Identifier or string names that read as an endpoint/service reference.
JS_ENDPOINTISH = re.compile(
    r"\b[A-Za-z0-9_]*(?:endpoint|service|gateway|backend|baseurl|base_url|"
    r"apibase|api_base)[A-Za-z0-9_]*\b", re.IGNORECASE)
JS_SOURCE_MAP = re.compile(r"sourceMappingURL=([^\s*]+)", re.IGNORECASE)
JS_WEBPACK = re.compile(r"__webpack_require__|webpackChunk")
JS_HOST_LIKE = re.compile(
    r"""["'`]([a-z0-9-]+\.(?:io|com|net|org|co|dev|app|cloud|internal|cn|ru)\b)["'`]""",
    re.IGNORECASE)


def extract_from_js(text: str, source: str = "<js>") -> Dict:
    """Pull endpoints, hosts, flags and config hints out of a JS bundle.

    Every item is a *string found in the file*. Whether the endpoint is live
    or in use is not established here.
    """
    out = {
        "source": source,
        "bytes": len(text or ""),
        "absolute_urls": [], "websocket_urls": [], "api_paths": [],
        "endpoint_named": [], "flag_like": [], "hosts": [],
        "source_maps": [], "bundler": None, "strings_total": 0,
    }
    if not text:
        return out
    strings = JS_STRING.findall(text)
    out["strings_total"] = len(strings)

    out["absolute_urls"] = sorted(set(
        u.rstrip(".,;") for u in JS_ABS_URL.findall(text)))[:300]
    out["websocket_urls"] = sorted(set(
        u.rstrip(".,;") for u in JS_WS_URL.findall(text)))[:100]
    out["api_paths"] = sorted(set(JS_PATH.findall(text)))[:300]
    out["source_maps"] = sorted(set(JS_SOURCE_MAP.findall(text)))[:20]
    out["hosts"] = sorted(set(JS_HOST_LIKE.findall(text)))[:200]

    # Flags and endpoint names are identifiers, which usually appear outside
    # quotes, so scan the whole source rather than only the string literals.
    flags = set(JS_FLAG_WORDS.findall(text))
    named = set(JS_ENDPOINTISH.findall(text))
    for s in strings:
        if JS_FLAG_WORDS.fullmatch(s):
            flags.add(s)
        if JS_ENDPOINTISH.search(s) and len(s) < 80:
            named.add(s)
    out["flag_like"] = sorted(flags)[:200]
    out["endpoint_named"] = sorted(named)[:200]

    if JS_WEBPACK.search(text):
        out["bundler"] = "webpack (marker strings present)"
    out["note"] = (
        "These are strings present in client-side code. An endpoint named in "
        "JavaScript is not thereby reachable, current, or intended for "
        "third-party use.")
    return out


# ---------------------------------------------------------------------------
# Client vs browser request comparison
# ---------------------------------------------------------------------------

# Order matters only for readability of the diff; each entry is compared
# independently.
COMPARABLE_FIELDS = [
    "method", "url", "path", "query", "http_version",
    "header:host", "header:user-agent", "header:accept",
    "header:accept-language", "header:accept-encoding",
    "header:content-type", "header:content-length", "header:origin",
    "header:referer", "header:authorization", "header:cookie",
    "header:sec-fetch-mode", "header:sec-fetch-site", "header:sec-fetch-dest",
    "header:sec-ch-ua", "header:x-requested-with",
    "body", "body_sha256", "tls", "websocket_handshake",
]

# Fields whose presence/absence commonly decides whether a request is
# accepted. Listed so the analyst knows where to look first, not as an answer.
SIGNAL_HEADERS = [
    "user-agent", "origin", "referer", "cookie", "authorization",
    "content-type", "accept", "accept-language", "x-requested-with",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
]


def normalise_request(req: Dict) -> Dict:
    """Reduce a captured request to comparable fields."""
    headers = {k.lower(): v for k, v in (req.get("headers") or {}).items()}
    url = req.get("url") or ""
    path, _, query = url.partition("?")
    body = req.get("body")
    import hashlib
    body_digest = None
    if isinstance(body, (bytes, bytearray)):
        body_digest = hashlib.sha256(body).hexdigest()
    elif isinstance(body, str):
        body_digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()

    out = {
        "method": (req.get("method") or "").upper() or None,
        "url": url or None,
        "path": path or None,
        "query": query or None,
        "http_version": req.get("http_version") or None,
        "body": body if isinstance(body, str) else (
            body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray))
            else None),
        "body_sha256": body_digest,
        "tls": req.get("tls") or req.get("tls_version") or None,
        "websocket_handshake": req.get("websocket_handshake"),
    }
    for name in ("host", "user-agent", "accept", "accept-language",
                 "accept-encoding", "content-type", "content-length", "origin",
                 "referer", "authorization", "cookie", "sec-fetch-mode",
                 "sec-fetch-site", "sec-fetch-dest", "sec-ch-ua",
                 "x-requested-with"):
        val = headers.get(name)
        out["header:" + name] = val if val is not None else None
    return out


def diff_requests(working: Dict, failing: Dict) -> Dict:
    """Compare a working and a failing request.

    The output is a list of *observed differences*, plus which signal headers
    are involved. It does not name a cause: the difference list is the input
    to a hypothesis, not the hypothesis.
    """
    a = normalise_request(working)
    b = normalise_request(failing)
    differences = []
    for field in COMPARABLE_FIELDS:
        va, vb = a.get(field), b.get(field)
        if va == vb:
            continue
        entry = {
            "field": field,
            "working_client": _redact(field, va),
            "failing_client": _redact(field, vb),
        }
        entry["differs_by"] = _describe(va, vb)
        differences.append(entry)

    signal_involved = [d["field"] for d in differences
                       if d["field"].startswith("header:")
                       and d["field"].split(":", 1)[1] in SIGNAL_HEADERS]

    return {
        "differences": differences,
        "difference_count": len(differences),
        "signal_header_differences": signal_involved,
        "note": "This is a list of observed differences, not a cause. The "
                "next step is a hypothesis about which difference matters, "
                "then a controlled test that changes one thing at a time.",
        "method": "Compare one variable at a time: replay the working request "
                  "while altering a single differing field to see whether the "
                  "failure follows that field.",
    }


def _redact(field: str, value) -> object:
    """Redact credentials before they land in a shared report."""
    if value is None:
        return None
    low = field.lower()
    if "authorization" in low or "cookie" in low:
        s = str(value)
        if len(s) > 24:
            return s[:8] + f"...<{len(s)} chars redacted>"
        return "<redacted>"
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + f"...<{len(value)} chars truncated>"
    return value


def _describe(va, vb) -> str:
    if va is None and vb is not None:
        return "only present in the failing client"
    if va is not None and vb is None:
        return "only present in the working client"
    if isinstance(va, str) and isinstance(vb, str):
        if va.split(".")[0] != vb.split(".")[0]:
            return f"differs ({va[:60]!r} vs {vb[:60]!r})"
        return f"differs ({va[:60]!r} vs {vb[:60]!r})"
    return f"differs ({va!r} vs {vb!r})"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV",
                    "CAA", "PTR"]


def resolve_dns(name: str, record_types: Optional[List[str]] = None) -> Dict:
    """Resolve DNS using the standard library.

    Uses ``socket.getaddrinfo`` for addresses and ``dnspython`` only if it
    happens to be installed -- never as a requirement. Records that need
    ``dig`` or ``dnspython`` are reported as unavailable rather than omitted.
    """
    import socket
    out = {"name": name, "records": {}, "errors": [],
           "resolver": "socket.getaddrinfo (stdlib)", "via_tools": False}
    try:
        infos = socket.getaddrinfo(name, None)
    except socket.gaierror as e:
        out["errors"].append(f"A/AAAA lookup failed: {e}")
        infos = []

    addrs = set()
    for family, _t, _p, _c, sockaddr in infos:
        try:
            addrs.add(ipaddress.ip_address(sockaddr[0]).version)
        except ValueError:
            pass
        addrs.add(sockaddr[0])
    if addrs:
        out["records"]["A/AAAA"] = sorted(str(a) for a in addrs)
    if not infos:
        out["errors"].append(
            "no address records resolved; this can mean the name does not "
            "exist, the resolver is unavailable, or the environment has no "
            "network -- distinguish before concluding")

    extra = [t for t in (record_types or ["MX", "NS", "TXT", "SOA", "CAA"])
             if t not in ("A", "AAAA")]
    if extra:
        out["tools_needed"] = {
            "records": extra,
            "note": "MX/NS/TXT/SOA/CAA need `dig`/`nslookup` or the optional "
                    "dnspython package. Neither is required; install or use "
                    "an external tool if these records matter.",
        }
    return out