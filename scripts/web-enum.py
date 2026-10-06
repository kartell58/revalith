#!/usr/bin/env python3
"""web-enum.py -- web target reconnaissance, passive by default.

Two clearly separated modes:

  passive (default)  Read what is already published: HTTP response headers,
                     cookies, security headers, robots.txt, sitemap.xml, and
                     the URLs and hosts inside the site's own JavaScript.
                     Nothing crafted is sent.

  active (--active)  Interaction beyond document retrieval: following
                     redirects, reading the TLS certificate, requesting
                     sibling paths. Every active step is logged so a reader
                     can see exactly what was asked.

The output separates observation from inference throughout. A ``Server:
nginx`` header is recorded as a self-declaration, not as proof of what is
behind the origin.

Scope note: this tool only inspects the hosts you name. Use it against
systems you own or are authorised to assess.

Examples
--------
  web-enum.py https://example.com                     # passive
  web-enum.py example.com --dns                        # resolve first
  web-enum.py https://example.com --tls                # read the certificate
  web-enum.py https://example.com --js --js-url /app.js
  web-enum.py https://example.com --active --json
  web-enum.py https://example.com --compare working.json failing.json
"""
import argparse
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _weblib as W  # noqa: E402

USER_AGENT = "revalith/web-enum (analysis tooling)"
TIMEOUT = 15
MAX_BODY = 3 * 1024 * 1024


class Recorder:
    """Logs every network interaction so active steps are auditable."""

    def __init__(self):
        self.entries: List[Dict] = []

    def add(self, method: str, url: str, mode: str, status=None,
            note: str = "", error: str = None):
        self.entries.append({"method": method, "url": url, "mode": mode,
                             "status": status, "note": note, "error": error})
        return self.entries[-1]


def http_get(url: str, method: str = "GET", headers: Optional[Dict] = None,
             recorder: Optional[Recorder] = None, mode: str = "passive",
             follow: bool = True) -> Dict:
    """One HTTP request. Returns a structured result; never raises."""
    hdrs = {"User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en",
            "Accept-Encoding": "identity"}
    hdrs.update(headers or {})

    req = urllib.request.Request(url, method=method, headers=hdrs)
    opener = urllib.request.build_opener()
    if not follow:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)

    entry = recorder.add(method, url, mode) if recorder else None
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BODY)
            result = {
                "ok": True, "status": resp.status, "url": url,
                "final_url": resp.geturl(),
                "headers": {k: v for k, v in resp.headers.items()},
                "body": raw,
                "body_size": len(raw),
                "http_version": getattr(resp, "version", None),
            }
            if entry:
                entry["status"] = resp.status
                entry["note"] = f"final={resp.geturl()}"
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(MAX_BODY)
        except Exception:                     # noqa: BLE001
            pass
        result = {"ok": False, "status": e.code, "url": url,
                  "final_url": url, "headers": {k: v for k, v in
                                                (e.headers or {}).items()},
                  "body": body, "body_size": len(body),
                  "http_version": None, "error": f"HTTP {e.code}"}
        if entry:
            entry["status"] = e.code
            entry["error"] = f"HTTP {e.code}"
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
        result = {"ok": False, "status": None, "url": url, "final_url": url,
                  "headers": {}, "body": b"", "body_size": 0,
                  "http_version": None, "error": f"{type(e).__name__}: {e}"}
        if entry:
            entry["error"] = f"{type(e).__name__}"

    chain = []
    try:
        chain = [{"status": r.status, "url": r.url,
                  "location": r.headers.get("Location")}
                 for r in (result.get("redirect_chain") or [])]
    except Exception:                         # noqa: BLE001
        chain = []
    result["redirects"] = chain
    return result


def decode_body(result: Dict) -> str:
    body = result.get("body") or b""
    charset = None
    ctype = ""
    for k, v in (result.get("headers") or {}).items():
        if k.lower() == "content-type":
            ctype = v
            if "charset=" in v.lower():
                charset = v.lower().split("charset=", 1)[1].split(";")[0].strip()
    if charset:
        try:
            return body.decode(charset, "replace")
        except LookupError:
            pass
    return body.decode("utf-8", "replace")


def tls_info(host: str, port: int = 443) -> Dict:
    """Read the TLS certificate. Active: it opens a connection."""
    out = {"host": host, "port": port, "read": False, "error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                out["tls_version"] = ss.version()
                out["cipher"] = (ss.cipher() or [None])[0]
                out["read"] = True
                if cert:
                    out["subject"] = dict(x[0] for x in cert.get("subject", []))
                    out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    out["not_before"] = cert.get("notBefore")
                    out["not_after"] = cert.get("notAfter")
                    sans = W.parse_san_entries(cert)
                    out["san"] = sans
                    out["san_summary"] = W.classify_san(sans)
                else:
                    out["error"] = ("peer sent no certificate: often a "
                                    "self-signed or untrusted chain, which "
                                    "this context rejects")
    except (ssl.SSLError, socket.timeout, OSError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def analyse(target: str, args, recorder: Recorder) -> Dict:
    host = W.normalise_cn(target)
    if not host:
        return {"error": f"could not parse a host from {target!r}"}
    scheme = "https" if "://" in target and target.startswith("https") else \
        ("http" if "://" in target else ("https" if args.tls else args.scheme))
    base = f"{scheme}://{host}"

    report: Dict = {
        "target": target,
        "normalised_host": host,
        "base_url": base,
        "generated_utc": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
        "mode": "active" if args.active else "passive",
        "observations": {},
        "inference": [],
        "warnings": [],
    }

    # -- DNS (passive) --
    if args.dns:
        dns = W.resolve_dns(host)
        report["observations"]["dns"] = dns
        for err in dns.get("errors", []):
            report["warnings"].append(f"dns: {err}")

    # -- TLS certificate (active) --
    if args.tls:
        report["observations"]["tls"] = tls_info(host, args.port)
        recorder.add("CONNECT", f"{host}:{args.port}", "active",
                     note="TLS handshake for certificate read")

    # -- main HTTP request --
    headers = {}
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
    resp = http_get(args.path and base + args.path or base, headers=headers,
                    recorder=recorder, mode="passive" if not args.active
                    else "active", follow=True)
    body_text = decode_body(resp)

    http_obs: Dict = {
        "status": resp.get("status"),
        "final_url": resp.get("final_url"),
        "http_version": resp.get("http_version"),
        "body_size": resp.get("body_size"),
        "error": resp.get("error"),
        "headers": resp.get("headers") or {},
    }
    if args.active:
        http_obs["redirect_chain"] = resp.get("redirects") or []
    report["observations"]["http"] = http_obs

    if resp.get("error") and not resp.get("headers"):
        report["warnings"].append(
            f"no usable response from {base}: {resp['error']}. Every "
            f"header-derived conclusion below is therefore unsupported.")
        report["inference"].append({
            "claim": "technology identification",
            "status": "not evaluated",
            "reason": "no headers were received",
        })
        report["observations"]["network_log"] = recorder.entries
        return report

    # -- technologies --
    techs = W.detect_technologies(resp.get("headers") or {}, body_text,
                                  urls=[resp.get("final_url") or base])
    report["observations"]["technologies"] = techs
    for t in techs:
        report["inference"].append({
            "claim": f"{t['technology']} ({t['class']})",
            "confidence": t["confidence"],
            "basis": t["evidence_kind"],
            "caveat": t.get("caveat"),
        })

    # -- security headers --
    report["observations"]["security_headers"] = \
        W.audit_security_headers(resp.get("headers") or {})

    # -- cookies --
    cookies = []
    for k, v in (resp.get("headers") or {}).items():
        if k.lower() == "set-cookie":
            name = v.split("=", 1)[0]
            attrs = [a.strip().lower() for a in v.split(";")[1:]]
            cookies.append({
                "name": name,
                "flags": sorted(set(attrs)),
                "httponly": any(a.startswith("httponly") for a in attrs),
                "secure": any(a.startswith("secure") for a in attrs),
                "samesite": next((a for a in attrs if a.startswith("samesite")),
                                 None),
                "note": "attributes as sent; a cookie without Secure/HttpOnly "
                        "is an observation, not a proven vulnerability",
            })
    report["observations"]["cookies"] = cookies

    # -- robots.txt --
    robots = http_get(f"{base}/robots.txt", recorder=recorder, mode="passive")
    if robots.get("ok") or robots.get("status") in (200, 301, 302):
        r = W.parse_robots(decode_body(robots), user_agent=USER_AGENT)
        report["observations"]["robots_txt"] = {
            "status": robots.get("status"),
            **r,
        }
    else:
        report["observations"]["robots_txt"] = {
            "status": robots.get("status"),
            "available": False,
            "error": robots.get("error"),
            "note": "absent or unreachable; absence is not a prohibition",
        }

    # -- sitemap.xml --
    sitemap = http_get(f"{base}/sitemap.xml", recorder=recorder, mode="passive")
    if sitemap.get("status") == 200:
        s = W.parse_sitemap(decode_body(sitemap))
        report["observations"]["sitemap"] = {"status": 200, **s}
    else:
        report["observations"]["sitemap"] = {
            "status": sitemap.get("status"),
            "available": False,
            "note": "no sitemap.xml at the root; some sites publish them "
                    "only via robots.txt or at other paths",
        }

    # -- JavaScript --
    js_reports: List[Dict] = []
    js_urls = list(args.js_url or [])
    if args.js and not args.js_url:
        for m in W.JS_PATH.finditer(body_text):
            if m.group(1).endswith(".js") or m.group(1).endswith(".mjs"):
                js_urls.append(m.group(1))
        for m in re_finditer_js(body_text):
            js_urls.append(m)
    if args.js_url:
        js_urls = list(args.js_url)
    for u in js_urls[:args.max_js]:
        full = u if u.startswith("http") else (base.rstrip("/") + "/" +
                                               u.lstrip("/"))
        r = http_get(full, recorder=recorder, mode="passive")
        if r.get("body"):
            js_reports.append(W.extract_from_js(decode_body(r),
                                               source=full))
        else:
            js_reports.append({"source": full, "error": r.get("error"),
                               "status": r.get("status")})
    if js_reports:
        agg = {
            "files": js_reports,
            "absolute_urls": sorted({u for j in js_reports
                                     for u in j.get("absolute_urls", [])}),
            "websocket_urls": sorted({u for j in js_reports
                                      for u in j.get("websocket_urls", [])}),
            "api_paths": sorted({p for j in js_reports
                                 for p in j.get("api_paths", [])}),
            "endpoint_named": sorted({e for j in js_reports
                                      for e in j.get("endpoint_named", [])}),
            "flag_like": sorted({f for j in js_reports
                                 for f in j.get("flag_like", [])}),
            "hosts": sorted({h for j in js_reports
                             for h in j.get("hosts", [])}),
            "source_maps": sorted({s for j in js_reports
                                   for s in j.get("source_maps", [])}),
            "note": "these are strings present in client-side code. An "
                    "endpoint named in JavaScript is not thereby reachable, "
                    "current, or intended for third-party use.",
        }
        report["observations"]["javascript"] = agg

    report["observations"]["network_log"] = recorder.entries
    report["coverage"] = {
        "dns": bool(args.dns), "tls": bool(args.tls),
        "robots": True, "sitemap": True,
        "javascript_files": len(js_reports),
        "note": "port scanning, directory brute-forcing and vulnerability "
                "testing are out of scope for this tool by design",
    }
    return report


def re_finditer_js(text: str) -> List[str]:
    import re
    out = []
    for m in re.finditer(r"""["'`]([/A-Za-z0-9_.-]*\.m?js)["'`]""", text):
        out.append(m.group(1))
    return out


def render(report: Dict, recorder: Recorder) -> str:
    L: List[str] = []
    add = L.append
    add("=" * 74)
    add("WEB ENUMERATION")
    add("=" * 74)
    add(f"target     : {report.get('target')}")
    add(f"host       : {report.get('normalised_host')}")
    add(f"generated  : {report.get('generated_utc')}")
    add(f"mode       : {report.get('mode')}")
    if report.get("error"):
        add(f"error      : {report['error']}")
        return "\n".join(L)

    obs = report.get("observations", {})

    http = obs.get("http") or {}
    add("")
    add("-" * 74)
    add("HTTP RESPONSE  (observed)")
    add("-" * 74)
    if http.get("error") and not http.get("headers"):
        add(f"  request failed: {http['error']}")
        add("  no header-based conclusions can be drawn")
    else:
        add(f"  status        : {http.get('status')}")
        add(f"  final url     : {http.get('final_url')}")
        add(f"  http version  : {http.get('http_version')}")
        add(f"  body size     : {http.get('body_size')}")
        if http.get("redirect_chain"):
            add("  redirects:")
            for r in http["redirect_chain"]:
                add(f"    {r.get('status')} -> {r.get('location')}")
        add("  headers:")
        for k in sorted(http.get("headers") or {}):
            add(f"    {k}: {http['headers'][k][:150]}")

    if obs.get("dns"):
        d = obs["dns"]
        add("")
        add("-" * 74)
        add("DNS  (observed)")
        add("-" * 74)
        for rt, vals in (d.get("records") or {}).items():
            add(f"  {rt}: {', '.join(map(str, vals[:10]))}")
        for e in d.get("errors", []):
            add(f"  note: {e}")
        if d.get("tools_needed"):
            add(f"  not queried : {', '.join(d['tools_needed']['records'])}")
            add(f"               {d['tools_needed']['note']}")

    if obs.get("tls"):
        t = obs["tls"]
        add("")
        add("-" * 74)
        add("TLS CERTIFICATE  (observed; requires an active connection)")
        add("-" * 74)
        if t.get("read"):
            add(f"  protocol : {t.get('tls_version')}")
            add(f"  cipher   : {t.get('cipher')}")
            add(f"  subject  : {t.get('subject')}")
            add(f"  issuer   : {t.get('issuer')}")
            add(f"  validity : {t.get('not_before')} .. {t.get('not_after')}")
            ss = t.get("san_summary") or {}
            for kind in ("dns", "wildcards", "ip", "email"):
                if ss.get(kind):
                    add(f"  SAN {kind:<10}: {', '.join(ss[kind][:15])}")
            add(f"  note     : {ss.get('note')}")
        else:
            add(f"  could not read: {t.get('error')}")

    techs = obs.get("technologies") or []
    add("")
    add("-" * 74)
    add("TECHNOLOGY  (observed evidence, then the inference it supports)")
    add("-" * 74)
    if not techs:
        add("  no indicators matched")
    for t in techs:
        add(f"  {t['technology']}  [{t['class']}]  "
            f"evidence={t['evidence_kind']}  confidence={t['confidence']}")
        for ev in t.get("observed", []):
            if ev.get("kind") == "header":
                add(f"      header {ev['header']}: {ev.get('value')}")
            else:
                add(f"      {ev.get('kind')} /{ev.get('pattern')}"
                    + (f" {ev.get('url')}" if ev.get("url") else ""))
        add(f"      claim  : {t['claim']}")
        if t.get("caveat"):
            add(f"      caveat : {t['caveat']}")

    sec = obs.get("security_headers") or {}
    add("")
    add("-" * 74)
    add("SECURITY HEADERS  (observed presence/absence, not a verdict)")
    add("-" * 74)
    for h in sec.get("present", []):
        add(f"  present: {h['header']}: {h['value'][:100]}")
    for h in sec.get("missing", []):
        add(f"  absent : {h['header']}  ({h['purpose']})")
    if sec.get("note"):
        add(f"  note   : {sec['note']}")

    cookies = obs.get("cookies") or []
    if cookies:
        add("")
        add("-" * 74)
        add("COOKIES  (observed)")
        add("-" * 74)
        for c in cookies:
            add(f"  {c['name']}  flags={','.join(c['flags']) or 'none'}  "
                f"httponly={c['httponly']}  secure={c['secure']}  "
                f"samesite={c['samesite']}")

    rob = obs.get("robots_txt") or {}
    add("")
    add("-" * 74)
    add("ROBOTS.TXT  (observed)")
    add("-" * 74)
    if rob.get("available") is False:
        add(f"  not available: status={rob.get('status')} "
            f"{rob.get('error') or ''}")
        add(f"  note: {rob.get('note')}")
    else:
        add(f"  status      : {rob.get('status')}")
        add(f"  user-agents : {', '.join(rob.get('user_agents') or [])[:200]}")
        add(f"  rules       : {rob.get('rule_count')}")
        for r in (rob.get("rules") or [])[:15]:
            add(f"    {r.get('field')}: {r.get('path') or r.get('value')}")
        for s in (rob.get("sitemaps") or [])[:10]:
            add(f"    sitemap: {s}")
        add(f"  note        : {rob.get('note')}")

    sm = obs.get("sitemap") or {}
    add("")
    add("-" * 74)
    add("SITEMAP  (observed)")
    add("-" * 74)
    if sm.get("available") is False:
        add(f"  not available: status={sm.get('status')}")
        add(f"  note: {sm.get('note')}")
    else:
        add(f"  urls: {sm.get('url_count')}  index={sm.get('is_index')}")
        for u in (sm.get("urls") or [])[:20]:
            add(f"    {u}")
        add(f"  note: {sm.get('note')}")

    js = obs.get("javascript")
    if js:
        add("")
        add("-" * 74)
        add("JAVASCRIPT  (strings observed in client code; not proven reachable)")
        add("-" * 74)
        add(f"  files scanned : {len(js.get('files', []))}")
        for label, key in (("absolute urls", "absolute_urls"),
                           ("websocket urls", "websocket_urls"),
                           ("api paths", "api_paths"),
                           ("endpoint-ish", "endpoint_named"),
                           ("flag-like", "flag_like"),
                           ("hosts", "hosts"),
                           ("source maps", "source_maps")):
            vals = js.get(key) or []
            if vals:
                add(f"  {label} ({len(vals)}):")
                for v in vals[:12]:
                    add(f"    {v}")
        add(f"  note: {js.get('note')}")

    add("")
    add("-" * 74)
    add("NETWORK ACTIVITY LOG  (every request made)")
    add("-" * 74)
    for e in recorder.entries:
        note = e.get("note") or e.get("error") or ""
        add(f"  [{e['mode']:<7}] {e['method']:<7} {e['url']}"
            + (f"  -> {e['status']}" if e.get("status") else "")
            + (f"  {note}" if note else ""))

    add("")
    add("-" * 74)
    add("LIMITS")
    add("-" * 74)
    for w in report.get("warnings", []):
        add(f"  warning: {w}")
    cov = report.get("coverage", {})
    add(f"  coverage: {cov.get('note')}")
    add("")
    add("Observations above are what the target sent. Conclusions about the")
    add("application behind it remain inference until independently tested.")
    add("=" * 74)
    return "\n".join(L)


def load_request_file(path: str) -> Dict:
    """Load a captured request (HAR-ish JSON) into the diff input shape."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "request" in data:
        return data["request"]
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and data:
        first = data[0]
        return first.get("request", first) if isinstance(first, dict) else {}
    return {}


def main():
    p = argparse.ArgumentParser(
        description="Passive-by-default web target reconnaissance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("target", help="URL or hostname")
    p.add_argument("--dns", action="store_true", help="resolve the hostname")
    p.add_argument("--tls", action="store_true",
                   help="read the TLS certificate (active)")
    p.add_argument("--active", action="store_true",
                   help="allow interaction beyond document retrieval")
    p.add_argument("--scheme", default="https", choices=["http", "https"],
                   help="scheme to use when the target has none (default https)")
    p.add_argument("--path", default="", help="path to request")
    p.add_argument("--port", type=int, default=443, help="TLS port (default 443)")
    p.add_argument("--user-agent", default=None, help="override User-Agent")
    p.add_argument("--js", action="store_true",
                   help="also fetch JavaScript referenced by the page")
    p.add_argument("--js-url", action="append",
                   help="fetch this JS path or URL (repeatable)")
    p.add_argument("--max-js", type=int, default=10,
                   help="max JS files to fetch (default 10)")
    p.add_argument("--compare", nargs=2, metavar=("WORKING", "FAILING"),
                   help="diff two captured requests (JSON) instead of probing")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args()

    recorder = Recorder()

    if args.compare:
        try:
            working = load_request_file(args.compare[0])
            failing = load_request_file(args.compare[1])
        except (OSError, json.JSONDecodeError) as e:
            print(f"error: could not load a capture: {e}", file=sys.stderr)
            return 1
        diff = W.diff_requests(working, failing)
        if args.json:
            print(json.dumps(diff, indent=2))
        else:
            print("=" * 74)
            print("CLIENT vs BROWSER REQUEST COMPARISON")
            print("=" * 74)
            print(f"differences observed: {diff['difference_count']}")
            print("")
            for i, d in enumerate(diff["differences"], 1):
                print(f"{i}. {d['field']}")
                print(f"     working client : {d['working_client']!r}")
                print(f"     failing client : {d['failing_client']!r}")
                print(f"     {d['differs_by']}")
            print("")
            print("signal headers involved:",
                  ", ".join(diff["signal_header_differences"]) or "none")
            print("")
            print("NOTE:", diff["note"])
            print("METHOD:", diff["method"])
            print("")
            print("A User-Agent difference alone does not explain a failure;")
            print("it is one candidate among the observed differences.")
        return 0

    report = analyse(args.target, args, recorder)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render(report, recorder))
    return 0 if not report.get("error") else 1


if __name__ == "__main__":
    sys.exit(main())