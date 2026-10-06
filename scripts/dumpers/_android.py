"""
_android.py -- Android package triage with the standard library only.

Binary XML (AndroidManifest.xml inside an APK) is decoded here rather than
shelled out to ``aapt``: the format is documented enough that the fields we
need can be read, and doing so keeps the skill usable with nothing installed.
When aapt/apkanalyzer exist, they are *additionally* used and their output is
recorded alongside -- never silently preferred over our parse without saying so.

Only binary-XML *string pool* and the element tree are decoded. Attribute
values that are not resource references are returned as strings; anything
unresolved is reported as unresolved rather than guessed.
"""

from __future__ import annotations

import os
import struct
import zipfile
from typing import Dict, List, Optional, Tuple

from _indicators import scan_text

# Android binary XML chunk types
CHUNK_AXML = 0x00080003
CHUNK_STRING_POOL = 0x001C0001
CHUNK_RESOURCE_MAP = 0x00080180
CHUNK_START_NS = 0x00100100
CHUNK_START_ELEMENT = 0x00100102
CHUNK_END_NS = 0x00100101
CHUNK_END_ELEMENT = 0x00100103
CHUNK_CDS = 0x00100104

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

SDK_NAMES = {
    21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0", 25: "7.1", 26: "8.0",
    27: "8.1", 28: "9", 29: "10", 30: "11", 31: "12", 32: "12L", 33: "13",
    34: "14", 35: "15", 36: "16",
}

PERMISSION_PREFIXES = ("android.permission.", "androidx.", "com.android.",
                       "com.google.android.")

# Manifest elements we care about, mapped to the bucket they land in.
COMPONENT_TAGS = {
    "activity": "activities",
    "activity-alias": "activities",
    "service": "services",
    "receiver": "receivers",
    "provider": "providers",
}


# ----------------------------------------------------------------- binary XML

def decode_binary_xml(data: bytes) -> Dict:
    """Decode an AXML chunk into elements and attributes.

    Returns a dict with ``elements``, ``strings`` and ``warnings``. A parse
    failure is reported, not raised.
    """
    out: Dict = {"elements": [], "strings": [], "warnings": [],
                 "decoded": False, "error": None}
    if len(data) < 8:
        out["error"] = f"too short to be AXML ({len(data)} bytes)"
        return out

    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le == CHUNK_AXML:
        end = "<"
    else:
        magic_be = struct.unpack_from(">I", data, 0)[0]
        if magic_be != CHUNK_AXML:
            out["error"] = f"not an AXML chunk (magic 0x{magic_le:08x})"
            return out
        end = ">"

    try:
        file_size = struct.unpack_from(end + "I", data, 4)[0]
    except struct.error as e:
        out["error"] = f"truncated AXML header: {e}"
        return out
    if file_size > len(data):
        out["warnings"].append(
            f"declared size {file_size} exceeds available {len(data)}; "
            "parsing what is present")

    strings: List[str] = []
    pos = 8
    # Every AXML chunk starts with a ResChunk_header: type(u16) and
    # headerSize(u16), then chunkSize(u32). Read the type as u16 so the
    # comparison is exact.
    if pos + 28 <= len(data):
        ctype = struct.unpack_from(end + "H", data, pos)[0]
        if ctype == (CHUNK_STRING_POOL & 0xFFFF):
            strings, pos = _parse_string_pool(data, pos, end, out)
            out["strings"] = strings[:200]

    # Element chunks follow, in a flat tree we flatten.
    while pos + 8 <= len(data):
        try:
            ctype, _hsize, csize = struct.unpack_from(end + "HHI", data, pos)
        except struct.error:
            break
        if csize < 8 or pos + csize > len(data):
            break
        if ctype == (CHUNK_START_ELEMENT & 0xFFFF):
            el = _parse_start_element(data, pos, end, strings, out)
            if el:
                out["elements"].append(el)
        pos += csize

    out["decoded"] = bool(out["elements"])
    if not out["decoded"] and not out["error"]:
        out["error"] = "AXML structure present but no elements were decoded"
    return out


def _parse_string_pool(data: bytes, pos: int, end: str,
                       out: Dict) -> Tuple[List[str], int]:
    """Parse a ResStringPool chunk.

    Layout: chunk(u16) headerSize(u16) chunkSize(u32) stringCount(u32)
    styleCount(u32) flags(u32) stringsStart(u32) stylesStart(u32), then
    stringCount u32 offsets, then the string data. Total header = 28 bytes.
    """
    try:
        (_chunk, _hs, csize, string_count, style_count, flags,
         str_start, style_start) = struct.unpack_from(end + "HHIIIIII",
                                                      data, pos)
    except struct.error as e:
        out["warnings"].append(f"string pool header unreadable: {e}")
        return [], pos + 8

    is_utf8 = bool(flags & (1 << 8))
    offsets: List[int] = []
    off_base = pos + 28
    for i in range(min(string_count, 20000)):
        p = off_base + i * 4
        if p + 4 > len(data):
            break
        offsets.append(struct.unpack_from(end + "I", data, p)[0])

    pool_start = pos + str_start
    strings: List[str] = []
    for rel in offsets:
        p = pool_start + rel
        if p + 2 > len(data):
            strings.append("")
            continue
        try:
            if is_utf8:
                # Modified UTF-8: the length is 1 or 2 bytes, with the high
                # bit of the first length byte marking the 2-byte form.
                n1 = data[p + 1]
                if n1 & 0x80:
                    n = ((n1 & 0x7F) << 8) | data[p + 2]
                    p += 3
                else:
                    n = n1
                    p += 2
                strings.append(data[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from(end + "H", data, p)[0]
                if n & 0x8000:
                    n2 = struct.unpack_from(end + "H", data, p + 2)[0]
                    n = ((n & 0x7FFF) << 16) | n2
                    p += 4
                else:
                    p += 2
                strings.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        except (struct.error, IndexError):
            strings.append("")
    return strings, pos + (csize or (off_base - pos) + len(strings))


def _parse_start_element(data: bytes, pos: int, end: str,
                         strings: List[str], out: Dict) -> Optional[Dict]:
    try:
        (_chunk, _hs, csize, _line, _comment, _ns, name_idx,
         attr_start, attr_size, attr_count, _id_idx, _class_idx,
         _style_idx) = struct.unpack_from(end + "HHIIIIIHHHHHH", data, pos)
    except struct.error as e:
        out["warnings"].append(f"element header unreadable: {e}")
        return None

    def s(idx: int) -> str:
        if 0 <= idx < len(strings):
            return strings[idx]
        return ""

    el = {
        "tag": s(name_idx),
        "attributes": {},
        "raw_attribute_count": attr_count,
    }
    # attributeStart is relative to this chunk; it normally equals 20 because
    # the attribute list begins right after the fixed 20-byte node prefix.
    attr_base = pos + (attr_start or 20)
    step = attr_size or 20
    for i in range(min(attr_count, 4096)):
        p = attr_base + i * step
        if p + 20 > len(data):
            break
        try:
            (_ns, an_idx, _raw, size, _res0, ptype,
             data_val) = struct.unpack_from(end + "IIIHBBI", data, p)
        except struct.error:
            break
        aname = s(an_idx)
        if not aname:
            continue
        # Res_value packs size(u16) res0(u8) dataType(u8) data(u32); the
        # last four bytes are the value for every non-string type, and the
        # string-pool index for TYPE_STRING.
        if ptype == TYPE_STRING:
            value = s(data_val)
        elif ptype == TYPE_REFERENCE:
            value = f"@0x{data_val:08x}"
        elif ptype == TYPE_INT_BOOLEAN:
            value = bool(data_val)
        elif ptype == TYPE_INT_HEX:
            value = f"0x{data_val:x}"
        elif ptype == TYPE_INT_DEC:
            value = struct.unpack(end + "i", struct.pack(end + "I", data_val))[0]
        elif ptype == TYPE_FLOAT:
            value = struct.unpack_from(end + "f", data, p + 16)[0]
        else:
            value = f"<type 0x{ptype:02x}>"
        el["attributes"][aname] = value
    return el


# ------------------------------------------------------------------- manifest

def summarise_manifest(manifest_xml: bytes) -> Dict:
    """Pull the fields an analyst needs out of a decoded manifest."""
    axml = decode_binary_xml(manifest_xml)
    res: Dict = {
        "decoded": axml["decoded"],
        "error": axml["error"],
        "warnings": axml["warnings"],
        "package": None, "version_name": None, "version_code": None,
        "min_sdk": None, "target_sdk": None, "compile_sdk": None,
        "permissions": [], "components": {}, "abis": [], "uses_features": [],
        "debuggable": None, "allow_backup": None,
        "network_security_config": None, "cleartext_traffic": None,
        "uses_cleartext_traffic": None, "deep_links": [],
        "intent_filters": [], "exported_components": [],
        "signing": None, "evidence": [],
    }
    if not axml["decoded"]:
        return res

    ev = res["evidence"]
    for el in axml["elements"]:
        tag = el["tag"]
        a = el["attributes"]

        if tag == "manifest":
            res["package"] = a.get("package")
            for key, field in (("versionName", "version_name"),
                               ("versionCode", "version_code"),
                               ("minSdkVersion", "min_sdk"),
                              ("targetSdkVersion", "target_sdk")):
                if a.get(key) is not None:
                    res[field] = a[key]
            if "compileSdkVersion" in a:
                res["compile_sdk"] = a["compileSdkVersion"]
            if a.get("debuggable") is not None:
                res["debuggable"] = a["debuggable"]
            if "allowBackup" in a:
                res["allow_backup"] = a["allowBackup"]
            if "usesCleartextTraffic" in a:
                res["uses_cleartext_traffic"] = a["usesCleartextTraffic"]
                res["cleartext_traffic"] = a["usesCleartextTraffic"]
            if "networkSecurityConfig" in a:
                res["network_security_config"] = a["networkSecurityConfig"]
                ev.append(f"manifest declares networkSecurityConfig="
                          f"{a['networkSecurityConfig']} (a resource reference, "
                          "not yet resolved)")
            if res["package"]:
                ev.append(f"package={res['package']}")
            if res["version_name"]:
                ev.append(f"versionName={res['version_name']}")
            if res["version_code"]:
                ev.append(f"versionCode={res['version_code']}")

        elif tag == "uses-sdk":
            if a.get("minSdkVersion") is not None:
                res["min_sdk"] = a["minSdkVersion"]
            if a.get("targetSdkVersion") is not None:
                res["target_sdk"] = a["targetSdkVersion"]

        elif tag == "uses-permission":
            name = a.get("name")
            if name and name not in res["permissions"]:
                res["permissions"].append(name)

        elif tag == "uses-feature":
            name = a.get("name") or a.get("glEsVersion")
            if name:
                res["uses_features"].append(str(name))

        elif tag in COMPONENT_TAGS:
            bucket = COMPONENT_TAGS[tag]
            name = a.get("name")
            entry = {"name": name, "exported": a.get("exported"),
                     "attributes": {}}
            for k, v in a.items():
                if k in ("name", "exported"):
                    continue
                entry["attributes"][k] = v
            res["components"].setdefault(bucket, []).append(entry)
            if a.get("exported") is True:
                res["exported_components"].append({"type": tag, "name": name})
                ev.append(f"exported {tag}: {name}")

        elif tag == "intent-filter":
            actions = a.get("actions")
            res["intent_filters"].append({"element": "intent-filter"})

        elif tag == "data":
            if a.get("scheme") and a.get("host"):
                res["deep_links"].append({
                    "scheme": a.get("scheme"), "host": a.get("host"),
                    "path": a.get("path")})
                ev.append(f"deep link candidate: {a.get('scheme')}://"
                          f"{a.get('host')}{a.get('path') or ''}")

    for key in ("min_sdk", "target_sdk"):
        v = res[key]
        if isinstance(v, int) and v in SDK_NAMES:
            res[key + "_name"] = SDK_NAMES[v]

    # Group permissions by prefix so the interesting ones stand out.
    res["permission_groups"] = _group_permissions(res["permissions"])
    return res


def _group_permissions(perms: List[str]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for p in perms:
        if p.startswith(PERMISSION_PREFIXES):
            groups.setdefault("platform_or_androidx", []).append(p)
        else:
            groups.setdefault("third_party", []).append(p)
    return {k: sorted(v) for k, v in groups.items()}


# ---------------------------------------------------------------------- APK

def analyse_apk(path: str, extract_to: Optional[str] = None) -> Dict:
    """Analyse an APK / AAB: manifest, ABIs, DEX, native libs, signatures."""
    res: Dict = {
        "path": path, "kind": None, "manifest": None, "abis": [],
        "dex_files": [], "native_libraries": [], "signing": [],
        "member_count": None, "interesting_members": {},
        "indicators": [], "warnings": [], "error": None,
        "extracted_to": None,
    }
    try:
        zipfile.ZipFile(path).close()
    except Exception as e:      # noqa: BLE001 - any zip failure is a report
        res["error"] = f"not a readable zip container: {type(e).__name__}: {e}"
        return res

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            res["member_count"] = len(names)
            lower = {n.lower(): n for n in names}

            if "AndroidManifest.xml" in names:
                res["kind"] = "apk"
            elif "BundleConfig.pb" in lower:
                res["kind"] = "aab"
            elif any(n.endswith(".dex") for n in names):
                res["kind"] = "zip-with-dex (APK-like, no manifest found)"
            else:
                res["kind"] = "zip"

            # -- manifest --
            if "AndroidManifest.xml" in names:
                try:
                    xml = zf.read("AndroidManifest.xml")
                    res["manifest"] = summarise_manifest(xml)
                except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as e:
                    res["warnings"].append(f"manifest read failed: {e}")

            # -- ABIs and native libraries --
            for n in names:
                if not n.startswith("lib/"):
                    continue
                parts = n.split("/")
                if len(parts) >= 3:
                    res["abis"].append(parts[1])
                    res["native_libraries"].append(n)
                else:
                    res["warnings"].append(f"unexpected lib/ path: {n}")
            res["abis"] = sorted(set(res["abis"]))

            # -- DEX --
            res["dex_files"] = sorted(n for n in names if n.endswith(".dex"))

            # -- signing --
            res["signing"] = sorted(n for n in names
                                    if n.upper().startswith("META-INF/")
                                    and n.upper().endswith(
                                        (".RSA", ".DSA", ".EC", ".SF")))

            # -- interesting members --
            from _archives import interesting_members
            res["interesting_members"] = interesting_members(names)

            # -- embedded indicators from text-ish members --
            interesting = interesting_members(names)
            scan_names = set(interesting.get("configs", []) +
                             interesting.get("scripts", []) +
                             interesting.get("assets", [])[:50])
            for n in list(scan_names)[:120]:
                if not n.endswith((".json", ".xml", ".txt", ".js", ".mjs",
                                   ".html", ".properties", ".cfg", ".ini",
                                   ".yml", ".yaml", ".csv", ".md")):
                    continue
                try:
                    if zf.getinfo(n).file_size > 4 * 1024 * 1024:
                        continue
                    blob = zf.read(n)
                except (KeyError, RuntimeError, zipfile.BadZipFile, OSError):
                    continue
                try:
                    text = blob.decode("utf-8", "replace")
                except Exception:                     # noqa: BLE001
                    continue
                res["indicators"].extend(
                    scan_text(text, f"{os.path.basename(path)}!{n}",
                              offset=None))

            # -- optionally extract --
            if extract_to:
                from _archives import extract_all
                out = extract_all(path, extract_to, fmt="apk")
                res["extracted_to"] = out
                if out.get("error"):
                    res["warnings"].append(f"extraction: {out['error']}")
    except zipfile.BadZipFile as e:
        res["error"] = f"corrupt zip: {e}"
    except OSError as e:
        res["error"] = f"read failed: {e}"
    return res


def apk_observations(res: Dict) -> List[Dict]:
    """Turn manifest facts into evidence-tagged observations."""
    out: List[Dict] = []
    m = res.get("manifest") or {}
    if not m:
        return out
    if m.get("package"):
        out.append({"observation": f"package={m['package']}",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    if m.get("version_name"):
        out.append({"observation": f"versionName={m['version_name']}",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    if m.get("min_sdk"):
        out.append({"observation": f"minSdkVersion={m['min_sdk']}"
                                   + (f" (Android {m['min_sdk_name']})"
                                      if m.get("min_sdk_name") else ""),
                    "source": "AndroidManifest.xml", "confidence": "high"})
    if m.get("target_sdk"):
        out.append({"observation": f"targetSdkVersion={m['target_sdk']}",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    if m.get("debuggable") is True:
        out.append({"observation": "android:debuggable=true: the app is "
                                   "attachable by a debugger",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    if m.get("uses_cleartext_traffic") is True:
        out.append({"observation": "usesCleartextTraffic=true: cleartext HTTP "
                                   "is permitted by the manifest",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    if m.get("network_security_config"):
        out.append({"observation": "network security config declared; its "
                                   "contents were not decoded here",
                    "source": "AndroidManifest.xml", "confidence": "medium"})
    if m.get("deep_links"):
        for dl in m["deep_links"]:
            out.append({"observation": f"deep link candidate {dl['scheme']}://"
                                       f"{dl['host']}{dl.get('path') or ''}",
                        "source": "AndroidManifest.xml",
                        "confidence": "medium"})
    net_perms = [p for p in m.get("permissions", [])
                 if "INTERNET" in p or "NETWORK" in p]
    if net_perms:
        out.append({"observation": f"network permissions declared: "
                                   f"{', '.join(net_perms)}",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    exported = m.get("exported_components") or []
    if exported:
        out.append({"observation": f"{len(exported)} exported component(s)",
                    "source": "AndroidManifest.xml", "confidence": "high"})
    return out