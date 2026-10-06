"""
_reconlib.py -- shared library for the reconstruction workflow.

The problem this addresses: a long reconstruction accumulates hypotheses, and
the failure mode is a hypothesis from week two being read as an established
fact in week eight. The defence is mechanical, not cultural -- every entry is
validated against a vocabulary and against its own evidence, and a status can
only advance if the entry carries what that status demands.

Vocabulary
----------

status      unknown | observed | hypothesized | partially-reconstructed |
            reconstructed | verified | refuted

confidence  very low | low | medium | high | very high

The status ladder is not decorative. ``hypothesized`` with a ``verified``
confidence is a contradiction and is reported as one; so is ``verified``
without a test that could have failed.

Everything here is dependency-free and offline.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "1.0"

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

STATUSES = [
    "unknown",
    "observed",
    "hypothesized",
    "partially-reconstructed",
    "reconstructed",
    "verified",
    "refuted",
]

# Confidence uses the skill's existing five levels so that a confidence read
# in reconstruction means the same thing as one read in analysis.
CONFIDENCES = ["very low", "low", "medium", "high", "very high"]

CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}

# A status this far ahead of its evidence is a defect in the ledger, not a
# strong result. The ceiling is what the status can justify on its own.
STATUS_IMPLIES_CONFIDENCE = {
    "unknown": "very low",
    "observed": "medium",
    "hypothesized": "low",
    "partially-reconstructed": "medium",
    "reconstructed": "high",
    "verified": "very high",
    "refuted": None,          # refuted is settled, confidence is about why
}

# Statuses that assert something about behaviour. Reaching one of these
# without a recorded test is the specific failure this module exists to catch.
STATUSES_REQUIRING_TEST = ("verified",)
STATUSES_REQUIRING_EVIDENCE = (
    "observed", "hypothesized", "partially-reconstructed", "reconstructed",
    "verified",
)

# The eight ledger files, with the entry kind each holds.
LEDGER_KINDS: Dict[str, str] = {
    "architecture": "architecture",
    "functions": "function",
    "structures": "structure",
    "states": "state",
    "systems": "system",
    "formats": "format",
    "hypotheses": "hypothesis",
    "verification": "verification",
}

REQUIRED_FIELDS = ("name", "kind", "status")

# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def validate_entry(entry: Dict, kind: Optional[str] = None) -> List[str]:
    """Return a list of problems with one ledger entry. Empty means valid.

    The checks are deliberately pedantic. The cost of a missing check is a
    hypothesis promoted to fact weeks later; the cost of a false alarm is a
    line in the report.
    """
    problems: List[str] = []
    if not isinstance(entry, dict):
        return ["entry is not an object"]

    for field in REQUIRED_FIELDS:
        if not entry.get(field):
            problems.append(f"missing required field '{field}'")

    status = entry.get("status")
    if status and status not in STATUSES:
        problems.append(f"status '{status}' is not one of: "
                        f"{', '.join(STATUSES)}")

    conf = entry.get("confidence")
    if conf is not None and conf not in CONFIDENCES:
        problems.append(f"confidence '{conf}' is not one of: "
                        f"{', '.join(CONFIDENCES)}")

    if kind and entry.get("kind") and entry["kind"] != kind:
        problems.append(f"kind '{entry['kind']}' does not match the ledger "
                        f"category '{kind}'")

    evidence = entry.get("evidence") or []
    if not isinstance(evidence, list):
        problems.append("evidence must be a list")
        evidence = []
    tests = entry.get("tests") or []
    if not isinstance(tests, list):
        problems.append("tests must be a list")
        tests = []

    if status in STATUSES_REQUIRING_EVIDENCE and not evidence:
        problems.append(
            f"status '{status}' claims something about behaviour but carries "
            f"no evidence; without it the entry is only 'unknown'")
    if status in STATUSES_REQUIRING_TEST and not tests:
        problems.append(
            f"status '{status}' requires at least one test that could have "
            f"failed; recording none means it was not verified")

    # Confidence must not exceed what the status can justify on its own.
    implied = STATUS_IMPLIES_CONFIDENCE.get(status or "unknown")
    if implied and conf in CONFIDENCE_RANK and status != "refuted":
        if CONFIDENCE_RANK[conf] > CONFIDENCE_RANK[implied]:
            problems.append(
                f"confidence '{conf}' exceeds what status '{status}' can "
                f"justify on its own (at most '{implied}')")

    # A hypothesis must be testable, but recording it before the test runs is
    # the normal case. Requiring a *result* would mean hypotheses only enter
    # the ledger once they are already settled, which defeats the purpose. So
    # a hypothesis needs a recorded test or a statement of what would settle
    # it -- not a passing test.
    if status == "hypothesized" and not (tests or entry.get("next_test")):
        problems.append(
            "status 'hypothesized' with neither a test nor a 'next_test': a "
            "hypothesis nobody can act on should be 'unknown'")

    # A refuted entry must record why, or it will be retried.
    if status == "refuted" and not (entry.get("refuted_by")
                                    or tests or entry.get("notes")):
        problems.append(
            "status 'refuted' with no record of what refuted it; this is how "
            "hypotheses get re-tested")

    # Related entries must exist as fields if used.
    for rel in ("related_functions", "related_data", "related_structures"):
        v = entry.get(rel)
        if v is not None and not isinstance(v, list):
            problems.append(f"{rel} must be a list")

    if entry.get("name") and not str(entry["name"]).strip():
        problems.append("name is empty")

    return problems


def summarise_entry(entry: Dict) -> Dict:
    """Compact view for list output and for cross-referencing."""
    return {
        "name": entry.get("name"),
        "kind": entry.get("kind"),
        "status": entry.get("status"),
        "confidence": entry.get("confidence"),
        "evidence_count": len(entry.get("evidence") or []),
        "test_count": len(entry.get("tests") or []),
        "contradiction_count": len(entry.get("contradicting") or []),
        "confidence_basis": entry.get("confidence_basis"),
    }


def facts_vs_hypotheses(entries: Iterable[Dict]) -> Dict:
    """Separate what is established from what is assumed.

    This is the query that answers "am I about to build on a guess?". An entry
    counts as load-bearing only if something else refers to it.
    """
    entries = list(entries)
    established, assumed, rejected = [], [], []
    referenced: Dict[str, int] = {}

    for e in entries:
        name = str(e.get("name") or "")
        for rel in ("related_functions", "related_data", "related_structures",
                    "depends_on", "uses", "related"):
            items = e.get(rel) or []
            if not isinstance(items, list):
                items = [items]
            for item in items:
                key = str(item)
                # An entry never references itself; counting that would make
                # every entry load-bearing by definition.
                if key and key != name:
                    referenced[key] = referenced.get(key, 0) + 1

    for e in entries:
        if e.get("status") == "refuted":
            rejected.append(e)
        elif e.get("status") in ("verified", "reconstructed",
                                 "partially-reconstructed", "observed"):
            established.append(e)
        else:
            assumed.append(e)

    load_bearing_assumptions = []
    for e in assumed:
        name = str(e.get("name") or "")
        if referenced.get(name):
            load_bearing_assumptions.append({
                "name": name,
                "status": e.get("status"),
                "confidence": e.get("confidence"),
                "referenced_by_count": referenced[name],
                "risk": "an assumed element that other reconstructions depend "
                        "on; verify it before building further on it",
            })

    return {
        "established": [e.get("name") for e in established],
        "assumed": [{"name": e.get("name"), "status": e.get("status"),
                     "confidence": e.get("confidence")} for e in assumed],
        "refuted": [e.get("name") for e in rejected],
        "load_bearing_assumptions": load_bearing_assumptions,
        "counts": {"established": len(established), "assumed": len(assumed),
                   "refuted": len(rejected)},
        "note": "an assumption that others depend on is the first thing to "
                "verify: everything above it inherits its uncertainty",
    }


# --------------------------------------------------------------------------
# Ledger storage
# --------------------------------------------------------------------------


class LedgerError(Exception):
    """Raised for a ledger problem the caller must handle."""


class Ledger:
    """A set of the eight ledger files, read and written as JSON.

    One JSON document per category keeps writes atomic and lets the whole
    ledger be diffed, so a status change is reviewable.
    """

    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.kinds = list(LEDGER_KINDS)

    # -- paths -----------------------------------------------------------
    def path_for(self, category: str) -> str:
        if category not in LEDGER_KINDS:
            raise LedgerError(
                f"unknown ledger '{category}'; expected one of: "
                f"{', '.join(LEDGER_KINDS)}")
        return os.path.join(self.root, f"{category}.json")

    def exists(self) -> bool:
        return all(os.path.isfile(self.path_for(k)) for k in self.kinds)

    def missing(self) -> List[str]:
        return [k for k in self.kinds if not os.path.isfile(self.path_for(k))]

    # -- io --------------------------------------------------------------
    def read(self, category: str) -> List[Dict]:
        path = self.path_for(category)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except FileNotFoundError:
            raise LedgerError(f"no such ledger: {path}")
        except json.JSONDecodeError as e:
            raise LedgerError(f"{path} is not valid JSON: {e}")
        if isinstance(doc, list):
            return [x for x in doc if isinstance(x, dict)]
        entries = doc.get("entries")
        if not isinstance(entries, list):
            raise LedgerError(
                f"{path} must contain a list, or an object with an 'entries' "
                f"list")
        return [x for x in entries if isinstance(x, dict)]

    def write(self, category: str, entries: List[Dict]) -> str:
        path = self.path_for(category)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "category": category,
            "kind": LEDGER_KINDS[category],
            "count": len(entries),
            "entries": entries,
        }
        try:
            os.makedirs(self.root, exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=False)
                fh.write("\n")
            os.replace(tmp, path)
        except OSError as e:
            raise LedgerError(f"cannot write {path}: {e}")
        return path

    def all_entries(self) -> List[Tuple[str, Dict]]:
        out: List[Tuple[str, Dict]] = []
        for category in self.kinds:
            if not os.path.isfile(self.path_for(category)):
                continue
            for e in self.read(category):
                out.append((category, e))
        return out

    # -- mutation --------------------------------------------------------
    def add(self, category: str, entry: Dict) -> Dict:
        entries = self.read(category)
        name = entry.get("name")
        if any(str(e.get("name")) == str(name) for e in entries):
            raise LedgerError(
                f"'{name}' already exists in {category}.json; use "
                f"`update` to change it, or pick a distinct name")
        entries.append(entry)
        self.write(category, entries)
        return entry

    def update(self, category: str, name: str,
               changes: Dict) -> Tuple[Dict, List[Dict]]:
        entries = self.read(category)
        for i, e in enumerate(entries):
            if str(e.get("name")) == str(name):
                before = dict(e)
                e.update(changes)
                # An append-only record of what moved. This is what stops a
                # hypothesis from quietly becoming a fact with no trace. The
                # log records the status transition specifically, because
                # that is the move whose loss does the damage.
                moved = {k: v for k, v in changes.items()
                         if before.get(k) != v}
                if moved:
                    log = e.setdefault("history", [])
                    if not isinstance(log, list):
                        log = []
                        e["history"] = log
                    log.append({
                        "from_status": before.get("status"),
                        "to_status": e.get("status"),
                        "from_confidence": before.get("confidence"),
                        "to_confidence": e.get("confidence"),
                        "changes": moved,
                    })
                entries[i] = e
                self.write(category, entries)
                return e, validate_entry(e, LEDGER_KINDS[category])
        raise LedgerError(f"no entry named '{name}' in {category}.json")

    def find(self, name: str) -> List[Tuple[str, Dict]]:
        return [(cat, e) for cat, e in self.all_entries()
                if str(e.get("name")) == str(name)]

    # -- validation ------------------------------------------------------
    def validate(self) -> Dict:
        report: Dict = {"ledger": self.root, "checked": 0, "valid": 0,
                        "problems": [], "load_bearing": []}
        entries: List[Dict] = []
        for category in self.kinds:
            if not os.path.isfile(self.path_for(category)):
                report["problems"].append({
                    "category": category,
                    "entry": None,
                    "problem": "ledger file is missing; run `init`"})
                continue
            try:
                cat_entries = self.read(category)
            except LedgerError as e:
                report["problems"].append({"category": category, "entry": None,
                                           "problem": str(e)})
                continue
            for e in cat_entries:
                entries.append(e)
                report["checked"] += 1
                problems = validate_entry(e, LEDGER_KINDS[category])
                if problems:
                    for p in problems:
                        report["problems"].append({
                            "category": category,
                            "entry": e.get("name"),
                            "problem": p})
                else:
                    report["valid"] += 1
        fv = facts_vs_hypotheses(entries)
        report["load_bearing"] = fv["load_bearing_assumptions"]
        report["counts"] = fv["counts"]
        report["facts_vs_hypotheses"] = fv
        report["ok"] = not report["problems"]
        return report


def new_entry(name: str, kind: str, status: str = "unknown",
              confidence: Optional[str] = None,
              evidence: Optional[List[str]] = None,
              hypothesis: Optional[str] = None,
              tests: Optional[List[str]] = None,
              observed_behavior: Optional[str] = None,
              next_test: Optional[str] = None,
              notes: Optional[str] = None,
              **extra) -> Dict:
    """Build an entry with the shape the validator expects.

    ``evidence`` entries are free text but should name what was seen and where,
    because an evidence string that cannot be located cannot be re-checked.

    ``next_test`` states what would settle the entry without claiming it was
    run. That distinction is what lets a hypothesis be recorded on the day it
    is formed rather than only once it is settled.
    """
    entry: Dict[str, Any] = {
        "name": name,
        "kind": kind,
        "status": status,
        "evidence": list(evidence or []),
    }
    if confidence is not None:
        entry["confidence"] = confidence
    if hypothesis:
        entry["hypothesis"] = hypothesis
    if observed_behavior:
        entry["observed_behavior"] = observed_behavior
    if next_test:
        entry["next_test"] = next_test
    if tests:
        entry["tests"] = list(tests)
    if notes:
        entry["notes"] = notes
    for k, v in extra.items():
        if v not in (None, [], {}):
            entry[k] = v
    return entry


# --------------------------------------------------------------------------
# Traces
# --------------------------------------------------------------------------

EVENT_KEYS = ("event", "name", "label", "op", "fn", "function", "addr",
              "address", "pc")


def parse_trace(text: str) -> List[Dict]:
    """Parse a trace into events.

    Two formats are accepted, because both occur in practice:

      * one event per line, ``#`` comments and blank lines ignored
        -- this is what a debugger or a logging hook produces.
      * a JSON array of objects, or ``{"events": [...]}``
        -- this is what an instrumented reimplementation produces.

    Each event is normalised to ``{"index", "label", "detail"}`` so the two
    sides are comparable even when one is text and the other JSON.
    """
    stripped = (text or "").strip()
    if not stripped:
        return []
    if stripped[0] in "[{":
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError(f"trace looks like JSON but does not parse: {e}")
        if isinstance(doc, dict):
            doc = doc.get("events", [])
        if not isinstance(doc, list):
            raise ValueError("JSON trace must be an array or an object with "
                             "an 'events' array")
        events = []
        for i, item in enumerate(doc):
            if not isinstance(item, dict):
                events.append({"index": i, "label": str(item), "detail": None})
                continue
            label = None
            for key in EVENT_KEYS:
                if key in item and item[key] is not None:
                    label = str(item[key])
                    break
            if label is None:
                label = json.dumps(item, sort_keys=True)
            detail = None
            for key in ("args", "detail", "value", "result", "state"):
                if key in item:
                    detail = item[key]
                    break
            events.append({"index": i, "label": label, "detail": detail,
                           "raw": item, "_typed": True})
        return events

    events = []
    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # "label detail" -- the label is the first token, the rest is context.
        parts = line.split(None, 1)
        events.append({"index": i, "label": parts[0],
                       "detail": parts[1] if len(parts) > 1 else None})
    return events


def event_label(ev: Dict) -> str:
    return str(ev.get("label") or "")


def event_detail(ev: Dict) -> Optional[str]:
    """Canonical text form of an event's arguments.

    Comparing events on their label alone produces a false all-clear: a
    reimplementation that performs the right calls with the wrong arguments
    looks identical. So the comparison key includes the arguments whenever the
    trace carries them.
    """
    detail = ev.get("detail")
    if detail is None:
        return None
    # A JSON trace carries typed values, so its arguments are re-encoded
    # rather than str()'d: the integer 2 and the string "2" are different
    # arguments, and a reimplementation passing the wrong one must not compare
    # equal. A text trace has no types, so its detail is used as written.
    if isinstance(detail, str) and not ev.get("_typed"):
        return detail
    try:
        return json.dumps(detail, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(detail)


def event_key(ev: Dict, labels_only: bool = False) -> str:
    """The string two events must match for the traces to agree here."""
    label = event_label(ev)
    if labels_only:
        return label
    detail = event_detail(ev)
    return label if detail is None else f"{label} {detail}"


def first_divergence(a: List[Dict], b: List[Dict],
                     include_detail: bool = False,
                     labels_only: bool = False) -> Dict:
    """Locate the first index where two traces stop agreeing.

    This is the whole point of trace comparison. A later difference may be a
    *consequence* of an earlier one, so patching whatever is visible at the
    end of the log fixes nothing. The first divergence is where the
    investigation belongs.

    Agreement is on label *and* arguments unless ``labels_only`` is set. Two
    traces that call the same functions with different arguments have not
    agreed, and reporting them as identical would be worse than reporting no
    result at all.
    """
    n = min(len(a), len(b))
    first = None
    kind = "none"
    for i in range(n):
        ka, kb = event_key(a[i], labels_only), event_key(b[i], labels_only)
        if ka != kb:
            first = i
            kind = "label" if event_label(a[i]) != event_label(b[i]) \
                else "detail"
            break
    identical = first is None and len(a) == len(b)

    result: Dict[str, Any] = {
        "identical": identical,
        "kind": "none" if identical else kind,
        "comparison": "labels only" if labels_only
        else "label and arguments",
        "common_prefix_length": (n if first is None else first),
        "first_divergence_index": first,
        "length_a": len(a),
        "length_b": len(b),
        "one_side_exhausted": len(a) != len(b) and first is None,
    }

    if identical:
        result["divergence"] = None
        result["note"] = (
            "the traces agree on every event checked. That is necessary but "
            "not sufficient: agreement here says nothing about state, only "
            "about which events happened")
        return result

    if first is None:
        # One trace is a strict prefix of the other: one side stopped early.
        shorter_len = min(len(a), len(b))
        result["kind"] = "truncation"
        result["divergence"] = {
            "index": shorter_len,
            "side_a": event_label(a[shorter_len]) if len(a) > shorter_len
            else None,
            "side_b": event_label(b[shorter_len]) if len(b) > shorter_len
            else None,
            "explanation": f"one trace has {shorter_len} events and the other "
                           f"{max(len(a), len(b))}; the shorter one stopped "
                           f"here. This is a difference in termination, not "
                           f"necessarily in behaviour",
        }
        return result

    da = a[first] if include_detail else {"label": event_label(a[first])}
    db = b[first] if include_detail else {"label": event_label(b[first])}
    result["divergence"] = {
        "index": first,
        "side_a": da,
        "side_b": db,
    }
    if kind == "detail":
        result["divergence"]["explanation"] = (
            "both sides perform the same event with different arguments. The "
            "call sequence agrees; the data does not. Compare the values and "
            "find which side is passing the specification's value.")
    return result


# --------------------------------------------------------------------------
# Observable state comparison
# --------------------------------------------------------------------------

def flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten nested JSON into dotted paths, so a missing key is a diff."""
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.update(flatten(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            out.update(flatten(v, path))
    else:
        out[prefix] = obj
    return out


# Numeric kinds that produce a plausible one-unit difference. These are
# candidates for investigation, never a fix to apply.
NUMERIC_CAUSE_PATTERNS = [
    ("fixed-point rounding",
     "an integer scaled by a fixed factor loses the low bits; a difference "
     "of one unit usually means the reimplementation rounds where the "
     "original truncates, or applies the scale at a different point"),
    ("integration order",
     "accumulating values in a different order gives a different result; "
     "the original's order may be observable from which writes occur first"),
    ("division vs shift",
     "a divide and a shift by a power of two agree for non-negative values "
     "and disagree for negative ones; check whether the value can be "
     "negative"),
    ("float vs fixed-point",
     "a float and a fixed-point representation of the same quantity drift "
     "apart as magnitude grows; the divergence growing with value is the "
     "signature"),
    ("overflow or wraparound",
     "a result exceeding the field width wraps; a difference of exactly the "
     "field range points here"),
    ("saturation or clamp",
     "a clamp at a limit makes the two implementations agree up to the "
     "limit and disagree beyond it"),
    ("sign or width mismatch",
     "signedness or width differences disagree only on particular values; "
     "test the boundary values explicitly"),
    ("unit or scale mismatch",
     "the values differ by a constant factor, which indicates a unit "
     "conversion applied at a different place"),
]

DIVERGENCE_TOLERANCE_NOTE = (
    "A difference within the tolerance is not recorded as a divergence. The "
    "tolerance is an assertion about acceptable numerical noise, and it "
    "should be justified by the format's actual precision, not chosen to "
    "make the comparison pass.")


def numeric_causes(a: Any, b: Any, field_path: str = "") -> List[Dict]:
    """Candidate explanations for a numeric divergence.

    Every entry is a hypothesis about the cause with the test that would
    settle it. Nothing here says which is true: the values alone cannot
    distinguish them, and guessing is how a reimplementation acquires a bug
    that looks like a fix.
    """
    if not isinstance(a, (int, float)) or isinstance(a, bool):
        return []
    if not isinstance(b, (int, float)) or isinstance(b, bool):
        return []
    if a == b:
        return []

    delta = b - a
    rel = abs(delta) / abs(a) if a else float("inf")
    causes = [{
        "cause": "observed",
        "delta": delta,
        "relative_delta": None if rel == float("inf") else round(rel, 6),
        "field": field_path,
        "sign_changed": (a > 0) != (b > 0),
    }]

    # Constant ratio across every divergence is the strongest signal there is
    # for a unit problem; the caller aggregates that, this only flags it.
    if a != 0 and abs(delta) > 0:
        ratio = b / a
        if abs(ratio - round(ratio)) < 1e-9 and round(ratio) not in (0, 1):
            causes.append({
                "cause": "integer ratio between the two values",
                "detail": f"b/a = {ratio:g}, a whole number; this is what a "
                          f"unit or scale difference looks like",
                "test": "confirm the scale factor used by the original, then "
                        "check whether the conversion is applied once or "
                        "twice",
            })
    if abs(delta) == 1:
        causes.append({
            "cause": "off-by-one at a discrete step",
            "detail": "the values differ by exactly one, which is the "
                      "signature of a rounding-mode or inclusive/exclusive "
                      "boundary difference",
            "test": "compare the value at the boundary itself, and one step "
                    "either side of it, where a truncation and a round-half-up "
                    "disagree",
        })
    if abs(a) > 1000 and abs(rel) < 1e-3:
        causes.append({
            "cause": "relative error consistent with accumulated float error",
            "detail": f"absolute difference {delta:g} is small relative to "
                      f"the magnitude ({rel:.2e})",
            "test": "compare the operation performed in the original: a "
                    "single multiply, or an accumulation over many steps",
        })
    return causes


def diff_observations(a: Dict, b: Dict,
                      tolerance: float = 0.0,
                      first_only: bool = False,
                      numeric_only: bool = False) -> Dict:
    """Compare two observable-state snapshots.

    Returns every divergent field with the evidence for the difference. The
    ordering is by field path so the report is deterministic; the caller
    decides what the *first* meaningful divergence is, because "first" for a
    state snapshot is a semantic judgement this function cannot make.
    """
    fa, fb = flatten(a), flatten(b)
    keys = sorted(set(fa) | set(fb))

    fields: List[Dict] = []
    for k in keys:
        in_a, in_b = k in fa, k in fb
        va, vb = fa.get(k), fb.get(k)

        if not in_a:
            fields.append({"field": k, "kind": "only_in_b",
                           "value_a": None, "value_b": vb,
                           "explanation": "the reimplementation reports a "
                                          "field the original does not have, "
                                          "or the original stopped recording "
                                          "before this point"})
            continue
        if not in_b:
            fields.append({"field": k, "kind": "only_in_a",
                           "value_a": va, "value_b": None,
                           "explanation": "the original observed this field "
                                          "but the reimplementation does not "
                                          "report it; the reimplementation may "
                                          "not be observing the same thing"})
            continue

        if va == vb:
            continue

        both_num = (isinstance(va, (int, float)) and not isinstance(va, bool)
                    and isinstance(vb, (int, float)) and not isinstance(vb, bool))
        if both_num and abs(vb - va) <= tolerance:
            continue

        entry = {"field": k, "kind": "value", "value_a": va, "value_b": vb}
        if both_num:
            entry["delta"] = vb - va
            entry["candidate_causes"] = numeric_causes(va, vb, k)
        elif type(va) is not type(vb):
            entry["kind"] = "type"
            entry["explanation"] = (
                f"the types differ ({type(va).__name__} vs "
                f"{type(vb).__name__}); a type change at this field is often "
                f"the real divergence, with the value difference as a symptom")
        else:
            entry["explanation"] = "the values differ"
        if numeric_only and not both_num:
            continue
        fields.append(entry)

    result = {
        "compared_fields": len(keys),
        "divergent_fields": len(fields),
        "identical": not fields,
        "tolerance": tolerance,
        "fields": fields,
        "note": DIVERGENCE_TOLERANCE_NOTE if tolerance else None,
        "method": (
            "Establish which side is correct before changing either. A "
            "divergence is a disagreement between two observations; only one "
            "of them can be the specification. Record the answer in the "
            "ledger before patching the implementation."),
    }
    if first_only and fields:
        result["first_divergence"] = fields[0]
        result["fields"] = [fields[0]]
        result["note"] = (
            "only the first divergent field by sorted path is shown; field "
            "order is not execution order, so this is the first to "
            "*investigate*, not necessarily the first to have occurred")
    return result