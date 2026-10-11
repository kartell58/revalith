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

# The ten ledger files, with the entry kind each holds.
LEDGER_KINDS: Dict[str, str] = {
    "architecture": "architecture",
    "functions": "function",
    "structures": "structure",
    "states": "state",
    "systems": "system",
    "formats": "format",
    "protocols": "protocol",
    "hypotheses": "hypothesis",
    "verification": "verification",
    "dead_ends": "dead_end",
}

# Where an entry's evidence came from. One vocabulary across all three layers,
# so "what do we actually know from runtime?" is answerable across the whole
# ledger instead of by remembering which file an entry was filed under.
SOURCES = [
    "static", "dynamic", "runtime", "dump", "diff", "asset", "protocol",
    "other",
]

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

    # Provenance. Optional, because a first entry often predates knowing how it
    # was found, but validated when present, because an entry that claims
    # 'static' while resting on a runtime trace misleads whoever re-checks it.
    source = entry.get("source")
    if source is not None and source not in SOURCES:
        problems.append(
            f"source '{source}' is not one of: {', '.join(SOURCES)}")

    # A dead end is a refuted investigation, and the three fields below are what
    # make it worth recording: what was believed, what killed it, and what not
    # to do instead. Without 'avoid' it is a note; with it, it prevents work.
    if kind == "dead_end":
        if status != "refuted":
            problems.append(
                "a dead end is by definition refuted; if the idea is live "
                "again, record the new evidence and add a fresh entry rather "
                "than reopening this one")
        if not entry.get("hypothesis"):
            problems.append(
                "a dead end must record what was believed ('hypothesis'); a "
                "refutation without the claim says only that something failed")
        if not entry.get("avoid"):
            problems.append(
                "a dead end must record what not to do next ('avoid'), "
                "otherwise it is history rather than guidance")

    # Related entries must exist as fields if used.
    for rel in ("related_functions", "related_data", "related_structures"):
        v = entry.get(rel)
        if v is not None and not isinstance(v, list):
            problems.append(f"{rel} must be a list")

    # Evidence accounting. A ledger that records only what supports a claim
    # is a summary of the case for it, not an audit of it. The field that
    # makes a stale claim catchable months later is the one holding what
    # argued against it, so it is weighed here rather than merely stored.
    #
    # 'contradicting' predates this check and keeps its name; the
    # complementary list is 'supporting_observations'.
    supporting = entry.get("supporting_observations")
    contradicting = entry.get("contradicting")
    for field, value in (("supporting_observations", supporting),
                         ("contradicting", contradicting)):
        if value is not None and not isinstance(value, list):
            problems.append(f"{field} must be a list")
        elif isinstance(value, list) and any(
                isinstance(x, str) and not x.strip() for x in value):
            problems.append(
                f"'{field}' contains an empty entry, which weighs nothing and "
                f"reads as though something did")

    if isinstance(contradicting, list) and contradicting:
        # An entry that knows what argues against it and still calls itself
        # settled is the failure this check exists to catch. 'verified' means
        # the evidence survived its test; surviving is not the same as never
        # having been contradicted, and the difference has to be recorded.
        if status == "verified" and not entry.get("contradiction_resolved"):
            problems.append(
                "status 'verified' with recorded contradicting observations: "
                "verified means the evidence survived its test, so either "
                "record how the contradiction was resolved "
                "('contradiction_resolved') or the status is wrong")
        if status == "refuted" and not (entry.get("refuted_by") or tests):
            problems.append(
                "contradicting observations recorded but nothing says what "
                "settled them; add the refuting test, 'refuted_by', or a note")

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


def _norm(value: Any) -> str:
    """Normalise a name for comparison: case and spacing are not identity."""
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


# Fields through which an entry can declare that it is about an existing entry.
_REOPEN_REFERENCES = (
    "about", "reopens", "related", "depends_on", "uses", "related_functions",
    "related_data", "related_structures",
)


def find_reopened_dead_ends(entry: Dict, dead_ends: Iterable[Dict],
                            new_evidence: Optional[Any] = None) -> List[Dict]:
    """Dead ends that ``entry`` reopens.

    The ledger can record a refutation, but recording it is not enough: the same
    idea gets proposed again anyway, usually by someone who has not read the
    dead-end file, or by a session that started from the artefacts rather than
    the notes. This function is the mechanical form of "have we been here
    before".

    It reports, it does not forbid. A refuted idea can legitimately come back --
    a tool that was missing is now present, a trace was too short, the code was
    patched. What must not happen is reopening it silently, so the caller
    requires ``new_evidence`` when there is a hit.
    """
    if not isinstance(entry, dict) or not dead_ends:
        return []

    name = _norm(entry.get("name"))
    refers: set = set()
    for field in _REOPEN_REFERENCES:
        value = entry.get(field)
        if isinstance(value, list):
            refers |= {_norm(v) for v in value}
        elif isinstance(value, str):
            refers.add(_norm(value))
    refers.discard("")

    hypothesis = _norm(entry.get("hypothesis"))
    hits: List[Dict] = []
    for dead in dead_ends:
        if not isinstance(dead, dict):
            continue
        dead_name = _norm(dead.get("name"))
        dead_claim = _norm(dead.get("hypothesis"))
        why = None
        if dead_name and dead_name == name:
            why = "it has the same name as a recorded dead end"
        elif dead_name and dead_name in refers:
            why = "it names a recorded dead end as what it is about"
        elif (dead_claim and hypothesis and len(dead_claim) >= 16
              and (dead_claim in hypothesis or hypothesis in dead_claim)):
            why = "it restates the hypothesis a recorded dead end refuted"
        if not why:
            continue
        hits.append({
            "dead_end": dead.get("name"),
            "refuted_by": dead.get("refuted_by") or dead.get("tests"),
            "avoid": dead.get("avoid"),
            "matched_because": why,
            "has_new_evidence": bool(new_evidence
                                     or entry.get("new_evidence")),
        })
    return hits


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


GENERATED_BANNER = (
    "<!-- GENERATED by `recon-ledger.py render` from the ledger. Do not edit\n"
    "     this file by hand: the next render overwrites it. Edit the ledger. -->"
)


def _cell(value: Any) -> str:
    """One table cell: a pipe or a newline would break the row."""
    text = str(value if value is not None else "").strip()
    return text.replace("|", "\\|").replace("\n", " ")


def _entries_sorted(ledger: "Ledger", category: str) -> List[Dict]:
    try:
        entries = ledger.read(category)
    except LedgerError:
        return []
    return sorted((e for e in entries if isinstance(e, dict)),
                  key=lambda e: str(e.get("name") or ""))


def gaps(ledger: "Ledger") -> Dict:
    """What the ledger cannot yet answer.

    Derived entirely from what is recorded, so it cannot invent a gap and
    cannot miss one that is already visible in the entries. This is the
    question that never got asked: not "what have I found" but "what is still
    unknown", which is the one that decides what to investigate next.
    """
    missing_tests: List[Dict] = []
    unactionable: List[Dict] = []
    unresolved: List[Dict] = []
    unsourced: List[Dict] = []
    empty: List[str] = []
    everything: List[Dict] = []

    for category in LEDGER_KINDS:
        entries = _entries_sorted(ledger, category)
        if not entries:
            empty.append(category)
        for e in entries:
            everything.append(e)
            name, status = e.get("name"), e.get("status")
            tests = e.get("tests") or []
            contradicting = e.get("contradicting") or []
            if status in STATUSES_REQUIRING_TEST and not tests:
                missing_tests.append({
                    "name": name, "category": category, "status": status,
                    "why": "the status claims it was tested; no test is recorded",
                })
            if status == "hypothesized" and not tests and not e.get("next_test"):
                unactionable.append({
                    "name": name, "category": category,
                    "why": "a hypothesis with nothing that could settle it",
                })
            if contradicting and not e.get("contradiction_resolved"):
                unresolved.append({
                    "name": name, "category": category, "status": status,
                    "why": "observations argue against it and nothing says how "
                           "that was answered",
                })
            if not e.get("source"):
                unsourced.append({"name": name, "category": category})

    fv = facts_vs_hypotheses(everything)
    report: Dict[str, Any] = {
        "ledger": ledger.root,
        "missing_tests": missing_tests,
        "unactionable_hypotheses": unactionable,
        "unresolved_contradictions": unresolved,
        "load_bearing_assumptions": fv["load_bearing_assumptions"],
        "empty_categories": empty,
        "unsourced_entries": unsourced,
        "counts": {
            "entries": len(everything),
            "missing_tests": len(missing_tests),
            "unactionable_hypotheses": len(unactionable),
            "unresolved_contradictions": len(unresolved),
            "load_bearing_assumptions": len(fv["load_bearing_assumptions"]),
            "dead_ends": len(_entries_sorted(ledger, "dead_ends")),
            "empty_categories": len(empty),
            "unsourced_entries": len(unsourced),
        },
        "note": "an empty category means the question was never asked, not "
                "that it was answered; 'unsourced' means the layer that "
                "produced the evidence was not recorded, so the entry cannot "
                "be re-checked the way it was found",
    }
    report["clear"] = not (missing_tests or unactionable or unresolved)
    return report


def _entry_block(e: Dict, lines: List[str]) -> None:
    """One entry in the readable, hand-editable formats the project state uses."""
    lines.append(f"## {e.get('name')}")
    lines.append("")
    status = e.get("status")
    if e.get("source"):
        status = f"{status} (source: {e['source']})"
    lines.append(f"Status:     {status}")
    if e.get("confidence"):
        lines.append(f"Confidence: {e['confidence']}"
                     + (f" -- {e['confidence_basis']}"
                        if e.get("confidence_basis") else ""))
    for label, field in (("Hypothesis", "hypothesis"),
                         ("Observed behaviour", "observed_behavior"),
                         ("Refuted by", "refuted_by"),
                         ("Do not", "avoid"),
                         ("Next test", "next_test"),
                         ("Notes", "notes")):
        if e.get(field):
            lines.append(f"{label + ':':<12} {e[field]}")
    for label, field in (("Tests performed", "tests"),
                         ("Evidence", "evidence")):
        values = e.get(field) or []
        if values:
            lines.append(f"{label + ':':<12}")
            for v in values:
                lines.append(f"  - {v}")
    lines.append("")


def render_state(ledger: "Ledger") -> Dict[str, str]:
    """Render the readable project-state files from the ledger.

    The point is that there is one place where an investigation's state lives.
    A second, hand-maintained store is how a session ends up contradicting the
    ledger: both are correct on different days and nothing notices.

    Output is fully determined by the ledger contents and is sorted by name, so
    two renders of the same ledger are byte-identical and a regenerated file
    shows a real change rather than a formatting one.
    """
    files: Dict[str, str] = {}

    # -- dead ends --------------------------------------------------------
    dead = _entries_sorted(ledger, "dead_ends")
    lines = ["# Dead ends", "", GENERATED_BANNER, "",
             "Hypotheses that were tested and did not survive. A refuted",
             "hypothesis that is not recorded here gets re-tested in a later",
             "session, and the time spent will be invisible to anyone",
             "reviewing the work.", ""]
    if dead:
        for e in dead:
            _entry_block(e, lines)
    else:
        lines += ["No dead ends recorded.", ""]
    files["dead-ends.md"] = "\n".join(lines).rstrip() + "\n"

    # -- live hypotheses --------------------------------------------------
    hyps = [e for e in _entries_sorted(ledger, "hypotheses")
            if e.get("status") != "refuted"]
    lines = ["# Hypotheses", "", GENERATED_BANNER, "",
             "Live hypotheses with their status and next test. A hypothesis",
             "that has been refuted belongs in `dead_ends.md`, not here in a",
             "stale state.", ""]
    if hyps:
        for e in hyps:
            _entry_block(e, lines)
    else:
        lines += ["No live hypotheses recorded.", ""]
    files["hypotheses.md"] = "\n".join(lines).rstrip() + "\n"

    # -- known formats and protocols --------------------------------------
    for category, title, filename, blurb in (
        ("formats", "Known formats", "known-formats.md",
         "Container and file formats decoded so far. A repeating record size is"
         " a structure, not yet a format."),
        ("protocols", "Known protocols", "known-protocols.md",
         "Wire formats decoded so far: framing, fields, state machine. A"
         " parser that has not been run against real bytes is a hypothesis."),
    ):
        entries = _entries_sorted(ledger, category)
        lines = [f"# {title}", "", GENERATED_BANNER, "", blurb, ""]
        if entries:
            for e in entries:
                _entry_block(e, lines)
        else:
            lines += [f"Nothing recorded in `{category}.json` yet.", ""]
        files[filename] = "\n".join(lines).rstrip() + "\n"

    # -- known offsets ----------------------------------------------------
    entries = _entries_sorted(ledger, "structures")
    lines = ["# Known offsets", "", GENERATED_BANNER, "",
             "Structures recovered from this target, with the evidence behind",
             "each field.", "",
             "Offsets shift between versions. Record which version an offset",
             "was derived from: an offset without a version is worse than no",
             "offset, because it will be trusted where it no longer holds.",
             "",
             "An unverified field is better than an invented one. Write",
             "`unknown` rather than guessing a semantic name.", ""]
    if entries:
        lines += ["## Structures", ""]
        for e in entries:
            lines.append(f"### {e.get('name')}")
            lines.append("")
            for label, field in (("Derived from", "derived_from"),
                                 ("Derived on", "derived_on"),
                                 ("Hypothesis", "hypothesis"),
                                 ("Confidence", "confidence"),
                                 ("Still unknown", "notes"),
                                 ("Next test", "next_test")):
                if e.get(field):
                    lines.append(f"{label + ':':<14} {e[field]}")
            fields = e.get("fields") or []
            if fields:
                lines += ["", "| Offset | Size | Proposed type | Evidence "
                          "| Confidence |",
                          "| --- | --- | --- | --- | --- |"]
                for f in fields:
                    if isinstance(f, dict):
                        lines.append("| " + " | ".join(_cell(f.get(k)) for k in
                                ("offset", "size", "type", "evidence",
                                 "confidence")) + " |")
                    else:
                        lines.append("| " + " | ".join(_cell(x) for x in
                                (f, "", "", "", "")) + " |")
            evidence = e.get("evidence") or []
            if evidence:
                lines += ["", "Evidence:"]
                for v in evidence:
                    lines.append(f"  - {v}")
            lines.append("")
    else:
        lines += ["Nothing recorded in `structures.json` yet.", ""]
    files["known-offsets.md"] = "\n".join(lines).rstrip() + "\n"

    # -- the overview -----------------------------------------------------
    report = gaps(ledger)
    by_status: Dict[str, int] = {}
    for e in everything_or_empty(ledger):
        by_status[str(e.get("status"))] = by_status.get(str(e.get("status")), 0) + 1
    lines = ["# Investigation state", "", GENERATED_BANNER, "",
             "One source of truth: the ledger in `reconstruction/`. Everything",
             "below is rendered from it, and `known-offsets.md`,",
             "`known-formats.md`, `known-protocols.md`, `hypotheses.md` and",
             "`dead-ends.md` are rendered from the same entries.", "",
             "## Working with it", "",
             "```sh",
             "recon-ledger.py add ./reconstruction functions 0x8120 --evidence ...",
             "recon-ledger.py validate ./reconstruction",
             "recon-ledger.py gaps    ./reconstruction     # what is still open",
             "recon-ledger.py render  ./reconstruction -o ./project-state/",
             "```", "",
             "## Counts by category", "",
             "| Category | Entries |", "| --- | --- |"]
    for category in LEDGER_KINDS:
        lines.append(f"| {category} | {len(_entries_sorted(ledger, category))} |")
    lines += ["", "## Counts by status", "", "| Status | Entries |",
              "| --- | --- |"]
    for status in sorted(by_status):
        lines.append(f"| {status} | {by_status[status]} |")
    counts = report["counts"]
    lines += ["", "## Open", "",
              f"- missing tests: {counts['missing_tests']}",
              f"- hypotheses nobody can act on: "
              f"{counts['unactionable_hypotheses']}",
              f"- contradictions unresolved: "
              f"{counts['unresolved_contradictions']}",
              f"- assumptions other entries depend on: "
              f"{counts['load_bearing_assumptions']}",
              f"- categories never asked: {counts['empty_categories']}",
              f"- entries with no recorded source: "
              f"{counts['unsourced_entries']}",
              f"- dead ends recorded: {counts['dead_ends']}", "",
              "An empty category means the question was never asked, not that",
              "it was answered.", ""]
    files["investigation-state.md"] = "\n".join(lines).rstrip() + "\n"

    return files


def everything_or_empty(ledger: "Ledger") -> List[Dict]:
    """Every entry in the ledger, skipping unreadable files rather than failing."""
    out: List[Dict] = []
    for category in LEDGER_KINDS:
        out.extend(_entries_sorted(ledger, category))
    return out


def new_entry(name: str, kind: str, status: str = "unknown",
              confidence: Optional[str] = None,
              evidence: Optional[List[str]] = None,
              hypothesis: Optional[str] = None,
              tests: Optional[List[str]] = None,
              observed_behavior: Optional[str] = None,
              next_test: Optional[str] = None,
              notes: Optional[str] = None,
              supporting_observations: Optional[List[str]] = None,
              contradicting: Optional[List[str]] = None,
              source: Optional[str] = None,
              avoid: Optional[str] = None,
              refuted_by: Optional[str] = None,
              **extra) -> Dict:
    """Build an entry with the shape the validator expects.

    ``evidence`` entries are free text but should name what was seen and where,
    because an evidence string that cannot be located cannot be re-checked.

    ``next_test`` states what would settle the entry without claiming it was
    run. That distinction is what lets a hypothesis be recorded on the day it
    is formed rather than only once it is settled.

    ``supporting_observations`` and ``contradicting`` are the evidence
    accounting, kept apart from ``evidence`` because they answer a different
    question. ``evidence`` says what was seen; these say what the claim rests
    on and what argued against it. An entry recording only support is a summary
    of the case, not an audit of it, and the second list is the field that
    makes a stale claim catchable months later.

    ``source`` records which layer produced the evidence, so a claim resting on
    a runtime trace is not later defended as a static one.

    ``avoid``, ``refuted_by`` and ``hypothesis`` are what a dead end needs to be
    worth more than a line in a scratch file.
    """
    entry: Dict[str, Any] = {
        "name": name,
        "kind": kind,
        "status": status,
        "evidence": list(evidence or []),
    }
    if source is not None:
        entry["source"] = source
    if avoid:
        entry["avoid"] = avoid
    if refuted_by:
        entry["refuted_by"] = refuted_by
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
    if supporting_observations:
        entry["supporting_observations"] = list(supporting_observations)
    if contradicting:
        entry["contradicting"] = list(contradicting)
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