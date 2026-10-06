# Changelog

All notable changes to this skill are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions are for the skill, not for a target being analysed.

## [3.0.0] — 2026-10-06

Software reconstruction added as a first-class capability, taking the skill
from understanding compiled software to reimplementing it.

### Added

**Reconstruction methodology**
- `references/reconstruction.md` — the ladder
  (analysis → understanding → reconstruction → reimplementation → verification
  → porting), the difference from decompilation, the iterative loop, the four
  fidelity goals, and what cannot be reconstructed.
- `references/semantic-modeling.md` — evidence to a named model: the graded
  naming rule, structure and bitfield recovery from access evidence, enums,
  subsystem grouping with the evidence that does not establish a group, and
  invariants.
- `references/behavioral-analysis.md` — a model independent of the
  original's implementation: entities, state machines, guards, timing, assets
  and I/O as behaviour.
- `references/differential-testing.md` — determinism, what to compare, locating
  the first divergence, explaining it, fixed-point and numeric reconstruction,
  and what a passing test does not prove.
- `references/reimplementation.md` — model to code, language selection, build
  reconstruction, porting, and declaring what was not implemented.

**The reconstruction ledger**
- `scripts/_reconlib.py` — status and confidence vocabulary, entry validation,
  ledger storage with an audit trail, trace parsing, first-divergence
  location, observable-state diffing, and numeric cause hypotheses.
- `scripts/recon-ledger.py` — `init`, `add`, `update`, `list`, `show`,
  `validate`, `stats`. The validator refuses `verified` without a recorded
  test, refuses a confidence above what the status justifies, and refuses a
  `hypothesized` entry with neither a test nor a `next_test`.
- `templates/reconstruction/` — eight ledgers (architecture, functions,
  structures, states, systems, formats, hypotheses, verification) plus the
  schema document they follow.

**Differential tooling**
- `scripts/state-diff.py` — compare observable state, locate the first
  divergent frame with `--all-elements`, and report candidate causes for a
  numeric divergence with the test that would settle each. Causes are never
  presented as fixes.
- `scripts/trace-diff.py` — locate the first divergence between two call
  traces, distinguishing a different event from the same event with different
  arguments, and treating a shorter trace as a termination difference.

**Universal dump integration**
- `universal-dump.py` now emits `reconstruction_candidates` in `report.json`
  and `report.txt`, ranked from the same observations as `next_steps` but for a
  different question: what is worth rebuilding, rather than what is worth
  reading.

**Examples**
- `reconstruct-function.md`, `reconstruct-structure.md`,
  `reconstruct-state-machine.md`, `reconstruct-protocol.md`,
  `reconstruct-legacy-game.md`, `differential-testing.md`,
  `reimplement-subsystem.md`.

### Changed

- `SKILL.md` — the ladder, a table for recognising which phase a request is
  in, the reconstruction scripts, and what reconstruction cannot deliver.
- `README.md` — reconstruction described as a second capability, with the
  ledger and the differential tools.
- `selftest.py` — expanded from 195 to 283 checks, covering ledger validation,
  the load-bearing-assumption query, ledger round-trips, the shipped
  templates, trace parsing and first divergence, state diffing, numeric cause
  hypotheses, and reconstruction candidate ranking.

### Notes

- Reconstruction is presented as distinct from decompilation throughout: a
  decompiler produces source-like text, reconstruction produces a model where
  every claim is refutable.
- A numeric divergence is reported with candidate causes and the test that
  would settle each. The tools never suggest an edit, because a constant that
  makes one frame agree is not evidence about the next.
- Traces compare labels *and arguments* by default. Matching calls with
  different arguments is not agreement, and reporting it as such would be a
  false all-clear.
- Every example marks its target data as synthetic. No example presents
  invented results as observations of a real target.

## [2.0.0] — 2026-10-06

Web reverse engineering and automated triage added as first-class areas.

### Added

**Web reverse engineering**
- `references/web-re.md` — passive vs active reconnaissance, technology
  identification as evidence, application mapping, and the
  client-vs-browser investigation.
- `scripts/web-enum.py` — passive-by-default reconnaissance: DNS, TLS
  certificate, HTTP headers, cookies, security headers, `robots.txt`,
  `sitemap.xml`, referenced JavaScript. Records every request made.
- `scripts/_weblib.py` — shared web parsing: technology fingerprints with
  evidence and confidence, security-header audit, SAN classification,
  robots/sitemap parsing, JavaScript endpoint extraction, and request
  normalisation/diffing with credential redaction.
- `examples/analyze-web-target.md` — the app-works-browser-fails
  investigation, ending in a controlled one-variable-at-a-time test.

**Automated triage**
- `scripts/universal-dump.py` — triage orchestrator. Identifies files by
  content, extracts strings and network indicators with provenance,
  delegates to external tools, and ranks next steps from observed evidence.
  Deliberately does not reimplement Ghidra, radare2 or IL2CPP dumpers.
- `scripts/dumpers/` — internal modules (`_`-prefixed, not CLI tools):
  `_tools` (tool discovery), `_formats` (content-based identification,
  entropy, unknown-classification), `_indicators` (IOCs with provenance),
  `_binaries` (ELF/PE/Mach-O triage), `_android` (APK/AAB, binary XML),
  `_unity` (Unity/IL2CPP detection and metadata probing), `_archives`,
  `_assets`, `_report` (report rendering and next-step ranking).
- `scripts/dump-diff.py` — compares two `universal-dump.py` reports across
  files, indicators, binaries, Android manifest and Unity state, emitting
  hypotheses each with the test that would confirm it.
- `examples/universal-dump.md` — triage workflow and reading its ranking.
- `examples/analyze-android-apk.md` — APK triage, manifest, JNI bridge.
- `examples/analyze-unity-il2cpp.md` — Unity/IL2CPP detection, metadata
  probing, and the obfuscated-metadata case.
- `examples/compare-binaries.md` — artefact diff vs behavioural diff.

**Long-running investigation state**
- `references/investigation-state.md` — how to keep state so refuted and
  blocked hypotheses are not re-tested.
- `templates/project-state/` — `dead-ends.md`, `known-formats.md`,
  `known-offsets.md`, `known-protocols.md`, `hypotheses.md`.

### Changed

- `SKILL.md` — widened to cover binary, mobile, Unity/IL2CPP, web and protocol
  reverse engineering; added a "choosing where to start" table and the
  observed/inferred/confirmed labelling used throughout.
- `README.md` — new capability matrix, script overview, output layout,
  templates, and an explicit statement that the scripts require no network.
- `selftest.py` — expanded from 60 to 195 checks, now covering content-based
  identification, indicator provenance, Android binary XML, APK analysis,
  IL2CPP metadata probing, archives, binary triage, web technology evidence,
  request diffing and redaction, robots/sitemap parsing, JavaScript
  extraction, report ranking and tool discovery.

### Fixed

Bugs found while writing the new modules, in existing or new code:

- `_android.py` read AXML chunk types as 16-bit when the layout packs them
  differently, and read the start-element header as 56 bytes instead of 36,
  which prevented any manifest from being decoded.
- `_android.py` resolved typed attribute values from the wrong field, so
  integer attributes such as `versionCode` decoded as `None`.
- `_archives.extract_all` used a `while`/`else` in which the `else` could
  never run, so no zip member was ever counted as extracted.
- `_indicators.API_PATH_RE` required a path segment after the prefix, so
  `/api` alone was not captured.
- `_weblib.parse_robots` mishandled user-agent grouping and returned rule
  counts that did not reflect the parsed directives.
- `_weblib` JavaScript extraction looked for feature flags and endpoint names
  only inside quoted strings, missing bare identifiers.
- `_tools.tool_version` accepted an argument-parsing complaint as a version
  string (unzip answering `--version` with usage output).

### Notes

- `universal-dump.py` identifies files by content first and treats the
  extension as corroboration; a disagreement is reported.
- High entropy alone never produces an "encrypted" claim; `classify_blob`
  requires compound conditions and always returns a confidence.
- Indicators carry `source` and `offset`; the offset is `null` when it cannot
  be determined rather than being invented.
- IL2CPP metadata that does not parse is reported as
  `status: obfuscated_or_custom` with a confidence, never as "broken".
- Technology fingerprints distinguish structural evidence from
  self-declaration, and self-declarations always carry a caveat.
- All documented tool behaviour was verified against real binaries or
  generated fixtures, not assumed.

## [1.0.0] — 2026-10-06

Initial release.

### Added

**Methodology**
- Evidence-first investigation loop: observation → hypothesis → test →
  confirm/refute → document.
- Five confidence levels with a required justification for each assignment.
- `unknown` and `insufficient evidence` as legitimate conclusions.
- Reporting template separating observed evidence from interpretation.
- Reproducibility requirements: hash, tool version, command, load base.
- Naming rules forbidding claims stronger than the supporting evidence.

**Knowledge references** (18 files, loaded on demand)
- `methodology.md`, `tooling.md`
- Formats: `elf.md`, `pe.md`, `macho.md`, `android.md`
- Architectures: `arm64.md`, `arm32.md`, `x86.md`
- Tools: `ghidra.md`, `radare2.md`, `binary-ninja.md`
- Dynamic: `dynamic-analysis.md`, `frida.md`, `gdb.md`, `lldb.md`
- Analysis: `binary-diff.md`, `protocols.md`

**Scripts** (Python 3 standard library only)
- `elf-summary.py`, `strings-map.py`, `find-xrefs.py`,
  `compare-symbols.py`, `function-signatures.py`
- `selftest.py`: 60 assertions over generated ELF/PE/Mach-O fixtures
- `_binlib.py`: dependency-free ELF/PE/Mach-O parsers

**Worked examples**
- `analyze-binary.md`, `analyze-library.md`, `trace-function.md`,
  `find-protocol-handler.md`, `compare-versions.md`

### Notes

- Every documented command was verified against a real binary.
- AArch64 `adrp`/`add` pairs are recombined when resolving references, and
  register-overwrite tracking prevents false pairings.
- Scripts report missing external tools explicitly instead of returning
  silently incomplete results.