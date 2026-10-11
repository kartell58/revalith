# Changelog

All notable changes to this skill are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions are for the skill, not for a target being analysed.

## [4.3.0] — 2026-10-11

Three domains the skill could not previously answer for, written as
methodology rather than tooling.

### `emulation.md`

The largest conceptual hole. `reconstruct-legacy-game.md` rests on emulation
and the topic had one paragraph in `gdb.md`, so an agent following that example
had nowhere to go.

It covers choosing a level (instruction-level, user-mode, full-system, library
emulation) and states the cost of each rung before you climb it. The
Unicorn section is the one that pays: it describes the harness you have to
write, and the three ways a harness produces a confident wrong answer —
stopping on a fixed instruction count, zeroing memory that was never
initialised, and letting an unhooked import return whatever the harness
returned.

The section that matters most is "what emulation does not prove". A table of
claims, of what emulation gives you, and of what it does not: that a path runs
on real hardware, that something takes 3 ms, that no device is required. The
two conclusions stated outright are that an emulated crash may be the
emulator's, and that a path which never executes under emulation may execute
on hardware — so "never observed" is a statement about the model.

### `firmware.md`

An entire domain was absent. Firmware has no container, no program headers, no
process and no `/proc`, which makes it a content-identification problem before
it is anything else.

Establishing architecture is ordered by reliability, with the vector table
first — initial stack pointer, reset handler, interrupt vectors — and what it
tells you beyond the ISA: the stack pointer marks the top of RAM, which gives
the flash↔RAM relationship needed to read a `const` table correctly. Region
classification carries its basis, and the MMIO row says plainly that a region
at 0x40000000 is consistent with MMIO while the specific peripheral is not
established.

The `.data` relocation step is called out because it is the one most often
missed: a non-zero global lives at a different run address in RAM than its
load address in flash, and reading the flash copy yields the initial value and
nothing about the current one.

### `obfuscation.md`

Opens with the rule that matters: obfuscation is a hypothesis, not a reading. A
two-hundred-block graph with a state variable may be flattening, a state
machine, a protocol dispatcher, or a deliberately unrolled loop — the structure
is the observation and the name is the interpretation.

One section per family with what to observe and what would confirm it, then a
closing table with the pattern worth noticing: every technique needing the code
to be static and readable is the one that breaks, and every technique that
watches the program run survives. That is why the file sits in the dynamic half
of the skill.

The "what not to do" section is the disciplined part — do not apply a
deobfuscator because the pattern resembles a known one, do not `nop` a
predicate because one path was never taken on the inputs you tried, and do not
let a deobfuscation script become the artefact, because then the
reconstruction has no evidence behind it.

No scripts. Firmware scanning without `binwalk` is covered by
`universal-dump.py`, which reports magic and entropy with offsets and
provenance without deciding what a region is; heuristic obfuscation detectors
would be unsound, and an unsound detector that reports "flattened" is worse
than none.

## [4.2.0] — 2026-10-11

One store for investigation state, and a determinism gate before any
differential comparison.

### The ledger is now the only store

An investigation's state lived in two places: the reconstruction ledger, which
was machine-readable and validated, and `templates/project-state/`, which was
Markdown maintained by hand. Both were correct when written, and they stopped
agreeing — a session read the Markdown, reached a conclusion, recorded it in
the ledger, and did not update the notes. Nothing reports that disagreement,
because nothing could.

The ledger gains the two categories that only the Markdown had:

- `dead_ends` — the file the skill's own docs called "the important one" had
  no equivalent in the machine-readable store. A dead end is validated: it
  must record what was believed (`hypothesis`), what killed it (`refuted_by`),
  and what not to do instead (`avoid`). Without `avoid` it is history rather
  than guidance.
- `protocols` — wire formats had no category of their own and lived loosely
  under `formats`.

The readable Markdown is now **rendered** from the ledger by
`recon-ledger.py render`, with a banner saying so. Two renders of one ledger
are byte-identical, so a regenerated file shows a real change rather than a
formatting one. `templates/project-state/` becomes the reference format.

### Reopening a dead end now needs a reason

An idea legitimately comes back: a tool was missing, a trace was too short, the
code was patched. Reopening it *silently* is what costs a day, because nobody
realises the question was already settled.

`add` checks every new entry against the dead ends and refuses a match that
records nothing new. Three routes match — the same name, a reference to the
dead end's subject, and a restatement of the claim. `--new-evidence` states
what changed and the entry goes in. The requirement is a recorded reason, not
a prohibition.

### `gaps` — what is still open

The counter-question to `stats`. Stats answers what has been found, which
makes a long investigation feel finished; `gaps` answers what has not, which is
what picks the next hour of work. Derived entirely from recorded entries, so it
cannot invent a gap: claims whose status outruns their tests, hypotheses
nothing can settle, contradictions with no recorded answer, assumptions others
depend on, and **categories never asked** — an empty category is an unasked
question, not an answered one.

### `source` — provenance per entry

`static` · `dynamic` · `runtime` · `dump` · `diff` · `asset` · `protocol` ·
`other`. Optional, because a first entry often predates knowing how it was
found, and validated when present. An entry whose source is unknown cannot be
re-checked the way it was found, and `gaps` reports the ones that omit it.

### `determinism-check.py`

`differential-testing.md` told you to establish determinism before comparing
anything, and nothing executed it. The new tool compares N observations, names
the fields that vary, and lists where variation usually comes from.

It deliberately does not name a cause. "position.y differs between runs" is a
measurement; "the clock is not stubbed" is a hypothesis, and a tool that
printed the second would be asserting what the data does not say. A field that
stops being reported counts as variation too — easier to miss than a changing
value, and just as fatal. Agreement across N runs is reported as evidence, not
proof, with the sample count attached.

## [4.1.0] — 2026-10-11

Evidence accounting for the reconstruction ledger, and ownership as a
modelled relationship.

### Ledger: counter-evidence is weighed, not just stored

The ledger already had a `contradicting` field, and it was written down and
never looked at again — which meant the field recorded that a disagreement was
noticed without anything following from it. The failure it permits is
specific: a hypothesis forms, evidence accumulates, and three weeks later an
observation that argued against it sits in a list while the entry reads
`verified`.

The validator now weighs it. An entry cannot be `verified` while carrying
`contradicting` observations unless `contradiction_resolved` records how the
conflict was settled, and a `refuted` entry that records counter-evidence must
say what settled it. A hypothesis carrying counter-evidence stays valid —
refusing that would only teach people to leave the counter-evidence
unrecorded, which is worse.

Added the complementary `supporting_observations` field and a `--supporting`
flag. The split is deliberate: `evidence` records what was seen,
`supporting_observations` records what the claim rests on, and `contradicting`
records what argued against it. An entry with evidence and nothing in the other
two is a summary of the case for a conclusion rather than an audit of it.

### Ownership as a modelled relationship

`semantic-modeling.md` had no ownership section, which left lifetime — the most
expensive thing to get wrong in a reimplementation — to be inferred from
prose. It now carries the evidence table for establishing ownership, the
distinction between a reference and an owner, and the three failure modes that
recur: two references read as two owners, a `free` in the same function read
as destruction, and a missing free read as a leak.

`"owner": "unknown"` is documented as a legitimate and useful answer. Guessing
an owner from the fact that a struct holds a pointer produces a
reimplementation that double-frees, which is worse than one that leaks.

Selftest 519 -> 529 checks.

## [4.0.0] — 2026-10-11

Memory and runtime intelligence added as a third layer, alongside static
analysis and reconstruction. The skill could already hook a function; what it
could not do was say where a value lived, which thread wrote it, or how a
runtime address relates to a file offset.

Added `references/memory-runtime.md` — the methodology for investigating a
running process: memory maps and region classification, the address spaces and
the load bias, processes and module loading, threads, call stacks, memory
writes and provenance, heap and allocation, object lifetime, pointer and alias
analysis, syscalls and protection changes, signals and crashes, breakpoints
and watchpoints, the Android JNI and ART runtime, runtime/static correlation,
runtime differential analysis, and state reconstruction.

Added six scripts, each with one responsibility:

| Script | Purpose |
| --- | --- |
| `memory-map.py` | Read and classify a memory map; group modules; derive load bias |
| `normalize-address.py` | Translate a runtime address through module, ELF and file spaces, or explain why it cannot |
| `runtime-events.py` | The runtime event schema: validate, summarise, filter, provenance |
| `stack-groups.py` | Normalise and group call stacks; hot paths, rare paths, two-run comparison |
| `correlate-runtime.py` | Join runtime events to static analysis; thread table; capabilities |
| `diff-runtime.py` | Compare two runtime traces; locate the first divergence |

And `_runtimelib.py`, the shared library behind them, following the existing
`_`-prefix convention.

### A correctness fix that the layer depended on

The naive `runtime_address - module_base` translation, which most tooling
uses, was wrong for any module whose `PT_LOAD` segments carry different
vaddr/offset skews — which is most of them. A module mapping three segments at
skews of `0`, `0x4000` and `0x8000` yields three different "load biases", and
the usual result is that data-section addresses are read as code-section
addresses, producing plausible and wrong symbols.

Translation now derives from the file offset and the segment table, which needs
no bias and cannot be wrong because of one. The bias is computed from the
segment table and used only as a cross-check, with disagreement reported rather
than propagated. The selftest ELF fixture gained real program headers and a
`load_base` parameter, since a fixture where vaddr equals file offset cannot
test load-bias derivation at all.

### Discipline kept explicit

- Region classification carries the basis for its claim. An anonymous writable
  region is not a heap without a kernel name, a kernel hint or observed growth.
- An anonymous executable region is reported as that. Calling it JIT, an
  unpacker or a patcher is a reading and is labelled one.
- A protection change is a fact; its reason is not, and `mprotect` alone is
  never evidence of anti-tampering.
- A `caused_by` field with no recorded experiment is rejected by the schema.
  That is the field where an inference becomes a fact.
- A missing observation is reported as a gap in the trace, never as an absence
  of behaviour.
- A `.bss` address gets a bss offset and its variable's symbol, not an
  invented file offset.

Added `examples/runtime-state-hunt.md`, the whole sequence end to end on a
small native fixture: process, modules, memory map, address translation,
event trace, provenance, differential run, and a state model recorded at low
confidence with its counter-evidence. The measurements and the synthetic parts
are marked separately, and the example closes with what it does not establish.

Selftest grew from 283 to 529 checks, all offline and deterministic, including
a fixture built so that load-bias arithmetic is genuinely exercised.

Cross-links added from `dynamic-analysis.md`, `frida.md`, `gdb.md`, `lldb.md`,
`elf.md`, `android.md`, `binary-diff.md`, `reconstruction.md`, `tooling.md`
and `investigation-state.md`. Runtime tool groups (`syscall_tracer`,
`profiler`, `memcheck`, `emulator`) added to capability detection.

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