# Changelog

All notable changes to this skill are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions are for the skill, not for a target being analysed.

## [1.0.0] — 2026-10-06

Initial release.

### Added

**Methodology**
- Evidence-first investigation loop: observation → hypothesis → test →
  confirm/refute → document.
- Five confidence levels (`very low` through `very high`) with a required
  justification for each assignment.
- Explicit `unknown` / `insufficient evidence` as legitimate conclusions.
- Reporting template separating observed evidence from interpretation.
- Reproducibility requirements: file hash, tool version, exact command,
  load base, test conditions, observed result.
- Naming rules that forbid claims stronger than the supporting evidence.
- Structure-reconstruction rules that keep unknown fields unknown.

**Knowledge references** (18 files, loaded on demand)
- `methodology.md`, `tooling.md`
- Formats: `elf.md`, `pe.md`, `macho.md`, `android.md`
- Architectures: `arm64.md`, `arm32.md`, `x86.md`
- Tools: `ghidra.md`, `radare2.md`, `binary-ninja.md`
- Dynamic: `dynamic-analysis.md`, `frida.md`, `gdb.md`, `lldb.md`
- Analysis: `binary-diff.md`, `protocols.md`

**Scripts** (Python 3 standard library only, no dependencies)
- `elf-summary.py` — format, architecture, layout, dependencies and symbol
  counts for ELF, PE and Mach-O; container summary for APKs.
- `strings-map.py` — string extraction with addresses; pointer and
  instruction-level cross-reference resolution.
- `find-xrefs.py` — references to an address, symbol or string, mapped to
  containing functions.
- `compare-symbols.py` — symbol, import and export diffs between two builds,
  with optional rename candidates.
- `function-signatures.py` — probable signatures inferred from register usage;
  output is labelled as inference.
- `selftest.py` — 60 assertions covering ELF (32/64-bit, little/big-endian),
  PE32+ and Mach-O, using generated fixtures with known contents.
- `_binlib.py` — dependency-free format parsers shared by the scripts.

**Worked examples**
- `analyze-binary.md`, `analyze-library.md`, `trace-function.md`,
  `find-protocol-handler.md`, `compare-versions.md`

### Notes

- Every documented command was verified against a real binary; documented
  tool behaviour (interpreter paths, `.eh_frame` surviving stripping, ADRP/ADD
  pairing) is confirmed rather than assumed.
- AArch64 `adrp`/`add` pairs are recombined when resolving references, and
  register-overwrite tracking prevents false pairings.
- Scripts report missing external tools explicitly instead of returning
  silently incomplete results.