---
name: Revalith
description: Investigate binaries, mobile apps, web targets, protocols and native code with evidence-driven static and dynamic analysis.
metadata:
  opencode/autoinvoke: true
---

# Revalith

Investigate unknown software: locate what matters, reconstruct data flow, and
validate conclusions against observed behaviour.

Covers **binary**, **Android/mobile**, **Unity/IL2CPP**, **web** and
**protocol** reverse engineering, plus binary diffing, automated triage and
long-running investigation state.

**Revalith** is a **methodology**, not a command list. The evidence discipline
is the value; the commands are how evidence is gathered.

## The one rule

**Never assign meaning without evidence.**

Do not write "this function authenticates the user" because it mentions an
authentication string. Write what was observed, what it suggests, and what
would confirm it:

```
Observed: references "login_failed"; called only from sub_4012a0;
          return value branched on by that caller.
Hypothesis: participates in authentication failure handling.
Test:     trace it during a failed login; compare with a successful one.
Confidence: medium
```

Confidence levels: `very low`, `low`, `medium`, `high`, `very high`. Say *why*
a level was chosen. When evidence is absent, the correct answer is `unknown`
or `insufficient evidence` — never a plausible invention.

Three labels are used consistently everywhere:

| Label | Means |
| --- | --- |
| `observed` | directly present in the artefact or at runtime |
| `inferred` | an interpretation consistent with the observations |
| `confirmed` | verified by a test that could have failed |

## Workflow

Adaptive, not a checklist. Moving backwards is expected, not a failure.

1. **Identify the target** — what is it, and what question are we answering?
2. **Determine format and architecture** — identify by *content*, not
   extension. See `references/web-re.md` for web targets.
3. **Inspect the environment** — never assume a tool exists. `references/tooling.md`.
4. **Collect metadata** — hash it first; you will compare versions.
5. **Triage** — for anything unfamiliar, `universal-dump.py` before deep work.
6. **Inspect sections/segments or surface** — layout, entropy, packing.
7. **Inspect symbols/imports/exports** — what is visible, what was stripped.
8. **Extract strings** — entry points for investigation, never proof.
9. **Map references** — string → function → callers → callees.
10. **Identify candidate functions** — where is this behaviour implemented?
11. **Analyse callers/callees** — what feeds it, what does it call?
12. **Reconstruct arguments and returns** — conservative naming.
13. **Infer structures** — offsets, not invented field names.
14. **Compare versions** — when another build exists.
15. **Dynamic analysis** — when static analysis stops being decisive.
16. **Hook and trace** — observe real arguments and returns.
17. **Test hypotheses** — design a test that could refute.
18. **Confirm or refute** — and say which.
19. **Record state** — so this work is not repeated. See `investigation-state.md`.
20. **Document** — evidence, hypothesis, test, conclusion, confidence.

A static finding that produces an unexpected runtime value sends you back to
step 11, not forward.

## Choosing where to start

| The target is | Start with | Then |
| --- | --- | --- |
| An unfamiliar file or package | `universal-dump.py` | its `next_steps` ranking |
| A web endpoint or client | `web-enum.py` (passive) | `references/web-re.md` |
| An Android APK/AAB | `universal-dump.py` | `references/android.md` |
| A known native binary | `elf-summary.py` | `function-signatures.py` |
| Two builds of the same thing | `universal-dump.py` ×2, then `dump-diff.py` | `references/binary-diff.md` |
| A protocol on the wire | capture bytes first | `references/protocols.md` |

`universal-dump.py` is an orchestrator, not an analyser. It identifies,
collects, delegates, and ranks. It deliberately does not reimplement Ghidra,
radare2 or IL2CPP dumpers — point it at the tools that do those jobs.

## Scripts

Standard-library Python 3. Each has `--help`; most support `--json`.

| Script | Purpose |
| --- | --- |
| `universal-dump.py` | Triage orchestrator: identify files by content, extract indicators, delegate to external tools, rank next steps. |
| `web-enum.py` | Passive-first web reconnaissance; `web-re.md` comparison of a working vs failing client. |
| `elf-summary.py` | Format, arch, sections, segments, deps, symbol counts. |
| `strings-map.py` | Strings with addresses; pointer and instruction references to them. |
| `find-xrefs.py` | Who references an address, symbol or string? Maps xrefs to functions. |
| `compare-symbols.py` | Diff symbols/imports/exports between two builds. |
| `function-signatures.py` | Infer probable signatures from register usage. Labelled inference. |
| `dump-diff.py` | Compare two `universal-dump.py` reports. |

`scripts/dumpers/` holds the internal modules the orchestrator uses
(`_formats`, `_indicators`, `_binaries`, `_android`, `_unity`, `_archives`,
`_assets`, `_report`, `_tools`). They are prefixed `_` because they are not
command-line tools.

Verify the parsers at any time:

```sh
python3 scripts/selftest.py     # 195 checks, offline, no tools required
```

Quick start:

```sh
scripts/universal-dump.py ./target.apk -o dump/        # triage
scripts/elf-summary.py ./libfoo.so --hash --sections   # orient
scripts/strings-map.py ./libfoo.so --search "error"    # entry points
scripts/web-enum.py https://target.example              # passive recon
scripts/dump-diff.py dump-v1/report.json dump-v2/report.json
```

## References

Load only what the question needs.

**Method** — `methodology.md` (evidence loop, confidence, reproducibility,
reporting), `tooling.md` (tool selection, probing, fallbacks),
`investigation-state.md` (dead ends, hypotheses, not repeating work)

**Formats** — `elf.md`, `pe.md`, `macho.md`, `android.md`, `web-re.md`

**Architectures** — `arm64.md`, `arm32.md`, `x86.md`

**Tools** — `ghidra.md`, `radare2.md`, `binary-ninja.md`

**Dynamic** — `dynamic-analysis.md`, `frida.md`, `gdb.md`, `lldb.md`

**Comparison** — `binary-diff.md`

**Protocols** — `protocols.md`

## Worked examples

- `analyze-binary.md` — unknown executable, from `file` to call graph
- `analyze-library.md` — shared library, metadata to dynamic validation
- `analyze-web-target.md` — web target; the app-works-browser-fails investigation
- `analyze-android-apk.md` — APK triage, manifest, JNI bridge
- `analyze-unity-il2cpp.md` — Unity/IL2CPP detection, metadata, obfuscated case
- `universal-dump.md` — automated triage and reading its ranking
- `trace-function.md` — settle one function with a debugger or Frida
- `find-protocol-handler.md` — string or opcode to parser and handler
- `compare-versions.md` — two builds to testable hypotheses
- `compare-binaries.md` — two targets, artefact diff vs behavioural diff

## Naming and structure rules

Names must be no more specific than the evidence supports.

```c
sub_4012a0        ->  parse_header        // ok: it parses a header
sub_4012a0        ->  validate_token_and_authenticate_user   // not ok
```

Reconstruct structures as raw layout; do not invent semantics:

```c
struct Player {   // partially inferred; field semantics unconfirmed
    +0x00 unknown
    +0x08 likely pointer   // accessed as [reg+8] then dereferenced
    +0x10 integer          // compared against 0..100 range
    +0x14 unknown
};
```

Record which **version** an offset came from. Structures shift, and an offset
without a version is worse than no offset.

## Limitations to expect

Stripped symbols, inlining, LTO, obfuscation, packing, encryption, ASLR/PIE,
indirect calls, virtual dispatch, JIT, self-modifying code, anti-debugging,
unknown architecture, restricted process access, protected IL2CPP metadata,
CDN-proxied origins. Any of these can make a technique inapplicable. Check
preconditions before promising a technique will work; state them when they will
not.

## Scope

Understanding, debugging, instrumentation, interoperability, compatibility
research, vulnerability analysis, and format/protocol investigation.

Documentation and read-only analysis tooling. Access techniques need
privileges and sandboxing that may not exist — say so rather than assuming. No
claim about a system should rest on evidence you did not actually collect.

Use the web tooling only against systems you own or are authorised to assess.