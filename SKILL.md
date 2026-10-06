---
name: Revalith
description: Investigate binaries, mobile apps, web targets, protocols and native code with evidence-driven static and dynamic analysis.
metadata:
  opencode/autoinvoke: true
---

# Revalith

Investigate unknown software, and — when the question calls for it —
reconstruct it. Locate what matters, reconstruct data flow, validate
conclusions against observed behaviour, and build equivalent software from
what you established.

Covers **binary**, **Android/mobile**, **Unity/IL2CPP**, **web** and
**protocol** reverse engineering, plus binary diffing, automated triage,
long-running investigation state, and **software reconstruction** through
differential testing.

**Revalith** is a **methodology**, not a command list. The evidence discipline
is the value; the commands are how evidence is gathered.

## The ladder

Understanding compiled software is the first half. The second half is
reconstructing it: building software that behaves the same, from evidence
rather than from the original's code.

```
Reverse Engineering   observe: what is there
        ↓
Understanding         explain: what it means
        ↓
Reconstruction        model: what it does, independent of how
        ↓
Reimplementation      build: an equivalent that works
        ↓
Verification          prove: the two agree
        ↓
Porting               adapt: it works somewhere else
```

Decompilation is not reconstruction. A decompiler gives you C that runs;
reconstruction gives you a model you can test, and each claim in that model
carries the evidence for it. See `references/reconstruction.md`.

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
21. **Reconstruct, if the question calls for it** — model, implement, and
    verify. See `references/reconstruction.md`.

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
| Software you intend to rebuild | `universal-dump.py` | `reconstruction_candidates`, then `references/reconstruction.md` |

`universal-dump.py` is an orchestrator, not an analyser. It identifies,
collects, delegates, and ranks. It deliberately does not reimplement Ghidra,
radare2 or IL2CPP dumpers — point it at the tools that do those jobs.

## Knowing which phase you are in

The methodology changes at each rung, and mixing them produces work that is
neither analysis nor reconstruction. The words in the request usually say which
one you are in:

| The request says | Phase | You owe |
| --- | --- | --- |
| "understand", "what does this do", "how does it work" | analysis | an explanation with evidence |
| "what subsystem is this", "where is the collision code" | analysis → reconstruction | a model with per-claim confidence |
| "reconstruct", "model", "what are its parts" | reconstruction | a model in the ledger, tested where possible |
| "reimplement", "clone", "write my own", "compatible" | reconstruction → reimplementation | working code **and** a verification argument |
| "port", "make it run on" | porting | a port that passes the same differential tests |

The transition is worth naming explicitly, because reconstruction without the
verification step produces something that looks finished and is not.

## Reconstruction

When the task is to rebuild rather than to explain, the ledger becomes the
working document. It records what has been reconstructed and — the part that
matters — **how far**, so an old hypothesis is never read as a settled fact.

```sh
scripts/recon-ledger.py init ./reconstruction
scripts/recon-ledger.py add ./reconstruction functions 0x8120 \
    --evidence "called once per frame" "writes the word at +0x10" \
    --hypothesis "per-frame state update" --next-test "trace the writes" \
    --status hypothesized --confidence low
scripts/recon-ledger.py validate ./reconstruction
```

Status is one of `unknown`, `observed`, `hypothesized`,
`partially-reconstructed`, `reconstructed`, `verified`, `refuted`. The
validator refuses `verified` without a recorded test, and refuses a confidence
above what the status can justify.

### Verification is the part that is easy to skip

```sh
scripts/state-diff.py original.json mine.json --all-elements   # first divergence
scripts/trace-diff.py original.log mine.log --context 4        # first divergence
```

Both locate the **first** divergence. Everything after it may be a consequence
of it, so fixing the last mismatch in a log is fixing a symptom.

A divergence is a question with two possible answers: the reimplementation is
wrong, or the model was. Establish which before changing either. And a fix
that is not explained is not a fix — a constant that makes one frame agree is
not evidence about the next.

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
| `recon-ledger.py` | The reconstruction ledger: status, evidence, confidence, validation. |
| `state-diff.py` | Compare observable state; locate the first divergence; candidate causes. |
| `trace-diff.py` | Compare call traces; locate the first divergence in the sequence. |

`scripts/dumpers/` holds the internal modules the orchestrator uses
(`_formats`, `_indicators`, `_binaries`, `_android`, `_unity`, `_archives`,
`_assets`, `_report`, `_tools`). They are prefixed `_` because they are not
command-line tools. `_reconlib.py` is the shared library for the
reconstruction scripts, and `_weblib.py` for the web ones.

Verify the parsers at any time:

```sh
python3 scripts/selftest.py     # 283 checks, offline, no tools required
```

Quick start:

```sh
scripts/universal-dump.py ./target.apk -o dump/        # triage
scripts/elf-summary.py ./libfoo.so --hash --sections   # orient
scripts/strings-map.py ./libfoo.so --search "error"    # entry points
scripts/web-enum.py https://target.example              # passive recon
scripts/dump-diff.py dump-v1/report.json dump-v2/report.json

# reconstruction
scripts/recon-ledger.py init ./reconstruction          # start a ledger
scripts/state-diff.py original.json mine.json --all-elements
scripts/trace-diff.py original.log mine.log --detail
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

**Reconstruction** — `reconstruction.md` (the ladder; reconstruction versus
decompilation), `semantic-modeling.md` (evidence to a named model),
`behavioral-analysis.md` (behaviour, state machines, observables),
`differential-testing.md` (finding and explaining a divergence),
`reimplementation.md` (model to code, language, build, porting)

## Worked examples

Analysis:

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

Reconstruction:

- `reconstruct-function.md` — one address to a named, evidence-backed model
- `reconstruct-structure.md` — recovering a layout from access patterns
- `reconstruct-state-machine.md` — states from traces, guards by forcing them
- `reconstruct-protocol.md` — wire format to an independent client
- `reconstruct-legacy-game.md` — a synthetic legacy target, end to end
- `differential-testing.md` — locating and explaining a divergence
- `reimplement-subsystem.md` — model to working, verified code

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

Reconstruction inherits those limits and adds its own. These cannot be
reconstructed in general, and the answer is to say so:

- the original source text — not the goal, and not achievable
- original variable names, without debug info or a justifying string
- the author's intent — you can reconstruct the constraints, not the reason
- behaviour on inputs you never tested
- behaviour where the original reads a clock, an RNG, or the network, unless
  you can control that source

Binary-compatible fidelity is a separate goal from behavioural equivalence,
and it requires being able to run both implementations to know whether you
reached it. If you cannot, the claim is not checkable and should not be made.

## Scope

Understanding, debugging, instrumentation, interoperability, compatibility
research, vulnerability analysis, format/protocol investigation, and
reconstruction and reimplementation of software you are authorised to study.

Documentation, read-only analysis tooling, and a methodology for building
equivalent software. Access techniques need privileges and sandboxing that may
not exist — say so rather than assuming. No claim about a system should rest on
evidence you did not actually collect.

Use the web tooling only against systems you own or are authorised to assess.