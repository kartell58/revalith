# Revalith

An evidence-driven methodology for investigating compiled software, native
libraries, mobile apps, web targets, binary formats and proprietary protocols —
packaged as a reusable agent skill.

This teaches an agent to **investigate** rather than to recite commands:
observe, hypothesise, test, confirm or refute, document. The methodology
carries the value; the commands are just how evidence gets collected.

> **The one rule:** never assign meaning to a function, structure, variable,
> field, protocol or behaviour without sufficient evidence.

---

## Why this exists

Most analysis goes wrong the same way: a suggestive string gets promoted to a
conclusion. This skill makes the reasoning step explicit and auditable.

```diff
- This function authenticates the user.
+ Evidence:
+   - references authentication-related strings
+   - called only by sub_4012a0
+   - its return value is checked by the caller
+   - dynamic tracing confirms execution during authentication
+ Hypothesis: likely participates in authentication validation.
+ Confidence: high
```

Same target. One is a guess wearing certainty; the other is a finding someone
else can re-check, confirm, or refute.

## Two things it does

**Understand compiled software.** Investigate binaries, libraries, apps,
web targets, protocols and formats, with the evidence discipline above.

**Reconstruct it.** Build a semantic and behavioural model from that evidence,
implement software that behaves the same, and prove the two agree.

```
analysis:      binary        -> what it does, with evidence
reconstruction binary        -> observations -> model -> implementation
verification   original vs yours -> first divergence, explained
```

Reconstruction is not decompilation. A decompiler produces C that runs;
reconstruction produces a model where every claim carries the evidence for it
and can be refuted by a test. See
[references/reconstruction.md](references/reconstruction.md).

## What it covers

| Area | Coverage |
| --- | --- |
| Binary formats | ELF, PE/COFF, Mach-O, DEX, static and shared libraries |
| Architectures | AArch64/ARM64, ARM32 (ARM + Thumb), x86, x86-64 |
| Mobile | Android (Bionic, JNI, ART, multi-ABI), Termux/rootless setups |
| Game clients | Unity, IL2CPP detection, metadata probing, dumper delegation |
| Web | Passive recon, technology evidence, app mapping, client-vs-browser diff |
| Protocols | Framing, headers, opcode dispatch, checksums, state machines |
| Static tools | `readelf`, `objdump`, `llvm-readobj`, `nm`, `strings`, `ldd` |
| RE suites | Ghidra, radare2/rizin, Cutter, Binary Ninja |
| Dynamic tools | gdb, lldb, Frida, strace, ltrace, `/proc` |
| Analysis | signatures, structures, call graphs, xrefs, binary diffing |
| Workflow | automated triage, long-running investigation state |
| Reconstruction | semantic and behavioural modelling, reconstruction ledger, differential testing, reimplementation, porting |

## Install

Clone the repository anywhere, then copy the skill into one of OpenCode's
skill directories:

```sh
git clone https://github.com/kartell58/revalith.git

# project-scoped
cp -r revalith <your-project>/.opencode/skills/

# or user-scoped (available everywhere)
cp -r revalith ~/.config/opencode/skills/
```

Discovery locations, in precedence order: built-in → `~/.claude/skills` and
`~/.agents/skills` → `~/.config/opencode/skills` → project `.opencode/skills`
→ explicit `skills` entries in `opencode.json`.

Advertised automatically because `SKILL.md` carries a `description`. Load it
with the `skill` tool using the ID `revalith`, or mention `@revalith` in a
prompt.

## Bundled scripts

Standard-library Python 3 only. No dependencies, no install step, no network.
Each has `--help`, validates inputs, and degrades honestly — if `objdump` is
missing it says so instead of silently returning incomplete results.

```sh
# what is this? and what should I look at first?
python3 scripts/universal-dump.py ./app.apk -o dump/

# what tools does this machine even have?
python3 scripts/universal-dump.py . --tools-only

# web reconnaissance, passive by default
python3 scripts/web-enum.py https://target.example --dns --tls

# what differs between a working client and a failing browser?
python3 scripts/web-enum.py x --compare working.json failing.json

# what is this binary?
python3 scripts/elf-summary.py ./libfoo.so --hash --sections

# where are these strings, and who references them?
python3 scripts/strings-map.py ./libfoo.so --search "error" --xrefs

# who references this address, symbol or string?
python3 scripts/find-xrefs.py ./libfoo.so --string "invalid session" \
    --containing-funcs

# probable signature from register usage (inference, not proof)
python3 scripts/function-signatures.py ./libfoo.so --symbol parse_header

# compare two builds, at symbol level or whole-target level
python3 scripts/compare-symbols.py ./v1.so ./v2.so --kind exports --fuzzy
python3 scripts/dump-diff.py dump-v1/report.json dump-v2/report.json
```

### Reconstruction tools

```sh
# a ledger that records how far each reconstruction has got
python3 scripts/recon-ledger.py init ./reconstruction
python3 scripts/recon-ledger.py add ./reconstruction functions 0x8120 \
    --evidence "called once per frame" "writes +0x10" \
    --hypothesis "per-frame state update" --next-test "trace the writes" \
    --status hypothesized --confidence low
python3 scripts/recon-ledger.py validate ./reconstruction   # refuses overreach
python3 scripts/recon-ledger.py stats ./reconstruction     # load-bearing assumptions

# where your implementation first differs from the original
python3 scripts/state-diff.py original.json mine.json --all-elements
python3 scripts/trace-diff.py original.log mine.log --detail
```

`recon-ledger.py` is the part worth having. Status is one of `unknown`,
`observed`, `hypothesized`, `partially-reconstructed`, `reconstructed`,
`verified`, `refuted`, and the validator enforces what each status requires:
`verified` without a recorded test is refused, and a confidence above what the
status can justify is refused. That is what stops a hypothesis from week two
being read as a fact in week eight.

`state-diff.py` and `trace-diff.py` locate the **first** divergence. Everything
after it may be a consequence of it, and a numeric divergence comes with
candidate causes and the test that would settle each — never a suggested edit.

### What `universal-dump.py` does, and does not, do

It **identifies files by content** (not extension), extracts strings and
network indicators with provenance, delegates to external tools when present,
and ranks next steps from observed evidence.

It does **not** reimplement Ghidra, radare2 or IL2CPP dumpers. Detection and
delegation are its job. Reports are written for both humans and agents:

```
dump/
├── report.json          # full structured result
├── report.txt           # human-readable rendering
├── hashes.txt           # sha256 per file
├── strings/             # all.txt, urls.txt, domains.txt, ips.txt, api_paths.txt
├── extracted/           # when --extract is used
└── unity/il2cpp/        # external dumper output, if one ran
```

Every indicator carries its source file and offset; when the offset cannot be
determined it is `null`, never invented. Unknown files stay `unknown`, with the
evidence recorded.

### Verifying the parsers

```sh
python3 scripts/selftest.py     # 283 checks, offline, no tools required
```

Generates ELF, PE, Mach-O, APK and AXML fixtures whose exact contents it
knows, then asserts on what the parsers extract. If you modify `_binlib.py`,
`_reconlib.py` or anything in `scripts/dumpers/`, run it first.

## How the workflow behaves

Adaptive, not a checklist. Moving backwards is expected:

```
static analysis  →  candidate function  →  dynamic trace  →  unexpected argument
       ↑                                                            │
       └──────────── return to static analysis, inspect caller ─────┘
```

Restraint is enforced in reporting:

- Confidence levels (`very low` … `very high`) with a stated reason
- `observed` / `inferred` / `confirmed` kept distinct, never blurred
- `unknown` and `insufficient evidence` as legitimate answers
- **Binary difference** distinguished from **semantic difference**
- Naming no more specific than the evidence supports
- Recording what was *not* investigated, so silence is never read as completeness

## Long-running investigations

Two directories, for two different jobs.

**`templates/project-state/`** is written by hand while thinking: dead ends,
hypotheses, formats, offsets, protocols. It stops a refuted hypothesis being
re-tested three weeks later.

**`templates/reconstruction/`** is written by `recon-ledger.py`: functions,
structures, states, systems, formats, hypotheses, verification. It records how
far each reconstruction has got, so a hypothesis cannot be mistaken for a
settled fact. JSON rather than Markdown, because a tool maintains it and a
status change should be reviewable as a diff.

```sh
cp -r templates/project-state/ ./project-state/
cp -r templates/reconstruction/ ./reconstruction/
```

## Repository layout

```
revalith/
├── SKILL.md                 entry point — loaded by the agent
├── README.md                this file
├── LICENSE                  MIT
├── CHANGELOG.md             release history
├── CONTRIBUTING.md          how to propose changes
├── SECURITY.md              reporting and scope of acceptable use
├── .gitignore
├── references/              25 files — loaded on demand, never all at once
│   ├── methodology.md       evidence loop, confidence, reporting
│   ├── tooling.md           tool selection, environment probing, fallbacks
│   ├── investigation-state.md  dead ends, hypotheses, versioned offsets
│   ├── elf.md  pe.md  macho.md  android.md  web-re.md
│   ├── arm64.md  arm32.md  x86.md
│   ├── ghidra.md  radare2.md  binary-ninja.md
│   ├── dynamic-analysis.md  frida.md  gdb.md  lldb.md
│   ├── binary-diff.md
│   ├── protocols.md
│   └── reconstruction.md  semantic-modeling.md  behavioral-analysis.md
│       differential-testing.md  reimplementation.md
├── scripts/
│   ├── universal-dump.py    triage orchestrator
│   ├── web-enum.py          web reconnaissance
│   ├── dump-diff.py         compare two dumps
│   ├── recon-ledger.py      the reconstruction ledger
│   ├── state-diff.py        observable state comparison
│   ├── trace-diff.py        call trace comparison
│   ├── elf-summary.py  strings-map.py  find-xrefs.py
│   ├── compare-symbols.py   function-signatures.py
│   ├── _binlib.py           ELF/PE/Mach-O parsers
│   ├── _weblib.py           web parsing helpers
│   ├── _reconlib.py         ledger, trace and divergence logic
│   ├── dumpers/             internal orchestrator modules (_-prefixed)
│   └── selftest.py          offline tests
├── templates/
│   ├── project-state/       dead-ends, formats, offsets, protocols, hypotheses
│   └── reconstruction/      8 ledgers plus the schema they follow
└── examples/                17 end-to-end worked investigations
```

`SKILL.md` stays short on purpose. Specialised knowledge lives in `references/`
and is loaded only when the question needs it.

## Worked examples

- **[analyze-binary.md](examples/analyze-binary.md)** — unknown executable, from `file` to call graph
- **[analyze-library.md](examples/analyze-library.md)** — shared library, metadata to dynamic validation
- **[universal-dump.md](examples/universal-dump.md)** — automated triage and reading its ranking
- **[analyze-web-target.md](examples/analyze-web-target.md)** — web target; the app-works-browser-fails investigation
- **[analyze-android-apk.md](examples/analyze-android-apk.md)** — APK triage, manifest, JNI bridge
- **[analyze-unity-il2cpp.md](examples/analyze-unity-il2cpp.md)** — Unity/IL2CPP detection, metadata, obfuscated case
- **[trace-function.md](examples/trace-function.md)** — settle one function with a debugger or Frida
- **[find-protocol-handler.md](examples/find-protocol-handler.md)** — string or opcode to parser and handler
- **[compare-versions.md](examples/compare-versions.md)** — two builds to testable hypotheses
- **[compare-binaries.md](examples/compare-binaries.md)** — artefact diff vs behavioural diff

Reconstruction:

- **[reconstruct-function.md](examples/reconstruct-function.md)** — one address to a named, evidence-backed model
- **[reconstruct-structure.md](examples/reconstruct-structure.md)** — recovering a layout from access patterns
- **[reconstruct-state-machine.md](examples/reconstruct-state-machine.md)** — states from traces, guards by forcing them
- **[reconstruct-protocol.md](examples/reconstruct-protocol.md)** — wire format to an independent client
- **[reconstruct-legacy-game.md](examples/reconstruct-legacy-game.md)** — a synthetic legacy target, end to end
- **[differential-testing.md](examples/differential-testing.md)** — locating and explaining a divergence
- **[reimplement-subsystem.md](examples/reimplement-subsystem.md)** — model to working, verified code

## Requirements

**Required:** Python 3.8+ to run the scripts. Nothing else.

**Optional, quality-of-life:** `readelf`/`objdump`/`llvm-*` improve output;
Ghidra/radare2/Binary Ninja improve decompilation; gdb/lldb/Frida enable
dynamic analysis; `aapt`/`jadx`/`apktool` improve Android analysis; an
IL2CPP dumper enables symbol recovery. The skill probes for tools and reports
their absence rather than failing, so it stays useful on a minimal system.

**Environment-dependent:** dynamic analysis needs a debugger or instrumentation
agent, ptrace permission, and a runnable target. These are preconditions, not
guarantees — the skill teaches stating them when they do not hold.

**Network:** the scripts never require network access. `web-enum.py` contacts
only the hosts you name; everything else is offline.

## Scope

Understanding, debugging, instrumentation, interoperability, compatibility
research, vulnerability analysis, format/protocol investigation, and
reconstruction and reimplementation of software you are authorised to study.

Documentation, read-only analysis tooling, and a methodology for building
equivalent software. It performs no exploitation, no credential access, and no
modification of third-party systems. Use the web tooling only against systems
you own or are authorised to assess. Techniques requiring elevated privileges
are described with their preconditions and limitations.

Reimplementation is legitimate for interoperability, compatibility,
archival, education, and recovery. It is not a licence to circumvent access
controls, and the methodology does not assume one.

## License

MIT — see [LICENSE](LICENSE).