# Revalith

An evidence-driven methodology for investigating compiled software, native
libraries, binary formats and proprietary protocols — packaged as a reusable
agent skill.

This teaches an agent to **investigate** rather than to recite commands:
observe, hypothesise, test, confirm or refute, document. The methodology
carries the value; the commands are just how evidence gets collected.

> **The one rule:** never assign meaning to a function, structure, variable,
> field, protocol or behaviour without sufficient evidence.

---

## Why this exists

Most binary analysis goes wrong the same way: a suggestive string gets promoted
to a conclusion. This skill makes the reasoning step explicit and auditable.

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

Same target. One is a guess wearing certainty; the other is a finding that
someone else can re-check, confirm, or refute.

## What it covers

| Area | Coverage |
| --- | --- |
| Formats | ELF, PE/COFF, Mach-O, DEX, APK/AAB, static and shared libraries |
| Architectures | AArch64/ARM64, ARM32 (ARM + Thumb), x86, x86-64 |
| Environments | Linux, Android (Bionic, JNI, ART, multi-ABI), Termux/rootless setups |
| Static tools | `readelf`, `objdump`, `llvm-readobj`, `nm`, `strings`, `ldd`, `patchelf` |
| RE suites | Ghidra, radare2/rizin, Cutter, Binary Ninja |
| Dynamic tools | gdb, lldb, Frida, strace, ltrace, `/proc` |
| Analysis | signatures, structures, call graphs, cross-references, binary diffing |
| Protocols | framing, headers, opcode dispatch, checksums, state machines |

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

The skill is advertised automatically because `SKILL.md` carries a
`description`. Load it explicitly with the `skill` tool using the ID
`revalith`, or mention `@revalith` in a prompt.

## Bundled scripts

Standard-library Python 3 only. No dependencies, no install step. Each has
`--help`, validates its inputs, and degrades honestly — if `objdump` is
missing it says so instead of silently returning incomplete results.

```sh
# what is this file?
python3 scripts/elf-summary.py ./target --hash --sections

# where are these strings, and who references them?
python3 scripts/strings-map.py ./target --search "error" --xrefs

# who references this address, symbol or string?
python3 scripts/find-xrefs.py ./target --string "invalid session" --containing-funcs

# what changed between two builds?
python3 scripts/compare-symbols.py ./v1/libfoo.so ./v2/libfoo.so --kind exports --fuzzy

# what does this function probably look like? (inference, not proof)
python3 scripts/function-signatures.py ./target --symbol parse_header
```

Every script supports `--json` for programmatic use.

### Verifying the parsers

```sh
python3 scripts/selftest.py     # 60 checks, no external tools required
```

`selftest.py` generates ELF, PE and Mach-O fixtures whose exact contents it
knows by construction, then asserts on what the parsers extract. It runs
offline and needs nothing installed. If you modify `_binlib.py`, run it first.

## How the workflow behaves

The workflow is adaptive, not a checklist. It is explicitly permitted — and
expected — to move backwards:

```
static analysis  →  candidate function  →  dynamic trace  →  unexpected argument
       ↑                                                            │
       └──────────── return to static analysis, inspect caller ─────┘
```

The skill also enforces restraint in reporting:

- Confidence levels (`very low` … `very high`) with a stated reason
- `unknown` and `insufficient evidence` as legitimate answers
- The distinction between **binary difference** and **semantic difference**
- Naming no more specific than the evidence supports
- Recording what was *not* investigated, so silence is never read as completeness

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
├── references/              18 files — loaded on demand, never all at once
│   ├── methodology.md       evidence loop, confidence, reporting
│   ├── tooling.md           tool selection, environment probing, fallbacks
│   ├── elf.md  pe.md  macho.md  android.md
│   ├── arm64.md  arm32.md  x86.md
│   ├── ghidra.md  radare2.md  binary-ninja.md
│   ├── dynamic-analysis.md  frida.md  gdb.md  lldb.md
│   ├── binary-diff.md
│   └── protocols.md
├── scripts/                 dependency-free Python 3 CLIs + parser tests
└── examples/                5 end-to-end worked investigations
```

`SKILL.md` stays short on purpose. Specialised knowledge lives in
`references/` and is loaded only when the current question needs it.

## Worked examples

Each is a complete, reproducible investigation — not a toy snippet:

- **[analyze-binary.md](examples/analyze-binary.md)** — unknown executable, from `file` to call graph
- **[analyze-library.md](examples/analyze-library.md)** — shared library, metadata to dynamic validation
- **[trace-function.md](examples/trace-function.md)** — settle one function with a debugger or Frida
- **[find-protocol-handler.md](examples/find-protocol-handler.md)** — string or opcode to parser and handler
- **[compare-versions.md](examples/compare-versions.md)** — two builds to testable hypotheses

## Requirements

**Required:** Python 3.8+ to run the scripts. Nothing else.

**Optional, quality-of-life only:** `readelf`/`objdump`/`llvm-*` improve output;
Ghidra/radare2/Binary Ninja improve decompilation; gdb/lldb/Frida enable
dynamic analysis. The skill probes for tools and reports their absence rather
than failing, so it stays useful on a minimal system.

**Environment-dependent:** dynamic analysis needs a debugger or instrumentation
agent, ptrace permission, and a runnable target. These are preconditions, not
guarantees — the skill teaches stating them when they do not hold.

## Scope

Understanding, debugging, instrumentation, interoperability, compatibility
research, vulnerability analysis, and format/protocol investigation.

The skill is documentation and analysis tooling. It performs no exploitation,
no credential access, and no modification of third-party systems. Techniques
requiring elevated privileges are described together with the preconditions
and limitations that apply to them.

## License

MIT — see [LICENSE](LICENSE).