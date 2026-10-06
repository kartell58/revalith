---
name: Revalith
description: Investigate compiled binaries, libraries, protocols and native code with evidence-driven static and dynamic analysis.
metadata:
  opencode/autoinvoke: true
---

# Revalith

Investigate unknown compiled software: locate the functions that matter,
reconstruct data flow, and validate conclusions against runtime behaviour.
Applies to ELF, PE/COFF, Mach-O, DEX, APKs and their native libraries.

**Revalith** is a **methodology**, not a command list. The value is in the
evidence discipline below; the commands are just how evidence is gathered.

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
a level was chosen. When evidence is absent, the correct answer is `unknown` or
`insufficient evidence` — never a plausible invention.

## Workflow

Adaptive, not a checklist. Go backwards whenever new evidence demands it.

1. **Identify the target** — what is it, where did it come from, what
   question are we answering?
2. **Determine format and architecture** — `file`, then read headers.
3. **Inspect the environment** — never assume a tool exists. See
   `references/tooling.md`.
4. **Collect metadata** — hash it first. Record it; you will compare versions.
5. **Inspect sections/segments** — layout, entropy, packing, TLS callbacks.
6. **Inspect symbols/imports/exports** — what is visible, what was stripped.
7. **Extract strings** — entry points for investigation, never proof.
8. **Map references** — string → function → callers → callees.
9. **Identify candidate functions** — where is this behaviour implemented?
10. **Analyse callers/callees** — what feeds it, what does it call?
11. **Reconstruct arguments and returns** — conservative naming.
12. **Infer structures** — offsets, not invented field names.
13. **Compare versions** — when another build exists.
14. **Dynamic analysis** — when static analysis stops being decisive.
15. **Hook and trace** — observe real arguments and returns.
16. **Test hypotheses** — design a test that could refute.
17. **Confirm or refute** — and say which.
18. **Document** — evidence, hypothesis, test, conclusion, confidence.

A static finding that produces an unexpected runtime value sends you back to
step 10, not forward.

## Bundled scripts

All are standard-library Python 3, run them with `--help`. They degrade
gracefully: if objdump is missing they say so rather than failing silently.

| Script | Purpose |
| --- | --- |
| `scripts/elf-summary.py` | Format, arch, sections, segments, deps, symbol counts. Also summarises APKs. |
| `scripts/strings-map.py` | Extract strings with addresses; find pointer and instruction references to them. |
| `scripts/find-xrefs.py` | Who references an address, symbol or string? Maps xrefs to containing functions. |
| `scripts/compare-symbols.py` | Diff symbols/imports/exports between two builds. |
| `scripts/function-signatures.py` | Infer probable signatures from register usage. Output is inference, labelled as such. |

Verify the parsers at any time with `python3 scripts/selftest.py`.

Quick start:

```sh
scripts/elf-summary.py ./target --hash --sections
scripts/strings-map.py ./target --search "error" --xrefs
scripts/find-xrefs.py ./target --string "error" --containing-funcs
scripts/compare-symbols.py ./v1.so ./v2.so --kind exports --fuzzy
```

## References

Load only what the current question needs.

**Method** — `references/methodology.md` (evidence loop, confidence,
reproducibility, reporting), `references/tooling.md` (tool selection,
environment probing, fallbacks)

**Formats** — `references/elf.md`, `references/pe.md`, `references/macho.md`,
`references/android.md`

**Architectures** — `references/arm64.md`, `references/arm32.md`,
`references/x86.md`

**Tools** — `references/ghidra.md`, `references/radare2.md`,
`references/binary-ninja.md`

**Dynamic** — `references/dynamic-analysis.md`, `references/frida.md`,
`references/gdb.md`, `references/lldb.md`

**Comparison** — `references/binary-diff.md`

**Protocols** — `references/protocols.md`

## Worked examples

- `examples/analyze-binary.md` — unknown executable, from `file` to call graph
- `examples/analyze-library.md` — shared library, metadata to dynamic analysis
- `examples/trace-function.md` — validate one function with Frida or a debugger
- `examples/find-protocol-handler.md` — string or opcode to parser and handler
- `examples/compare-versions.md` — two builds to testable hypotheses

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

## Limitations to expect

Stripped symbols, inlining, LTO, obfuscation, packing, encryption, ASLR/PIE,
indirect calls, virtual dispatch, JIT, self-modifying code, anti-debugging,
unknown architecture, restricted process access. Any of these can make a
technique inapplicable. Check preconditions before promising a technique will
work; state them when they will not.

## Scope

Understanding, debugging, instrumentation, interoperability, compatibility
research, vulnerability analysis, and format/protocol investigation. Access
techniques need privileges and sandboxing that may not exist — say so rather
than assuming. No claim about a system should rest on evidence you did not
actually collect.