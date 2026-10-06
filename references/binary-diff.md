# Binary diffing

Comparing two builds turns speculation into testable questions. The critical
distinction:

> **Binary difference** — bytes, or symbols, or structure changed.
> **Semantic difference** — behaviour changed.

The first does not imply the second. A rebuild without source changes moves
addresses, changes alignment, and reorders code while behaving identically.
Every finding needs a test that could show no behavioural change.

## Before anything else

Establish that you are comparing the right things:

```sh
sha256sum v1/libfoo.so v2/libfoo.so
file v1/libfoo.so v2/libfoo.so
readelf -h v1/libfoo.so | grep Machine      # same architecture?
readelf -d v1/libfoo.so | grep SONAME
```

If the architectures differ, every address-based comparison is meaningless.
If the SONAMEs differ, you may be looking at a rename rather than a code
change.

Also confirm neither binary is stripped differently — comparing a stripped
build against an unstripped one produces a wall of "removed" symbols that
says nothing about behaviour.

## Level 1: symbols

Cheapest, and enough for many questions.

```sh
scripts/compare-symbols.py v1/libfoo.so v2/libfoo.so --kind exports
scripts/compare-symbols.py v1/libfoo.so v2/libfoo.so --kind imports --json
```

Added exports suggest new capability. Removed exports suggest removal or
made-private. Changed import sets hint at behavioural change — a new
networking dependency is far more interesting than a new export.

For stripped binaries, symbol comparison is unavailable. Go to level 2.

## Level 2: function-level matching

Tools match functions across builds even without symbols:

- **Diaphora** (Ghidra plugin) — best-in-class matching plus side-by-side
  decompilation and annotation transfer
- **BinDiff** — mature, IDA-centric
- **Ghidra Version Tracking** — built into Ghidra
- **radare2** — `r2 -q -c 'aaa; ...'` with diff scripting

Matching quality depends on how much changed. A one-line patch matches
everything around it. A refactor matches little.

## Level 3: byte-level diff

```sh
cmp -l v1/libfoo.so v2/libfoo.so | head -50
```

Raw output needs interpretation: many differing bytes in one region is
usually a moved function or a changed string table, not many changes. Compute
what fraction of the file differs and where:

```sh
cmp v1/libfoo.so v2/libfoo.so     # first and byte number of each difference
```

A single-byte difference in an executable region is a strong candidate for a
deliberate patch — a version check, a feature toggle, a signature bypass.
Confirm by disassembling around that offset.

## Reading a diff

For each candidate difference, ask in order:

1. **Is it code or data?** Disassemble vs dump as strings.
2. **Is it inlined?** A function that vanished may now be inlined in its
   callers — no behaviour change.
3. **Is it a moved function?** Compare instruction sequences, not addresses.
4. **Does it change control flow?** A new conditional means a new path.
5. **Is it observable?** Trace both versions and compare.

## From difference to hypothesis

Never write "this build added anti-debugging". Write:

```markdown
Finding: v2 checks a value that v1 does not.

Evidence:
  - v2 contains "TracerPid" in .rodata at 0x8f21c; v1 does not
  - the string is referenced only from sub_401900 (v2)
  - sub_401900 is called from main at 0x401a40 (v2)
  - the corresponding region in v1 is a 3-instruction stub

Hypothesis: v2 reads /proc/self/status and behaves differently when a
            debugger is attached.

Test: run both under gdb, compare the value read from sub_401900 and the
      subsequent control flow.

Confidence: low -- consistent with the hypothesis, not yet demonstrated.
```

The test is what makes this a finding rather than a guess.

## Where behaviour actually changes

Ranked by how informative a difference is:

| Difference | What it usually means |
| --- | --- |
| New export | New public capability |
| New import | New dependency, often new subsystem |
| New error string | New failure mode handled |
| New conditional branch | New behaviour, possibly a feature flag |
| Changed constant | Possibly a limit, version or timeout |
| Changed string, no new code | Reworded message or moved data |
| Address change only | Rebuild noise |

## Pitfalls

- **Comparing different builds of dependencies.** Diff the target, not its
  toolchain.
- **Assuming a build number change implies a code change.** It often implies
  a rebuild only.
- **Trusting a tool's match percentage.** Check a few matched functions
  manually.
- **Reporting size changes as behaviour changes.** A function can grow in
  logging and behave identically.
- **Forgetting determinism.** Two builds of the *same* source can differ;
  build the same commit twice to establish the noise floor before claiming
  anything.

That last point matters: without a same-source baseline, you cannot separate
real changes from build nondeterminism.