# Example: compare two versions

Two builds of the same software, and the difference between "the bytes
changed" and "the behaviour changed".

## 1. Establish the baseline

```sh
OLD=./libfoo-1.4.2.so
NEW=./libfoo-1.5.0.so
sha256sum "$OLD" "$NEW"
file "$OLD" "$NEW"
```

Same architecture? If not, every address-based comparison is meaningless.

```sh
readelf -h "$OLD" | grep Machine
readelf -h "$NEW" | grep Machine
readelf -d "$OLD" | grep SONAME
readelf -d "$NEW" | grep SONAME
```

Check how each was built:

```sh
readelf -S "$OLD" | grep -c symtab
readelf -S "$NEW" | grep -c symtab
```

Comparing a stripped build against an unstripped one produces a wall of
"removed" symbols that says nothing about behaviour.

## 2. Establish the noise floor

Before claiming a difference, know what a *no-change* rebuild looks like. If
you have the source or a reproducible build, build the same commit twice:

```sh
scripts/compare-symbols.py ./build1/libfoo.so ./build2/libfoo.so
cmp -l ./build1/libfoo.so ./build2/libfoo.so | wc -l
```

Anything that appears here is build nondeterminism, not a change. Without
this step you cannot separate the two, and every finding is suspect.

## 3. Compare symbols

```sh
scripts/compare-symbols.py "$OLD" "$NEW" --kind exports
```

```
added   : 2
removed : 1
changed : 0
same    : 47

added:
  + foo_verify_checksum
  + foo_get_version
removed:
  - foo_legacy_checksum
```

Read this carefully. Two new exports and one removal suggests a checksum
algorithm change — **that is a hypothesis about intent, not a finding about
behaviour.** It is a good place to start looking.

```sh
scripts/compare-symbols.py "$OLD" "$NEW" --kind imports
```

New imports are usually more informative than new exports: they reveal which
new subsystem was brought in.

```sh
scripts/compare-symbols.py "$OLD" "$NEW" --kind exports --fuzzy
```

`--fuzzy` proposes renames by symbol shape. Treat the output as a list of
candidates to verify, never as a conclusion.

## 4. Locate the differences in the binary

```sh
cmp -l "$OLD" "$NEW" | head -30
cmp "$OLD" "$NEW"          # first difference and count
```

Map the differing offsets to functions:

```sh
scripts/elf-summary.py "$OLD" --sections
```

If the differences cluster in one section, that localises the change. If they
are scattered uniformly, suspect a rebuild rather than an edit.

## 5. Function-level comparison

For real understanding, a function-aware diff:

- **Diaphora** (Ghidra plugin) — matching plus side-by-side decompilation
- **BinDiff** — if IDA is available
- **Ghidra Version Tracking** — built in

The value is not the match percentage; it is seeing two decompilations
side by side. That usually turns "this function changed" into "this function
now checks a second condition".

## 6. Form hypotheses from the diff

Each difference becomes a testable claim. The discipline is the whole point.

```markdown
### Difference 1: new export foo_verify_checksum

Evidence:
  - present in NEW's exports, absent from OLD
  - foo_legacy_checksum present only in OLD
  - both called from the same region in NEW

Hypothesis: checksum validation changed algorithm between versions.
Test:     identify the algorithm in NEW and compare against OLD's.
Confidence: low

### Difference 2: new string "checksum mismatch"

Evidence:
  - in NEW's .rodata at 0x8f21c; absent from OLD
  - referenced from foo_verify_checksum only

Hypothesis: NEW reports checksum failures explicitly.
Test:     feed a packet with a deliberately wrong checksum to both versions.
Confidence: low
```

Low confidence is correct at this stage. These are *statements about bytes*
framed as *testable claims about behaviour* — which is exactly what they are.

## 7. Test each hypothesis

Both versions must be runnable. If they are not, the tests are limited to
static analysis, and say so.

```sh
OLDVER=1.4.2 NEWVER=1.5.0
./server --version
```

For the checksum test:

```markdown
Test: same payload, one byte of checksum corrupted, sent to both versions.

  v1.4.2: accepted the message, no error logged
  v1.5.0: rejected with "checksum mismatch", connection closed

Conclusion: v1.5.0 validates a checksum that v1.4.2 did not. High confidence.
```

One controlled experiment, differing in one variable, converting a low-
confidence hypothesis into a high-confidence finding. That is the entire
value of the diff exercise.

## 8. Check for the patches people actually care about

Deliberate patches are small and targeted:

```sh
cmp -l "$OLD" "$NEW"          # a handful of differing bytes?
scripts/elf-summary.py "$NEW" --sections | grep -A3 text
```

A single differing byte in an executable region is a strong candidate for a
version check, a feature toggle, or a signature bypass. Disassemble around it:

```sh
objdump -d --start-address 0x401200 --stop-address 0x401260 \
        --no-show-raw-insn "$NEW"
```

Do not claim what it does until you have read the instruction and traced the
branch.

## 9. Write the report

```markdown
## Comparison: libfoo 1.4.2 -> 1.5.0

baseline : sha256:3c91... 1.4.2, stripped
current  : sha256:7de4... 1.5.0, stripped
arch     : aarch64, both PIE
noise    : same-commit rebuild differs in 0 bytes (noise floor established)

Symbol differences:
  added   : foo_verify_checksum, foo_get_version
  removed : foo_legacy_checksum

Confirmed behavioural differences:
  - v1.5.0 rejects payloads whose checksum is wrong; v1.4.2 accepts them.
    Tested with 3 corrupted packets against both binaries. High confidence.

Unresolved:
  - foo_get_version added but no call site found in either version.
    Purpose unknown.
  - byte differences in .text around 0x401230 not yet explained;
    did not correspond to any symbol change.

Coverage: exports and imports compared; the ~400 internal functions were not
matched individually (no symbol table, no Diaphora available).
```

The last line matters. Partial coverage stated explicitly is trustworthy;
implied coverage is not.

## Pitfalls

- **No noise floor.** Every finding is unreliable until build nondeterminism
  is bounded.
- **Comparing stripped against unstripped.** Produces meaningless "removed
  symbols".
- **Reading size changes as behaviour changes.** A function can double in
  size from added logging and behave identically.
- **Trusting a tool's match percentage.** Spot-check matched functions
  manually; the percentage is not evidence.
- **Comparing different builds of a dependency** rather than the target.
- **Assuming both versions are runnable.** When the old version cannot run,
  limit claims to static analysis and say that is what happened.
- **Stopping at the symbol diff.** The interesting changes are usually inside
  functions whose names did not change at all.