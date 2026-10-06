# Example: analyse an unknown binary

Starting from "here is an executable I do not understand" to a defensible
picture of its structure. Commands are real and runnable; adapt paths to your
target.

## 1. Establish the facts

```sh
T=/path/to/target
file "$T"
sha256sum "$T"
ls -l "$T"
```

Record the hash before anything else — it identifies this exact build for the
rest of the investigation and any future comparison.

`file` is a hint, not a verdict. Confirm with the header:

```sh
scripts/elf-summary.py "$T" --hash
```

Output to establish: format, architecture, bits, endianness, entrypoint,
stripped or not, position-independent or not.

**Write down the architecture now.** It selects the calling convention and
which architecture reference to load (`arm64.md`, `x86.md`, `arm32.md`).
Everything downstream depends on it.

## 2. Layout and dependencies

```sh
readelf -h "$T"
readelf -S "$T"
readelf -d "$T" | grep -E 'NEEDED|SONAME|RPATH|RUNPATH'
readelf -l "$T"
```

`elf-summary.py --sections` gives the same content in one pass, including
entropy per section.

Look for:

- **Dependencies** — which subsystems can plausibly be involved. A `libssl`
  dependency means TLS is *available*, not that this function uses it.
- **Entropy above ~7.0** in a section that should hold code or text — possible
  packing or embedded compressed data.
- **`INTERP` present** — dynamically linked executable. Absent on a static
  binary or a library.
- **`.init_array` / `.fini_array`** — constructors run before `main`, and can
  execute before any breakpoint you set in `main` would fire.

## 3. Symbols

```sh
readelf --dyn-syms -W "$T" | head -40
nm -D --defined-only "$T" | head
```

If the binary is stripped, say so explicitly. Every later address is then a
raw address, and function boundaries must come from `.eh_frame` or prologues.

Exports are the author's own statement about what matters:

```sh
scripts/elf-summary.py "$T" --symbols exports
```

## 4. Strings

```sh
strings -a -t x "$T" > /tmp/strings.txt
wc -l /tmp/strings.txt
grep -iE 'error|fail|version|auth|password|http' /tmp/strings.txt | head -30
```

Error messages are the highest-value strings: they reveal behaviour *and* the
subsystem. Format strings reveal data flow — a `%s:%d` argument order tells
you which value is which.

```sh
scripts/strings-map.py "$T" --search "error" --limit 40
```

**A string is an entry point, not a conclusion.** It identifies a place to
look. Its referencing function is the starting point for real analysis.

## 5. From string to function

Pick a string that matters and ask who references it:

```sh
scripts/strings-map.py "$T" --string "invalid session" --xrefs \
    --containing-funcs
```

`--containing-funcs` maps each reference to the enclosing function, which is
the answer to "which function handles this". On a stripped binary without
symbol sizes this may return nothing — then locate the function by prologue.

With a disassembly tool:

```sh
r2 -q -c 'aaa; axt @ 0x4a2f1c' "$T"          # xrefs to the string
objdump -d --start-address 0x401000 \
        --stop-address 0x401100 --no-show-raw-insn "$T"
```

Always bound the range. Full disassembly of a large binary is unusable and
makes accidental misattribution likely.

## 6. Read the function

Work from the ABI reference for this architecture. On AArch64:

1. Prologue — is there a stack frame? How large?
2. Which of `x0`–`x7` are read before written? Those are arguments.
3. `bl` targets — the callees.
4. `adrp`/`add` pairs — the globals referenced.
5. Conditional branches — the control-flow shape.
6. Is `x0` written with something other than its incoming value before the
   return? That is the return value.

```sh
scripts/function-signatures.py "$T" --addr 0x401234 --size 0x120
```

The output is **inference** and is labelled as such. It reports which
registers are read before written — evidence about arity, not proof of types.

## 7. Follow the callers

```sh
r2 -q -c 'aaa; axt @ fcn.00401234' "$T"
```

The caller usually reveals intent far better than the callee. A function that
receives a buffer built by a network read path is probably a parser, whatever
its strings say.

## 8. Validate at runtime

Static analysis now produces hypotheses. Test them.

```sh
gdb -q ./target
(gdb) b *0x401234
(gdb) run
(gdb) info registers x0 x1 x2
(gdb) x/s $x0
(gdb) finish
(gdb) info registers x0
```

For an architecture mismatch, `qemu-aarch64 -g 1234 ./target` and
`gdb-multiarch -ex 'target remote :1234'`.

Design the test so it could fail — run the same flow twice with one variable
changed, and compare.

## 9. Document

```markdown
## Analysis: target v3.2.1

file    : sha256:9f2c...  ELF aarch64, PIE, stripped, dynamically linked
deps    : libc.so, libssl.so, libcrypto.so
entry   : 0x2a4c0

Observed:
  - "invalid session" at 0x4a2f1c, referenced only from sub_402310
  - sub_402310 called from sub_4018a0 on the path following recv()
  - returns 0 on malformed input, non-zero on valid input (traced, 8 runs)

Hypothesis:
  - sub_402310 validates the session header of an inbound message

Confidence: medium -- traced in 8 of 8 runs, but the structure fields at
offset 6..9 are still unexplained.

Not investigated: TLS path, which requires keys not available here.
```

State what you did *not* cover. "Analysed the non-TLS path; TLS not
examined" is honest and useful. Silence implies completeness that does not
exist.