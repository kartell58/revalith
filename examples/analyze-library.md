# Example: analyse a shared library

A `.so` or `.dll` is investigated differently from an executable: it has no
entry point you care about, it runs inside someone else's process, and its
exports are the contract.

## 1. What is it and who needs it

```sh
L=./libfoo.so
file "$L"
scripts/elf-summary.py "$L" --hash --sections
```

For a library, the interesting fields are `SONAME`, `DT_NEEDED` and the
exports — not the entry point.

```sh
readelf -d "$L" | grep -E 'SONAME|NEEDED|RPATH|RUNPATH'
scripts/elf-summary.py "$L" --symbols exports
```

An exports list of three functions against 400 imports says this is a thin
wrapper over another library, not a substantial subsystem. That is a useful
conclusion early.

## 2. What it needs from the host

```sh
readelf --dyn-syms -W "$L" | awk '$7=="UND"{print $8}' | sort -u
```

Undefined symbols are what the library expects to be provided by its host —
the host's libc, or another library that supplies them.

A symbol like `__android_log_print` or a JNI symbol tells you the calling
environment. `Java_com_example_Foo_bar` means the native half of a Java method
(see `android.md`).

## 3. Interfaces

Exports are the library's public contract, and the first place to look for
what it is for:

```sh
nm -D --defined-only "$L" | awk '$2=="T"||$2=="W"'
```

For each export, ask what the contract implies. A function named
`foo_init`/`foo_process`/`foo_shutdown` is a lifecycle API. That is evidence
from the author's own naming, not a guess about internals.

## 4. Internal structure

```sh
r2 -q -c 'aaa; afl' "$L" | head -40          # functions by size
scripts/strings-map.py "$L" --limit 60        # strings by section
```

Large functions are where behaviour concentrates; small ones are often thin
wrappers. String density per function localises subsystems quickly.

```sh
scripts/find-xrefs.py "$L" --string "initialising engine" \
    --containing-funcs
```

## 5. Candidate functions

Rank by evidence quality rather than by size:

1. Exported functions — the author's own priority
2. Functions referencing revealing strings
3. Large functions (compiler output tends to be generated from complexity)
4. Functions called by many others (utilities and dispatchers)

For each candidate, get a signature estimate:

```sh
scripts/function-signatures.py "$L" --symbol foo_process
```

Read it as arity evidence. Confirm types by examining how the arguments are
used, not by trusting the estimate.

## 6. Call graph

```sh
r2 -q -c 'aaa; agC @ sym.foo_process' "$L" > callgraph.dot
```

The graph shows whether the export is a leaf, an orchestrator, or part of a
cycle. A dispatcher calling many same-named handlers suggests a table-driven
design.

## 7. Structures

Field offsets appear as displacement constants. Collect the offsets each
function touches on a common pointer:

```sh
r2 -q -c 'aaa; afij @ sym.foo_process' "$L" | grep -o '"[^"]*"'
```

On x86-64 that is `[rdi+0x10]`, `[rdi+0x18]`. On AArch64 it is
`ldr x1, [x0, #16]`. A consistent set across several functions is a
structure. Record offsets without semantic names until behaviour forces them:

```c
// offsets derived from accesses in foo_read and foo_write
struct foo_object {   // partially inferred
    +0x00 unknown
    +0x08 pointer     // dereferenced before use in foo_read
    +0x10 integer     // compared against 0..1000 range
    +0x18 pointer     // passed to malloc in foo_init
    +0x20 unknown
};
```

Then rename fields only where a test supports it.

## 8. Runtime validation

A library must be loaded by a host. Find one:

```sh
ldd ./app | grep libfoo           # what links against it
```

or identify the loading process from `strings` and `grep` over the host
artifacts.

**Load address:** the library is PIE, so static addresses are relative.

```sh
PID=$(pgrep -n app)
awk '/libfoo\.so/' /proc/$PID/maps
```

The base from that output converts a static address to runtime:
`base + 0x2a4c0`.

**Trace it:**

```sh
gdb -q -p $PID
(gdb) b *($base + 0x2a4c0)      # substitute the real base
(gdb) c
(gdb) info registers
(gdb) finish
```

**Or instrument without a debugger:**

```javascript
const m = Process.getModuleByName("libfoo.so");
Interceptor.attach(m.base.add(0x2a4c0), {
  onEnter(args) { console.log("arg0:", args[0], "arg1:", args[1].toInt32()); },
  onLeave(r)    { console.log("ret:", r); }
});
```

If no host is available, say so and mark runtime-dependent claims as
untested.

## 9. Document

```markdown
## Analysis: libfoo.so 1.4.2

file    : sha256:3c91...  ELF aarch64, PIE, stripped, SONAME libfoo.so
deps    : libc.so, libm.so
exports : foo_init, foo_process, foo_shutdown, foo_version

Observed:
  - exports form a lifecycle API; foo_shutdown is referenced by no other
    exported function, so it is caller-driven
  - foo_process takes 3 arguments (x0-x2 read before written)
  - struct foo_object accessed at offsets 0x08/0x10/0x18 across 4 functions
  - foo_process traced in the host app: arg0 is a buffer, arg1 a length,
    returns the number of bytes consumed (traced, 5 calls)

Hypothesis:
  - foo_process parses a buffer of arg1 bytes and returns bytes consumed

Confidence: high for arity and buffer role; medium for the return meaning
(consistent across 5 calls but never tested with malformed input).

Not investigated: foo_init error paths; no failing-initialisation host
available.
```