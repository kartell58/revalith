# ELF

The dominant format on Linux, Android and embedded systems. Understand the
header, sections and dynamic segment before drawing conclusions.

## Header essentials

`e_type` tells you what kind of object you have:

| Value | Meaning | Consequence |
| --- | --- | --- |
| `ET_EXEC` (2) | Fixed load address | Addresses in the file are absolute |
| `ET_DYN` (3) | Shared object or PIE | **Addresses are relative to a load base** |
| `ET_REL` (1) | Relocatable object | No fixed layout; used in `.o` files |
| `ET_CORE` (4) | Core dump | Contains memory images, not code layout |

`ET_DYN` covers both shared libraries and position-independent executables.
Distinguish them by the presence of an `INTERP` segment: a PIE has one, a
library does not.

`ET_DYN` matters for every address you report. A string at `0x2a4c0` in a
library is `0x2a4c0` only relative to whatever base the loader chose. Say so
when reporting.

`e_machine` gives the architecture (183 = AArch64, 62 = x86-64, 40 = ARM,
243 = RISC-V). `e_entry` is the entry point, but for shared libraries it is
usually `_init`-adjacent and rarely meaningful.

## Sections vs segments

**Sections** describe how the linker organised the file:

- `.text` — code
- `.rodata` — read-only data, including most string literals
- `.data` — initialised writable data
- `.bss` — zero-initialised data, occupies no file space
- `.dynamic`, `.dynsym`, `.dynstr` — runtime linking
- `.plt`, `.got` — procedure linkage table and global offset table
- `.init_array`, `.fini_array` — constructors and destructors, run by the
  loader before/after `main`
- `.eh_frame` — exception unwinding, and a goldmine of function boundaries
- `.symtab` / `.strtab` — full symbol table (absent when stripped)

**Segments** (`PT_LOAD`, `PT_DYNAMIC`, `PT_INTERP`, `PT_GNU_STACK`) describe
how the loader maps the file into memory.

Sections are for humans and tools; segments are what the loader uses. A
stripped binary can lose all section headers while remaining perfectly
loadable — analysis tooling that assumes sections exist will fail there.

## Inspecting

```sh
readelf -h ./libfoo.so                  # header
readelf -S ./libfoo.so                  # sections
readelf -l ./libfoo.so                  # segments (program headers)
readelf -d ./libfoo.so                  # dynamic: NEEDED, SONAME, RPATH
readelf --dyn-syms -W ./libfoo.so       # dynamic symbols
readelf -r ./libfoo.so                  # relocations
readelf --notes ./libfoo.so             # build-id, Android ident
```

`readelf -S` prints flags; `A` (alloc), `X` (executable) and `W` (writable)
tell you what a section is for.

## Dynamic linking

`DT_NEEDED` lists direct dependencies. This is a strong localisation signal:
a library that imports `SSL_read` participates in TLS, one importing
`dlopen` loads code at runtime.

`DT_SONAME` is the name other binaries should link against. It frequently
differs from the filename, which matters when comparing versions.

`DT_RPATH` / `DT_RUNPATH` affect resolution. A library with a `RUNPATH`
pointing somewhere unexpected may load a different dependency at runtime than
a static reading suggests.

The GOT holds addresses that must be resolved by the loader. Because of
lazy binding, a GOT entry often points back into the PLT until first call.
This is normal, not a sign of tampering.

## Relocations

`readelf -r` shows how the loader patches the file. Relocations are how you
find indirect references:

- `R_AARCH64_GLOB_DAT`, `R_X86_64_GLOB_DAT` — a global pointer
- `R_AARCH64_JUMP_SLOT`, `R_X86_64_JUMP_SLOT` — PLT/GOT entries
- `R_AARCH64_RELATIVE` — a relocated pointer, i.e. a table of addresses

A run of `RELATIVE` relocations in one region is very often a vtable, a
function-pointer table, or an array of strings. That inference is testable:
read the entries and see whether they point into `.text`.

## Symbol visibility

`STB_LOCAL` symbols come from `.symtab`; `STB_GLOBAL` and `STB_WEAK` can be
exported. A function that is `STB_WEAK` may be overridden at link time —
a common interposition mechanism and a frequent source of confusion.

`.symtab` may be stripped while `.dynsym` survives, because the dynamic
loader needs it. That is why a "stripped" binary still shows symbols: they
are only the ones the loader requires.

## Android specifics

Android `.so` files carry an `NT_ANDROID_IDENT` note recording the NDK
version and minimum API level — useful for explaining unexpected symbols.
The interpreter is `/system/bin/linker64` on 64-bit.

Native libraries are stored under `lib/<abi>/` in an APK. Multiple ABIs mean
one logical library and several binaries; differences between them are a
frequent source of "impossible" findings.

## Static libraries

`.a` files are archives of `.o` members, not ELF images. Use `ar t` to list
and `ar x` to extract, then analyse each member separately.

## Packing and protection

Indicators:

- entropy above ~7.0 in a section that should hold code or text
- tiny `.text` with a large high-entropy blob
- `PT_INTERP` missing from an executable
- `DT_INIT` pointing into a small stub that unpacks

If packing is suspected, static analysis of the *packed* code tells you
nothing about the real program. Identify the unpacker, then dump the process
after it runs and analyse the memory image instead.

## Stripped binaries

With no `.symtab`, function boundaries come from:

- `.eh_frame` records — usually present even when stripped, and reliable
- `.dynsym` entries with nonzero `st_size`
- prologue/epilogue patterns in the disassembly

`.eh_frame` is the best fallback: most toolchains emit it regardless of
symbol stripping.

## Anti-debugging and integrity checks

`ptrace(PTRACE_TRACEME)` self-attachment, `/proc/self/status` inspection,
timing checks, and direct reads of `.text` to detect patching. If observed,
dynamic analysis needs a different approach — see `dynamic-analysis.md`.