# Mach-O

macOS and iOS binaries: executables, dylibs, bundles, and universal
("fat") binaries containing several slices.

## Universal binaries

A fat binary starts with `0xcafebabe` and contains several per-architecture
slices. **Analysis must target one slice.** Mixing addresses from an arm64
slice with a disassembler in x86_64 mode produces confident nonsense.

```sh
lipo -info ./app                        # list architectures
lipo -thin arm64 -output arm64.bin ./app
file arm64.bin                          # confirm the slice
```

If `lipo` is unavailable, `llvm-objdump --macho --private-headers` shows the
offsets, and `dd` can extract a slice.

## Header

Magic identifies the struct width:

| Magic | Meaning |
| --- | --- |
| `0xfeedface` | 32-bit |
| `0xfeedfacf` | 64-bit |
| `0xcefaedfe` / `0xcffaedfe` | byte-swapped (big-endian) 32/64 |

`cputype` gives the architecture (`CPU_TYPE_X86_64` = `0x01000007`,
`CPU_TYPE_ARM64` = `0x0100000c`), `filetype` distinguishes `MH_EXECUTE`
(2), `MH_DYLIB` (6), `MH_BUNDLE` (8).

Mach-O executables and dylibs are position-independent (PIE) with a typical
load address near `0x100000000`. Static addresses are relative to that base.

## Load commands

Everything else is a load command: `cmd` plus `cmdsize`, where `cmdsize`
includes any nested structures. The important ones:

- `LC_SEGMENT` / `LC_SEGMENT_64` — vmaddr, vmsize, fileoff, filesize, plus
  inline `section` records
- `LC_SYMTAB` — symoff, nsyms, stroff, strsize
- `LC_DYSYMTAB` — index ranges for symbols
- `LC_LOAD_DYLIB` / `LC_ID_DYLIB` — dependencies and the install name
- `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` — lazy and export binding tables
- `LC_MAIN` — the real entry point (`entryoff`, relative to `__TEXT`)
- `LC_ENCRYPTION_INFO` — `cryptid`: nonzero means FairPlay encryption
- `LC_BUILD_VERSION` / `LC_VERSION_MIN_*` — deployment target
- `LC_FUNCTION_STARTS` — a compressed list of function start addresses; a
  reliable boundary source when symbols are stripped

Note the trap: the `cmdsize` of a segment command covers its section records
too. A parser that advances by the fixed header size desynchronises and then
misreads everything after.

```sh
otool -h ./app                     # header
otool -l ./app                     # load commands
otool -L ./app                     # dependencies
nm -m ./app                        # symbols
objdump --macho -d ./app           # disassembly without otool
llvm-objdump --macho --private-headers ./app
```

`otool` ships with Xcode command line tools. On Linux, `objdump --macho` and
`llvm-objdump` cover most needs.

## Symbols and names

Mach-O prepends `_` to C symbols. `_main` is `main`. Stripping that leading
underscore makes names comparable with other formats and with source.

Symbols come from `LC_SYMTAB`; the *dynamic* symbol table is an index range
within it, described by `LC_DYSYMTAB`. A symbol's type is in `n_type`, but the
actual kind (`N_SECT`, `N_UNDF`, `N_ABS`) is separate from the symbol kind,
which lives in `n_desc & N_TYPE`. Confusing the two produces symbols typed
`NOTYPE` for what are really functions.

## Binding

Symbols bound at load time through the dyld binding tables rather than by an
IAT. `LC_DYLD_CHAINED_FIXUPS` and `LC_DYLD_EXPORTS_TRIE` encode the same
information in a compressed form used on newer systems — parsing them is
more work than reading `LC_DYSYMTAB`, which remains present.

## Sections

Named `__TEXT,__text`, `__DATA,__data`, `__DATA_CONST` and so on — the section
name itself carries the segment, which is why addressing them by the
qualified name is common. `__objc_*` sections indicate Objective-C metadata,
which changes how class and method analysis is done (symbols alone are
misleading; use a class-dump style tool).

## Encryption

`LC_ENCRYPTION_INFO` with `cryptid != 0` means the `__TEXT` segment is
encrypted and decrypted into memory by the kernel at load. Static analysis of
the on-disk text yields encrypted bytes. Options are dumping the decrypted
image from a running process, or analysing the decrypted IPA where one
exists. This is a hard precondition failure for naive static analysis —
state it rather than interpreting the noise.

## Sandbox

macOS restricts what a process may read and debug. Attaching a debugger to
another user's process, reading `/proc`-equivalent facilities (absent on
macOS), or inspecting a hardened runtime binary all require entitlements or
root. Check what is permitted before promising dynamic analysis.

## Comparison notes

| Concern | ELF | Mach-O |
| --- | --- | --- |
| Multi-arch container | separate files | one fat binary |
| Function table | `.symtab`, `.eh_frame` | `LC_SYMTAB`, `LC_FUNCTION_STARTS` |
| Lazy binding | GOT/PLT | dyld bind opcodes |
| Stripping prefix | none | `_` on C names |
| Entry point | `e_entry` | `LC_MAIN.entryoff` |