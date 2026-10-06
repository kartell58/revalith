# Tooling

Choose tools by the question, verify they exist, and fall back honestly.

## Never assume

A command that is "usually available" is not available. Probe first:

```sh
for t in file readelf objdump llvm-objdump llvm-readobj nm strings ldd \
         patchelf gdb lldb frida frida-ps radare2 r2 rizin ghidra \
         binja qemu-aarch64 upx binwalk jadx apktool; do
  command -v "$t" >/dev/null 2>&1 && echo "yes  $t" || echo "no   $t"
done
```

Record the result in your notes. A conclusion drawn from a tool you never ran
is a guess.

## Environment facts that change the answer

Before choosing an approach, establish:

- host OS and architecture
- **target** architecture and format (often differs from the host)
- whether the target can execute here at all
- whether process/memory access is permitted
- privileges, sandbox, ptrace scope
- available device or emulator
- whether an oracle exists (source, symbols, docs)

Host and target differ constantly. A full x86-64 disassembler tells you
nothing useful about an AArch64 binary, and a host debugger cannot trace a
process built for another architecture.

## Static analysis

| Tool | Use it when | Notes |
| --- | --- | --- |
| `file` | Always, first | Cheap format/arch hint. Not authoritative. |
| `readelf` | ELF headers, sections, dynamic, relocations | `-h -S -l -d -s --dyn-syms -r` |
| `llvm-readobj` | Same, often clearer output | `--elf-output-style=GNU` matches binutils |
| `objdump` | Disassembly, headers for any format | `--start-address/--stop-address` to bound output |
| `llvm-objdump` | Disassembly with better raw output | `--no-show-raw-insn` is far more readable |
| `nm` | Symbol listing | `-D` dynamic only, `--defined-only` |
| `strings` | First-pass string survey | `-a -t x` for offsets; `-e l` for UTF-16LE |
| `ldd` | Runtime library resolution | Executes the loader — see warning below |
| `patchelf` | Inspect/change `DT_NEEDED`, `RPATH` | Read-only inspection is safe |
| `readelf -r` | Relocations tell you what is indirect | The cheapest way to find vtables and GOT usage |

`ldd` runs the dynamic loader on the target. On untrusted binaries prefer
`readelf -d`, which only reads the file.

## Reverse engineering suites

| Tool | Strengths | When |
| --- | --- | --- |
| **Ghidra** | Free, decompiler, scripting, multi-arch | Default when available; decompilation is the main advantage |
| **radare2 / rizin** | Scriptable, scriptable headless | Automated batch analysis |
| **Cutter** | radare2 GUI | Interactive radare2 |
| **Binary Ninja** | Fast, clean IL | Best interactive experience if licensed |

All four answer the same core questions: who calls this, what does it call,
what does this structure look like, where are xrefs. Prefer whichever is
installed rather than installing a new one mid-investigation.

## Dynamic analysis

| Tool | Use it when |
| --- | --- |
| `gdb` | Linux native debugging, scripting, core dumps |
| `lldb` | macOS/iOS, or when gdb is unavailable |
| `frida` | Instrument without recompiling; cross-process; hook by symbol |
| `strace` | Syscall behaviour, file/network access |
| `ltrace` | Library call interception |
| `/proc/<pid>/` | Module maps, memory maps, when ptrace is restricted |

`/proc` deserves special mention: `/proc/<pid>/maps` gives the load base
needed to convert a static address to a runtime one, and `/proc/<pid>/mem`
allows reads where ptrace is blocked. Both need permission, and both are
frequently restricted.

See `dynamic-analysis.md` for preconditions and fallbacks.

## Choosing by question

| Question | Cheapest tool |
| --- | --- |
| What is this file? | `file`, `elf-summary.py` |
| What does it depend on? | `readelf -d`, `objdump -p`, `elf-summary.py` |
| What strings exist? | `strings -a -t x`, `strings-map.py` |
| Who references this string? | `strings-map.py --xrefs`, Ghidra/r2 xrefs |
| What does this function call? | `objdump -d` bounded to the range |
| How did this change between builds? | `compare-symbols.py`, then Diaphora/BinDiff |
| What really happens at runtime? | gdb/lldb, or Frida |

Prefer the narrowest tool that answers the question. Disassembling a 200 MB
binary to answer "what does this function call" is slow and invites mistakes.

## Bounding output

Full disassembly of a large binary is unusable. Always bound it:

```sh
objdump -d --start-address 0x2a4c0 --stop-address 0x2a600 ./libfoo.so
```

`--no-show-raw-insn` removes bytes you are not using.

## Working without a disassembler

If nothing beyond `readelf`, `objdump`, `nm` and `strings` exists, real
analysis is still possible:

1. `strings -t x` to locate strings and their offsets.
2. Find the enclosing function by address range from `nm` or the section table.
3. `objdump -d --start-address/--stop-address` around that range.
4. Manual xrefs by searching for the string's address in little/big-endian
   form (`strings-map.py` automates this).
5. Follow calls in the disassembly by hand.

This is slower, not impossible. Say the tooling was limited so the reader
knows why coverage is partial.

## Trust but verify

Tool output can be wrong, and parsed symbol tables can disagree with raw
bytes. When a result is surprising, confirm it independently:

```sh
readelf -h ./libfoo.so | grep Entry      # reported entry
xxd -s 0x1234 -l 16 ./libfoo.so          # bytes at that address
```

Disagreement means one of them is wrong. Find out which before building on it.

## Reproducibility

Record the tool version alongside the command. Output formats change between
releases, and "objdump said so" is not reproducible six months later without
the version.

```sh
objdump --version | head -1
strings --version | head -1
```