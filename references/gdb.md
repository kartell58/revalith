# GDB

The standard Linux debugger. Strong on scripting, breakpoints by condition and
post-mortem analysis.

## Attaching

```sh
gdb -q ./app                        # start under the debugger
gdb -q -p $(pgrep app)             # attach to a running process
gdb -q ./core                       # post-mortem from a core dump
```

Attaching needs ptrace permission. A process calling
`ptrace(PTRACE_TRACEME)` will refuse a second debugger — that is an
anti-debugging measure, not a bug.

## Layout

```
(gdb) b *0x401230          # breakpoint at an address
(gdb) b *main+0x24         # offset from a symbol
(gdb) b parse_header       # by name
(gdb) b file.c:42          # by source line, needs debug info
(gdb) run                  # start
(gdb) c                    # continue
(gdb) finish               # run until the current function returns
(gdb) next / step          # over / into
(gdb) until <addr>         # run to an address
```

`finish` is the highest-value command for reverse engineering: it returns at
the `ret` with the return value in the return register.

## Inspecting state

```
(gdb) info registers rdi rsi rax rsp rbp
(gdb) x/16x $rsp              # 16 words as hex
(gdb) x/s $rdi                # NUL-terminated string at a pointer
(gdb) x/32xb $rdi             # 32 bytes as hex
(gdb) p/x $rax                # print a register as hex
(gdb) p *((int*)$rdi)         # dereference as int
(gdb) p/x *(long*)$rsp        # first stack argument (SysV x86-64: 8(%rsp))
(gdb) disas $pc, $pc+40       # disassemble a range
(gdb) x/i $pc                 # the instruction at pc
(gdb) bt / frame 0 / info args  # call stack
```

`info args` prints argument names when debug info exists — without it, read
them from registers per the calling convention in `x86.md`.

## Architecture awareness

GDB follows the architecture of the binary, so register names change:

| | x86-64 | AArch64 |
| --- | --- | --- |
| Args | `rdi rsi rdx rcx r8 r9` | `x0`–`x7` |
| Return | `rax` | `x0` |
| Frame | `rbp` | `x29` |
| Link | *(on stack)* | `x30` |
| PC | `$pc` | `$pc` |

AArch64 breakpoints must be 4-byte aligned; gdb usually reports this itself
when they are not.

For a foreign-architecture binary use `gdb-multiarch` plus a sysroot, or
`qemu-user -g <port>` and attach to that port.

## Conditional breakpoints

```sh
(gdb) break *0x401230 if $rdi == 0x7f1a40
(gdb) break parse_header if counter == 0
(gdb) ignore 1 100          # skip the first 100 hits
(gdb) commands 1
  silent
  printf "rdi=%p rsi=%d\n", $rdi, $esi
  continue
  end
```

`commands` plus `silent` turns GDB into a logger without stopping the target —
essential when a breakpoint would otherwise fire thousands of times.

## Watchpoints

```
(gdb) watch *0x405000       # break on writes to an address
(gdb) rwatch *0x405000      # break on reads
(gdb) awatch *0x405000      # both
```

The fastest way to find who corrupts a global or reveals when a flag is set.

## Scripting

```python
# ~/.gdbinit.py
class BreakLogger(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi"))
        print("hit: rdi=%#x" % rdi)
        return False        # do not stop
BreakLogger("*0x401230")
```

Automating `gdb -batch -x script.gdb` makes debugger sessions reproducible —
worth the effort once a workflow repeats.

## Core dumps

A core dump is a full memory image plus registers: excellent for analysis
without re-running the target.

```sh
ulimit -c unlimited
gdb -q ./app /path/to/core
(gdb) bt full
(gdb) info registers
(gdb) x/64x $rsp
```

## Practical notes

- Stripped binaries still work; addresses are all you get.
- `set disassembly-flavor intel` if the default syntax is AT&T.
- `set disable-randomization on` keeps addresses stable across runs — helpful
  for scripted work, and it also defeats ASLR so do not mistake stability for
  a property of the target.
- Ctrl-C interrupts; `set confirm off` avoids prompts in scripts.
- If the target forks, `set follow-fork-mode child` follows the child.