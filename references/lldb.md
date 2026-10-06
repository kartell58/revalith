# LLDB

The debugger for macOS and iOS, and a capable alternative to GDB elsewhere.
Same command vocabulary as GDB with different register names and some renamed
commands.

## Attaching

```sh
lldb ./app                      # launch
lldb -p $(pgrep app)            # attach
lldb --core /path/to/core
```

On macOS, debugging another user's process needs `sudo` or the Developer Tools
permission; hardened runtime binaries resist injection. Check before planning
around a trace.

## Essentials

```
(lldb) b *0x401230             # breakpoint at an address
(lldb) b -n main               # by name
(lldb) run / process launch
(lldb) c / continue
(lldb) finish                  # run to return from the current frame
(lldb) next / step
(lldb) register read rdi rsi rax
(lldb) memory read --format x --size 8 --count 4 $rsp
(lldb) memory read -s -f c $rdi
(lldb) thread backtrace
(lldb) image list              # loaded modules and their base addresses
```

`image list` is the practical way to get load addresses on macOS, where there
is no `/proc/<pid>/maps`.

## Architecture registers

| | x86-64 | ARM64 |
| --- | --- | --- |
| Args | `rdi rsi rdx rcx r8 r9` | `x0`–`x7` |
| Return | `rax` | `x0` |
| Frame | `rbp` | `x29` |
| Link | *(stack)* | `x30` |

macOS on Apple silicon is almost always arm64; an x86-64 build under Rosetta
means the process is being translated, and breakpoints at translated
addresses behave differently. Confirm the architecture before tracing.

## Platform differences from GDB

- `b` not `break`; `c` not `continue`
- `finish` is `finish` in both, but LLDB steps *into* by default on `step`
- memory syntax is a subcommand: `memory read`/`memory write`, not `x`/`set`
- `thread backtrace all` for every thread
- `image lookup -a <addr>` to resolve an address to a symbol
- `process attach --name <n>` or `--pid <pid>` instead of `-p`

## Conditional breakpoints

```
(lldb) breakpoint set --name parse_header --condition 'counter == 0'
(lldb) breakpoint set --address 0x401230 --condition '$rdi == 0x7f1a40'
(lldb) breakpoint modify --ignore-count 100 1
(lldb) breakpoint command add 1
  script print("hit: rdi =", *(void**)$rdi)
  continue
  end
```

## Scripting

Python is built in:

```python
# ~/.lldbinit
def bp_hook(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    print("hit in", frame.GetFunctionName())
    return False

debugger.HandleCommand("breakpoint set -n parse_header")
debugger.GetCommandInterpreter().HandleCommand(
    "breakpoint command add -o 'script bp_hook(None,None,None,None)' 1")
```

`lldb -b -s commands.txt` runs non-interactively, which makes captures
reproducible.

## Instruments and other tools

`xcrun` wraps Xcode tools; `instruments` covers profiling; `atos` and
`image lookup` map runtime addresses back to symbols and source lines when
dSYM files are present. dSYMs are what make source-level stepping possible on
a release build — without them, everything is address-level.

## Remote and device debugging

```sh
lldb -o "gdb-remote localhost:1234"      # attach to gdbserver
xcrun devicectl device process launch ...  # modern device workflow
```

Android uses `gdbserver` on the device with a forwarded port; LLDB's
`gdb-remote` handles it as well as GDB does.

## When to use LLDB over GDB

On macOS and iOS it is the native choice with the better device story. On
Linux the two are close to equivalent — pick whichever is installed. The
skills that matter (read registers, break on a condition, dump memory,
script the session) are identical in both.