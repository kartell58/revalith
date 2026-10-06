# Dynamic analysis

Static analysis says what *could* happen. Dynamic analysis shows what
actually does. Switch to it when static reasoning stops being decisive.

## When to leave static analysis

- A function's purpose is unclear despite xrefs, strings and callers
- A value's meaning is unknown and only its use will reveal it
- Control flow depends on data you cannot derive statically
- A hypothesis is specific enough to design an experiment for
- The code is obfuscated, packed, or generated at runtime
- You need a ground-truth observation to settle a disagreement

Do not stay static when the only remaining question is "what value actually
arrives here".

## Preconditions — check before promising anything

Dynamic analysis can be impossible. Establish first:

| Requirement | If missing |
| --- | --- |
| Target must execute on this host or an emulator | No tracing at all |
| Debugger or instrumentation tool present | Fall back to static |
| `ptrace` permitted (`/proc/sys/kernel/yama/ptrace_scope`) | Try `/proc/<pid>/mem` |
| Symbols or address computation | Use offsets from `/proc/<pid>/maps` |
| Not anti-debugging / anti-instrumentation | See below |
| Root or elevated rights (varies by target) | Work unprivileged or stop |

```sh
cat /proc/sys/kernel/yama/ptrace_scope   # 0 permissive, 1 restricted, 3 none
```

State the precondition in your notes when it fails. "Could not trace because
ptrace_scope is 3" is a useful finding; silently switching tactics is not.

## Techniques by availability

### Debugger (gdb / lldb)

Strongest observation: you see registers, memory, and full control flow.

```sh
gdb -q ./app
(gdb) b *0x401230        # break at a static address
(gdb) run
(gdb) info registers rdi rsi rax
(gdb) x/s $rdi            # read the string argument
(gdb) finish               # run to return, see the return value
```

`finish` is the single most useful command for signature work: it returns
control at the return instruction with the return value visible.

### Instrumentation (Frida)

Hooks without recompiling, and survives most anti-debugging. See `frida.md`.

### Syscall and library tracing

```sh
strace -f -e trace=network,file ./app    # syscalls
ltrace -e 'malloc+free+open' ./app      # library calls
```

Cheap and non-invasive, and often enough to characterise behaviour: which
files it opens, which hosts it contacts, what it allocates.

### /proc

```sh
cat /proc/<pid>/maps                    # load addresses
cat /proc/<pid>/cmdline
ls -l /proc/<pid>/fd                    # open files and sockets
```

`maps` gives the load base needed to convert a static address into a runtime
one — the step that makes every other dynamic technique work.

```sh
BASE=$(awk '/libfoo\.so/{print $1; exit}' /proc/$PID/maps | cut -d- -f1)
printf 'runtime address = 0x%x\n' $((0x$BASE + 0x2a4c0))
```

Reading `/proc/<pid>/mem` is possible where `ptrace` is blocked, though
permission is still required and it does not give control flow.

### Emulation

`qemu-user` runs foreign-architecture binaries on the host; full-system
emulation handles whole systems. Useful when the target architecture is not
native. Slower than native execution, and some syscalls behave differently.

## Making the experiment capable of refutation

A trace is only evidence if a different outcome was possible.

```
Weak:   Run the login once, observe the call.
Strong: Run it twice, differing only in the credential.
        If 0x401230 runs only in the failing run, that supports the
        hypothesis; if it runs in both, the hypothesis is refuted.
```

Always look for the negative case. A single execution cannot distinguish
"always runs" from "runs on this path only".

## Anti-analysis

Encountered, they change the plan rather than the goal:

| Technique | Counter |
| --- | --- |
| `ptrace(PTRACE_TRACEME)` self-attach | Patch the call, or use Frida |
| `/proc/self/status` `TracerPid` check | Same |
| Timing checks | Run under emulation, or patch the comparison |
| Reading `.text` to detect patching | Patch the checksum, or dump and restore |
| Anti-Frida: port scanning, name checks | Rename the agent, use a different tool |
| Timing-based environment checks | Slow execution, or virtualise |

Bypassing protections is environment-specific and often fragile. If it is not
working, consider whether the question can be answered differently — a
memory dump of the unpacked image, or analysis on a device without the
protection.

## Recording dynamic findings

Runtime values are the strongest evidence available. Record enough to replay:

```markdown
Test:        traced sub_4012a0 during a failed login
Binary:      sha256:9f2c...  libfoo.so 0.4.1 aarch64
Environment: device, Android 14, libfoo.so loaded at 0x7a3b2c0000
Setup:       base from /proc/4821/maps, breakpoint at base+0x1230
Conditions:  valid user, wrong password; single run, no retry
Observed:    called once; arg0 = 0x7f1a40 ("login_failed");
             return value 1; caller branched to the error path at 0x4012c0
Conclusion:  participates in login failure handling. Confidence: high
```

## Common mistakes

- Breaking on a static address without computing the load base — ASLR means
  it will not be there
- Concluding a function "does not exist" because it was never hit — it may
  simply not have run on that path
- One run, no control case
- Assuming observed argument values are the only possible values
- Forgetting that instrumentation changes timing, and that code may behave
  differently under a debugger
- Not recording which binary was traced — values are meaningless without it