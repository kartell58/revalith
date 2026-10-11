# Memory & Runtime Intelligence

Static analysis tells you what the code *can* do. Only runtime evidence tells
you what it *does*, on which thread, in what order, writing which memory.

This reference is the methodology for getting that evidence and turning it
into claims that survive scrutiny. The three failure modes it exists to
prevent:

1. **A confident wrong address.** Runtime and static addresses live in
   different spaces, and `runtime - base` is not a file offset.
2. **A resemblance promoted to a fact.** An anonymous writable region is not a
   heap. An anonymous executable region is not a JIT compiler.
3. **Correlation promoted to causation.** A function ran, then a field
   changed. That is two observations, not a cause.

## Contents

- [The strategy](#the-strategy)
- [Capability detection](#capability-detection)
- [The memory map](#the-memory-map)
- [Address spaces and ASLR](#address-spaces-and-aslr)
- [Processes and modules](#processes-and-modules)
- [Threads](#threads)
- [Call stacks](#call-stacks)
- [Memory: writes, reads, provenance](#memory-writes-reads-provenance)
- [Heap and allocation](#heap-and-allocation)
- [Object lifetime](#object-lifetime)
- [Pointer and alias analysis](#pointer-and-alias-analysis)
- [Syscalls, protection changes, module loads](#syscalls-protection-changes-module-loads)
- [Signals, exceptions, crashes](#signals-exceptions-crashes)
- [Breakpoints and watchpoints](#breakpoints-and-watchpoints)
- [Android and JNI runtime](#android-and-jni-runtime)
- [The runtime evidence record](#the-runtime-evidence-record)
- [Correlating runtime with static](#correlating-runtime-with-static)
- [Runtime differential analysis](#runtime-differential-analysis)
- [Runtime state reconstruction](#runtime-state-reconstruction)
- [Correlation is not causation](#correlation-is-not-causation)
- [Concurrency](#concurrency)
- [Instrumentation cost](#instrumentation-cost)
- [Scripts](#scripts)

## The strategy

Fifteen steps, in the order that wastes the least time. Each is cheap; the
expensive instruments come after the cheap observations have narrowed the
question.

| # | Step | Yields |
| --- | --- | --- |
| 1 | process discovery | pid, ppid, children, the process tree |
| 2 | module discovery | what is loaded, what was `dlopen`ed |
| 3 | memory map | regions, permissions, the heap, thread stacks |
| 4 | thread discovery | who exists, which is busy, which is blocked |
| 5 | baseline execution | one ordinary run, recorded |
| 6 | event identification | what actually happens, in order |
| 7 | function correlation | which code, via the module map |
| 8 | memory correlation | which addresses, via watchpoints |
| 9 | state reconstruction | the state machine, with evidence |
| 10 | targeted instrumentation | hooks only what step 6-9 pointed at |
| 11 | controlled experiment | change one thing |
| 12 | differential run | baseline vs modified |
| 13 | hypothesis update | the ledger, corrected |
| 14 | reconstruction | the model |
| 15 | verification | a test that could have failed |

The order is not a rule. It is a cost ordering. Step 3 costs one file read;
step 10 costs a slowdown of the target.

```sh
# 1-4: what is running, and what is in memory
scripts/memory-map.py <pid> --smaps
scripts/memory-map.py <pid> --watch 2        # growth between samples

# 5-6: one run, then what happened
scripts/memory-map.py <pid> -o maps.txt --json

# 7: which code
scripts/normalize-address.py <runtime-addr> --map-file maps.txt \
    --binary ./libfoo.so
```

## Capability detection

Before promising a technique, establish that it can work here. Three states,
never two.

```sh
scripts/memory-map.py --self          # includes a capability report
```

| Capability | Provides | Without it |
| --- | --- | --- |
| `/proc/<pid>/maps` | regions, permissions, offsets, inodes | no region classification at all |
| `/proc/<pid>/smaps` | `VmFlags`: `mg` = malloc-eligible, `gd` = grows down | heap and stack claims stay inferences |
| `/proc/<pid>/mem` | read process memory | addresses resolve, bytes do not |
| `ptrace` | breakpoints, watchpoints, registers | no dynamic instrumentation of a running process |
| `frida` + `frida-server` | in-process hooks, argument interception | no in-process observation; use a debugger |
| `strace`/`ltrace` | syscalls with arguments and return | the syscall layer is inferred from effects |
| `perf` | sampling profiles | no timing-based evidence |
| `gdb`/`lldb` | breakpoints, watchpoints, backtraces | static analysis only |

Two things are separate and both matter:

**Tool presence is not permission.** A debugger that cannot attach is no
better than an absent one. Check `/proc/sys/kernel/yama/ptrace_scope`, and
whether the target is yours.

**Absence reduces what can be observed; it never changes what is evidence.**
If there is no syscall tracer, the honest statement is "the syscall layer was
not observed", not "no syscalls occurred".

## The memory map

```sh
scripts/memory-map.py <pid> --smaps --json > maps.json
```

A map answers what the process actually has, which no static view can:

- a library present that is absent from the executable's `DT_NEEDED`
- an executable region with no file behind it
- a shared-memory segment
- thread stacks, one per thread, labelled by the kernel
- which regions are writable, and therefore where data can live

### Classification needs a basis

The region table in the report carries a `basis` for every row. The order
encodes the discipline — a kernel name outranks a kernel hint, which outranks
a file, which outranks an observed growth.

| Classification | Basis | Confidence |
| --- | --- | --- |
| `[heap]` | the kernel labelled it | high |
| `[stack]`, `[stack:tid]` | the kernel labelled it | high |
| malloc-eligible | `VmFlags` contains `mg` | high |
| stack | `VmFlags` contains `gd` | high |
| locked allocation | `VmFlags` contains `lo` | medium |
| file-backed mapping | a path and an inode | high |
| growing anonymous region | it grew between two samples | medium |
| anonymous executable mapping | exec + no file | medium |
| **anonymous mapping** | **nothing** | **very low** |

The last row is the point. An anonymous writable region that has no kernel
hint and did not grow is reported as `anonymous mapping` with basis `unknown`,
and the report says what is not established: whether it is heap, a stack, an
arena, a thread-local block, or something else.

`mg` does not mean allocations are being handed out from that region now. It
means the kernel recorded that the region *may* be used for malloc. The tool
says so in a note rather than quietly upgrading it.

### Anonymous executable is a fact; JIT is a reading

```
0x7f00c0000000-0x7f00c0002000 r-xp 00000000 00:00 0
    classification : anonymous executable mapping
    basis          : observed
    basis_detail   : exec + no file. Inferred: code generated at runtime
                     (JIT, unpacker, patcher). Nothing observed here
                     distinguishes those.
```

Three candidates fit the observation equally. Which one it is needs
something more: writes to the region, execution from it, a symbol, or a
matching region in a different process.

**Do not** conclude "anti-debugging", "packer", or "hook framework" from a
protection change or an executable region alone. That is a hypothesis, and
the commonest confident error in this area.

### Growth over time

```sh
scripts/memory-map.py <pid> --watch 2 --sleep 2
```

Growth is evidence and nothing more. It separates the regions that grow from
the ones that do not, which narrows where the working set is. It does not
identify a heap: a stack grows too, an arena grows, and a thread-local block
grows.

## Address spaces and ASLR

This is where memory analysis most often goes quietly wrong.

There are five spaces, and a runtime address lives in only one of them:

```
runtime address        0x7f1a40001230     where the instruction pointer is
module-relative        libfoo.so+0x1230   stable across runs (if ASLR is off)
                        ...               NOT stable with ASLR
ELF virtual address    0x1230             what the symbol table uses
file offset            0x1230             where the bytes are in the file
symbol address         parse_header+0x40  what the source said
```

### The rule

**`runtime_address - module_base` is not a file offset.**

A module maps at several file offsets. The lowest is usually the header page,
not the code. ASLR moves the whole thing. And the segment table decides the
mapping — not arithmetic on the base.

For a mapping at file offset `O` starting at address `S`, the kernel placed
it at `bias + O`, so `bias = S - O`. That holds for every segment, which
makes it checkable: all segments must agree. Where they do not, the module is
not safe to translate and the tool says so.

The subtle case: the term `p_vaddr - p_offset`. When the first `PT_LOAD` has
`p_vaddr == p_offset` — true of most PIE binaries — it is zero and the naive
form happens to work. When they differ, dropping it returns the wrong virtual
address, which lands the analysis in the wrong section of the file and
produces a symbol that looks plausible and is wrong.

```sh
scripts/normalize-address.py 0x7f1a40001230 --map-file maps.txt \
    --binary ./libfoo.so
```

```
status          : ok
module          : libfoo.so
module-relative : 0x1230
ELF vaddr       : 0x1230
file offset     : 0x1230
section         : .text
symbol          : parse_header
```

Every step reports its status. `ok` means every space was determined;
`partial` says which step stopped; `unresolved` explains why. A partial
translation presented as a whole one is worse than no translation, because
everything downstream agrees with the mistake.

### When there is no file offset

A `.bss` address has no file offset. It is inside the segment's `memsz` but
past its `filesz`, so the bytes exist only in memory:

```
status      : partial
bss_offset  : 0x150
! this address is beyond the segment's file size... There is no file offset:
  the bytes exist only in memory
```

Without the module's binary there is no segment table, so there is no file
offset. The tool reports `partial` and says the segment table is what it
needs — rather than inventing an offset from the base.

### Verify the direction you care about

```sh
# a static address, resolved to where it lives at runtime
scripts/normalize-address.py --static 0x1230 --map-file maps.txt \
    --binary ./libfoo.so
```

This is the check that catches a wrong load bias before it misleads a whole
investigation: if the static address does not land inside a mapped region of
the expected module, the bias is wrong.

### Android and Bionic

The same translation applies. Android's linker places modules at
ASLR-dependent bases and the offsets differ between releases, so:

- record the module base at the moment of observation, not from a script
- `dlopen`ed libraries may map at non-contiguous offsets, as on desktop
- `/apex/com.android.runtime/lib64/bionic/libc.so` is a path like any other

## Processes and modules

```sh
scripts/memory-map.py <pid> --modules-only
```

Grouping is by file, not by address range. One library maps at several
non-contiguous offsets and is still one module; grouping by address would
split every library into several and make the load bias underivable.

### Dynamic loading

A library in the map but absent from the executable's `DT_NEEDED` was loaded
at runtime. That is a real finding: static analysis of the executable alone
cannot reach it, so it needs its own analysis.

```sh
scripts/runtime-events.py events.json --modules
```

```
1. libc.so            t=1    base=0x7f1a40000000  by=None
2. libextra.so        t=5    base=0x7f1b00000000  by=dlopen+0x40
```

The `by=` field is the loading caller. Its presence is what distinguishes a
real `dlopen` from a partial snapshot — and its absence is not evidence
against one, which is why the tool carries that caveat.

Hook `dlopen` early rather than polling the map. A library can be loaded and
unloaded between two map reads.

## Threads

```sh
scripts/correlate-runtime.py events.json --threads --map-file maps.txt
```

```
tid         events dominant          share  label
4821           412 memory_write         61%  worker candidate
4902            88 call                 94%  worker candidate
5104             6 syscalls             100%  short-lived or occasional
```

**Frequency is not role.** A thread that spins on a futex produces a
continuous event stream and looks exactly like a worker until you see what it
touches. What distinguishes them:

- what memory it writes (a worker touches entity state; a spinner touches its
  own stack)
- what it calls
- whether it blocks (`/proc/<pid>/task/<tid>/stack`, `/proc/<pid>/task/<tid>/wchan`)
- whether it holds a lock

### Concurrency questions that have answers

| Question | Where |
| --- | --- |
| Which threads exist? | `/proc/<pid>/task/`, `ps -T` |
| Which thread runs a function? | hook records the tid |
| Which thread modifies state? | the write events, by tid |
| Where was a thread created? | the `clone`/`pthread_create` call site |
| Which thread is blocked? | `wchan`, or the futex address |
| Which thread handles a packet? | the tid on the read and the parse |

A thread's write to shared state is the one observation most often
misattributed. The thread you attached to is not necessarily the thread that
wrote.

### Thread-local storage

TLS lives in a region that moves per thread and is not in the map by name.
Find it from the code: `__thread` variables compile to accesses against the
thread pointer, and on AArch64 that is `TPIDR_EL0`.

Two TLS facts worth stating early: TLS is per-thread, so a value there cannot
be shared, and a TLS variable's address is not stable across thread creation,
so a watchpoint on one thread's copy says nothing about another's.

## Call stacks

The cheapest runtime evidence there is. It turns "this event happened" into
"these functions ran to produce it".

```sh
gdb -p <pid> -batch -ex 'thread apply all bt' 2>/dev/null \
  | scripts/stack-groups.py - --detail 5

scripts/stack-groups.py stacks.txt --compare baseline.txt modified.txt
```

### With no symbols

`module+0xoffset` is the honest form. It is not a deficiency to work around:
it is what the evidence supports. A name invented from proximity to a string
is worse than no name, because it will be used.

Without symbols, what still identifies a function:

- **module + offset** — stable for a given build, and enough to diff two runs
- **function boundaries** — from the symbol table, or from prologue scanning
- **unwind information** — `.eh_frame` gives ranges even with no symbols
- **nearby strings and xrefs** — `find-xrefs.py` on the containing function
- **call signature** — how many arguments, which registers touched

### Grouping

Repeated stacks separate a hot path from a rare one:

```
count    freq  label                  leaf
   412  68.0%  hot path candidate     update_entity@libfoo.so+0x1400
    12   2.0%  repeated              apply_damage@libfoo.so+0x1500
     1   0.2%  rare path (seen once)  debug_draw@libfoo.so+0x2200
```

A group of one is a rare path worth a look — often an error path, a rarely
hit guard, or a debug affordance left in a release build. A high count is not
by itself a performance problem.

The process entry prologue (`__libc_start_main`, `_start`) is dropped when
grouping. Including it would make every stack in the process identical.

Counts are counts of **what was observed under instrumentation**, not
measurements of execution time. A hook that fires on every call changes what
runs.

## Memory: writes, reads, provenance

The question is always the same: *where does this value live, who writes it,
and what does it do?*

### Find the writer

Watchpoints are the direct method. `state-diff.py` and
`correlate-runtime.py` consume the resulting records.

```sh
# gdb: break on a write to a candidate address
(gdb) watch *(int*)0x7ffd1a2b0410
Hardware watchpoint 2: -location
(gdb) bt          # who wrote, and from where
```

Every write is recorded with its thread, its caller and its value:

```json
{"type": "memory_write", "address": "0x7ffd00002020", "size": 4,
 "value": "0x00000003", "tid": 4902, "caller": "libfoo.so+0x1500",
 "timestamp": 13}
```

### Provenance

```sh
scripts/correlate-runtime.py events.json --write-to 0x7ffd00002020 \
    --map-file maps.txt
```

```
events 4, writes 4, reads 0
threads 4821, 4902  agreement=False
! events on this address come from 2 different threads. The thread that
  wrote is not necessarily the thread you observed from
first write: initialisation candidate (value 0x00000001, basis inferred)
  classified by whether an earlier read was recorded; a path that was not
  instrumented would break this
cadence: irregular (interval 1, 67%)
stages without evidence: source, storage, read, decision, output
```

Read the labels:

- **`initialisation candidate`** — no earlier read was recorded. Inferred,
  and conditional on the instrumentation being complete.
- **`periodic`** — writes at a regular interval. A per-frame update. But a
  path you did not instrument would break the pattern.
- **`stages without evidence`** — a gap in the trace, not an absence of
  behaviour. This is the most important line: a stage missing because you did
  not instrument it looks identical to a stage that does not exist.

### Two threads wrote here

That is the finding, and the confidence drops to `low` with the reason
attached. See [Concurrency](#concurrency).

## Heap and allocation

Not every pointer into the heap is an object.

| Allocator | What to look for |
| --- | --- |
| `malloc`/`calloc`/`realloc`/`free` | the glibc hooks; per-size classes |
| `new`/`delete` | calls to the allocator, often inlined |
| arenas | one large region, sub-allocated; `mg` hint present |
| object pools | fixed-size blocks reused; same address repeatedly |
| slab allocators | size classes, per-type caches |
| placement `new` | memory supplied by the caller; no allocation call |
| custom allocators | a bump pointer: compare, increment, return |

A bump allocator is easy to mistake for corruption: the pointer advances
monotonically and nothing is freed. Before reporting a leak, establish which
allocator is in play.

```json
{"type": "alloc", "address": "0x7ffd00002000", "size": 64,
 "tid": 4821, "caller": "libfoo.so+0x1230"}
```

Track one allocation:

```
alloc 0x7ffd00002000  size 64  caller libfoo.so+0x1230
  → writes: +0x00 (init), +0x10 (frame 3), +0x10 (frame 4)
  → reads:  +0x08
  → free:  0x7ffd00002000  caller libfoo.so+0x19c0  t=310
```

Lifetime is the useful part. An allocation written every frame and freed once
at shutdown is per-frame scratch; one written once and freed late is state.

## Object lifetime

```
Object X
  created by      function_A      evidence: alloc call site
  initialized by  function_B      evidence: first write within 1 frame of alloc
  mutated by      function_C, D   evidence: write records, both threads
  consumed by     function_E      evidence: read records immediately after
  destroyed by    function_F      evidence: free at the same call site as A
```

Each relationship needs its own evidence and its own confidence. The commonest
error is asserting destruction because a `free` exists somewhere — the free
may be for a different allocation.

Ways to observe each stage:

| Stage | Evidence |
| --- | --- |
| creation | allocator call site; constructor writes |
| initialisation | first write after allocation, before any read |
| mutation | write watchpoint on the object |
| ownership transfer | reference count, or the pointer moving to a new holder |
| destruction | free/delete at the creation call site; vtable change |
| reuse | same address allocated again with different content |

Ownership is the hard one. A pointer appearing in two structures means two
references, not two owners, unless a release or a free on one path is observed
to affect the other.

## Pointer and alias analysis

```
base + 0x18    base + 0x20    base + 0x38
```

These offsets are candidates, not fields. Propose a layout with the evidence
for each entry, and leave a name off anything you cannot support:

```json
{"offset": "0x18", "access": "read, compared against 0..1000",
 "meaning": null, "confidence": "low",
 "evidence": ["cmp against bounds in 0x1400, never written in the trace"]}
```

`"meaning": null` is a legitimate answer and a better one than a guess.

### Aliasing

Two addresses holding the same value are usually *not* the same storage. The
question has to be asked:

```sh
scripts/runtime-events.py --write-to 0x... --map-file maps.txt
# with no events, the report offers the alias hypothesis
```

```
alias hypothesis: another address may hold the same storage. Runtime address
- module base is not an identity: confirm by writing through one address and
reading through the other
```

Three checks, in order of cost:

1. **Write one, read the other.** Decisive. If the value appears, they alias.
2. **Same region in the map?** One region cannot hold two storages.
3. **Same inode and offset?** Two regions of one mapping share an inode; two
   separate files do not.

Possible aliases to expect: a struct and a pointer into its middle; a base
pointer and an interior pointer; the same array through two handles; a global
and a copy.

## Syscalls, protection changes, module loads

### A syscall alone means nothing

`connect()` is a syscall. That it initialises a protocol and enters an
authenticated state requires a correlation:

```
12:00:01.102  packet received
12:00:01.104  syscall: read
12:00:01.105  call:    packet_parse
12:00:01.106  write:   field +0x04  value 0x2   (state = authenticated)
12:00:01.107  call:    begin_session
```

Now `connect` is tied to a state change, because something was read, parsed,
and written between them. Each reading the tool offers names what would make
it more than a reading.

### Protection changes

```
syscall mprotect -> PROT_READ|PROT_EXEC
    reading: a protection change on an existing mapping
    needs: the address and length, to say which region changed
```

Three candidates fit: a JIT committing code, an unpacker revealing code, or
a runtime patcher. Distinguish by what was written there first — code bytes,
data, or nothing.

**A protection change is not evidence of anti-tampering.** It is evidence
that a mapping's permissions changed.

### Module loads

Covered under [Processes and modules](#processes-and-modules).

## Signals, exceptions, crashes

```
signal          : SIGSEGV
fault address   : 0x7ffd00000010
instruction     : 0x7f1a40001120  (libfoo.so+0x1120)
crash site      : observed
root cause      : unknown
```

**The crash site is not the cause.** The site is where execution was when the
fault was raised. The cause is the write, or the assumption, that made the
state invalid earlier — usually much earlier.

How to reach the cause:

1. **Last write to the faulting region**, across *every* thread, not only the
   crashing one.
2. **Was the region ever initialised?** An uninitialised read and an overrun
   are different bugs with the same fault address.
3. **Small offset from a known allocation?** Suggests an overrun rather than
   a wild pointer.
4. **Replay with a watchpoint.** The first write after a known-good value is
   the candidate.

Symptom to cause:

| Signal | Common causes |
| --- | --- |
| `SIGSEGV` on read | null or uninitialised pointer, freed memory |
| `SIGSEGV` on write | read-only mapping, out-of-bounds, stack overflow |
| `SIGBUS` | misaligned access on strict-alignment targets |
| `SIGILL` | executed data, or an instruction the CPU does not have |
| `SIGABRT` | C++ exception, assertion, `abort()`, allocator corruption |
| `SIGFPE` | integer division by zero |
| `SIGTRAP` | breakpoint, single-step, or a deliberate trap instruction |

`SIGABRT` from glibc carries a message naming the allocator's complaint
(`malloc(): corrupted top size`), which is more specific than the signal.

## Breakpoints and watchpoints

| Technique | Use when | Cost |
| --- | --- | --- |
| software breakpoint | most code hits | patches an instruction; slow, and visible to checksum checks |
| hardware breakpoint | a few addresses, precise | 1–4 on x86; 2 on ARM64 |
| write watchpoint | "who writes this?" | hardware slots; granularity is the access width |
| read watchpoint | "who reads this?" | same limit, and fires far more often |
| access watchpoint | either direction | same |
| single-step | instruction-level causality | one trap per instruction: unusable over a whole path |

Limits that bite:

- **Slot count is small.** Four on x86, two on ARM64. Exceed them and the
  debugger will silently use a slower mechanism, or refuse.
- **Granularity is the access width.** A watchpoint on a 4-byte address fires
  on any access touching those 4 bytes. To catch a single byte, cover the
  word and read the trace.
- **Other threads run.** A watchpoint fires on whichever thread touches the
  address. That is information, not noise — but only if the tid is recorded.
- **The mapping can go away.** A watchpoint on unmapped memory is invalid.
- **Cost scales with hit rate.** A watchpoint on a hot field can stop the
  process more often than a scheduler tick.

Choose by the question, not by habit:

| Question | Instrument |
| --- | --- |
| who calls this function | breakpoint, or a hook |
| what does this function return | breakpoint with a finish |
| who writes this field | write watchpoint |
| what is the call path | breakpoint, then `bt` |
| which thread does this | breakpoint, then record the tid |
| what runs at all | sampling profiler, not a breakpoint |

## Android and JNI runtime

```
Java/Kotlin  →  JNI  →  native function  →  native state
```

Both directions matter, and the reverse one is where the interesting behaviour
usually is.

### Find the boundary

```sh
scripts/universal-dump.py app.apk -o dump/
scripts/elf-summary.py dump/extracted/lib/arm64-v8a/libfoo.so --symbols exports
```

Two registration mechanisms, and they look different:

**Static export.** `Java_com_example_Crypto_decrypt` — the name encodes the
class and method. `nm -D` lists them; `jni.h` mangles them.

**Dynamic registration.** `RegisterNatives` in `JNI_OnLoad` — no export name
to find. Hook `RegisterNatives` or walk it:

```sh
# the method table is passed as a JNINativeMethod array
#   { name, signature, fnPtr }
# three consecutive pointers per entry, terminated by a null name
```

The table is the authoritative list of Java methods this library implements,
and reading it is cheaper than inferring from exports.

### ART

ART compiles ahead of time, so `/data/dalvik-cache` or the APK's `oat` holds
native code whose symbols correspond to the DEX. When a native frame appears
in a backtrace with an ART-looking address:

```sh
# ART and oatdump, when available
adb shell dumpsys <package> | grep -i oat
```

Without oatdump, treat the mapping as another module: it has a base and a
load bias like any other, and `normalize-address.py` handles it.

### Process and thread names

Android thread names are useful and easy to miss:

```sh
adb shell ps -T -p <pid>       # thread names
```

Names like `Binder:1234_2`, `FinalizerDaemon`, `glide-main` are strong
hints. They are hints: a thread can set any name it likes.

## The runtime evidence record

One schema, so observations are comparable across runs and across targets.

```json
{"type": "memory_write",
 "pid": 4821, "tid": 4902, "thread": "render",
 "module": "libfoo.so", "module_relative": "0x1500",
 "address": "0x7ffd00002020", "size": 4, "value": "0x00000003",
 "instruction": "0x7f1a40001504", "caller": "libfoo.so+0x1400",
 "timestamp": 13,
 "evidence": "hardware watchpoint, 3 of 4 writes recorded",
 "confidence": "high",
 "basis": "observed"}
```

Required per type:

| Type | Requires |
| --- | --- |
| `memory_write`, `memory_read` | `address`, `size` |
| `alloc`, `free` | `address` |
| `call` | `address` |
| `module_load`, `module_unload` | `module` |

Three rules the validator enforces:

**A memory event needs a size.** Without it nobody can reproduce the
observation, and a claim nobody can re-check is an assertion.

**High confidence needs evidence.** `verified` and `high` without an
`evidence` field is rejected.

**`caused_by` needs an experiment.** This is the field where an inference
would be laundered into a fact, so it is refused without one:

```
'caused_by' asserts causation from observation alone. Nearness in time is
not cause: another thread, a callback, a signal or a shared write can be
responsible. Record the experiment that isolates it, or state it as a
hypothesis
```

```sh
scripts/runtime-events.py events.json --validate
```

## Correlating runtime with static

Two directions, both necessary.

### Runtime address → static

```sh
scripts/normalize-address.py 0x7f1a40001230 --map-file maps.txt \
    --binary ./libfoo.so
scripts/find-xrefs.py ./libfoo.so --addr 0x1230 --containing-funcs
scripts/strings-map.py ./libfoo.so --xrefs --search "session"
```

Runtime address → module → offset → segment table → file offset → section →
symbol → xrefs → callers and callees → strings → the reconstructed structure.

### Static function → runtime

```
static function (module+0x1400)
  ↓  load bias from the map
runtime address
  ↓  hook or breakpoint
observed execution: tid, arguments, memory effects, return value
```

Both directions must agree. When they do not, one of three things is true:
the load bias is wrong, the module was rebuilt between the map and the trace,
or the address was a stale offset. Find out which before continuing.

### The reference in `correlate-runtime.py`

The tool correlates; it does not disassemble. What it prints:

```
STATIC ANALYSIS THIS TOOL DID NOT DO
  readelf -hSsWd --dyn-syms        headers, sections, dynamic, symbols
  llvm-readobj --file-headers...   same, clearer
  objdump -d                       disassembly
  nm -D --defined-only             dynamic symbols
  strings -a -t x                  strings with offsets
```

Those are the static tools. Run them yourself; a correlation report that
quietly implies a disassembly happened would be a different tool.

## Runtime differential analysis

Two runs, one question: **where do they first differ?**

```sh
scripts/diff-runtime.py baseline.json modified.json --detail
```

```
first divergence at index 4  (kind: field)
  both runs performed the same kind of event with different details.
  The sequence agrees; the data does not
  differing fields: address

  A[4]: {"address": "0x2", "tid": 1, "type": "call"}
  B[4]: {"address": "0x3", "tid": 1, "type": "call"}

  5 further event mismatches follow the first. That is the expected shape
  when one early difference cascades, so the first divergence is the one to
  investigate; treat the tail as consequence until proven otherwise
```

Timestamps are **excluded** from comparison by default. Two runs of the same
input do not align on wall-clock time, and including them would report a
divergence at every event.

`kind` distinguishes two cases worth telling apart:

| kind | Means | Look for |
| --- | --- | --- |
| `event` | different kinds of event at that index | a missing or extra call |
| `field` | same event, different data | a changed argument or value |
| `truncation` | one run stopped early | the termination condition |

The comparisons worth running:

| Comparison | Answers |
| --- | --- |
| normal vs modified | what a patch changed |
| working vs crashing | where the failure path begins |
| old version vs new | which event moved first |
| feature off vs on | what the feature actually does |
| input A vs input B | what a control is sensitive to |

## Runtime state reconstruction

States are reconstructed from evidence, and named only when the evidence
distinguishes them.

```
Observed: a byte at 0x4312 takes values 0, 1, 2, 3
Evidence: 0 and 1 lead to different writes; 2 and 3 never both observed
Hypothesis: four states, 2 and 3 distinguished by something not yet found
Confidence: low
```

Sources, strongest first:

| Source | Strength |
| --- | --- |
| a computed jump table on the state field | strong: the program branches on it |
| an if/else chain on the field | strong |
| a value passed to a state-named function | moderate |
| a value correlated with an external event | weak until tested |
| a value in a save file next to other known values | moderate |

The naming rule applies as everywhere: `state_candidate_0` becomes
`authenticated_state` when something distinguishes it from the others, not
before. Two states that behave identically are one state until proven
otherwise.

```sh
scripts/correlate-runtime.py events.json --threads --syscalls --json
```

## Correlation is not causation

```
function_A executed
field_X changed
```

This does **not** prove function_A caused field_X. What else is consistent:

- another thread wrote it in the interval
- a callback fired between the two
- a signal handler ran
- the two are both consequences of a third event
- `field_X` is written through a pointer aliasing something else
- a race: both threads wrote it and you caught one

Four ways to establish cause, in increasing cost:

| Test | What it settles |
| --- | --- |
| change one input, see if the effect follows | whether the relationship is real |
| disable the suspected function | whether it is necessary |
| add a breakpoint on both | whether they are actually adjacent in time |
| record the thread on both | whether concurrency explains it |

Until one of those runs, the claim is:

```
Observed:  0x1400 executed at t=12; field +0x10 written at t=13 by tid 4821
Hypothesis: 0x1400 wrote the field
Not established: that it did. Another thread (4902) also wrote this address
                 in the same window, and the caller field was not recorded.
Next test:  record the caller on every write to +0x10 and replay
```

That paragraph is the deliverable at this stage — not the first line.

## Concurrency

Every runtime claim is a claim about one thread unless you checked.

| Race | Symptom | Evidence |
| --- | --- | --- |
| unsynchronised write | torn or impossible values | two writes, two threads, one address |
| lock ordering | deadlock under load | `wchan` on the futex |
| check-then-act | behaviour changes under timing | result depends on scheduling |
| ABA | double free, corrupted list | address reused between check and use |
| torn read | a value that is neither old nor new | a multi-word value never observed valid |

Recording the tid on every event is not optional in a concurrent target. An
event without one cannot be attributed, and the attribution is usually the
point.

```sh
scripts/runtime-events.py events.json --summarize
```

```
by thread (tid):
    412  4821
     88  4902
```

If two threads touch one address, the answer to "who wrote this" is a set, and
`build_provenance` says so and drops the confidence to `low`.

## Instrumentation cost

Heavy tracing changes what it measures:

- timing, and therefore frame pacing and race windows
- thread scheduling
- allocation patterns (a hook that allocates perturbs the allocator)
- network behaviour, if you log payloads synchronously

The habit that avoids this:

```
coarse observation  →  narrow hypothesis  →  targeted instrumentation
```

Start with `memory-map`, `strace`, and a sample of backtraces. Narrow down.
Then instrument exactly one function or one address.

If timing matters to the question, do not use a debugger for the
measurement: a sampling profiler (`perf`, `poor-man's-profiler`) has far lower
overhead, and the difference between them is often the finding.

Report the instrumentation when reporting the result. "Observed under a
debugger with a breakpoint on every frame" and "observed in production" are
different claims.

## Scripts

Standard library only, offline, each with a clear responsibility.

| Script | Responsibility |
| --- | --- |
| `memory-map.py` | read and classify a memory map; group modules; derive load bias |
| `normalize-address.py` | translate runtime addresses through every space, or explain why not |
| `runtime-events.py` | validate, summarise and filter runtime event records |
| `stack-groups.py` | normalise and group call stacks; compare two sets |
| `correlate-runtime.py` | join runtime events to static analysis; provenance; threads |
| `diff-runtime.py` | compare two runtime traces; find the first divergence |

```sh
scripts/memory-map.py <pid> --smaps --json
scripts/memory-map.py --map-file saved.maps          # offline
scripts/normalize-address.py 0x7f1a40001230 --map-file maps.txt --binary ./libfoo.so
scripts/runtime-events.py events.json --validate
scripts/correlate-runtime.py events.json --write-to 0x7ffd1a2b0410 --map-file maps.txt
scripts/stack-groups.py stacks.txt --top 10 --detail 5
scripts/diff-runtime.py baseline.json modified.json --detail
```

Every one reports what it could not do. A missing map, an absent binary, an
unparseable address — all produce a reason, never a plausible value.

## Where to go next

| Question | Read |
| --- | --- |
| how to hook, and what it costs | `frida.md`, `dynamic-analysis.md` |
| how to drive a debugger | `gdb.md`, `lldb.md` |
| what to do when the target will not run here | `emulation.md` |
| the region is code, but it was written at runtime | `obfuscation.md` |
| what the offset now means statically | `elf.md` |
| what the structure is | `semantic-modeling.md` |
| how to record the model | `reconstruction.md` |
| how to prove a reimplementation | `differential-testing.md` |
| how to record a dead end | `investigation-state.md` |

`examples/runtime-state-hunt.md` is the whole sequence end to end, from a
running process to a verified state model.