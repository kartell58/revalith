# Runtime state hunt: from a running process to a verified model

A worked investigation, end to end, on a small native fixture. The point is
not the answer — it is the order the evidence arrived in and what each step was
allowed to conclude.

## What is real and what is not

Read this first; it is the distinction the rest of the example depends on.

| | |
| --- | --- |
| **Measured** | The memory map, the module list, the address translations, the ELF facts. Captured on the host described below with the tools in `scripts/`, and the output shown here is what they actually printed. |
| **Synthetic** | The event trace in steps 6–8. This host has no `gdb`, `lldb`, `frida`, `strace` or `perf`, so no instrumentation could run. The trace was **written by hand to match what a watchpoint would record**. Every command that consumes it runs normally; the input is not real observation. |

The fixture is deliberately boring: three threads, one shared struct, one
state byte. It is compiled from source that exists, so every claim below can
be checked against it — which is the point. A reader should be able to confirm
the reconstruction without taking any of it on trust, including the parts that
are wrong.

```c
/* ledger.c — a fixture for the runtime example. Not obfuscated. */
struct account {
    unsigned magic;       /* +0x00 */
    unsigned pad;         /* +0x04 */
    unsigned player_id;   /* +0x08 */
    int      state;       /* +0x0c */
    unsigned coins;       /* +0x10 */
};
static struct account g_account;

static void *feed(void *a)  { g_account.magic = 0x4c454447;
                              g_account.player_id = (unsigned)(long)a; ... }
static void *netloop(void *a){ g_account.state = 1; g_account.state = 2;
                              g_account.coins = g_account.player_id * 10u; ... }
static void *ticker(void *a) { g_account.pad++; ... }
int main(void) { /* creates the three, joins them, prints the result */ }
```

Host: Termux/PRoot on Android aarch64. That matters: PRoot maps the guest's
segments in its own way, and step 3 shows the tools noticing rather than
guessing.

---

## Step 0 — The question

> Where is the state stored, which thread changes it, which function makes the
> change, what event triggers it, and how can I reproduce it?

Written down before any tool runs, because a question written afterwards is a
question shaped by whatever the tools happened to show.

---

## Step 1 — What is here at all?

```sh
$ command -v gdb lldb frida strace perf valgrind ltrace
   (nothing)
```

**Observed.** No debugger, no tracer, no instrumentation runtime, no
profiler.

**Consequence, stated now so it is not forgotten later:** every dynamic
observation in this example is unavailable. The static layers and the memory
map still work, and they are enough to locate the state and decide *what* to
instrument — on a host where instrumentation exists.

This is the capability check from `references/memory-runtime.md`. It costs one
command and it decides the shape of the whole investigation.

---

## Step 2 — Process discovery

```sh
$ ./ledger 4 &
$ PID=$(pgrep -n -f 'ledger 4')
$ cp /proc/$PID/maps live.maps
```

**Observed.** One process, three threads created inside `main`.

Not yet known: which thread does what. Three candidates, no evidence.

---

## Step 3 — Memory map

```sh
$ scripts/memory-map.py --map-file ledger.maps --modules-only
```

Three regions back the binary:

```
0x3000000000-0x3000001000 r-xp 00000000 fe:40 2941746   .../rtfix/ledger
0x3000004000-0x3000005000 r--p 00000000 fe:40 2941746   .../rtfix/ledger
0x3000008000-0x3000009000 rw-p 00000000 fe:40 2941746   .../rtfix/ledger
```

and the tool's verdict:

```
load bias 0x3000000000  basis maps_partial
! mappings disagree on the load bias by 0x4000, 0x8000 when derived
  matched to PT_LOAD segments; the anchor is 0x3000000000. Addresses are
  translated from the file offset and the segment table, and this bias is
  used only to check them, so a disagreement here is reported rather
  than propagated
```

**This is the most important output in the example.**

All three regions report file offset `0`. The naive derivation
`load_bias = start - file_offset` therefore yields three different answers,
and a tool that picked one would silently mistranslate every address in the
other two.

The segment table says why:

```sh
$ llvm-readelf -lW ledger | grep LOAD
  LOAD  0x000000 0x0000000000000000 0x0c10 0x0c10 R E 0x4000
  LOAD  0x000c10 0x0000000000004c10 0x01e8 0x03f0 RW  0x4000
  LOAD  0x000df8 0x0000000000008df8 0x0018 0x0034 RW  0x4000
```

Three segments, three different vaddr/offset skews: `0`, `0x4000`, `0x8000`.
Any one of them can be the right anchor and the shortcut would be wrong for
the others.

**Observed:** the module maps at `0x3000000000`.
**Observed:** the shortcuts disagree; the segment table resolves it.
**Not established:** whether PRoot's mapping matches a bare-metal kernel's.
That does not matter for the translation — it is derived from the file offset
and the segment table, which do not depend on who did the mapping.

---

## Step 4 — Where is the state?

`g_account` is a static in `.bss`:

```sh
$ llvm-nm ledger | grep g_account
0000000000008e18 b g_account
```

```sh
$ scripts/normalize-address.py 0x3000008e18 --map-file ledger.maps --binary ./ledger
  status          : partial
  module          : ledger
  module-relative : 0x8e18
  ELF vaddr       : 0x8e18
  file offset     : -
  bss offset      : 0x20  (past filesz: no file offset exists)
  symbol          : g_account (data)
  segment         : offset 0xdf8 filesz 24 memsz 52
```

**Observed:** `g_account` is at runtime `0x3000008e18`.
**Observed:** it has no file offset — it is in the zero-filled tail of the
last segment, so the bytes exist only in memory.
**Observed:** the `(data)` suffix. It is a variable, not code, and saying so
prevents a later reader from looking for a function at that address.

The candidate field addresses are now concrete:

```
+0x00  0x3000008e18   magic
+0x04  0x3000008e1c   pad
+0x08  0x3000008e20   player_id
+0x0c  0x3000008e24   state
+0x10  0x3000008e28   coins
```

**These names come from the source, not from the memory.** Nothing in a watch-
point recording would reveal that `+0x0c` is a state machine. From here on the
investigation must earn every name it uses.

---

## Step 5 — Confirm the translation before trusting it

```sh
$ scripts/normalize-address.py 0x3000000900 --map-file ledger.maps --binary ./ledger
  ELF vaddr       : 0x900
  file offset     : 0x900
  section         : .text +0x100
  symbol          : main
```

`llvm-nm` puts `main` at `0x900`. The derivation agrees.

This check is worth running before reading a single byte: a wrong load bias
does not announce itself, it just returns confident wrong numbers. Comparing
the tool's output against an independent listing is the cheapest way to catch
it.

```sh
$ scripts/normalize-address.py 0x3000000a7c --map-file ledger.maps --binary ./ledger
  ELF vaddr       : 0xa7c
  file offset     : 0xa7c
  section         : .text +0x27c
  symbol          : netloop
```

**Observed:** runtime `ledger+0xa7c` is `netloop`. This is the direction the
rest of the investigation needs: an offset from a trace becomes a function.

---

## Step 6 — Who writes it? *(synthetic trace)*

The remaining steps need a watchpoint, which this host does not have. What
follows is a hand-written trace standing in for one, marked so it cannot be
mistaken for observation.

`ledger+0xa7c` is inside `netloop`, which suggests where to put a watchpoint —
and *suggests*, which is as far as static evidence goes. Only a recorded write
establishes it.

```json
{"type": "memory_write", "address": "0x3000008e24", "size": 4,
 "value": "0x00000000", "timestamp": 11, "tid": 4821,
 "caller": "ledger+0x944"},
{"type": "memory_write", "address": "0x3000008e24", "size": 4,
 "value": "0x00000001", "timestamp": 18, "tid": 4910,
 "caller": "ledger+0xa7c"},
{"type": "memory_write", "address": "0x3000008e24", "size": 4,
 "value": "0x00000002", "timestamp": 19, "tid": 4910,
 "caller": "ledger+0xa88"}
```

Validate before interpreting. The schema rejects the things that quietly
ruin an investigation:

```sh
$ scripts/runtime-events.py synthetic-trace.json --validate
events checked : 15
valid           : 15
```

A trace with an event missing its `size`, or a `caused_by` field with no
experiment behind it, fails here instead of becoming a conclusion three steps
later.

---

## Step 7 — Provenance of one field

```sh
$ scripts/correlate-runtime.py synthetic-trace.json \
      --write-to 0x3000008e24 --map-file ledger.maps --binary ./ledger
```

```
PROVENANCE  0x3000008e24
events 5, writes 5, reads 0
threads 4821, 4910  agreement=False
  ! events on this address come from 2 different threads. The thread that
    wrote is not necessarily the thread you observed from, and attributing a
    write to the observing thread is wrong under concurrency
first write: initialisation candidate (value 0x00000000, basis inferred)
  classified by whether an earlier read was recorded; a path that was not
  instrumented would break this
cadence: irregular (interval 1, 50%)
stages without evidence: source, storage, read, decision, output
transform:
  t=11 tid=4821 memory_write value=0x00000000 caller=ledger+0x944
  t=18 tid=4910 memory_write value=0x00000001 caller=ledger+0xa7c
  t=19 tid=4910 memory_write value=0x00000002 caller=ledger+0xa88
  t=29 tid=4910 memory_write value=0x00000001 caller=ledger+0xa7c
  t=30 tid=4910 memory_write value=0x00000002 caller=ledger+0xa88
```

Read the labels before the values.

- **`initialisation candidate`** — inferred, and true only if no earlier read
  was recorded. A path nobody instrumented would break it.
- **`agreement=False`** — two threads touched this address. Confidence drops
  to `low`. The correct answer to "which thread modifies the state" is a
  *set*, not a single tid.
- **`stages without evidence`** — the most important line. Every missing stage
  is a gap in the trace, and a gap looks exactly like an absence of behaviour.
  Nothing here claims the value is never read; it claims the trace never
  showed a read.

**Hypothesis, at low confidence:** `+0x0c` is a small state field, written by
`netloop`, taking the values 0, 1 and 2.

**Not established:** what those values mean. `0x1` and `0x2` are not "loading"
and "ready" because the numbers look like a progression. They are numbers.

---

## Step 8 — Correlating the writers with functions

```sh
$ scripts/normalize-address.py 0x3000000a7c 0x3000000a88 \
      --map-file ledger.maps --binary ./ledger
```

Both land inside `netloop`. `ledger+0xa88` is 12 bytes later.

**Observed:** two writes, one thread, two addresses 12 bytes apart, one
function.

**Hypothesis:** the function writes a value, then overwrites it. Which is what
`state = 1; state = 2;` looks like from memory, and it is still a hypothesis —
the disassembly was not read here.

Note what the tool refuses to do. `correlate-runtime.py` prints the static
tools it did **not** invoke:

```
STATIC ANALYSIS THIS TOOL DID NOT DO
  readelf -hSsWd --dyn-syms    headers, sections, dynamic, symbols
  objdump -d                   disassembly
  nm -D --defined-only         dynamic symbols
  strings -a -t x              strings with offsets
```

Disassembly is how the hypothesis would be settled. A correlation tool that
implied it had looked would be a different tool, and a dishonest one.

---

## Step 9 — Controlled experiment

The question the trace cannot answer: does the caller *cause* the write, or
did something else write it in the interval?

```sh
# on a host with a debugger:
(gdb) watch -l *(int*)0x3000008e24
Hardware watchpoint 2: -location
(gdb) bt                      # the caller, on every hit
(gdb) info threads            # which tid, on every hit
(gdb) continue
```

Recording the tid on **every** hit is the part that matters. One hit with a
backtrace would show `netloop` adjacent to a write; hits with tids showing that
only `4910` ever wrote it would make the relationship real. Without them the
two observations stay adjacent and unordered, which is not the same thing.

**The experiment that settles it:** change the input to `netloop` only, with
nothing else running, and check whether the write follows. A write that follows
one changed input and one changed input alone is cause, not correlation.

---

## Step 10 — Differential run

```sh
$ scripts/diff-runtime.py baseline.json modified.json
first divergence at index 5  (kind: field)

  both runs performed the same kind of event with different details.
  The sequence agrees; the data does not
  differing fields: caller, value

  A[5]: {"address": "0x3000008e24", "caller": "ledger+0xa88", "size": 4,
         "tid": 4910, "type": "memory_write", "value": "0x00000002"}
  B[5]: {"address": "0x3000008e24", "caller": "ledger+0xb40", "size": 4,
         "tid": 4910, "type": "memory_write", "value": "0x00000003"}
```

Two observations worth separating:

- The **sequence** agrees. Same events, same order, same thread.
- The **data** diverges: a new value, and a caller 184 bytes further on.

A tool reporting "the traces differ" would be right and useless. The first
divergence is the finding; everything after it is most likely consequence, and
is treated as such until a test says otherwise.

Timestamps are excluded from comparison. Two runs of the same input do not
align on wall-clock time, and including them would report a divergence at
every event.

---

## Step 11 — The model

```
state_candidate_0  @ g_account+0x0c
  address          0x3000008e24  (bss; no file offset)
  module           ledger+0xa7c / +0xa88  (netloop)
  thread           4910  writes;  4821  wrote the initial 0
  values observed  0, 1, 2
  named            NO. Nothing distinguishes 0x1 from 0x2 except
                   that they follow one another in time.
  confidence       low
  evidence         write records; two modules' mappings disagreeing on
                   the naive load bias, resolved through PT_LOAD
  counter-evidence a read of +0x0c was never recorded, so "state" as a
                   word is unsupported: it may be a counter
  next test        change only the transition order and see whether the
                   values swap; a counter and a state machine behave
                   differently under that change
```

Recording the counter-evidence is not optional. A ledger entry for this field
that lists only the supporting observations is not a ledger entry; it is a
summary of the case for the conclusion, which is the thing most likely to be
wrong.

The name `state_candidate_0` is what gets recorded. `state` becomes
`authenticated_state` when something *distinguishes* it — a branch on the
field in the disassembly, a different downstream behaviour per value, a value
in a save file next to values already known. Not before. Two values that have
never been seen to behave differently are one value until shown otherwise.

---

## Step 12 — Reproduction

The model is a claim someone else can test:

```sh
scripts/memory-map.py --pid <pid> --smaps --json > maps.json
scripts/normalize-address.py 0x3000008e24 --map-file live.maps --binary ./ledger
scripts/runtime-events.py synthetic-trace.json --validate
scripts/correlate-runtime.py synthetic-trace.json --write-to 0x3000008e24 \
    --map-file live.maps --binary ./ledger
scripts/diff-runtime.py baseline.json modified.json --detail
```

Every step prints its own limitations, so a reader can see exactly which parts
of the reconstruction rest on the measurements in this example and which rest
on the hand-written trace.

---

## What this example does not establish

Stated plainly, because an example that hides its gaps teaches the wrong
habit.

1. **The trace is synthetic.** Nothing here observed a write. The address
   arithmetic, the module map, the load-bias analysis and the symbol
   resolution are real measurements; the causal chain is not evidence, it is
   an illustration of the shape the evidence would take.
2. **`state` is not a state machine.** Only that one field was written by one
   thread in a trace with no reads recorded. That is compatible with a
   counter.
3. **No call stack was captured.** Steps 6–8 use the `caller` field of a
   synthetic record. With no symbols this host would have produced
   `module+0xoffset` and nothing more.
4. **PRoot's mapping is not a bare kernel's.** The file-offset derivation does
   not depend on who did the mapping, which is why the translations hold — but
   a real device should be checked before these specific addresses are reused.
5. **No crash, no aliasing, no ownership.** `references/memory-runtime.md`
   covers them; this fixture exercises none of them, and pretending otherwise
   would be the same mistake this skill exists to prevent.