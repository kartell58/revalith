# Obfuscation

Code made deliberately hard to read, so that analysis costs more than the
implementation is worth. It is not damage; it is a design decision, and it is
the reason some of this skill's techniques stop applying.

## The rule

**Obfuscation is a hypothesis, not a reading.**

A control-flow graph with two hundred blocks and a state variable may be
flattening, or a deliberately unrolled loop, or a state machine, or a
dispatcher for a protocol. The structure is the observation. The naming is the
interpretation, and it needs the same evidence as any other.

| What you see | Consistent with | Not established |
| --- | --- | --- |
| one huge basic block, straight-line | flattening | that there is a state variable |
| a `switch` on one variable, every case jumping | flattening | that the cases are real states |
| a branch whose condition is always true | opaque predicate | which side is real without tracing |
| `a*a`, `x^0`, `x+0` | opaque predicate or MBA | that it was inserted rather than emitted |
| strings decoded by a loop at startup | string encryption | the key, or the algorithm |
| a `switch` over ~256 states inside a loop | a VM | the opcode set, or the handlers |
| no strings, no xrefs to anything | packing or stripping | which of the two |

Run the experiment before the label. For a suspected opaque predicate, patch
one side and see whether the unreachable branch is ever taken across the paths
you exercise. That is a test; the pattern was a guess.

## Families, and how to tell

### Packing and compression

The code is a loader; the payload is elsewhere.

**Identify:** high entropy in a mapped region, a write-then-jump into memory
that was writable but not executable at load time, a protection change
recorded as a syscall, very few strings.

**Confirm:** dump the image *after* the unpacking has run, from a live process
or at a breakpoint just before it jumps. That dumped image is the artefact to
analyse. The packed image is not.

**What to record:** where the unpacked image was dumped, and under what
conditions. The two images differ, and only one is the program.

### Control-flow flattening

The structured control flow is replaced by a dispatcher loop over a state
variable.

**Identify:** a single loop head that many blocks branch back to; a variable
compared against many constants, one per block; every basic block ends in a
state assignment.

**Approach:** you rarely need to defeat it. Recover the state variable's
assignment at each block end, build the real control flow from those, and
analyse the graph that results. That is the same work as a normal call graph
with one extra reconstruction step in front of it.

**What to record:** the state variable, the block boundaries, and the
assignment at each boundary — as a structure and a map, with confidence per
block. A partly-recovered flattening is still useful; a guessed one is worse
than the original.

### Opaque predicates

Branches on conditions that are constant but do not look it, so that a reader
(or a decompiler) follows both sides.

**Identify:** a condition computed by a long chain that reduces; `x*2/2`,
`x^x`, `x|0`; a condition with no path reaching it.

**Approach:** the predicate is usually provable by simplifying the expression.
When it is not, test it: force each side and observe which the program takes,
across inputs. "Never observed on these paths" is weaker than "provably
constant", and the ledger should say which one you have.

### Mixed boolean-arithmetic

Boolean operations replaced by equivalent arithmetic (`x ^ y` as
`~x + y + 1`, and so on), so that data flow analysis loses track.

**Identify:** arithmetic on values that were boolean, operations that cancel,
constants that are suspiciously large.

**Approach:** recognise the idiom and restore it by hand, one site at a
time. There is no shortcut, and a tool that "simplifies" an MBA expression can
produce an equivalent expression that is no easier to read.

### String and identifier encryption

Strings are decoded at runtime, so `strings` finds nothing and xrefs lead
nowhere.

**Identify:** a decoding loop early in startup, a buffer filled one byte at a
time from a table, code that indexes into a constant array.

**Approach:** this is the highest-value case for dynamic work. Hook the
consumer of the decoded string, or read the buffer after decoding, and record
the mapping from stored bytes to plaintext. That mapping is an asset — it
reconstructs what static analysis could not see, and every future string xref
then works.

**What to record:** the plaintext *and the address where it was read*, or the
hook, because "this becomes 'login failed' at startup" without a way to find
the site again is worth much less.

### Anti-disassembly

Bytes that disassemble differently than they execute, so a linear disassembler
produces nonsense after a certain point.

**Identify:** a jump into the middle of an instruction; a `jmp` whose target
lands one byte into a multi-byte opcode; code that disassembles cleanly on
one path and not another.

**Approach:** recursive descent from known entry points rather than a linear
sweep, and check whether the instruction stream stays aligned at every branch
target. Also try disassembling from the address a branch actually reaches.

### Virtual-machine obfuscation

The program is an interpreter for a custom bytecode; the original
instructions are the opcodes.

**Identify:** a large dispatch loop switching over a byte or word; a register
file or virtual stack; handlers that are uniformly small and end by returning
to the dispatcher.

**Approach:** identify the dispatcher, recover the opcode set by running
distinct bytecode and observing the handler transitions, then lift the
opcodes to a readable form. This is a genuine project, not a step. Say so when
it is one — it changes what the reconstruction is expected to deliver.

## What to do, in order

1. **Do not fight it in the packed form.** Dump the unpacked image and work
   there. Most time is lost analysing something that is about to be replaced.
2. **Prefer observation to transformation.** A trace of what actually executed
   is evidence; a deobfuscated listing is an interpretation of it.
3. **Reconstruct, do not deobfuscate.** Recovering the state variable and the
   real control flow is reconstruction, and it goes in the ledger with the same
   evidence and the same status vocabulary as anything else.
4. **Record what is still obfuscated.** An obfuscated path that was never
   recovered is untested, and saying so is part of the result.

The entry below is illustrative — the shape is what to copy, the values are an
example:

```
scripts/recon-ledger.py add ./reconstruction systems "dispatcher loop" \
    --status partially-reconstructed --source dynamic \
    --evidence "every block branches to 0x4010d0; the state variable is the \
                byte at +0x2c" \
    --hypothesis "control-flow flattening over 47 states" \
    --next-test "record the state assignment at each block end and rebuild \
                 the real control flow from those"
```

## What not to do

- **Do not apply a deobfuscator because the pattern resembles a known one.**
  A tool that rewrites the image to match what it recognised produces code
  that runs and evidence that describes something else.
- **Do not `nop` a predicate because one path was never taken on the inputs
  you tried.** That is untested, and the branch may be the one the target
  takes on inputs you did not supply.
- **Do not name the obfuscator from its output.** "This is VMProtect" is a
  claim about a commercial product, and it needs the signature library, not the
  shape.
- **Do not let a deobfuscation script become the artefact.** If the only
  thing anyone can run is the tool's output, the reconstruction has no
  evidence behind it.

## What obfuscation does not defeat, and what it does

| Technique | Survives packing | Survives flattening | Survives VM |
| --- | --- | --- | --- |
| runtime tracing | yes | yes | yes, slowly |
| memory watchpoints | yes | yes | yes |
| `maps`/`smaps` observation | yes | yes | yes |
| string extraction from the dump | **no** — must be after unpacking | yes | yes |
| static call graph | **no** | badly degraded | no |
| decompilation | **no** | degraded | no |
| differential testing | yes | yes | yes |

The pattern to notice: every technique that needs the code to be *static and
readable* is the one that breaks, and every technique that watches the program
*run* survives. That is why this file is in the dynamic half of the skill
rather than the static half.

## Limits

- The author's intent is not recoverable, and neither is the original variable
  names. `reconstruction.md` covers that more fully.
- An obfuscation whose only defence is a key held in hardware or derived from
  the device is not a reverse-engineering problem; it is a key-extraction one.
- Where a protection resists analysis, the honest answer is that the code was
  not understood, with what *was* understood recorded.

## See also

- `dynamic-analysis.md` — the techniques that survive obfuscation
- `memory-runtime.md` — dumping the unpacked image, and provenance for it
- `emulation.md` — running a target that will not run natively
- `reconstruction.md`, `semantic-modeling.md` — recovering a structure from
  observed behaviour
- `investigation-state.md` — recording an obfuscated path as untested