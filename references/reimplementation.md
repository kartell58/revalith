# Reimplementation

Turning a verified model into code. The discipline does not change here — it
just has to survive the temptation to make a test pass.

```
model (reconstructed + tested)
   ↓  design: what the interfaces are, not where the code goes
implementation
   ↓  build
runnable
   ↓  differential test
verdict
   ↓  explain, fix the model, repeat
```

## The rule that carries the whole method

**Write the implementation from the model, not from the decompilation.**

Reading decompiled code while writing is how a reimplementation ends up
mirroring the original's structure — including its bugs, its wasted work, and
its accidentals — which defeats the point and produces something nobody can
maintain.

The model is the specification. If the model is incomplete, that is a gap in
the model, and it shows up as a divergence. Filling the gap by consulting the
decompilation converts an honest gap into a silent import of the original's
implementation.

Keep the decompilation open as evidence for *investigating* a divergence.
Close it while *writing*.

## Design before code

The model describes behaviour. Design turns it into interfaces.

```json
{"name": "entity", "status": "reconstructed", "confidence": "high",
 "behaviour": {
   "state": ["idle", "walk", "jump", "fall"],
   "transitions": [
     {"from": "idle", "event": "move", "to": "walk",
      "guard": "on_ground", "evidence": "tested both guard values"},
     {"from": "jump", "event": "land", "to": "idle"},
     {"from": "fall", "event": "timer", "to": "idle"}]},
 "observables": ["position", "velocity", "state", "sprite"],
 "invariants": ["position.x in [0,511]", "state==fall implies velocity.y>=0"]}
```

Design questions, in order:

1. **What are the interfaces?** The model names observables; those become the
   API. Anything the model does not constrain is your choice.
2. **What are the units?** The original stores fixed-point integers. Your
   implementation can use floats — and if equivalence is verified, that is a
   legitimate improvement. Internal representation is not behaviour.
3. **What is state, and who owns it?** The original's ownership is often
   implicit. Make yours explicit.
4. **What is the error path?** Behaviour on invalid input is behaviour. If the
   original crashes, do you need to?

### Where the original's choice is not yours

Some things are externally observable and must match:

- file formats written
- network messages
- anything a third party reads
- timing, where timing is the behaviour

Everything else is yours. Use floats if equivalence holds. Use a hash map if
the model has no ordering requirement. Use a loop where the original used
recursion.

## Choosing a language

The language follows from what the system is, not from preference.

| The system is | Use | Why |
| --- | --- | --- |
| a low-level engine, per-frame hot loop | C, C++, Rust | predictable cost; no runtime surprises in a tight loop |
| a network protocol or service | Go, Rust, TypeScript | concurrency and maintenance; no unsafe surface |
| a data conversion or analysis tool | Python, TypeScript | iteration speed; the bottleneck is I/O, not compute |
| something that must embed in an existing runtime | that runtime's language | the embedding constraint outranks everything else |
| a one-off verification harness | Python | it only has to run once |

**Match the original's arithmetic when it is observable.** If the original
uses fixed-point integers and a fixed rounding mode, and you implement in
floats, you will be chasing divergences that are really representation
differences. Either reproduce the fixed-point arithmetic, or accept that
divergence hunting will be harder and start by checking whether floats even
reproduce the observable values.

For a legacy fixed-point engine being reimplemented for fidelity, matching the
arithmetic is usually faster than debugging the difference.

## Build reconstruction

The build environment is a reconstruction target too, and it is usually
skipped until it blocks you.

| Question | Why it matters |
| --- | --- |
| architecture | the reimplementation must run there, or be ported |
| ABI | calling convention, struct layout, alignment |
| compiler assumptions | signed overflow, struct padding, char signedness |
| linker behaviour | symbol versioning, default libraries |
| required libraries | what must be present at runtime |
| calling convention | argument order, register use, who saves what |
| alignment | misaligned access is a crash or a silent wrong answer |
| resource packaging | where assets live and how they are found |
| build flags | optimisations that change float behaviour |

Two of these cause silent divergence rather than build failure, so check them
deliberately:

**Alignment.** A struct packed differently reads the same values at different
offsets. Symptom: a field that is always wrong by a small amount, or garbage in
the field after it.

**Float behaviour.** Optimisation levels and `fast-math` change float results.
`fast-math` in particular permits reassociation, which changes the last bits of
an accumulation. Symptom: divergence that grows slowly over many iterations,
and disappears in a debug build. That combination is diagnostic.

The goal is a working build, not a byte-identical one:

```
source-level reconstruction      the same program, written from the model
behavioural reconstruction      the same behaviour; internals differ
binary-compatible reconstruction  interchangeable at the binary level
bit-for-bit reproduction         the same bytes
```

These are four different goals. State which one you are pursuing. Bit-for-bit
requires reproducing the original's compiler, version, flags, and library
versions — and even then, build timestamps and path strings in the output can
differ. Attempting it accidentally wastes weeks.

## Porting

Porting is a verification problem, not a porting problem: the behaviour was
already verified on the source platform, so the question is only whether the
port changed it.

```
verified behaviour
   ↓  implement on the target
port
   ↓  run the same differential tests
verdict on the new platform
```

Re-run the tests, do not assume. Port-specific divergences come from:

| Source | Symptom | Check |
| --- | --- | --- |
| integer width | truncation of a value that grew | `int` width on the target |
| char signedness | behaviour differs above 127 | plain `char` vs `signed char` |
| endianness | byte-swapped values | the target's endianness |
| alignment rules | crash or wrong value | required alignment |
| float representation | last-bit differences | float width, and any long-double use |
| time epoch | timestamps wildly off | epoch and time zone |
| text encoding | corrupted strings | encoding assumptions |
| locale-dependent formatting | different number or date output | locale in the original |
| path separators | files not found | path handling |
| unsigned overflow semantics | different wraparound | signedness of accumulators |

Most of these are compile-time or configuration-time, so they are cheap to
check and expensive to discover late. Check them first.

Porting does **not** require preserving platform accidents. If the original
reads a config file with a Windows path separator on Linux, that is not
behaviour worth reproducing — unless something depends on it, and if
something does, that something is observable and must be tested.

## Not implementing everything

An incomplete reimplementation is a legitimate outcome, provided the gap is
visible.

```
implemented:  input, movement, collision, rendering
not tested:   audio (no observable output in the captured runs)
not found:    the save-file path (no string, no cross-reference, no trace)
deliberately skipped: the debug overlay (observable only with a flag set)
```

"Deliberately skipped" and "not found" are different claims and must not be
merged. The first is a decision; the second is a gap in the investigation, and
it belongs in the ledger as `unknown` so a later session can pick it up.

## Finishing

The work is done when:

1. The model is `verified` for the behaviours implemented.
2. The differential tests pass over a stated input set.
3. The unimplemented parts are named.
4. The confidence levels reflect what was actually tested.

Point 4 is the one to be honest about. A reimplementation that matches on six
seed inputs is verified at `medium`, and the report should say so. Claiming
`high` because "it works" is the habit this skill exists to break, and it is
most tempting exactly at the end, when there is no test left to run.

## See also

- `reconstruction.md` — the ladder and the fidelity choices
- `semantic-modeling.md` — building the model this implements
- `differential-testing.md` — establishing the verdict
- `examples/reimplement-subsystem.md`