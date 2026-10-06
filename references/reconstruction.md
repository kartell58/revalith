# Software Reconstruction

Reconstruction is a different activity from analysis. Analysis answers "what
does this do"; reconstruction answers "what would produce this behaviour".

This is the layer where a reverse engineer stops describing and starts
building. It is also where the discipline that governs the rest of this skill
either holds or quietly stops applying — because once you are writing code,
the temptation is to make the tests pass rather than to understand why they
failed.

## The ladder

```
Reverse Engineering   observe: what is there
        ↓
Understanding         explain: what it means
        ↓
Reconstruction        model: what it does, independent of how
        ↓
Reimplementation      build: an equivalent that works
        ↓
Verification          prove: the two agree
        ↓
Porting               adapt: it works somewhere else
```

Each step has a precondition. Skipping one is not a shortcut, it is a debt
that surfaces at the worst possible moment — usually when the reimplementation
is already in use.

| Step | You may start it when |
| --- | --- |
| Understanding | you can name the behaviour in terms of observations, not strings |
| Reconstruction | you can describe the behaviour without referring to the original's code structure |
| Reimplementation | the model has a testable prediction, not just a description |
| Verification | the original and your implementation can both be run with the same input |
| Porting | the behaviour is verified on the source platform first |

## Reconstruction is not decompilation

The two look similar from outside and are not remotely the same.

**Decompilation** is a mechanical transform:

```
binary  →  approximate source
```

A decompiler produces C that compiles and runs. It preserves control flow and
data flow because those are recoverable from the machine code. It does not
recover names, intent, comments, or the reason a structure is laid out the way
it is. Decompiled code is a *view* of the binary, useful for reading and
paying no dividends for the recovery.

**Reconstruction** is an evidence-driven process:

```
binary  →  observations  →  behavioural model  →  semantic model  →  implementation
```

Each arrow is a step where evidence is gathered, a hypothesis is formed, and a
test can refute it. Each is a place to be wrong in a way you can detect.

| | Decompilation | Reconstruction |
| --- | --- | --- |
| Output | source-like text | a working implementation |
| What backs it | the control flow being recoverable | nothing; each claim is earned separately |
| Names | invented or lost | recovered where evidence supports them, invented nowhere |
| Fails by | looking wrong (which is visible) | looking right (which is not) |
| Testable | barely | at every step |
| Effort | low | high |

The failure modes are worth contrasting. A decompiler that produces garbage is
obviously garbage. A reconstruction that produces a subtly wrong result looks
exactly like a correct one — which is why reconstruction needs the
verification step, and why the ledger records status rather than prose.

## When the task has become a reconstruction

The task changes character, and it is worth naming when, because the
methodology after this point is different.

> "Understand this function" → analysis.
> "What subsystem is this, and what are its parts?" → analysis, approaching
> reconstruction.
> "Reconstruct this subsystem" → you owe a working implementation and a
> verification argument.
> "Build a compatible implementation" → you owe behavioural equivalence with
> the original, and you may choose your own architecture.

The words to watch for in a request: *reconstruct*, *reimplement*, *clone*,
*compatible*, *equivalent*, *port*, *clean-room*, *write my own*.

A request to "make it work like the original" is a reconstruction request even
if it never uses the word.

## The iterative loop

Reconstruction is not a waterfall. The loop is short and it repeats:

```
  Observe ──┐
            │  a divergence or an unexplained observation
  Model ────┤
            │
  Hypothesise
      │
  Implement
      │
  Build
      │
  Execute  ── compare against the original
      │
  Locate the first divergence
      │
  Investigate ──┘
```

Two properties make this converge.

**Prioritise the first divergence.** Everything after the first difference may
be a consequence of it. Fixing the last symptom in a log is the classic way to
make a reimplementation pass its tests while remaining wrong.
`scripts/trace-diff.py` locates it.

**Move backwards freely.** A dynamic trace that shows an unexpected branch
sends you back to static analysis of the condition. Treating the loop as
linear is how a hypothesis gets baked into code before it is tested.

## Standing rules

These are the parts of the evidence discipline that reconstruction is most
likely to erode, restated for the code-writing phase.

**One claim, one test.** An entry in the ledger at
`status: hypothesized` becomes `reconstructed` when a test supports it, and
`refuted` when one does not. Not when it becomes convenient.

**The original is the specification.** Not your reading of it. Where they
disagree, the original wins, and your model is what was wrong.

**Never patch towards a symptom.** If the reimplementation is off by one, the
answer is a rounding mode, an ordering, or a clamp — not a `- 1` that makes
the frame match. A constant that fixes one frame is not evidence about the
next one.

**Record what you skipped.** An unimplemented path that was never exercised is
not "not needed"; it is untested. Say which.

## Fidelity: choose before you start

These are four different goals. Deciding late means discovering the mismatch
after the work is done.

| Goal | Means | Cost |
| --- | --- | --- |
| **Behavioural** | same observable behaviour on specified inputs | lowest |
| **Interface** | same API, same outputs; internals may differ | low–medium |
| **Source-level** | same structure, same functions, same algorithms | medium–high |
| **Binary-compatible** | a build that behaves identically in every case, including unobserved ones | high |

Most reimplementations want **behavioural** or **interface** fidelity. Say
which one you are doing, in the ledger, in the first entry. If the target is
legacy software with an obscure format and no documentation, binary-compatible
fidelity is occasionally the honest goal, and it is worth the cost — but it is
a choice, not a default.

Binary-compatible fidelity has one requirement the others do not: you must be
able to run both implementations to know whether you have succeeded. Without
that, the claim cannot be checked and should not be made.

## What reconstruction cannot deliver

Some things are not recoverable, and the honest response is to say so rather
than to produce a plausible substitute.

- **Original source text.** Not the goal, and not achievable in general. See
  the table above.
- **Original variable names.** Recoverable when debug info survives; otherwise
  only where a string, an export, or a protocol field justifies one.
- **The author's intent.** You can reconstruct the constraints the code
  satisfies. The reason it was written that way is not in the artefact.
- **Behaviour on untested inputs.** Your model is validated where you tested
  it. Everywhere else it is unverified, and saying so is part of the result.
- **Timing and nondeterminism.** Where the original reads a clock, a random
  source, or the network, equivalence is only achievable with the same
  environment. `differential-testing.md` covers establishing determinism.

## Where to go next

| The question | Read |
| --- | --- |
| how do I get from disassembly to a named model | `semantic-modeling.md` |
| what does it do, independent of how it is written | `behavioral-analysis.md` |
| how do I know my implementation is right | `differential-testing.md` |
| how do I write the code | `reimplementation.md` |

Practical, end to end:

- `examples/reconstruct-function.md` — one function, evidence to model
- `examples/reconstruct-structure.md` — recovering a layout
- `examples/reconstruct-state-machine.md` — states from traces
- `examples/reconstruct-protocol.md` — wire format to independent client
- `examples/differential-testing.md` — locating and explaining a divergence
- `examples/reconstruct-legacy-game.md` — end to end on synthetic legacy software
- `examples/reimplement-subsystem.md` — model to working subsystem