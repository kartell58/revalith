# Differential testing

The original is the specification. This is the method for finding out whether
your implementation is equivalent to it — and, when it is not, why.

A divergence is not a bug report. It is a question with two possible answers:
*the reimplementation is wrong*, or *the model was wrong about the original*.
Both occur. Neither is the default, and the difference between a good and a bad
reconstruction is whether you ask.

Verification is the step that separates reconstruction from decompilation.
Decompiled code has no differential test — it either compiles or it does not.
Everything below exists because a reimplementation can be subtly wrong while
looking completely correct.

## The loop

```
original ──┐
           │  same input, same initial state, same environment
           ▼
   observable state ──── compare ────┬── agree:  widen the input set
           │                         │
           │                         └── differ: locate the FIRST divergence
           ▼                                     │
   reimplementation                             ▼
                                    explain, then fix the model first
```

Order matters. The comparison comes before the investigation, and the
investigation comes before any change.

## Establish determinism first

A comparison is only meaningful if the two runs are comparable. Before
differentially testing anything, establish what the original's output depends
on.

| Source | How to detect it | How to control it |
| --- | --- | --- |
| RNG | same input, different output across runs | seed it, or record its state |
| wall clock | output changes with sleep or `date` | freeze it, or mock it |
| frame counter | output depends on how long it ran | fix the frame count |
| input | interactive | replay a recorded sequence |
| threading | output varies run to run | single-thread the test, or pin |
| network | depends on a server | stub the transport |
| uninitialised memory | output varies with ASLR | zero the state region first |
| float environment | differs across machines | fix the rounding mode |

Test empirically rather than by inspection:

```sh
# run the original twice with the same input
for i in 1 2 3; do
  ./original --seed 42 --input input.bin --frames 600 > out.$i.bin
done
cmp out.1.bin out.2.bin && cmp out.2.bin out.3.bin \
  && echo "deterministic on this input" \
  || echo "NOT deterministic: investigate the source before comparing"
```

If it is not deterministic, find out what varies and control it. Comparing a
deterministic implementation against a nondeterministic one produces
divergences that are noise, and the temptation is to "fix" them in the
reimplementation — which makes it worse, not better.

If the original cannot be made deterministic, say so and compare
distributions or invariants instead of exact state. Record that as a
limitation on the claim.

## What to compare

Compare what is observable from outside the process. Inside the process, you
are reading the implementation, which is the thing you are not trying to
reproduce.

**Good observables**

- output files, return values, exit codes
- network messages sent and received
- files written, and their contents
- rendered frames, audio events
- public API results
- console output, log lines

**Not observables for equivalence**

- internal field layout
- call counts and call order, except where timing is the behaviour
- memory addresses
- the original's intermediate values

Trace comparison belongs to a different purpose: locating where two
implementations take different *paths*, which is diagnostic. State comparison
is what establishes equivalence.

## Locating the first divergence

With a per-frame snapshot, the first frame that differs is where the cause is.
Everything after it may be a consequence.

```sh
scripts/state-diff.py original-frames.json mine-frames.json --all-elements
```

```
first divergent element: 1832   (1 field)
  position.y
      original      : 104
      reimpl        : 103
      delta         : -1
      candidate causes:
        - off-by-one at a discrete step
```

Frame 1832. Frames 1..1831 agree. The bug is not spread across the run; it is
one thing that begins at 1832, and understanding that one thing is the whole
task.

For call traces:

```sh
scripts/trace-diff.py original.log mine.log --context 4
```

```
   idx  original                    reimplementation
   179  update_physics              update_physics               =
   180  resolve_collision           clamp_speed                  <<< first divergence
   181  render                      render                       =
```

`resolve_collision` versus `clamp_speed` at index 180. Everything after is
downstream. Investigating the `render` mismatch at 181 would be chasing a
consequence.

Traces are compared on **labels and arguments** by default. Matching calls
with different arguments is not agreement, and reporting it as such would be a
false all-clear.

## Explaining a divergence

This is the step that separates a reconstruction from a fit. Three rules.

**Rule one: establish which side is right before changing either.** If the
original truncates and you round, you do not know yet whether you should round.
Find out what the original does, then decide.

**Rule two: find the boundary, not the instance.** A difference of one at
frame 1832 has a cause that applies at every frame; frame 1832 is just where
it became visible. The question is "at what input do the two implementations
disagree?", not "how do I make frame 1832 match?"

**Rule three: a fix that is not explained is not a fix.** If you cannot state
the mechanism, you have tuned a constant, and the tuning will fail on the next
input you did not tune for.

### Worked example

```
frame 1832
  original      position.y = 104   velocity.y = 2   state = FALLING
  reimpl        position.y = 103   velocity.y = 2   state = FALLING
  divergence    position.y only
```

The velocities agree, so the input is not the difference. The state agrees, so
the branch is not the difference. One field, off by one, after 1831 agreeing
frames.

Candidate causes, all currently hypotheses:

| Cause | What would confirm it |
| --- | --- |
| rounding vs truncation on a scale factor | read the original's arithmetic at the point of the write; a `lsr` versus a rounding add settles it |
| integration order | check the order of the original's operations; accumulate-then-round differs from round-then-accumulate |
| collision resolution ran on one side only | check whether the collision branch was taken in that frame on each side |
| a clamp applied at a different threshold | compare velocity.y at the boundary, where a clamp at a different limit diverges |

The test that discriminates: find the **smallest input** that produces the
difference. If it is a fixed-point value, the scale is the suspect. If it is
only above a velocity threshold, the clamp is. If it appears only on a frame
where a collision occurred, collision resolution is.

That test is worth more than any of the hypotheses, because it eliminates
three of them at once.

### Fixed-point and numeric reconstruction

Legacy software and low-level targets use integers to represent fractions.
Recovering that representation is common and easy to get subtly wrong.

**Recover the scale, do not assume it.**

```
raw = 0x0180     384
observed: drawn at 1.5 pixels from the left edge of a 256-wide view
  384 / 256 = 1.5          consistent with scale 256 (8.8 fixed-point)

This is consistent. It is not established. Establish it by prediction:
  if the scale is 256, then a raw value of 0x0080 must render at 0.5,
  and 0x0200 at 2.0. Drive those values and measure.
```

The prediction test is what makes it evidence. A scale that fits one value is
a coincidence until it predicts another.

**Where rounding differs.** These produce exactly the off-by-one that
differential testing surfaces:

| Operation | Truncates | Rounds |
| --- | --- | --- |
| `x / 256` | toward zero | away from zero |
| `x >> 8` | toward zero (arithmetic shift, rounds down) | — |
| `(x + 128) >> 8` | — | to nearest |
| float multiply | to nearest, per the FP mode | — |

`(x * s) >> 8` and `(x + 128) >> 8` agree for positive values and differ for
negative ones — and for exactly the negative values that a falling entity has.
That is a common cause of "the falling case is off by one" and it is invisible
until you test the negative side.

**Signedness.** The same 32 bits read as signed and unsigned differ for every
value with the high bit set. Symptom: a coordinate is fine until it goes
negative, then it is enormous.

**Accumulation order.** Floating-point addition is not associative.
`a + b + c` differs from `a + (b + c)` in the last bits, and the difference
accumulates. Reimplementing a loop that accumulates over thousands of
iterations will drift even when the operation is correct. Symptom: agreement
for a while, then divergence that grows.

### Memory layout comparison

Layout is not usually behaviour, and a reimplementation is free to choose its
own. Compare it only when the layout is externally observable — a file format
the original writes, a shared-memory region, a serialised save.

Where it must match, the evidence for each field comes from access:

```
offset  size  access evidence                          candidate
0x00    4     read once at init, never after            seed
0x04    2     compared against 0..1                     state (2 bits)
0x08    4     read each frame, added to 0x10            velocity.y
0x0C    4     read each frame, added to 0x10            velocity.x
0x10    4     written each frame                         position.y
0x14    4     written each frame                         position.x
```

What justifies each: the read-write pairs at 0x08/0x0C feeding 0x10/0x14 is a
velocity-to-position relationship, which is a hypothesis at `medium` until
traced. The `0..1` comparison at 0x04 is a narrow range, which is consistent
with a small enum, and consistent with other things too.

## What agreement does and does not prove

Passing a differential test establishes that the two implementations agree **on
the inputs tested**. It does not establish:

- agreement on untested inputs
- agreement on inputs the original rejects
- agreement on behaviour you did not compare
- agreement after a state divergence in the original

A report that says "verified" without naming the inputs is making a larger
claim than it tested. Write the inputs down:

```
compared: 4 seed inputs x 600 frames, fixed initial state, single-threaded
divergent: seed 3, frame 1832, position.y
explained: original truncates ((x*s) >> 8); reimplementation rounded
           (x*s + 128) >> 8. Confirmed by reading the original's arithmetic
           and by a test showing the two agree for x >= 0 and differ for x < 0.
not tested: inputs with collisions; network activity; save-file output
```

The `not tested` line is what makes the rest trustworthy.

## Recording

Divergence work belongs in the ledger under `verification`:

```sh
scripts/recon-ledger.py add ./reconstruction verification \
    position_rounding \
    --evidence "diverges at frame 1832 for seed 3 only" \
    --evidence "original computes (x*256) >> 8; reimplementation used rounding" \
    --tests "compared x in [-256, 256): implementations agree for x >= 0, " \
             "differ by 1 for x < 0; matches the original's arithmetic" \
    --status verified --confidence high
```

The test entry says what was compared and what it showed. "Passes" is not a
result; "agree for non-negative, differ by one for negative, and the original's
arithmetic is a truncating shift" is.

## See also

- `behavioral-analysis.md` — deciding what to compare
- `reimplementation.md` — what to do with the explanation
- `scripts/state-diff.py`, `scripts/trace-diff.py`
- `examples/differential-testing.md`