# Behavioural analysis

A behavioural model describes what a system does, in terms that do not depend
on how the original wrote it. That independence is the point: it is what lets
you implement the behaviour in a different structure and still call the result
equivalent.

This is not decompilation. Decompilation reconstructs the original's *code*;
this reconstructs its *behaviour*. The two can disagree, and when they do the
behaviour is what you implement — the code was one way of producing it.

## Why separate from the semantic model

| | Semantic model | Behavioural model |
| --- | --- | --- |
| Answers | what the parts *are* | what the system *does* |
| Anchored in | the original's memory layout | the observable effects |
| Contains | structs, fields, call graphs | states, transitions, outputs |
| Changes if you reimplement | yes — your layout differs | no — the behaviour is the same |

A reimplementation with a completely different internal layout still satisfies
the behavioural model. That is the definition of behavioural equivalence, and
it is why the behavioural model is what you write code from.

## Recording behaviour

### From a dynamic trace

A trace is behaviour over time. Read it as a sequence of state transitions:

```
frame 1   input: none      -> velocity (0, 0)   -> position unchanged
frame 2   input: right     -> velocity (2, 0)   -> position.x 512 -> 514
frame 3   input: right     -> velocity (2, 0)   -> position.x 514 -> 516
frame 4   input: none      -> velocity (0, 0)   -> position.x 516 -> 516
frame 5   input: none      -> velocity (0, 0)   -> position unchanged
```

From this: movement persists after input stops for one frame, then stops. That
is an observation about behaviour. "There is a friction constant" is a
hypothesis about the mechanism. Both are worth recording; only the first is
established.

### From static analysis

Behaviour can be read off the code when control flow is clear:

```
0x8120:
  load +0x08, +0x0c         ; two values
  if (+0x0c > 0) goto fall  ; a branch on one of them
  add +0x08 to +0x10
  store +0x10
  ret
```

The branch on `+0x0c` gates whether the write happens. That is observed. What
`+0x0c` means is inferred. Testing both sides of the branch with known values
is what settles it.

## Entities

Model an entity as observable state, not as a struct:

```
Player
├── Position          observed at (x, y), integer
├── Velocity          observed at (vx, vy), integer
├── State             observed: 4 values, meaning partly unknown
├── Collision         reacts with the world boundary
├── Animation         changes on state transitions
└── Input             read once per frame
```

The section list is a hypothesis about decomposition. Each line needs its own
evidence:

| Field | Evidence for it being a separate concern |
| --- | --- |
| Position | written by the integration step, read by render and collision |
| Velocity | written by input, read by integration |
| State | gates which branch runs |
| Collision | a distinct routine, called only on overlap |
| Animation | a distinct table, changed on transitions |
| Input | read once per frame, before everything else |

If Animation turns out to be read only inside the render phase, it is part of
render, not part of the entity. The grouping is a hypothesis and stays one
until evidence settles it.

## State machines

States are the most reconstructible part of behaviour, because they are
directly observable: run the system, watch which state it is in.

### Collecting transitions

Drive the system into each state and record what leaves it. The method is
mechanical:

1. Find the state variable (a small field with few observed values).
2. Put the system in each observed state.
3. For each, apply one input at a time.
4. Record the resulting state.
5. Repeat until no new state appears.

```
IDLE
  input: right   -> WALK
  input: jump    -> JUMP
  input: damage  -> HURT

WALK
  input: none    -> IDLE
  input: jump    -> JUMP
  input: damage  -> HURT

JUMP
  gravity        -> FALLING
  input: damage  -> HURT
  landing        -> IDLE

HURT
  timer          -> IDLE
```

Each arrow is a testable claim: apply that input in that state, and the
predicted state follows. That makes the model a specification.

### What the model does not say

The diagram says which state follows which. It does not say:

- what the states are **for** — name them `STATE_2` until a behaviour
  distinguishes them
- whether the machine is a switch, a jump table, or scattered comparisons —
  the original's choice, not the model's
- whether a transition is possible at all times, or only under a condition you
  have not hit

The last one matters most for a reimplementation. If you omit a guard the
original has, your machine reaches states the original cannot, and the
difference will look like a bug in your physics rather than a missing
condition. Record guards when you find them:

```
transition: IDLE -> WALK
guard:      on_ground == 1
evidence:   with on_ground forced to 0, walking input leaves the state IDLE
confidence: high
```

### Mermaid and text

Either is fine; both are derived views of the same data. Keep the canonical
form in the ledger, so a state machine can be validated and diffed:

```sh
scripts/recon-ledger.py add ./reconstruction states entity_state_machine \
    --evidence "state field at +0x0c takes values 0,1,2,3" \
    --evidence "0 -> 1 on movement input with on_ground set" \
    --evidence "0 -> 2 on jump input, 2 -> 3 on landing" \
    --observed_behavior "4 states; transitions from 0 and 2 fully mapped" \
    --hypothesis "a four-state entity machine" \
    --status partially-reconstructed --confidence medium \
    --next-test "force state 3 with each input and record the outcome"
```

## Invariants as behaviour

`semantic-modeling.md` covers invariants over memory. Over behaviour, the same
idea applies and is easier to test: an invariant is a property that holds
across every observed run.

```
never: position.x outside [0, 511]
never: state == 3 while position.y < 0
always: after a jump, y decreases monotonically until landing
```

These are the constraints a reimplementation must respect to be a drop-in
replacement, and they are cheap to state and cheap to break.

## Timing

Timing is behaviour and it is often the part a reimplementation misses:

| Property | How to observe |
| --- | --- |
| update order | the sequence of calls in one frame |
| frame budget | what runs every frame vs. occasionally |
| debounce | how many inputs are dropped |
| cooldown | the minimum interval between two actions |
| interpolation | whether a value moves per frame or per tick |

Order matters most. If the original reads input, then applies physics, then
renders, and yours reads input, renders, then applies physics, the rendered
frame is one step behind — which looks like a one-frame lag rather than an
ordering error, and is easy to misattribute to interpolation.

## Assets and I/O as behaviour

Assets participate in behaviour: a level is loaded and its contents determine
what the system can do.

```
assets/world.bin
  256 bytes, header magic 0x574C44, then 64 records of 4 bytes
  read by 0x2200 during init, before the first frame
  record 0: 0x0001 0x0000 0x0010 0x0002
  record 1: 0x0001 0x0004 0x0008 0x0001
```

What is established: the file is read at init, by that function, in that
order. What is not: what the four fields mean, or whether 64 is the real
count. Both gaps are worth recording as gaps.

The behavioural question is the useful one: **what does the system do
differently for record 0 than record 1?** Compare two runs whose only
difference is that record, and the field's meaning follows from the
behavioural difference.

## Recording

Behaviour goes in the ledger under `states`, `systems` and `formats`. The
discipline is unchanged from the rest of the skill:

```sh
scripts/recon-ledger.py add ./reconstruction systems collision \
    --evidence "called from 0x8120 only when the overlap test passes" \
    --evidence "6 functions share the collision data block" \
    --hypothesis "collision resolution is one subsystem" \
    --status hypothesized --confidence medium \
    --next-test "disable it and confirm movement no longer stops at walls"
```

## Before writing code

You have a behavioural model when you can answer all four:

1. **What state does the system hold, and what can each state do?**
2. **What transitions exist, and under what conditions?**
3. **What is observable from outside, and how would you measure it?**
4. **What must always be true?**

Question 3 is the one people skip, and it is the one that makes differential
testing possible. If you cannot say how you would observe the behaviour, you
cannot verify a reimplementation of it, and you have not finished the model.

## See also

- `semantic-modeling.md` — the memory-level model this is derived from
- `differential-testing.md` — measuring the observables you just listed
- `reimplementation.md` — building from this model
- `examples/reconstruct-state-machine.md`