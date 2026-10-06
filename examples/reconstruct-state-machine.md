# Example: reconstruct a state machine

From a small integer field to a testable transition table.

> Target data is **synthetic**. Commands are real and runnable.

## The starting point

> "There's a byte at 0x4312 that only ever holds 0, 1, 2 or 3. What are
> they?"

An enum field, most likely — or a bitfield, or a coincidence. The value is
observable; the meaning is not.

## Find the variable

```sh
scripts/strings-map.py ./game.bin --xrefs --search "state"
objdump -d ./game.bin | grep -E '\$4312|\$4313'
```

```
0x8200: lda  $4312      ; read
0x8202: cmp  #$00
0x8204: beq  0x8210
0x8206: cmp  #$01
0x8208: beq  0x8240
0x820A: cmp  #$02
0x820C: beq  0x8270
0x820E: cmp  #$03
0x8210: rts
```

A four-way dispatch. That is a state machine, and the dispatch is the
strongest possible evidence for it — the program itself branches on the value.

## Collect values by observation, not by reading

Do not read the four branches and assume they are the states. Read them for
the writes, and drive the program for the transitions.

```sh
# break on 0x8200, run scenarios, record the value at entry and exit
```

```
scenario: player idle, no input
  entered with 0, left with 0

scenario: press right
  entered with 0, left with 1

scenario: press jump from standing
  entered with 0, left with 2

scenario: jump, then wait
  entered with 2, left with 3
  entered with 3, left with 0     (after a timer)
```

So far: `0 → 1` on movement, `0 → 2` on jump, `2 → 3` on falling, `3 → 0` on
a timer.

## Fill the transition table

The method is mechanical: for each state, apply each input, record the result.

```
state  input      result  observed how
0      none       0       no change without input
0      move right 1       velocity becomes 2
0      move left  1       velocity becomes -2
0      jump       2       upward velocity set
1      none       0       returns to idle after one frame
1      move right 1       stays walking
1      jump       2       jumps from walking
1      damage     3       enters the same state as falling -- see below
2      none       3       gravity applies
2      land       0       on contact with ground
3      timer      0       after a fixed number of frames
3      none       3       stays until the timer expires
```

`1 --damage--> 3` is the interesting one. It lands in the same state as
falling. Either `3` is a general "interrupted" state that falling also enters,
or there is a third thing happening at 3 that the name "falling" will hide.

Do not name them yet.

## Check the guards

A transition that happens in one condition and not another has a guard, and
omitting it is how a reimplementation reaches states the original cannot.

```sh
# force on_ground to 0, then press move
```

```
0 --move--> ?  with on_ground = 0:   value stays 0
0 --move--> 1  with on_ground = 1:   value becomes 1
```

```
state  input      result  guard              confidence
0      none       0       --                 high
0      move       1       on_ground = 1      high
0      jump       2       (none observed)    medium
1      none       0       after 1 frame      high
1      move       1       on_ground = 1      high
1      jump       2       (none observed)    medium
2      none       3       (none observed)    high
2      land       0       on_ground = 1      high
3      timer      0       after N frames     medium   <-- N not measured
1      damage     3       (none observed)    low
```

Two honest gaps: `N` was not measured, and `(none observed)` means the guard
was not tested, not that none exists. That distinction matters — the second is
a risk for a reimplementation, because a missing guard produces states the
original cannot reach.

## Name the states

Now, and only now:

```
0  idle      no velocity, nothing scheduled
1  walking   horizontal velocity, exits to idle when input stops
2  jumping   upward velocity set, exits on landing
3  airborne gravity applies; entered both by falling and by damage
```

The name `airborne` for 3 rather than `falling` is the payoff of the
observation. It is entered from `damage` as well as from `jump`, so calling it
`falling` would have baked an assumption into the model — and a
reimplementation would then have no state for the damage case, and would fail
in a way that looks like a physics bug.

Two states remain partly unnamed: why `2 → 3` exists as a separate state when
both are "not on the ground", and whether `damage` from `3` does anything.
Record both as open.

## Record it

```sh
scripts/recon-ledger.py add ./reconstruction states entity_state_machine \
    --evidence "0x4312 read at 0x8200 and dispatched four ways" \
    --evidence "values observed: 0, 1, 2, 3 only, across 40 scenarios" \
    --evidence "0 -> 1 on move input with on_ground = 1; not with on_ground = 0" \
    --evidence "1 -> 3 on damage input, entering the same state as falling" \
    --evidence "2 -> 3 under gravity; 3 -> 0 on a timer" \
    --evidence "no observed transition out of 3 on input" \
    --observed-behavior "4 states; walking exits to idle after one frame of no input" \
    --hypothesis "idle / walking / jumping / airborne, with airborne shared by falling and damage" \
    --next-test "measure the timer duration from state 3 to state 0" \
    --next-test "test every input from state 3 to confirm the machine is closed" \
    --status partially-reconstructed --confidence medium
```

`partially-reconstructed` rather than `reconstructed`: the transitions are
mapped but the guards are incompletely tested, and one timer duration is
unmeasured.

## Draw it

```
IDLE
 ├─ move (on_ground=1) ──→ WALKING
 └─ jump ────────────────→ JUMPING

WALKING
 ├─ none ─────────────────→ IDLE
 ├─ move ─────────────────→ WALKING
 ├─ jump ─────────────────→ JUMPING
 └─ damage ───────────────→ AIRBORNE

JUMPING
 ├─ none (gravity) ───────→ AIRBORNE
 └─ land (on_ground=1) ───→ IDLE

AIRBORNE
 └─ timer ────────────────→ IDLE
```

Drawn as a diagram, read as a specification: for each state and input, the
predicted next state. That is what makes the model testable against a
reimplementation, and it is the form you implement from.

## Implement it

```c
typedef enum { IDLE, WALKING, JUMPING, AIRBORNE } entity_state;

/* Transitions reconstructed from 40 scenarios. The damage transition from
 * WALKING and the gravity transition from JUMPING reach the same state,
 * observed rather than assumed. */
static entity_state step(entity_state s, input i, int on_ground)
{
    switch (s) {
    case IDLE:
        if (i == JUMP)        return JUMPING;
        if (i == MOVE && on_ground) return WALKING;
        return IDLE;
    case WALKING:
        if (i == DAMAGE)      return AIRBORNE;
        if (i == JUMP)        return JUMPING;
        if (i == MOVE && on_ground) return WALKING;
        return IDLE;
    case JUMPING:
        if (on_ground)        return IDLE;     /* landed */
        return AIRBORNE;                       /* gravity */
    case AIRBORNE:
        return timer_elapsed() ? IDLE : AIRBORNE;
    }
}
```

The guards are in the code because they were in the evidence. The unmeasured
timer is called out rather than guessed:

```c
/* The AIRBORNE -> IDLE delay was observed to exist but not measured.
   This constant is a placeholder, not a reconstructed value; a
   differential test against the original will pin it down. */
#define AIRBORNE_FRAMES 18   /* TODO: unmeasured */
```

A placeholder marked as a placeholder is fine. A plausible constant with no
marker is a claim you did not make.

## Verify

Drive both implementations through the same scenarios and compare the state
sequences:

```sh
scripts/trace-diff.py original-trace.log reimpl-trace.log --detail
```

```
   idx  original                    reimplementation
   ...
  211   AIRBORNE                    AIRBORNE                    =
  212   IDLE                        AIRBORNE                    <<< first divergence
```

The timer is wrong, and the trace comparison says so at the first frame it
matters rather than at the end of the log. Measure the original's delay, set
the constant, and the model moves to `verified`.

## What this example shows

- the four-way dispatch is what makes it a state machine, not the four values
- the `damage → 3` observation changed a name, and would have changed the code
- guards were tested by forcing them, not assumed from the absence of a check
- two things are recorded as untested rather than as absent
- an unmeasured constant is marked as a placeholder

The discipline: **drive every state with every input, test the guards by
forcing them, and let an observation change the name you were about to use.**