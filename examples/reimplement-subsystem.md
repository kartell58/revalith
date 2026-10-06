# Example: reimplement a subsystem

From a verified model to working code, and the discipline that keeps the two
from drifting apart.

> Target data is **synthetic**. Commands are real and runnable.

## The starting point

> "I have a model of the entity system. Now write it."

This is where reconstruction usually goes wrong: the code is written with the
decompilation open, and the result mirrors the original's structure — including
its accidents. The model is the specification. The decompilation is evidence
for investigating a divergence, not a template for writing code.

## The model

From the ledger:

```json
{"name": "entity", "status": "verified", "confidence": "high",
 "behaviour": {
   "state": ["idle", "walking", "jumping", "airborne"],
   "transitions": [
     {"from":"idle","event":"move","to":"walking","guard":"on_ground"},
     {"from":"idle","event":"jump","to":"jumping"},
     {"from":"walking","event":"idle","to":"idle"},
     {"from":"walking","event":"jump","to":"jumping"},
     {"from":"walking","event":"damage","to":"airborne"},
     {"from":"jumping","event":"tick","to":"airborne"},
     {"from":"jumping","event":"land","to":"idle","guard":"on_ground"},
     {"from":"airborne","event":"timer","to":"idle"}]},
 "observables": ["position","velocity","state","on_ground"],
 "invariants": ["position.x within [0,511]",
                "state == airborne implies velocity.y >= 0",
                "velocity.x == 0 unless state == walking"],
 "numerics": {"position": "16.16 fixed-point, truncated on conversion",
              "gravity": "2 per frame, applied before collision"}}
```

Every field here has a test behind it. That is what makes the implementation
below defensible.

## Design

The model constrains the interface and nothing else.

```c
/* entity.h -- written from the reconstructed model.
 *
 * Internal representation is a design choice, not a reconstruction: the
 * original stores 16.16 fixed-point integers, this stores int32 pixels.
 * Equivalence is verified at the boundary, not assumed internally.
 */
#ifndef ENTITY_H
#define ENTITY_H

typedef enum {
    ENTITY_IDLE,
    ENTITY_WALKING,
    ENTITY_JUMPING,
    ENTITY_AIRBORNE,
    ENTITY_STATE_COUNT
} entity_state;

typedef enum {
    EVENT_NONE,
    EVENT_MOVE,
    EVENT_JUMP,
    EVENT_LAND,
    EVENT_DAMAGE,
    EVENT_TIMER,
    EVENT_COUNT
} entity_event;

typedef struct {
    int32_t x, y;          /* pixels; 16.16 at the boundary */
    int32_t vx, vy;
    entity_state state;
    int on_ground;
    int frames_in_state;
} entity;

void entity_init(entity *e, int x, int y);
void entity_step(entity *e, entity_event ev);

/* Reconstructed invariants. Exposed so tests can assert them rather than
 * re-deriving the expectation. */
int entity_invariant_holds(const entity *e);

#endif
```

Two decisions worth naming:

**Integers, not floats.** The model records `position` as 16.16 fixed-point
because that is what the original uses. Storing `int32` pixels internally is
free, provided conversion truncates — and `entity_invariant_holds` plus the
differential test are what make that safe.

**The invariants are exported.** That lets a test assert them directly, so a
regression is caught by a test rather than by a user noticing.

## Implement

```c
/* entity.c */
#include "entity.h"

#define GRAVITY      2
#define WALK_SPEED   2
#define AIRBORNE_TICKS 18      /* the delay was observed, not measured:
                                * see the model. Confirm against the original. */

static entity_state next_state(entity_state s, entity_event ev, int on_ground)
{
    switch (s) {
    case ENTITY_IDLE:
        if (ev == EVENT_MOVE && on_ground) return ENTITY_WALKING;
        if (ev == EVENT_JUMP)               return ENTITY_JUMPING;
        return ENTITY_IDLE;
    case ENTITY_WALKING:
        if (ev == EVENT_DAMAGE)             return ENTITY_AIRBORNE;
        if (ev == EVENT_JUMP)               return ENTITY_JUMPING;
        if (ev != EVENT_MOVE)               return ENTITY_IDLE;
        return on_ground ? ENTITY_WALKING : ENTITY_IDLE;
    case ENTITY_JUMPING:
        if (ev == EVENT_LAND && on_ground)  return ENTITY_IDLE;
        return ENTITY_AIRBORNE;
    case ENTITY_AIRBORNE:
        return ENTITY_IDLE;   /* the timer is handled by the caller */
    default:
        return ENTITY_IDLE;
    }
}

void entity_init(entity *e, int x, int y)
{
    e->x = x; e->y = y;
    e->vx = 0; e->vy = 0;
    e->state = ENTITY_IDLE;
    e->on_ground = 1;
    e->frames_in_state = 0;
}

void entity_step(entity *e, entity_event ev)
{
    entity_state before = e->state;

    /* Velocity, reconstructed: only walking has horizontal velocity. */
    switch (ev) {
    case EVENT_MOVE:
        if (e->state == ENTITY_WALKING || before == ENTITY_IDLE)
            e->vx = WALK_SPEED;
        break;
    case EVENT_JUMP:
        e->vy = -JUMP_IMPULSE;
        break;
    case EVENT_NONE:
    default:
        if (e->state != ENTITY_WALKING) e->vx = 0;
        break;
    }

    if (e->state == ENTITY_JUMPING || e->state == ENTITY_AIRBORNE)
        e->vy += GRAVITY;

    e->x += e->vx;
    e->y += e->vy;

    e->state = next_state(before, ev, e->on_ground);
    if (e->state != before) e->frames_in_state = 0;
    else                     e->frames_in_state++;

    if (e->state == ENTITY_IDLE && before == ENTITY_AIRBORNE) {
        e->vy = 0;
    }
}

int entity_invariant_holds(const entity *e)
{
    if (e->x < 0 || e->x > 511)                 return 0;
    if (e->state == ENTITY_AIRBORNE && e->vy < 0) return 0;
    if (e->state != ENTITY_WALKING && e->vx != 0)  return 0;
    return 1;
}
```

## Verify against the original

```sh
./original  --input inputs/walk.bin --frames 600 --trace state,pos > frames/orig.json
./reimpl    --input inputs/walk.bin --frames 600 --trace state,pos > frames/mine.json

scripts/state-diff.py frames/orig.json frames/mine.json --all-elements
```

```
first divergent element: 12   (2 fields)
  state
      original      : walking
      reimpl        : idle
  position.x
      original      : 26
      reimpl        : 24
```

Frame 12, two fields, and `state` diverging tells you the ordering is wrong
rather than the arithmetic. An arithmetic bug would move `position.x` and
leave `state` alone.

## Investigate before fixing

The divergence is a symptom. Find the cause in the model.

```
observation: the reimplementation returns to IDLE after one frame of no input,
             but the original stays in WALKING and only returns to IDLE on
             the following frame
```

The model says `"walking" → "idle" : "after 1 frame"` — reconstructed from a
trace that recorded the transition one frame late, or from a trace where the
input event was consumed differently.

Check the transition directly, which is the cheap test:

```sh
# drive: move, then hold no input, recording the state each frame
./original --input inputs/move-then-idle.bin --frames 6 --trace state
```

```
frame 0  idle
frame 1  walking
frame 2  walking
frame 3  walking
frame 4  idle
frame 5  idle
```

Walking persists for three frames after the input stops, then returns. Not
one. The model's transition table is wrong, and it was wrong in a way that
produced a plausible-looking single-frame exit.

Find the mechanism in the original:

```sh
objdump -d ./game.rom | sed -n '/8620/,/86c0/p'
```

```
8642: a5 02      LDA $02
8644: 29 03      AND #$03
8646: f0 12      BEQ idle
8648: a5 06      LDA $06
864a: 38         SEC
864b: e9 03      SBC #$03
864e: 90 08      BCC idle
8650: a9 01      LDA #$01
8652: 85 02      STA $02
```

The state is not cleared directly. `AND #$03 / BEQ idle` tests the low bits,
and `LDA $06 / SEC / SBC #$03 / BCC idle` tests a counter against 3. So
walking exits when a separate counter reaches 3, and the exit is a *counter*,
not a frame count from the state machine.

The model had the right idea and the wrong parameter: it recorded the frame
count as a property of the transition when it is actually a separate
observable with its own lifecycle.

```sh
scripts/recon-ledger.py update ./reconstruction states entity_state_machine \
    --status partially-reconstructed --confidence medium \
    --tests "re-derived from a 6-frame trace: walking persists 3 frames" \
    --evidence "the original tests a separate counter against 3 before " \
               "clearing the state; the transition is not a one-frame exit" \
    --next-test "confirm the counter's reset condition and its initial value" \
    --note "the earlier model recorded this as a 1-frame exit; that was " \
          "wrong and is superseded by this entry"
```

`--note` records the correction rather than overwriting it, so a later reader
can see that both claims existed and which one survived.

Fix the implementation from the corrected model:

```c
    /* Walking persists for 3 frames after the input stops. This is a
     * separate counter in the original (tested against 3 at 0x864a), not a
     * property of the transition. Reconstructed; see the ledger entry, which
     * supersedes an earlier single-frame reading. */
    if (e->state == ENTITY_WALKING) {
        if (ev == EVENT_MOVE) {
            e->idle_frames = 0;
        } else {
            e->idle_frames++;
            if (e->idle_frames >= WALK_EXIT_FRAMES) e->state = ENTITY_IDLE;
        }
    }
```

## Verify again

```sh
scripts/state-diff.py frames/orig.json frames/mine.json --all-elements
```

```
every compared element agrees at this tolerance.
```

600 frames agree. But that is one input, and the honest report says so:

```sh
scripts/recon-ledger.py add ./reconstruction verification entity_system \
    --evidence "600 frames agree for inputs/walk.bin" \
    --evidence "600 frames agree for inputs/jump-land.bin" \
    --evidence "600 frames agree for inputs/damage.bin" \
    --tests "invariant entity_invariant_holds() true across all three inputs" \
    --status verified --confidence medium \
    --note "not tested: collision resolution (not reconstructed); the " \
          "AIRBORNE timer duration (measured as 18 in the model, never " \
          "verified against the original); simultaneous jump+damage"
```

`confidence: medium`, not `high`. Three inputs is a real test and not a
comprehensive one, and the two untested areas are named. Claiming `high` here
because the tests pass is the habit this skill exists to break, and it is most
tempting at exactly this point.

## When the implementation is ported

```sh
make TARGET=linux
make TARGET=windows
make TARGET=android-arm64
```

Re-run the same tests on each target. Do not assume — the differences that
bite are compile-time:

| Check | Symptom if wrong |
| --- | --- |
| `sizeof(int32_t)` | values truncated on a 16-bit target |
| plain `char` signedness | behaviour differs above 127 |
| struct packing | a field reads the wrong offset |
| float mode (no `-ffast-math`) | accumulation drift over long runs |
| time epoch | timestamps off by decades |

```sh
for t in linux windows android-arm64; do
  make TARGET=$t || continue
  ./build-$t --input inputs/walk.bin --frames 600 > frames/$t.json
  scripts/state-diff.py frames/orig.json frames/$t.json --all-elements
done
```

## What this example shows

- the model was written from the ledger, not from the disassembly
- the fix came from correcting the model, and the correction is recorded
- the divergence in `state` pointed at the ordering rather than the arithmetic
- one constant is marked as measured-but-unverified
- the final claim is `medium`, with two untested areas named
- the port re-runs the tests instead of assuming them

The discipline, at the point where it is most tempting to abandon it: **the
tests passing is not the claim. The claim is what the tests covered, and a
reimplementation that says "verified" without saying so has converted an
unverified guess into an assertion.**