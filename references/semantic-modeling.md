# Semantic modelling

Turning low-level evidence into a model. The direction of travel is:

```
assembly
   ↓  basic blocks
functions
   ↓  call graph
subsystems
   ↓  data flow
structures
   ↓  invariants
a model you can write code from
```

Each step is evidence-driven and each can fail. This reference is about the
steps.

## Not decompilation

This is a model, not source-like text. A decompiler can produce a C struct
recovered from the field accesses below, and that struct will carry the same
five fields with the same offsets — while asserting nothing about what they
mean, because a decompiler has no evidence about meaning. Everything on this
page is about the second half: the claim, its support, and how it can be
refuted. `reconstruction.md` covers the difference in full.

## The jump you may not make

This is the failure this reference exists to prevent:

```
function_0x8120  →  updatePlayerPhysics()
```

The right-hand side is a claim. It asserts that this function updates player
physics — which implies a player, a physics model, and a specific operation.
None of that is in the disassembly. The name will be used, will appear in
code, and will be inherited by everything built on it. An unsupported name
propagates further than a supported one, because nobody re-examines a name
that reads naturally.

## The graded version

The name is earned in steps. Each step is recorded, and each is weaker than
the one that follows.

```
function_0x8120
  "a function that writes one dword and calls one other function"
  status: observed                        confidence: high

function_0x8120  [writes entity +0x10]
  "per-frame update of a 16-byte block at a persistent pointer"
  status: partially-reconstructed         confidence: medium

0x8120  [update_entity_state]
  "per-frame update: reads velocity from +0x08/+0x0c, integrates, writes
   position to +0x10"
  status: reconstructed                   confidence: high

PlayerPhysics.update
  status: verified                        confidence: high
  "traced during 60 frames; reads +0x08/+0x0c, writes +0x10, calls the
   collision routine on overlap. Reproduced by the reimplementation for 600
   frames with no divergence."
```

Each step names what the previous one could not. The last one is short
enough to use because everything it compresses is recorded somewhere.

### Rules for naming

| Evidence | Defensible name | Not defensible |
| --- | --- | --- |
| writes one dword | `write_state_dword` | `savePlayerPosition` |
| called once per frame | `per_frame_update` | `updatePlayerPhysics` |
| reads +0x08/+0x0c, writes +0x10 | `integrate_velocity_to_position` | `updatePlayerPhysics` |
| traced doing exactly that, both branches | `integrate_velocity_to_position` | `updatePlayerAndHandleCollisions` |
| also calls the collision routine, traced | `move_and_resolve_collision` | `updatePlayerPhysics` |

The test for a name: **would this name still be right if you learned something
that contradicts your current understanding?** If not, it is asserting more
than you know.

The `scripts/elf-summary.py` and `find-xrefs.py` outputs give you the observed
half. The rest is judgement, and the judgement goes in the ledger.

## Structures

A structure is a claim about layout plus a claim about meaning. The first is
usually recoverable; the second is not.

Recover the layout from access evidence:

```sh
# every offset touched, with width and direction
scripts/elf-summary.py ./libgame.so --sections
objdump -d ./libgame.so | grep -E 'ldr|str.*\[x[0-9]' | head -40
```

Then classify each field by what the access looks like. These are observations,
not names:

| Access pattern | Observed as | Consistent with |
| --- | --- | --- |
| always loaded, then dereferenced | pointer | a pointer to something |
| compared against small bounds (0..1000) | narrow integer | a small count or index |
| written once during init, never in a loop | initialised value | configuration |
| compared against a pointer to another object | identity check | an owner or link |
| written as `str` after an `ldr` from it | struct field | a nested structure |
| read-modify-write with shifts or masks | bitfield | a flags or state word |

Record each field with the access evidence and the proposed meaning separately:

```json
{"name": "entity_state", "status": "partially-reconstructed",
 "fields": [
   {"offset": "0x00", "width": 8, "access": "loaded then dereferenced",
    "meaning": null, "confidence": "low",
    "evidence": ["passed to memcpy as src in 0x8120"]},
   {"offset": "0x08", "width": 4, "access": "read, added, stored to +0x10",
    "meaning": "velocity", "confidence": "medium",
    "evidence": ["read in 0x8120", "sum with +0x0c appears in +0x10"]},
   {"offset": "0x10", "width": 4, "access": "written once per frame",
    "meaning": "position", "confidence": "medium",
    "evidence": ["written at the end of 0x8120"]}]}
```

`"meaning": null` is a legitimate answer, and a better one than a guess. It
keeps the offset available for the next reader while refusing to assert
something unsupported.

### Bitfields

A read-modify-write with a mask is the observation. Recover each bit
independently, because each one is a separate claim with separate evidence:

```asm
ldr  w1, [x0, #8]
bic  w1, w1, #0xf       ; clear the low nibble
orr  w1, w1, #2        ; set bit 1
str  w1, [x0, #8]
```

Bits 0..3 form a field. Bits 4+ are a different field with different evidence
and possibly a different meaning. Record the mask, the observed values, and
for each value, what happened.

## Enums and constants

A constant table is easier to reconstruct than a struct, because the values
are usually in one place.

```sh
scripts/strings-map.py ./libgame.so --xrefs --search "state"
objdump -s -j .rodata ./libgame.so | head -40
```

For each observed value, record what it *does*, not what it is called:

```
0  : entity idle, no velocity written
1  : entity falling, gravity applied
2  : entity jumping, upward velocity set
```

Until you can produce a value you have never observed, the vocabulary is
incomplete. Say so: `"values observed": [0,1,2], "completeness": "unknown"`.
An enum reconstructed from three values is three values, not three cases.

## Subsystems

Grouping functions is where reconstruction adds the most and risks the most,
because the grouping determines what you build.

### Evidence that a group is real

- **Shared data.** Functions touching the same state block are plausibly one
  subsystem.
- **Execution phase.** Functions called in the same phase of the frame.
- **Call graph connectivity.** Dense mutual calls, a shared caller, a shared
  callee.
- **Common constants.** The same magic numbers, the same lookup tables.
- **Memory region.** Adjacent code, or one contiguous data block.
- **Assets and I/O.** The same files, the same sockets.

### Evidence that does not establish a group

- **Name similarity.** `func_update_a` and `func_update_b` may be unrelated.
  Names come from the binary and mean whatever the author meant.
- **Adjacency in the binary.** The linker decides layout. Two functions
  adjacent in `.text` were adjacent in the object file, and nothing more.
- **A shared callee.** `malloc` is called by everything.

Record a subsystem with its evidence and its confidence:

```json
{"name": "physics", "status": "hypothesized", "confidence": "medium",
 "evidence": ["14 functions all read/write the block at 0x8120",
              "all 14 are called between the input and render phases",
              "they share 4 constants not used outside the group"],
 "hypothesis": "one coherent subsystem",
 "contradicting": ["one of them also handles audio state"],
 "next_test": "disable the group and see whether movement stops while audio continues"}
```

That `contradicting` entry is the useful one. A subsystem with a known
exception is worth more than a clean story, because it tells you the boundary
is not where you assumed.

## Invariants

An invariant is a property that holds across observed states. It is the most
valuable thing to reconstruct and the easiest to skip, because it is only
visible after you have watched several states.

How to find them:

1. Snapshot the state at many points (idle, moving, falling, colliding).
2. Compare across snapshots.
3. Anything that never varies, or varies in a constrained way, is a candidate.

```
across 40 sampled frames:
  state.x + 0x00 ... not observed to change
  state.y + 0x10 ... 90..140, integer, always in range
  flag + 0x0c       ... only values 0 and 1 observed; 2 and 3 never occur
  ptr  + 0x00       ... non-null whenever state != 0
```

A constraint you have not seen violated is an invariant *you have not tested*,
not a proven one. Record how many samples support it, and whether you
deliberately tried to violate it.

```
"invariant": "state != 0 implies ptr != null",
"supporting_samples": 40,
"deliberately_tested": false,
"confidence": "medium",
"note": "consistent across 40 samples; a path that sets state non-zero with a
         null pointer has not been found or excluded"
```

That last line is the honest version. Invariants are how a reimplementation
acquires a crash the original never had.

## Order of work

Reconstruct in dependency order, not in address order. A structure that ten
functions interpret is worth more than ten functions that touch an
ununderstood structure.

```
1. Entry points and the frame loop        what runs, and in what order
2. The state block                         what persists
3. The functions that write it             what changes it
4. The functions that read it              what consumes it
5. Subsystem boundaries                    where one concern ends
6. Invariants                              what must stay true
```

Each layer is checkable against the layer below. Skip a layer and the next
one is built on nothing.

## Recording

Everything here goes in the ledger:

```sh
scripts/recon-ledger.py add ./reconstruction functions 0x8120 \
    --evidence "called once per frame from the main loop" \
    --evidence "reads +0x08 and +0x0c, writes +0x10" \
    --hypothesis "per-frame update of a persistent entity state" \
    --next-test "trace the three writes across two frames" \
    --status hypothesized --confidence low \
    --related-data entity_state
```

Run `scripts/recon-ledger.py validate` before building on it. The validator
refuses an entry whose status outruns its evidence, which is the specific
mistake that makes a reconstruction wrong in a way nobody notices.

## See also

- `behavioral-analysis.md` — the model once the semantic one exists
- `differential-testing.md` — testing a model against the original
- `investigation-state.md` — dead ends, so a refuted model is not retried
- `examples/reconstruct-function.md`, `examples/reconstruct-structure.md`