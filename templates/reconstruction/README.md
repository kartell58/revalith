# Reconstruction ledger

Eight JSON files, one per category. A tool maintains them; the schema is
enforced so a hypothesis cannot quietly become a fact.

## The problem this solves

A reconstruction spans weeks. What was a hypothesis in week two is read as
settled in week eight, something is built on it, and the error surfaces far
from its cause. Documentation does not prevent this reliably. A validator
does.

## Status vocabulary

Use exactly one status per entry. Each demands something, and the demand is
checked.

| Status | Means | Requires |
| --- | --- | --- |
| `unknown` | looked at, nothing established | nothing |
| `observed` | a fact was seen | evidence |
| `hypothesized` | an interpretation consistent with the evidence | evidence, and a test or a `next_test` |
| `partially-reconstructed` | some of the element is understood | evidence |
| `reconstructed` | the model is complete enough to act on | evidence |
| `verified` | tested against the original | evidence, **and** a test that could have failed |
| `refuted` | tested and wrong | a record of what refuted it |

`verified` without a test is refused. That is the single most important rule
in the file: "verified" is a claim about a test having been run, and an entry
that cannot name one has not been verified.

## Confidence

The skill's usual five levels, unchanged:

`very low` · `low` · `medium` · `high` · `very high`

A status bounds the confidence it can justify. `observed` cannot carry `very
high` — an observation is not a test result, however striking. `validate`
reports the violation rather than silently accepting it.

## Entry fields

```
name                 required. Unique within its file.
kind                 set from the category; do not write it by hand.
status               required. One of the values above.
evidence             required by most statuses. One observation per entry,
                     naming what was seen and where. "Reads the word at
                     +0x08 in 0x8120", not "looks like a coordinate".
observed_behavior    what was actually seen happening.
hypothesis           the interpretation. Separate from evidence: this is the
                     claim, that is the support.
confidence           five levels.
confidence_basis     why that level. Required in practice, not by the
                     validator.
tests                a test that could have failed, and what it showed.
next_test            what would settle this, when it has not been run.
                     Recording this is not the same as recording a test.
contradicting        observations that argue against this entry.
refuted_by           what ruled it out, when status is refuted.
related_functions    cross-references. These make the entry load-bearing, and
related_data            `stats` reports assumptions that others depend on.
related_structures
history              appended automatically on every change.
```

## Why JSON and not markdown

`templates/project-state/` is Markdown because a human maintains it while
thinking. This ledger is written by `recon-ledger.py`, queried by status, and
diffed when a status changes. Machine-readable storage makes those possible,
and makes a status change reviewable as a diff rather than an edit hidden in
prose.

## Commands

```sh
scripts/recon-ledger.py init ./reconstruction

# record a hypothesis the day it is formed, before it is tested
scripts/recon-ledger.py add ./reconstruction functions 0x8120 \
    --evidence "called once per frame from the main loop" \
    --evidence "writes the word at +0x10" \
    --hypothesis "per-frame update of a persistent entity state" \
    --next-test "trace writes to +0x08/+0x0c/+0x10 across two frames" \
    --status hypothesized --confidence low

# move it when the test settles it
scripts/recon-ledger.py update ./reconstruction functions 0x8120 \
    --status reconstructed --confidence high \
    --tests "traced over 60 frames: all three writes advance together"

# what is assumed, and what depends on it
scripts/recon-ledger.py stats ./reconstruction
scripts/recon-ledger.py validate ./reconstruction
```

## The habit that matters

Run `stats` before extending the reconstruction. It reports assumptions that
other entries depend on. Those are the places where an error propagates
furthest, and they are the first things worth confirming.

## Categories

| File | Holds |
| --- | --- |
| `architecture.json` | the target's shape: platform, subsystems, entry points |
| `functions.json` | one entry per function whose behaviour is understood |
| `structures.json` | one entry per recovered layout |
| `states.json` | states, state machines, observable transitions |
| `systems.json` | groups of functions forming a subsystem |
| `formats.json` | asset and file formats, decoded |
| `hypotheses.json` | open claims, each with a next test |
| `verification.json` | tests run, and what each one showed |