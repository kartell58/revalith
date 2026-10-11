# Reconstruction ledger

Ten JSON files, one per category. A tool maintains them; the schema is
enforced so a hypothesis cannot quietly become a fact.

This is the **single source of truth** for an investigation's state. The
Markdown in `templates/project-state/` is a rendered view of this ledger, not a
second store to keep in sync by hand.

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
source               which layer produced the evidence: `static`, `dynamic`,
                     `runtime`, `dump`, `diff`, `asset`, `protocol`,
                     `other`. Optional but worth recording: an entry whose
                     source is unknown cannot be re-checked the way it was
                     found, and `gaps` reports the ones that omit it.
evidence             required by most statuses. One observation per entry,
                     naming what was seen and where. "Reads the word at
                     +0x08 in 0x8120", not "looks like a coordinate".
observed_behavior    what was actually seen happening.
hypothesis           the interpretation. Separate from evidence: this is the
                     claim, that is the support.
confidence           five levels.
confidence_basis     why that level. Required in practice, not by the
                     validator.
supporting_observations
                     what the claim rests on, as distinct from `evidence`,
                     which records what was seen. An entry with evidence and
                     nothing here is a summary of the case rather than an
                     audit of it.
contradicting        observations that argue against this entry. This is the
                     field that makes a stale claim catchable months later,
                     so it is weighed by the validator, not just stored: an
                     entry cannot be `verified` while carrying
                     `contradicting` unless `contradiction_resolved` says how
                     the conflict was settled.
contradiction_resolved
                     how a recorded contradiction was answered. Required when
                     status is `verified` and `contradicting` is not empty;
                     `null` while it is still open.
tests                a test that could have failed, and what it showed.
next_test            what would settle this, when it has not been run.
                     Recording this is not the same as recording a test.
refuted_by           what ruled it out, when status is refuted.
avoid                what not to do next. Required on a `dead_ends` entry,
                     where it is the difference between a note and guidance.
new_evidence          what changed since a recorded dead end refuted this.
                     `add` refuses an entry that reopens a dead end without
                     it, because reopening an idea silently is how a settled
                     question costs a day.
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
    --status hypothesized --confidence low --source static

# move it when the test settles it
scripts/recon-ledger.py update ./reconstruction functions 0x8120 \
    --status reconstructed --confidence high \
    --tests "traced over 60 frames: all three writes advance together"

# a refutation, the moment it happens
scripts/recon-ledger.py add ./reconstruction dead_ends "LZ4 payload" \
    --status refuted --source static \
    --evidence "lz4 -d at 0x1a40 -> bad magic" \
    --hypothesis "the asset payload is LZ4-compressed" \
    --refuted-by "two decoders and the magic bytes all disagree" \
    --avoid "do not retry LZ4; measure entropy before choosing the codec"

# what is assumed, and what depends on it
scripts/recon-ledger.py stats ./reconstruction
scripts/recon-ledger.py validate ./reconstruction

# what is still open
scripts/recon-ledger.py gaps ./reconstruction

# write the readable project-state files from the ledger
scripts/recon-ledger.py render ./reconstruction -o ./project-state/
```

## The habits that matter

Run `stats` before extending the reconstruction. It reports assumptions that
other entries depend on. Those are the places where an error propagates
furthest, and they are the first things worth confirming.

Run `gaps` when deciding what to investigate next. `stats` answers "what have I
found", which makes a long investigation feel finished; `gaps` answers "what is
still unknown", which is what picks the next hour of work. An empty category
there means the question was never asked, not that it was answered.

Record a refutation the moment it happens. `add` refuses an entry that reopens
a dead end without `--new-evidence`, so an idea can come back only with a
reason — a tool that was missing, a trace that was too short, code that
changed.

## Categories

| File | Holds |
| --- | --- |
| `architecture.json` | the target's shape: platform, subsystems, entry points |
| `functions.json` | one entry per function whose behaviour is understood |
| `structures.json` | one entry per recovered layout |
| `states.json` | states, state machines, observable transitions |
| `systems.json` | groups of functions forming a subsystem |
| `formats.json` | asset and file formats, decoded |
| `protocols.json` | wire protocols: framing, fields, state machine |
| `hypotheses.json` | open claims, each with a next test |
| `verification.json` | tests run, and what each one showed |
| `dead_ends.json` | refuted investigations, with what not to retry |

`dead_ends.json` is the one that pays for itself. A refuted hypothesis that is
recorded here is never re-tested; one that is not, will be — usually by the
same investigation, weeks later, paying for it twice.