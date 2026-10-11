# Investigation state

Long-running investigations fail in a specific way: the same hypothesis gets
re-tested three weeks later because nobody recorded that it was already
refuted. This reference is about keeping state that prevents that.

## The problem

Without a record, an agent re-derives from scratch:

```
session 1: hypothesis "payload uses LZ4" -> tested -> refuted
session 2: hypothesis "payload uses LZ4" -> tested -> refuted   (again)
session 3: 30 minutes wasted on a settled question
```

The waste compounds across a large target: hundreds of small refutations,
each cheap individually, add up to a day of redundant work.

## One store, not two

The state of an investigation lives in **the ledger**:

```
reconstruction/
├── architecture.json   ├── formats.json      ├── verification.json
├── functions.json      ├── protocols.json    └── dead_ends.json
├── structures.json     ├── hypotheses.json
├── states.json         └── systems.json
```

Ten JSON files, one per category, each entry carrying a status, its evidence,
and the confidence the status can justify. `scripts/recon-ledger.py` maintains
them and refuses entries that outrun their own evidence.

The readable Markdown — `dead-ends.md`, `hypotheses.md`,
`known-formats.md`, `known-offsets.md`, `known-protocols.md` — is **rendered
from the ledger**:

```sh
scripts/recon-ledger.py render ./reconstruction -o ./project-state/
```

This is the part worth insisting on. Keeping the notes as a second,
hand-maintained store does not work, and it fails in a specific way: a session
reads the Markdown, decides something, writes the conclusion in the ledger,
and does not update the notes. Both are correct on different days. The next
session reads the notes, finds a stale answer, and acts on it. Nothing
reports the disagreement, because there is nothing that could.

One store, or two that disagree. Generating the second from the first is the
only version of "two" that survives a month.

## Working with it

```sh
scripts/recon-ledger.py init ./reconstruction

# record a hypothesis the day it is formed, before it is tested
scripts/recon-ledger.py add ./reconstruction hypotheses "asset at 0x1a40" \
    --status hypothesized --source static \
    --evidence "4 KiB region, entropy 7.8, no known magic" \
    --evidence "referenced by exactly one function, sub_4a2010" \
    --hypothesis "encrypted with a key derived at runtime" \
    --next-test "trace sub_4a2010 at startup and look for a key-sized write"

# and the moment it is refuted -- as a dead end, not a deleted hypothesis
scripts/recon-ledger.py add ./reconstruction dead_ends "LZ4 payload" \
    --status refuted --source static \
    --evidence "lz4 -d at 0x1a40 -> bad magic" \
    --evidence "lz4.frame.decompress -> LZ4Error" \
    --evidence "frame magic 0x184D2204 absent" \
    --hypothesis "the asset payload is LZ4-compressed" \
    --refuted-by "two decoders and the magic bytes all disagree" \
    --avoid "measure entropy before choosing the next codec"

# what is still open -- the question that picks the next hour of work
scripts/recon-ledger.py gaps ./reconstruction
```

`--source` records which layer produced the evidence: `static`, `dynamic`,
`runtime`, `dump`, `diff`, `asset`, `protocol`, `other`. It matters more than
it looks. An entry whose source is unknown cannot be re-checked the way it was
found, and a claim that rests on a watchpoint defended later as a static
reading is how a static conclusion gets made from a dynamic observation.

## dead_ends.json — the important one

Record a refuted hypothesis *as soon as it is refuted*, with enough detail that
the next reader can tell the test was adequate rather than merely abandoned.

Three fields carry the weight:

| Field | Why it is required |
| --- | --- |
| `hypothesis` | a refutation without the claim says only that something failed |
| `refuted_by` | what actually settled it, so nobody repeats the test |
| `avoid` | what not to do instead — this is what turns history into guidance |

```sh
scripts/recon-ledger.py add ./reconstruction dead_ends "LZ4 payload" \
    --status refuted --source static \
    --evidence "lz4 -d on the region at 0x1a40 -> bad magic" \
    --evidence "Python lz4.frame.decompress() -> LZ4Error" \
    --evidence "byte distribution vs LZ4 output entropy (~6.9 bits) -> 7.8" \
    --hypothesis "the asset payload is LZ4-compressed" \
    --refuted-by "two decoders and the magic bytes all disagree" \
    --avoid "do not retry LZ4; the entropy is already-compressed level" \
    --next-test "compare against a zstd frame, which fits 7.8 bits"
```

The `next_test` is the redirect: a refutation that points at the next
candidate is not a dead end, it is progress.

### Reopening one

An idea legitimately comes back — a tool was missing, a trace was too short,
the code was patched. Reopening it *silently* is what costs a day, because
nobody realises the question was already settled.

So `add` checks every new entry against the dead ends and refuses a match that
records nothing new:

```
$ recon-ledger.py add ./reconstruction formats "payload codec" \
    --hypothesis "the asset payload is LZ4-compressed" ...
error: this entry reopens a recorded dead end, and nothing records what is new:
  - LZ4 payload: it restates the hypothesis a recorded dead end refuted
      refuted by: two decoders and the magic bytes all disagree
      recorded as: do not retry LZ4; measure entropy before choosing the codec
```

Three things match: the same name, a reference to the dead end's subject, and
a restatement of the claim. `--new-evidence` states what changed — a decoder
that is now installed, a longer trace — and the entry goes in. A record of the
reason is the whole requirement.

## hypotheses.json — live status

`status: hypothesized` is the normal state of a claim the day it is formed.
What it demands is a `next_test` or a recorded test, so that every live
hypothesis is actionable by whoever picks it up.

```sh
scripts/recon-ledger.py add ./reconstruction hypotheses "asset at 0x1a40" \
    --status hypothesized --confidence low --source static \
    --evidence "entropy 7.8, no magic, referenced only by sub_4a2010" \
    --hypothesis "encrypted, key derived at runtime" \
    --next-test "trace sub_4a2010 at startup for a key-sized write"
```

A test that cannot be run in this environment is not a different status — it is
a `next_test` that states the precondition, so it is not silently retried
under identical conditions.

## formats.json and protocols.json

Record what has been decoded, with the decoder and any version assumption.
This stops a format being re-derived from scratch, and stops a *different*
format being assumed to match.

```sh
scripts/recon-ledger.py add ./reconstruction formats "package header" \
    --status reconstructed --source asset \
    --evidence "magic 0x5051474M at 0x0000, fields parse for 40 entries" \
    --hypothesis "custom TLV: tag u16, length u32" \
    --tests "round-tripped 40 entries byte-identically" \
    --next-test "check whether the length counts the tag"

scripts/recon-ledger.py add ./reconstruction protocols "session control" \
    --status observed --source protocol \
    --evidence "40 captures; the length at +0x00 equals the frame size" \
    --observed-behavior "one connection, client sends type 2, server type 1"
```

A parser that has not run against real bytes is a hypothesis, not a protocol.

## structures.json — offsets

Structures shift between versions. Record the version each offset was derived
from, or the note is worthless next month.

```json
{"name": "entity_state", "kind": "structure",
 "status": "partially-reconstructed", "source": "runtime",
 "derived_from": "libfoo.so v1.4.2 (sha256:…)",
 "fields": [
   {"offset": "+0x08", "size": 4, "type": "int32",
    "evidence": "compared against 0..1000 in sub_4a1300", "confidence": "medium"},
   {"offset": "+0x0c", "size": 4, "type": "unknown",
    "evidence": "written once at init, never in the hot path", "confidence": "low"}],
 "notes": "no access past +0x0c observed; the struct may be larger"}
```

The `fields` list is optional and only affects how `render` lays out
`known-offsets.md`. The "no access past +0x0c" line is load-bearing: it tells
the next reader where the layout stops being known.

## Reading state before working

```sh
scripts/recon-ledger.py gaps ./reconstruction        # what is still open
scripts/recon-ledger.py render ./reconstruction -o ./project-state/
cat project-state/dead-ends.md
```

`gaps` is the command that replaces reading five files. It reports, from the
ledger:

- claims whose status outruns their recorded tests;
- hypotheses with nothing that could settle them;
- recorded contradictions with no recorded answer;
- assumptions that other entries depend on;
- **categories never asked** — an empty category means the question was never
  asked, not that it was answered;
- entries with no recorded `source`.

That last distinction is the one a status summary gets wrong most easily. A
ledger full of `verified` entries and seven empty categories is not a finished
investigation.

## Keeping the state honest

- Record a refutation the moment it happens. A dead end recorded late is a
  dead end retried.
- Date every entry. A refutation from three versions ago may be stale.
- Record the version the evidence came from.
- Prefer "refuted" with detail over silence. Silence loses the information.
- Say what was tried, not just what failed. "Three decompressors" is a result;
  "tried x" is a lead.
- When a dead end is reopened, `--new-evidence` says why.

## Runtime observations in the state

A runtime finding is recorded like any other entry, with `source: runtime`, and
it brings two fields a static finding does not have: the **thread**, and the
**version of the build the address was taken from**.

- A write with no tid cannot be attributed, and under concurrency the
  attribution is usually the point.
- A runtime address is meaningless in the state file. Record `module+0xoffset`,
  which survives ASLR, and note the module base separately if the map is saved.
- Record whether the observation came from a saved map, a debugger, or an
  in-process hook. `memory-map.py` reading a file and a watchpoint under a
  debugger are not the same evidence, and only one of them perturbs the run.

A hypothesis that came from runtime correlation needs its experiment recorded
beside it. "0x1400 ran and then the field changed" is a correlation; the
experiment that makes it a cause is a separate entry, and until it runs the
claim stays a hypothesis. `scripts/runtime-events.py --validate` rejects the
`caused_by` field without one.

## See also

- `reconstruction.md` — where reconstruction sits, and what it owes
- `methodology.md` — the evidence loop these entries serve
- `differential-testing.md` — recording tests and what they showed
- `memory-runtime.md` — the runtime observations that enter here
- `emulation.md`, `obfuscation.md` — investigations that go through an
  emulator, or through code that resists reading
- `templates/reconstruction/README.md` — the full entry schema